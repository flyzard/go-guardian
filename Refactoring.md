# Go Guardian Framework Refactoring Plan

## Executive Summary

This document outlines a comprehensive refactoring plan for the Go Guardian framework to reduce code duplication, minimize code size, and improve architecture while maintaining full backward compatibility. The refactoring is designed to be implemented in phases to minimize risk and allow for gradual adoption.

## Current Analysis

### Code Duplication Identified

#### 1. Configuration Pattern Duplication (30% reduction potential)
- **Location**: `guardian.go`, `auth/auth.go`, `database/connection.go`, `middleware/*.go`
- **Pattern**: Each module defines its own `Default*Config()` function and configuration struct
- **Impact**: ~500 lines of duplicated configuration code

#### 2. Table/Column Name Mapping (20% reduction potential)
- **Location**: 
  - `guardian.go`: `TableNames`, `ColumnNames` structs
  - `auth/auth.go`: `TableConfig`, `ColumnConfig` structs
  - `database/connection.go`: `TableMapping` struct
- **Impact**: ~150 lines of duplicated struct definitions and default functions

#### 3. HTMX Handling Scattered (15% reduction potential)
- **Location**: 
  - `middleware/csrf.go`: Lines 47, 76-81, 88-90
  - `web/response.go`: HTMX-aware response building
  - `web/template/htmx.go`: HTMX utilities
- **Pattern**: `r.Header.Get("HX-Request") == "true"` check repeated
- **Impact**: ~100 lines of duplicated HTMX detection and handling

#### 4. Response Building Patterns (25% reduction potential)
- **Location**: `web/response.go`, `web/errors.go`, `middleware/*.go`
- **Pattern**: Multiple ways to build error responses, alerts, and JSON responses
- **Impact**: ~200 lines of duplicated response building logic

#### 5. Session Management Code (10% reduction potential)
- **Location**: `guardian.go`, `auth/sessions.go`, `middleware/session.go`
- **Pattern**: Session creation, retrieval, and cookie handling duplicated
- **Impact**: ~80 lines of duplicated session operations

## Proposed Architecture Improvements

### Phase 1: Configuration Consolidation (Low Risk, High Impact)

#### 1.1 Create Unified Configuration Framework

```go
// config/base.go
package config

import "reflect"

// Configurable provides a standard interface for all configurations
type Configurable[T any] interface {
    // Defaults returns the default configuration
    Defaults() T
    // Validate validates the configuration
    Validate() error
    // Merge merges with another configuration (for partial configs)
    Merge(other T) T
}

// BaseConfig provides common configuration functionality
type BaseConfig[T any] struct {
    defaults T
}

// ApplyDefaults uses reflection to apply default values to zero fields
func ApplyDefaults[T any](cfg *T, defaults T) {
    // Implementation using reflection to fill zero values
}
```

#### 1.2 Centralize Table/Column Configuration

```go
// config/schema.go
package config

// SchemaConfig centralizes all table and column name mappings
type SchemaConfig struct {
    Tables  TableNames
    Columns ColumnNames
}

// Single source of truth for table names
type TableNames struct {
    Users           string `default:"users"`
    Tokens          string `default:"tokens"`
    Sessions        string `default:"sessions"`
    Roles           string `default:"roles"`
    Permissions     string `default:"permissions"`
    RolePermissions string `default:"role_permissions"`
    RememberTokens  string `default:"remember_tokens"`
}

// Single source of truth for column names
type ColumnNames struct {
    User  UserColumns
    Token TokenColumns
}

type UserColumns struct {
    ID       string `default:"id"`
    Email    string `default:"email"`
    Password string `default:"password_hash"`
    Verified string `default:"verified"`
    Created  string `default:"created_at"`
    RoleID   string `default:"role_id"`
}
```

### Phase 2: HTMX Centralization (Low Risk, Medium Impact)

#### 2.1 Create HTMX Package

```go
// htmx/detector.go
package htmx

import "net/http"

// IsHTMXRequest checks if request is from HTMX
func IsHTMXRequest(r *http.Request) bool {
    return r.Header.Get("HX-Request") == "true"
}

// GetTrigger returns the HX-Trigger header value
func GetTrigger(r *http.Request) string {
    return r.Header.Get("HX-Trigger")
}

// ResponseWriter wraps http.ResponseWriter with HTMX helpers
type ResponseWriter struct {
    http.ResponseWriter
}

// SetTrigger sets HX-Trigger response header
func (w *ResponseWriter) SetTrigger(event string) {
    w.Header().Set("HX-Trigger", event)
}

// Redirect performs HTMX-aware redirect
func (w *ResponseWriter) Redirect(url string) {
    w.Header().Set("HX-Redirect", url)
}
```

### Phase 3: Response Builder Unification (Medium Risk, High Impact)

#### 3.1 Unified Response Interface

```go
// response/builder.go
package response

// Response provides a unified response building interface
type Response interface {
    Status(code int) Response
    Header(key, value string) Response
    JSON(data any) error
    HTML(content string) error
    Error(err error) error
    Success(message string) error
}

// Builder implements Response with HTMX awareness
type Builder struct {
    w      http.ResponseWriter
    r      *http.Request
    status int
}

// New creates a response builder that automatically detects context
func New(w http.ResponseWriter, r *http.Request) Response {
    return &Builder{w: w, r: r, status: http.StatusOK}
}
```

### Phase 4: Feature Plugin System (High Risk, High Impact)

#### 4.1 Plugin Architecture

```go
// plugin/interface.go
package plugin

// Plugin defines the interface for Guardian plugins
type Plugin interface {
    // Name returns the plugin name
    Name() string
    // Init initializes the plugin
    Init(g *guardian.Guardian) error
    // Routes returns routes to register
    Routes() []Route
    // Middleware returns middleware to apply
    Middleware() []func(http.Handler) http.Handler
    // Migrations returns database migrations
    Migrations() []Migration
}

// Registry manages plugins
type Registry struct {
    plugins map[string]Plugin
}

// Enable activates a plugin
func (r *Registry) Enable(name string) error {
    // Implementation
}
```

#### 4.2 Convert Features to Plugins

```go
// plugins/auth/plugin.go
package auth

type AuthPlugin struct {
    config AuthConfig
}

func (p *AuthPlugin) Name() string { return "auth" }

func (p *AuthPlugin) Init(g *guardian.Guardian) error {
    // Initialize auth service
    return nil
}

func (p *AuthPlugin) Routes() []plugin.Route {
    return []plugin.Route{
        {Method: "POST", Path: "/login", Handler: p.handleLogin},
        {Method: "POST", Path: "/logout", Handler: p.handleLogout},
    }
}
```

## Implementation Strategy

### Phase 1 Implementation (Week 1-2)
1. Create `config` package with base configuration types
2. Migrate all configuration structs to use new base
3. Create backward-compatible adapters
4. Update tests

### Phase 2 Implementation (Week 3)
1. Create `htmx` package
2. Replace all HTMX detection with centralized version
3. Update middleware to use HTMX package
4. Ensure backward compatibility

### Phase 3 Implementation (Week 4-5)
1. Create unified response package
2. Deprecate old response methods
3. Provide migration guide
4. Update all internal usage

### Phase 4 Implementation (Week 6-8)
1. Design plugin interface
2. Convert one feature (e.g., CSRF) as proof of concept
3. Create plugin registry
4. Document plugin development

## Backward Compatibility Strategy

### 1. Adapter Pattern
```go
// Maintain old API with adapters
func DefaultTableNames() TableNames {
    return config.DefaultSchema().Tables
}
```

### 2. Deprecation Warnings
```go
// Deprecated: Use config.DefaultSchema() instead
func DefaultTableNames() TableNames {
    log.Println("DEPRECATED: DefaultTableNames() will be removed in v2.0")
    return config.DefaultSchema().Tables
}
```

### 3. Feature Flags for New Architecture
```go
type Config struct {
    // Existing fields...
    
    // EnablePluginSystem enables the new plugin architecture
    EnablePluginSystem bool `default:"false"`
}
```

## Code Reduction Estimates

### Current vs. Projected Lines of Code

| Component | Current | After Refactoring | Reduction |
|-----------|---------|-------------------|-----------|
| Configuration | ~800 | ~300 | 62.5% |
| Table/Column Mapping | ~250 | ~100 | 60% |
| HTMX Handling | ~150 | ~50 | 66.7% |
| Response Building | ~400 | ~200 | 50% |
| Session Management | ~300 | ~200 | 33.3% |
| **Total** | **~1900** | **~850** | **55.3%** |

## Benefits

### 1. Reduced Maintenance Burden
- Single source of truth for configurations
- Centralized HTMX handling
- Unified response patterns

### 2. Improved Developer Experience
- Clearer architecture
- Better IDE support with generics
- Easier to understand and extend

### 3. Better Performance
- Reduced binary size with plugin system
- Compile-time optimizations with generics
- Less reflection usage

### 4. Enhanced Testability
- Mockable interfaces
- Plugin isolation
- Configuration validation

## Risk Mitigation

### 1. Comprehensive Testing
- Maintain 100% backward compatibility tests
- Add integration tests for each phase
- Performance benchmarks before/after

### 2. Gradual Rollout
- Feature flags for new systems
- Parallel old/new implementations
- Clear migration documentation

### 3. Community Feedback
- RFC for major changes
- Beta releases for each phase
- Migration tools and guides

## Metrics for Success

1. **Code Reduction**: Achieve 50%+ reduction in duplicated code
2. **Performance**: No regression in benchmarks
3. **Compatibility**: 100% backward compatibility maintained
4. **Adoption**: Smooth migration for existing users
5. **Maintainability**: Reduced issue count related to configuration

## Timeline

- **Month 1**: Phase 1 & 2 (Configuration & HTMX)
- **Month 2**: Phase 3 (Response Building)
- **Month 3**: Phase 4 (Plugin System) - Initial
- **Month 4**: Testing, Documentation, Migration Tools
- **Month 5**: Beta Release
- **Month 6**: Stable Release

## Conclusion

This refactoring plan provides a path to a leaner, more maintainable Go Guardian framework while ensuring full backward compatibility. The phased approach minimizes risk and allows for community feedback throughout the process. The result will be a more elegant architecture that's easier to understand, extend, and maintain.