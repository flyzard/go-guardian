# Guardian Plugin Development Guide

## Overview

The Guardian Plugin System allows you to extend the framework with modular features that can be enabled/disabled at runtime. This guide explains how to develop custom plugins for Guardian.

## Plugin Interface

All plugins must implement the `Plugin` interface:

```go
type Plugin interface {
    Name() string                        // Unique plugin identifier
    Description() string                 // Brief description
    Init(ctx *Context) error            // Initialize with Guardian context
    Routes() []Route                    // HTTP routes to register
    Middleware() []Middleware           // HTTP middleware to apply
    Migrations() []database.Migration   // Database migrations
    RequiredTables() []string          // Required database tables
    Cleanup() error                    // Cleanup on disable
}
```

## Basic Plugin Example

Here's a simple plugin that adds a health check endpoint:

```go
package health

import (
    "net/http"
    "github.com/flyzard/go-guardian/plugin"
    "github.com/flyzard/go-guardian/database"
)

type HealthPlugin struct {
    db *database.DB
}

func New() *HealthPlugin {
    return &HealthPlugin{}
}

func (p *HealthPlugin) Name() string {
    return "health"
}

func (p *HealthPlugin) Description() string {
    return "Provides health check endpoints"
}

func (p *HealthPlugin) Init(ctx *plugin.Context) error {
    p.db = ctx.DB
    return nil
}

func (p *HealthPlugin) Routes() []plugin.Route {
    return []plugin.Route{
        {
            Method:      "GET",
            Path:        "/health",
            Handler:     p.handleHealth,
            Description: "Health check endpoint",
        },
    }
}

func (p *HealthPlugin) Middleware() []plugin.Middleware {
    return nil // No middleware needed
}

func (p *HealthPlugin) Migrations() []database.Migration {
    return nil // No database tables needed
}

func (p *HealthPlugin) RequiredTables() []string {
    return nil
}

func (p *HealthPlugin) Cleanup() error {
    return nil
}

func (p *HealthPlugin) handleHealth(w http.ResponseWriter, r *http.Request) {
    // Check database connection
    if err := p.db.DB.Ping(); err != nil {
        w.WriteHeader(http.StatusServiceUnavailable)
        w.Write([]byte("Database unavailable"))
        return
    }
    
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}
```

## Optional Interfaces

### ConfigurablePlugin

For plugins that support configuration:

```go
type ConfigurablePlugin interface {
    Plugin
    DefaultConfig() interface{}
    ValidateConfig(config interface{}) error
}
```

Example:

```go
type Config struct {
    Timeout     time.Duration
    MaxRetries  int
}

func (p *MyPlugin) DefaultConfig() interface{} {
    return Config{
        Timeout:    30 * time.Second,
        MaxRetries: 3,
    }
}

func (p *MyPlugin) ValidateConfig(config interface{}) error {
    cfg, ok := config.(Config)
    if !ok {
        return plugin.ErrInvalidConfig
    }
    
    if cfg.Timeout < 0 {
        return errors.New("timeout must be positive")
    }
    
    return nil
}
```

### LifecyclePlugin

For plugins that need startup/shutdown hooks:

```go
type LifecyclePlugin interface {
    Plugin
    OnStart() error
    OnStop() error
}
```

Example:

```go
func (p *MyPlugin) OnStart() error {
    // Start background workers
    go p.startWorker()
    return nil
}

func (p *MyPlugin) OnStop() error {
    // Stop background workers
    close(p.stopChan)
    return nil
}
```

### DependentPlugin

For plugins with dependencies on other plugins:

```go
type DependentPlugin interface {
    Plugin
    Dependencies() []string
}
```

Example:

```go
func (p *MyPlugin) Dependencies() []string {
    return []string{"auth", "csrf"} // Requires auth and csrf plugins
}
```

## Plugin Context

The `Context` provides access to Guardian services:

```go
type Context struct {
    DB           *database.DB          // Database connection
    SessionStore interface{}           // Session management
    Config       map[string]interface{} // Plugin configurations
}
```

## Middleware Priority

Middleware is sorted by priority (lower values execute first):

```go
func (p *MyPlugin) Middleware() []plugin.Middleware {
    return []plugin.Middleware{
        {
            Handler:     p.authMiddleware,
            Priority:    10,  // Runs early
            Description: "Authentication check",
        },
        {
            Handler:     p.loggingMiddleware,
            Priority:    100, // Runs later
            Description: "Request logging",
        },
    }
}
```

## Database Migrations

Plugins can provide database migrations:

```go
func (p *MyPlugin) Migrations() []database.Migration {
    return []database.Migration{
        {
            Version: "myplugin_001",
            Name:    "create_my_table",
            UpSQLite: `
                CREATE TABLE IF NOT EXISTS my_table (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            `,
            DownSQLite: `DROP TABLE IF EXISTS my_table;`,
            UpMySQL: `
                CREATE TABLE IF NOT EXISTS my_table (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    name VARCHAR(255) NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            `,
            DownMySQL: `DROP TABLE IF EXISTS my_table;`,
        },
    }
}
```

## Registration and Usage

### 1. Register your plugin in Guardian:

```go
func registerBuiltinPlugins(registry *plugin.Registry) {
    // Existing plugins...
    
    // Register your plugin
    if err := registry.Register(health.New()); err != nil {
        log.Printf("Failed to register health plugin: %v", err)
    }
}
```

### 2. Enable in configuration:

```go
app := guardian.New(guardian.Config{
    EnablePluginSystem: true,
    Plugins: []string{"health"}, // Enable your plugin
    // ... other config
})
```

### 3. Or enable programmatically:

```go
if err := app.EnablePlugin("health"); err != nil {
    log.Fatal(err)
}
```

## Best Practices

1. **Naming**: Use lowercase, descriptive names without spaces
2. **Error Handling**: Always return meaningful errors from Init()
3. **Cleanup**: Implement proper cleanup to avoid resource leaks
4. **Dependencies**: Declare all dependencies explicitly
5. **Configuration**: Provide sensible defaults
6. **Documentation**: Document all routes and configuration options
7. **Testing**: Write tests for your plugin functionality

## Example: Rate Limiting Plugin

Here's a more complex example implementing rate limiting:

```go
package ratelimit

import (
    "net/http"
    "sync"
    "time"
    
    "github.com/flyzard/go-guardian/plugin"
    "github.com/flyzard/go-guardian/response"
)

type Config struct {
    RequestsPerMinute int
    BurstSize        int
}

type RateLimitPlugin struct {
    config   Config
    limiters map[string]*rateLimiter
    mu       sync.RWMutex
}

func New() *RateLimitPlugin {
    return &RateLimitPlugin{
        config: Config{
            RequestsPerMinute: 60,
            BurstSize:        10,
        },
        limiters: make(map[string]*rateLimiter),
    }
}

func (p *RateLimitPlugin) Name() string { return "ratelimit" }

func (p *RateLimitPlugin) Description() string {
    return "Provides request rate limiting"
}

func (p *RateLimitPlugin) Init(ctx *plugin.Context) error {
    if cfg, ok := ctx.Config["ratelimit"]; ok {
        if rlConfig, ok := cfg.(Config); ok {
            p.config = rlConfig
        }
    }
    
    // Start cleanup routine
    go p.cleanupRoutine()
    
    return nil
}

func (p *RateLimitPlugin) Middleware() []plugin.Middleware {
    return []plugin.Middleware{
        {
            Handler:     p.rateLimitMiddleware(),
            Priority:    5, // Run very early
            Description: "Rate limiting",
        },
    }
}

func (p *RateLimitPlugin) rateLimitMiddleware() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get client IP
            clientIP := r.RemoteAddr
            
            // Get or create limiter
            p.mu.Lock()
            limiter, exists := p.limiters[clientIP]
            if !exists {
                limiter = newRateLimiter(p.config.RequestsPerMinute, p.config.BurstSize)
                p.limiters[clientIP] = limiter
            }
            p.mu.Unlock()
            
            // Check rate limit
            if !limiter.Allow() {
                response.New(w, r).
                    Status(http.StatusTooManyRequests).
                    Header("Retry-After", "60").
                    Text("Rate limit exceeded").
                    Send()
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}

// ... implementation details ...
```

## Testing Your Plugin

```go
func TestRateLimitPlugin(t *testing.T) {
    ctx := &plugin.Context{
        Config: map[string]interface{}{
            "ratelimit": Config{
                RequestsPerMinute: 10,
                BurstSize:        2,
            },
        },
    }
    
    p := New()
    if err := p.Init(ctx); err != nil {
        t.Fatalf("Failed to init plugin: %v", err)
    }
    
    // Test rate limiting logic...
}
```

## Debugging

Enable debug logging to see plugin lifecycle:

```go
export GUARDIAN_DEBUG=true
```

This will log:
- Plugin registration
- Plugin enable/disable
- Route registration
- Middleware application

## Common Pitfalls

1. **Not handling nil context**: Always check context fields before use
2. **Forgetting cleanup**: Resources allocated in Init() should be released in Cleanup()
3. **Blocking in Init()**: Long-running operations should be done in goroutines
4. **Not checking features**: Respect feature flags when applicable
5. **Circular dependencies**: Avoid plugins that depend on each other

## Future Enhancements

The plugin system is designed to support future features like:
- Dynamic plugin loading from external files
- Plugin marketplace/registry
- Hot reload of plugins
- Plugin-to-plugin communication
- Event system for plugins