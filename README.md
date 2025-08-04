# Go Guardian

A security-focused web framework for Go that makes secure web development simple, intuitive, and robust. Built on top of the high-performance Chi router, Go Guardian provides enterprise-grade security features while maintaining the simplicity and elegance of Go.

## Table of Contents

- [Introduction & Philosophy](#introduction--philosophy)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Core Concepts](#core-concepts)
- [Configuration](#configuration)
- [Authentication System](#authentication-system)
- [Database Layer](#database-layer)
- [Middleware System](#middleware-system)
- [Web Features](#web-features)
- [Security Features](#security-features)
- [Advanced Topics](#advanced-topics)
- [Production Deployment](#production-deployment)
- [API Reference](#api-reference)
- [Examples](#examples)

## Introduction & Philosophy

Go Guardian is designed with three core principles:

1. **Security First**: Every feature is built with security as the primary concern. From CSRF protection to SQL injection prevention, security isn't an afterthought—it's the foundation.

2. **Modular Flexibility**: Enable only what you need. Through feature flags, you can run a minimal setup with just a users table, or enable full features including RBAC, email verification, and more.

3. **Production Ready**: Sensible defaults, comprehensive error handling, and battle-tested patterns make Go Guardian suitable for production use from day one.

### Why Go Guardian?

Unlike many web frameworks that add security as middleware layers, Go Guardian integrates security at every level:

- **Input validation** happens before data reaches your handlers
- **SQL queries** are always parameterized through our query builder
- **Sessions** are encrypted and tamper-proof by default
- **Authentication** includes rate limiting and secure password handling out of the box
- **CSRF protection** uses the double-submit cookie pattern automatically
- **Realtime support** through WebSocket and Server-Sent Events middleware

## Architecture Overview

Go Guardian is built as a layered architecture:

```
┌─────────────────────────────────────────────────┐
│                   Application                    │
├─────────────────────────────────────────────────┤
│                  Web Features                    │
│  (Handlers, Templates, Response Builders)        │
├─────────────────────────────────────────────────┤
│                  Middleware                      │
│  (Security, CSRF, Auth, Logging, HTMX)         │
├─────────────────────────────────────────────────┤
│                    Router                        │
│         (Chi-based with Guardian extensions)     │
├─────────────────────────────────────────────────┤
│                 Core Services                    │
│        (Auth, Sessions, Database, Security)      │
├─────────────────────────────────────────────────┤
│                   Database                       │
│        (Query Builder, Migrations, Schema)       │
└─────────────────────────────────────────────────┘
```

### Key Components

- **Guardian**: The main application instance that ties everything together
- **Router**: Extended Chi router with Guardian-specific features
- **Auth**: Complete authentication system with pluggable backends
- **Database**: Safe query builder with migration support
- **Middleware**: Composable middleware for security, logging, and more (including WebSocket/SSE)
- **Web**: Advanced handler patterns and template rendering

## Installation

```bash
go get github.com/flyzard/go-guardian
```

### Prerequisites

- Go 1.21 or higher
- SQLite or MySQL database
- 32-byte secret key for sessions

## Getting Started

### Minimal Example

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/flyzard/go-guardian"
    "github.com/flyzard/go-guardian/middleware"
)

func main() {
    // Create Guardian instance with minimal config
    app := guardian.New(guardian.Config{
        SessionKey: []byte("your-32-byte-secret-key-here!!!"), // Generate with: openssl rand -base64 32
    })
    
    // Apply essential security middleware
    app.Use(middleware.SecurityHeaders)  // Adds security headers
    app.Use(middleware.CSRF)             // CSRF protection
    app.Use(middleware.Logger)           // Request logging
    
    // Define a simple route
    app.GET("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("<h1>Welcome to Go Guardian!</h1>"))
    })
    
    // Start the server
    log.Fatal(app.Listen(":8080"))
}
```

### Understanding the Minimal Example

1. **SessionKey**: Required 32-byte key for encrypting session cookies. In production, load this from environment variables.
2. **Default Configuration**: Uses SQLite database (`app.db`), cookie-based sessions, and development mode.
3. **Middleware Order**: Security headers should come first, followed by CSRF protection.
4. **Database Creation**: Guardian automatically creates required tables on first run.

## Core Concepts

### The Guardian Instance

The Guardian instance is your application's core:

```go
type Guardian struct {
    *router.Router      // Chi router with extensions
    config    Config    // Application configuration
    auth      *auth.Auth // Authentication service
    db        *database.DB // Database connection
    sessions  sessions.Store // Session store
}
```

### Router and Route Groups

Guardian extends Chi's router with additional functionality:

```go
// Basic routing
app.GET("/users", listUsers)
app.POST("/users", createUser)
app.PUT("/users/{id}", updateUser)
app.DELETE("/users/{id}", deleteUser)

// Route groups with shared middleware
api := app.Group("/api/v1")
api.Use(middleware.JSON) // All API routes return JSON

// Nested groups
admin := api.Group("/admin")
admin.Use(middleware.RequireAuth(app.Sessions()))
admin.Use(middleware.RequirePermission("admin.access"))
```

### Request Context

Guardian enriches the request context with useful data:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Get authenticated user
    user, err := app.Auth().GetUser(r)
    
    // Get CSRF token
    token := middleware.GetCSRFToken(r)
    
    // Get request ID for logging
    reqID := middleware.GetRequestID(r)
}
```

### Handler Patterns

Guardian supports multiple handler patterns:

```go
// Standard http.HandlerFunc
app.GET("/", func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello"))
})

// http.Handler interface
app.GET("/", http.HandlerFunc(handler))

// Method handlers
app.Route("/users", func(r chi.Router) {
    r.Get("/", listUsers)
    r.Post("/", createUser)
})
```

## Configuration

### Basic Configuration Structure

```go
type Config struct {
    // Required
    SessionKey []byte // Must be exactly 32 bytes
    
    // Environment
    Environment string // "development" or "production"
    
    // Database
    DatabaseType     string        // "sqlite" or "mysql"
    DatabasePath     string        // For SQLite
    DatabaseDSN      string        // For MySQL
    MaxOpenConns     int          // Connection pool size
    MaxIdleConns     int          // Idle connection pool
    ConnMaxLifetime  time.Duration // Connection lifetime
    
    // Features
    Features         Features      // Feature flags
    
    // Customization
    TableNames       TableNames    // Custom table names
    ColumnNames      ColumnNames   // Custom column names
    
    // Session
    SessionBackend   SessionBackend // "cookie", "memory", or "database"
    SessionOptions   *sessions.Options // Cookie settings
    
    // Migration
    AutoMigrate      bool          // Run migrations on startup
    ValidateSchema   bool          // Validate database schema
}
```

### Feature Flags

Control which features are enabled and their database requirements:

```go
type Features struct {
    EmailVerification bool // Requires: tokens table
    PasswordReset     bool // Requires: tokens table  
    RememberMe        bool // Requires: remember_tokens table
    RBAC              bool // Requires: roles, permissions, role_permissions tables
    ExternalAuth      bool // Enables passwordless auth for SSO/LDAP
}
```

#### Minimal Setup (External Auth Only)

```go
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    Features: guardian.Features{
        EmailVerification: false,
        PasswordReset:     false,
        RememberMe:        false,
        RBAC:              false,
        ExternalAuth:      true,
    },
})
// Only requires: users table (id, email, created_at)
```

#### Full-Featured Setup

```go
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    Environment: "production",
    DatabaseType: "mysql",
    DatabaseDSN: "user:password@tcp(localhost:3306)/myapp?parseTime=true",
    // All features enabled by default
})
// Requires all tables: users, tokens, sessions, roles, permissions, role_permissions, remember_tokens
```

### Custom Table and Column Names

Integrate with existing database schemas:

```go
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    TableNames: guardian.TableNames{
        Users:  "members",        // Default: "users"
        Tokens: "auth_tokens",    // Default: "tokens"
        Roles:  "member_roles",   // Default: "roles"
    },
    ColumnNames: guardian.ColumnNames{
        UserEmail:    "email_address",  // Default: "email"
        UserPassword: "pwd_hash",       // Default: "password_hash"
        UserVerified: "is_active",      // Default: "verified"
    },
})
```

### Session Configuration

#### Cookie Sessions (Default)

```go
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    SessionBackend: guardian.SessionBackendCookie,
    SessionOptions: &sessions.Options{
        Path:     "/",
        Domain:   "example.com",
        MaxAge:   86400 * 7, // 1 week
        Secure:   true,      // HTTPS only
        HttpOnly: true,      // No JavaScript access
        SameSite: http.SameSiteStrictMode,
    },
})
```

#### Memory Sessions

```go
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    SessionBackend: guardian.SessionBackendMemory,
    // Sessions stored in memory, lost on restart
})
```

#### Database Sessions (Coming Soon)

```go
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    SessionBackend: guardian.SessionBackendDatabase,
    // Sessions stored in database for horizontal scaling
})
```

### Environment-Specific Defaults

Development mode (`Environment: "development"`):
- Relaxed CORS settings
- Detailed error messages
- Insecure cookie settings allowed
- Verbose logging

Production mode (`Environment: "production"`):
- Strict CORS validation
- Generic error messages
- Secure cookies enforced
- Structured logging
- HTTPS required for secure cookies

## Authentication System

### Architecture Overview

The authentication system provides:
- User registration and login
- Session management
- Email verification (optional)
- Password reset (optional)
- Remember me functionality (optional)
- Role-based access control (optional)
- External authentication support

### Basic Authentication Flow

#### Registration

```go
app.POST("/register", func(w http.ResponseWriter, r *http.Request) {
    // Parse and validate input
    input := auth.RegisterInput{
        Email:    r.FormValue("email"),
        Password: r.FormValue("password"),
    }
    
    if err := input.Validate(); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    // Register user
    user, err := app.Auth().Register(input.Email, input.Password)
    if err != nil {
        if errors.Is(err, auth.ErrUserExists) {
            http.Error(w, "Email already registered", http.StatusConflict)
            return
        }
        http.Error(w, "Registration failed", http.StatusInternalServerError)
        return
    }
    
    // Auto-login after registration (optional)
    err = app.Auth().CreateSession(w, r, user.ID, user.Email)
    if err != nil {
        http.Error(w, "Login failed", http.StatusInternalServerError)
        return
    }
    
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
})
```

#### Login

```go
app.POST("/login", func(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    rememberMe := r.FormValue("remember_me") == "on"
    
    // Attempt login
    err := app.Auth().Login(w, r, email, password)
    if err != nil {
        if errors.Is(err, auth.ErrInvalidCredentials) {
            http.Error(w, "Invalid email or password", http.StatusUnauthorized)
            return
        }
        http.Error(w, "Login failed", http.StatusInternalServerError)
        return
    }
    
    // Handle remember me
    if rememberMe && app.Config.Features.RememberMe {
        user, _ := app.Auth().GetUser(r)
        app.Auth().CreateRememberToken(w, user.ID)
    }
    
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
})
```

#### Logout

```go
app.POST("/logout", func(w http.ResponseWriter, r *http.Request) {
    app.Auth().Logout(w, r)
    http.Redirect(w, r, "/", http.StatusSeeOther)
})
```

### Email Verification

When enabled, users must verify their email before accessing protected resources:

```go
// After registration
if app.Config.Features.EmailVerification {
    token, err := app.Auth().CreateVerificationToken(user.ID)
    if err != nil {
        // Handle error
    }
    
    // Send verification email
    verifyURL := fmt.Sprintf("https://example.com/verify?token=%s", token.Token)
    sendEmail(user.Email, "Verify your email", verifyURL)
}

// Verification handler
app.GET("/verify", func(w http.ResponseWriter, r *http.Request) {
    tokenValue := r.URL.Query().Get("token")
    
    validated, err := app.Auth().ValidateToken(tokenValue, auth.TokenEmailVerification)
    if err != nil {
        http.Error(w, "Invalid or expired token", http.StatusBadRequest)
        return
    }
    
    err = app.Auth().VerifyUserEmail(validated.UserID)
    if err != nil {
        http.Error(w, "Verification failed", http.StatusInternalServerError)
        return
    }
    
    w.Write([]byte("Email verified successfully!"))
})
```

### Password Reset

```go
// Request password reset
app.POST("/forgot-password", func(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    
    token, err := app.Auth().CreatePasswordResetToken(email)
    if err != nil {
        // Always return success to prevent email enumeration
        w.Write([]byte("If that email exists, we've sent a reset link"))
        return
    }
    
    resetURL := fmt.Sprintf("https://example.com/reset-password?token=%s", token.Token)
    sendEmail(email, "Reset your password", resetURL)
    
    w.Write([]byte("If that email exists, we've sent a reset link"))
})

// Reset password
app.POST("/reset-password", func(w http.ResponseWriter, r *http.Request) {
    tokenValue := r.FormValue("token")
    newPassword := r.FormValue("password")
    
    validated, err := app.Auth().ValidateToken(tokenValue, auth.TokenPasswordReset)
    if err != nil {
        http.Error(w, "Invalid or expired token", http.StatusBadRequest)
        return
    }
    
    err = app.Auth().UpdatePassword(validated.UserID, newPassword)
    if err != nil {
        http.Error(w, "Password update failed", http.StatusInternalServerError)
        return
    }
    
    // Invalidate all existing sessions
    app.Auth().InvalidateAllSessions(validated.UserID)
    
    w.Write([]byte("Password reset successfully"))
})
```

### External Authentication (SSO/LDAP)

For applications using external authentication:

```go
// After external auth validation (e.g., SAML, OAuth, LDAP)
app.POST("/sso/callback", func(w http.ResponseWriter, r *http.Request) {
    // Validate external auth token/response
    email := validateExternalAuth(r)
    if email == "" {
        http.Error(w, "Invalid authentication", http.StatusUnauthorized)
        return
    }
    
    // Check if user exists
    user, err := app.Auth().GetUserByEmail(email)
    if err != nil {
        // Register new user without password
        user, err = app.Auth().RegisterExternalUser(email)
        if err != nil {
            http.Error(w, "Registration failed", http.StatusInternalServerError)
            return
        }
    }
    
    // Create session
    err = app.Auth().CreateSession(w, r, user.ID, user.Email)
    if err != nil {
        http.Error(w, "Session creation failed", http.StatusInternalServerError)
        return
    }
    
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
})
```

### Role-Based Access Control (RBAC)

When RBAC is enabled:

```go
// Check permissions in handlers
func adminHandler(w http.ResponseWriter, r *http.Request) {
    user, _ := app.Auth().GetUser(r)
    
    if !app.Auth().UserHasPermission(user.ID, "admin.users.edit") {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    
    // Handle admin action
}

// Assign roles
err := app.Auth().AssignRole(userID, roleID)

// Create custom roles
role, err := app.Auth().CreateRole("editor", "Content Editor")
err = app.Auth().AssignPermissionToRole(role.ID, "content.edit")
err = app.Auth().AssignPermissionToRole(role.ID, "content.publish")

// Use middleware for route protection
admin := app.Group("/admin")
admin.Use(middleware.RequirePermission("admin.access"))
```

### Session Management

```go
// Get current user
user, err := app.Auth().GetUser(r)
if err != nil {
    // User not authenticated
}

// Check if authenticated
if app.Auth().IsAuthenticated(r) {
    // User is logged in
}

// Refresh session
app.Auth().RefreshSession(w, r)

// Invalidate specific session
app.Auth().InvalidateSession(sessionID)

// Invalidate all user sessions (e.g., after password change)
app.Auth().InvalidateAllSessions(userID)
```

## Database Layer

### Query Builder

Guardian's query builder provides a safe, fluent interface for database operations:

```go
// SELECT queries
var users []User
err := app.DB().Query().
    Select("users", "id", "email", "created_at").
    Where("verified", "=", true).
    Where("created_at", ">", time.Now().AddDate(0, -1, 0)).
    OrderBy("created_at", "DESC").
    Limit(10).
    QueryAll(&users)

// Single row
var user User
err := app.DB().Query().
    Select("users", "id", "email").
    Where("id", "=", userID).
    QueryRow(&user)

// INSERT
result, err := app.DB().Query().
    Insert("users", map[string]interface{}{
        "email":        email,
        "password_hash": hash,
        "verified":     false,
        "created_at":   time.Now(),
    })
lastID, _ := result.LastInsertId()

// UPDATE
result, err := app.DB().Query().
    Update("users",
        map[string]interface{}{
            "verified": true,
            "verified_at": time.Now(),
        },
        map[string]interface{}{
            "id": userID,
        },
    )

// DELETE
result, err := app.DB().Query().
    Delete("users", map[string]interface{}{
        "id": userID,
    })

// Raw queries (use sparingly)
rows, err := app.DB().Raw(
    "SELECT u.*, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.id WHERE u.verified = ?",
    true,
)
```

### Transactions

```go
tx, err := app.DB().Begin()
if err != nil {
    return err
}
defer tx.Rollback()

// Multiple operations in transaction
_, err = tx.Query().Insert("users", userData)
if err != nil {
    return err
}

_, err = tx.Query().Insert("profiles", profileData)
if err != nil {
    return err
}

// Commit if all successful
err = tx.Commit()
```

### Migrations

Guardian includes a built-in migration system:

```go
// Auto-migration (runs on startup by default)
app := guardian.New(guardian.Config{
    SessionKey: []byte("secret"),
    AutoMigrate: true,
})

// Manual migration
app.DB().RunMigrations()

// Run specific migrations
app.DB().RunMigration("001_create_users")
app.DB().RunMigration("002_add_roles")

// Check migration status
status, err := app.DB().GetMigrationStatus()
for _, migration := range status {
    fmt.Printf("%s: %s\n", migration.ID, migration.Status)
}
```

### Schema Validation

```go
// Validate that required tables and columns exist
app := guardian.New(guardian.Config{
    SessionKey: []byte("secret"),
    ValidateSchema: true, // Validates on startup
})

// Manual validation
errors := app.DB().ValidateSchema()
if len(errors) > 0 {
    for _, err := range errors {
        log.Printf("Schema error: %v", err)
    }
}
```

### Connection Management

```go
// Configure connection pool
app := guardian.New(guardian.Config{
    DatabaseType:    "mysql",
    DatabaseDSN:     "user:password@tcp(localhost:3306)/myapp",
    MaxOpenConns:    25,        // Maximum open connections
    MaxIdleConns:    5,         // Maximum idle connections
    ConnMaxLifetime: 5 * time.Minute, // Connection lifetime
})

// Get connection stats
stats := app.DB().Stats()
fmt.Printf("Open connections: %d\n", stats.OpenConnections)
fmt.Printf("In use: %d\n", stats.InUse)
fmt.Printf("Idle: %d\n", stats.Idle)
```

## Middleware System

### Built-in Middleware

#### Security Headers

Adds comprehensive security headers to all responses:

```go
app.Use(middleware.SecurityHeaders)

// Adds:
// - X-Content-Type-Options: nosniff
// - X-Frame-Options: DENY
// - X-XSS-Protection: 1; mode=block
// - Referrer-Policy: strict-origin-when-cross-origin
// - Content-Security-Policy: default-src 'self'
```

#### CSRF Protection

Implements double-submit cookie pattern:

```go
app.Use(middleware.CSRF)

// In forms
<form method="POST">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <!-- form fields -->
</form>

// In AJAX requests
fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
    },
    body: JSON.stringify(data)
})
```

#### Authentication

```go
// Require authentication
protected := app.Group("/protected")
protected.Use(middleware.RequireAuth(app.Sessions()))

// Optional authentication (sets user in context if authenticated)
app.Use(middleware.OptionalAuth(app.Sessions()))

// Require specific permission
admin := app.Group("/admin")
admin.Use(middleware.RequireAuth(app.Sessions()))
admin.Use(middleware.RequirePermission("admin.access"))
```

#### Rate Limiting

```go
// Global rate limiting
app.Use(middleware.RateLimit(middleware.RateLimitConfig{
    RequestsPerMinute: 100,
    BurstSize:        10,
}))

// Per-route rate limiting
app.POST("/api/expensive", 
    middleware.RateLimit(middleware.RateLimitConfig{
        RequestsPerMinute: 10,
        BurstSize:        2,
    }),
    expensiveHandler,
)

// IP-based rate limiting with Redis backend (coming soon)
app.Use(middleware.RateLimit(middleware.RateLimitConfig{
    RequestsPerMinute: 100,
    Backend:          middleware.RedisBackend(redisClient),
    KeyFunc: func(r *http.Request) string {
        return middleware.GetIP(r)
    },
}))
```

#### CORS

```go
app.Use(middleware.CORS(middleware.CORSConfig{
    AllowedOrigins:   []string{"https://example.com", "https://app.example.com"},
    AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
    AllowedHeaders:   []string{"Authorization", "Content-Type"},
    ExposedHeaders:   []string{"X-Total-Count"},
    AllowCredentials: true,
    MaxAge:          86400,
}))

// Development mode - allow all origins
app.Use(middleware.CORS(middleware.CORSConfig{
    AllowedOrigins: []string{"*"},
}))
```

#### Logging

```go
// Basic request logging
app.Use(middleware.Logger)

// Custom logger
app.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
    Format: "${time} ${method} ${path} ${status} ${latency}",
    Output: os.Stdout,
}))

// Structured logging with context
app.Use(middleware.StructuredLogger(logger))
```

#### HTMX Support

```go
app.Use(middleware.HTMX(middleware.HTMXConfig{
    PushURL:           true,  // Support HX-Push-URL
    ReplaceURL:        true,  // Support HX-Replace-URL
    Reswap:            true,  // Support HX-Reswap
    Retarget:          true,  // Support HX-Retarget
    Reselect:          true,  // Support HX-Reselect
    Trigger:           true,  // Support HX-Trigger
    TriggerAfterSwap:  true,  // Support HX-Trigger-After-Swap
    TriggerAfterSettle: true, // Support HX-Trigger-After-Settle
    IncludeCSRFHeader: true,  // Auto-include CSRF token
}))

// In handlers
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := router.NewContext(w, r)
    
    if ctx.IsHTMX() {
        // Return partial HTML
        ctx.HTML(200, "<div>Updated content</div>")
        ctx.HXTrigger("contentUpdated")
    } else {
        // Return full page
        ctx.HTML(200, fullPageHTML)
    }
}
```

#### Static Files

```go
// Serve static files
app.Use("/static", middleware.Static("/static", middleware.StaticConfig{
    Root:      "./public",
    Index:     "index.html",
    Browse:    false,
    MaxAge:    86400,
    Compress:  true,
    ByteRange: true,
}))

// With caching headers
app.Use("/assets", middleware.Static("/assets", middleware.StaticConfig{
    Root:   "./assets",
    MaxAge: 31536000, // 1 year for versioned assets
}))
```

#### Template Rendering

```go
// Configure template middleware
app.Use(middleware.Template(middleware.TemplateConfig{
    Manager: template.NewManager(template.Config{
        Development: true,
        BaseDir:     "./templates",
    }),
    EnableCache: true,
    CacheTTL:    5 * time.Minute,
}))

// In handlers
func handler(w http.ResponseWriter, r *http.Request) {
    middleware.RenderTemplate(w, r, "users/list", map[string]interface{}{
        "Users": users,
        "Title": "User List",
    })
}
```

#### Validation

```go
// Input validation middleware
app.POST("/api/users", 
    middleware.ValidateJSON(CreateUserInput{}),
    createUserHandler,
)

// Custom validation rules
app.Use(middleware.ValidationRules(map[string]middleware.ValidationRule{
    "email": middleware.Email(),
    "age":   middleware.Min(18),
    "url":   middleware.URL(),
}))
```

### Middleware Composition

```go
// Create middleware chains
apiMiddleware := middleware.Chain(
    middleware.Logger,
    middleware.CORS(corsConfig),
    middleware.RateLimit(rateLimitConfig),
    middleware.ValidateJSON,
)

// Apply to routes
api := app.Group("/api")
api.Use(apiMiddleware)

// Conditional middleware
app.Use(middleware.Conditional(
    func(r *http.Request) bool {
        return strings.HasPrefix(r.URL.Path, "/api")
    },
    middleware.RequireAuth(app.Sessions()),
))
```

### Custom Middleware

```go
// Basic middleware pattern
func MyMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Before request
        start := time.Now()
        
        // Call next handler
        next.ServeHTTP(w, r)
        
        // After request
        duration := time.Since(start)
        log.Printf("Request took %v", duration)
    })
}

// Middleware with configuration
func TimingMiddleware(threshold time.Duration) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            
            // Wrap response writer to capture status
            wrapped := middleware.WrapResponseWriter(w)
            
            next.ServeHTTP(wrapped, r)
            
            duration := time.Since(start)
            if duration > threshold {
                log.Printf("Slow request: %s %s took %v", r.Method, r.URL.Path, duration)
            }
        })
    }
}

// Context-aware middleware
func UserMiddleware(auth *auth.Auth) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user, err := auth.GetUser(r)
            if err == nil {
                ctx := context.WithValue(r.Context(), "user", user)
                r = r.WithContext(ctx)
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

## Web Features

### Handler Composition Framework

Guardian's handler composition eliminates boilerplate when organizing related handlers:

#### Traditional Approach (Before)

```go
type UserHandler struct {
    listHandler   *UserListHandler
    createHandler *UserCreateHandler
    updateHandler *UserUpdateHandler
    deleteHandler *UserDeleteHandler
}

func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
    h.listHandler.ServeHTTP(w, r)
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
    h.createHandler.ServeHTTP(w, r)
}

// ... more delegation methods
```

#### Guardian Approach (After)

```go
// Using HandlerFacade
userHandlers := web.NewHandlerFacade("/api/users").
    WithHandler("list", NewUserListHandler(app)).
    WithHandler("create", NewUserCreateHandler(app)).
    WithHandler("update", NewUserUpdateHandler(app)).
    WithHandler("delete", NewUserDeleteHandler(app)).
    WithSharedData("validator", validator).
    WithMiddleware(middleware.RequireAuth(app.Sessions())).
    Build()

// Automatic routing with RESTful conventions
app.Mount("/api/users", userHandlers)
```

#### RESTful Handlers

```go
type ProductHandler struct {
    app *guardian.Guardian
}

// Implement RESTHandler interface
func (h *ProductHandler) Index(w http.ResponseWriter, r *http.Request) {
    // GET /products
}

func (h *ProductHandler) Create(w http.ResponseWriter, r *http.Request) {
    // POST /products
}

func (h *ProductHandler) Show(w http.ResponseWriter, r *http.Request) {
    // GET /products/{id}
}

func (h *ProductHandler) Update(w http.ResponseWriter, r *http.Request) {
    // PUT /products/{id}
}

func (h *ProductHandler) Delete(w http.ResponseWriter, r *http.Request) {
    // DELETE /products/{id}
}

// Register RESTful routes automatically
handlers := web.NewHandlerFacade("/api").
    WithRESTHandler("products", &ProductHandler{app: app}).
    Build()
```

### Response Builder

Fluent API for building HTTP responses:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // JSON response
    web.NewResponse(w).
        Status(http.StatusOK).
        JSON(map[string]interface{}{
            "users": users,
            "total": len(users),
        })
    
    // HTML response with template
    web.NewResponse(w).
        HTML("users/list", map[string]interface{}{
            "Users": users,
        })
    
    // Error response
    web.NewResponse(w).
        Status(http.StatusBadRequest).
        Error("Invalid input", map[string]string{
            "email": "Email is required",
            "age":   "Must be at least 18",
        })
    
    // File download
    web.NewResponse(w).
        Header("Content-Disposition", "attachment; filename=report.pdf").
        File("./reports/monthly.pdf")
    
    // Chained headers
    web.NewResponse(w).
        Header("X-Total-Count", strconv.Itoa(total)).
        Header("X-Page", strconv.Itoa(page)).
        JSON(results)
}
```

### Error Handling

Structured error types with context:

```go
// Define custom errors
var (
    ErrUserNotFound = web.NotFound("User not found").
        WithField("suggestion", "Check the user ID")
    
    ErrInvalidInput = web.Validation("Invalid input").
        WithDetails("Email and password are required")
)

// Use in handlers
func getUser(w http.ResponseWriter, r *http.Request) {
    userID := chi.URLParam(r, "id")
    
    user, err := getUserByID(userID)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            web.NewResponse(w).WebError(
                web.NotFound("User not found").
                    WithField("id", userID),
            )
            return
        }
        
        web.NewResponse(w).WebError(
            web.Internal("Database error").
                WithDetails(err.Error()),
        )
        return
    }
    
    web.NewResponse(w).JSON(user)
}

// Global error handler
app.Use(middleware.ErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
    if webErr, ok := web.IsWebError(err); ok {
        web.NewResponse(w).WebError(webErr)
        return
    }
    
    web.NewResponse(w).
        Status(http.StatusInternalServerError).
        JSON(map[string]string{
            "error": "Internal server error",
        })
}))
```

### Template System

Guardian includes a powerful template system with component support:

```go
// Configure templates
templateManager := template.NewManager(template.Config{
    Development: true,           // Auto-reload templates
    BaseDir:     "./templates",  // Template directory
    Extension:   ".html",        // File extension
})

// Register components
registry := template.NewComponentRegistry(templateManager)
registry.Register("button", template.Component{
    Template: `<button class="btn {{.class}}" {{if .disabled}}disabled{{end}}>{{.label}}</button>`,
    Defaults: map[string]interface{}{
        "class":    "btn-primary",
        "disabled": false,
    },
})

// Use in templates
{{component "button" "label" "Click me" "class" "btn-success"}}

// Layouts and partials
{{define "layout"}}
<!DOCTYPE html>
<html>
<head>
    <title>{{block "title" .}}Default Title{{end}}</title>
</head>
<body>
    {{block "content" .}}{{end}}
</body>
</html>
{{end}}

{{define "content"}}
    <h1>Welcome {{.User.Name}}</h1>
{{end}}
```

### HTMX Integration

First-class support for hypermedia applications:

```go
// HTMX-aware handlers
func todoHandler(w http.ResponseWriter, r *http.Request) {
    ctx := router.NewContext(w, r)
    
    todos := getTodos()
    
    if ctx.IsHTMX() {
        // Return just the todo list partial
        ctx.HTML(200, "partials/todo-list", todos)
        
        // Trigger client-side events
        ctx.HXTrigger("todos-updated")
        
        // Update browser URL
        ctx.HXPushURL("/todos?filter=active")
    } else {
        // Return full page for non-HTMX requests
        ctx.HTML(200, "pages/todos", map[string]interface{}{
            "Todos": todos,
            "Page":  "todos",
        })
    }
}

// Out-of-band updates
func updateTodo(w http.ResponseWriter, r *http.Request) {
    ctx := router.NewContext(w, r)
    
    todo := updateTodoInDB(r)
    
    // Return multiple partial updates
    ctx.HTML(200, "partials/todo-item", todo)
    ctx.HXOOBSwap("partials/todo-count", todoCount, "#todo-count")
    ctx.HXOOBSwap("partials/notifications", notification, "#notifications", "afterbegin")
}
```

## Security Features

### Input Validation and Sanitization

Guardian provides comprehensive input validation:

```go
// Struct validation
type CreateUserInput struct {
    Email    string `validate:"required,email"`
    Password string `validate:"required,min=8,password"`
    Age      int    `validate:"required,min=18,max=120"`
    Website  string `validate:"omitempty,url"`
}

// Validate in handler
func createUser(w http.ResponseWriter, r *http.Request) {
    var input CreateUserInput
    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        web.NewResponse(w).Error("Invalid JSON", nil)
        return
    }
    
    if err := security.ValidateInput(input); err != nil {
        web.NewResponse(w).ValidationError(err)
        return
    }
    
    // Input is valid and safe
}

// HTML sanitization
sanitized := security.SanitizeHTML(userInput)

// SQL-safe strings (though you should use query builder)
safe := security.EscapeSQL(userInput)

// Custom validation rules
security.RegisterValidation("password", func(fl validator.FieldLevel) bool {
    password := fl.Field().String()
    return len(password) >= 8 && 
           regexp.MustCompile(`[A-Z]`).MatchString(password) &&
           regexp.MustCompile(`[a-z]`).MatchString(password) &&
           regexp.MustCompile(`[0-9]`).MatchString(password)
})
```

### CSRF Protection

Double-submit cookie pattern with stateless tokens:

```go
// Automatic CSRF protection
app.Use(middleware.CSRF)

// Get token in handler
func formHandler(w http.ResponseWriter, r *http.Request) {
    token := middleware.GetCSRFToken(r)
    
    web.NewResponse(w).HTML("form", map[string]interface{}{
        "CSRFToken": token,
    })
}

// Verify in API endpoints
func apiHandler(w http.ResponseWriter, r *http.Request) {
    // Automatically verified by middleware
    // Checks X-CSRF-Token header or csrf_token form field
}

// Exclude specific routes
csrf := middleware.CSRFWithConfig(middleware.CSRFConfig{
    Skipper: func(r *http.Request) bool {
        return strings.HasPrefix(r.URL.Path, "/webhook/")
    },
})
```

### XSS Prevention

Multiple layers of XSS protection:

```go
// Automatic HTML escaping in templates
{{.UserInput}} <!-- Automatically escaped -->
{{.TrustedHTML | safe}} <!-- Explicitly marked as safe -->

// Content-Type sniffing prevention
app.Use(middleware.SecurityHeaders) // Sets X-Content-Type-Options: nosniff

// CSP headers
app.Use(middleware.CSP(middleware.CSPConfig{
    DefaultSrc: []string{"'self'"},
    ScriptSrc:  []string{"'self'", "https://cdn.example.com"},
    StyleSrc:   []string{"'self'", "'unsafe-inline'"}, // For HTMX
    ImgSrc:     []string{"'self'", "data:", "https:"},
}))

// Manual sanitization when needed
clean := security.SanitizeHTML(userHTML, security.SanitizeConfig{
    AllowedTags:       []string{"p", "br", "strong", "em"},
    AllowedAttributes: map[string][]string{},
})
```

### SQL Injection Prevention

Query builder prevents SQL injection by design:

```go
// Safe by default - all values are parameterized
users, err := app.DB().Query().
    Select("users", "id", "email").
    Where("email", "=", userInput). // userInput is parameterized
    Where("active", "=", true).
    QueryAll(&users)

// Even with raw queries, use parameters
rows, err := app.DB().Raw(
    "SELECT * FROM users WHERE email = ? AND active = ?",
    userInput, // Parameterized
    true,
)

// NEVER do this
// BAD: rows, err := app.DB().Raw("SELECT * FROM users WHERE email = '" + userInput + "'")

// Table/column names are validated
_, err := app.DB().Query().
    Select(userTable, "id", "email"). // Table name is validated
    QueryAll(&results)
```

### Password Security

Argon2id hashing with secure defaults:

```go
// Password hashing (automatic in Auth.Register)
hash, err := security.HashPassword(password)

// Password verification (automatic in Auth.Login)
valid := security.VerifyPassword(password, hash)

// Password strength requirements
type PasswordPolicy struct {
    MinLength      int
    RequireUpper   bool
    RequireLower   bool
    RequireDigit   bool
    RequireSpecial bool
}

policy := security.DefaultPasswordPolicy() // 8+ chars, mixed case, digit
if err := security.ValidatePasswordPolicy(password, policy); err != nil {
    // Password doesn't meet requirements
}

// Configurable Argon2 parameters
security.SetArgon2Params(security.Argon2Params{
    Memory:      64 * 1024, // 64MB
    Iterations:  3,
    Parallelism: 2,
    SaltLength:  16,
    KeyLength:   32,
})
```

### Session Security

```go
// Secure session configuration
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"), // Must be 32 bytes
    SessionOptions: &sessions.Options{
        Path:     "/",
        Domain:   "example.com",
        MaxAge:   86400,    // 1 day
        Secure:   true,     // HTTPS only
        HttpOnly: true,     // No JS access
        SameSite: http.SameSiteStrictMode,
    },
})

// Session fixation prevention (automatic on login)
app.Auth().RegenerateSession(w, r)

// Session encryption (automatic with cookie backend)
// All session data is encrypted with AES-GCM

// Session expiration
app.Sessions().Options.MaxAge = 3600 // 1 hour
```

### Security Headers

Comprehensive security headers applied automatically:

```go
// Default security headers
app.Use(middleware.SecurityHeaders)

// Adds:
// X-Content-Type-Options: nosniff
// X-Frame-Options: DENY  
// X-XSS-Protection: 1; mode=block
// Referrer-Policy: strict-origin-when-cross-origin
// Permissions-Policy: geolocation=(), microphone=(), camera=()

// Custom security headers
app.Use(middleware.SecurityHeadersWithConfig(middleware.SecurityConfig{
    XFrameOptions:         "SAMEORIGIN", // Allow same-origin framing
    ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'",
    StrictTransportSecurity: "max-age=31536000; includeSubDomains",
}))
```

## Advanced Topics

### Handler Composition Patterns

#### Shared State Between Handlers

```go
// Create handler group with shared dependencies
handlers := web.NewHandlerFacade("/api/orders").
    WithSharedData("orderService", orderService).
    WithSharedData("emailService", emailService).
    WithSharedData("validator", validator).
    WithHandler("create", createOrderHandler).
    WithHandler("status", orderStatusHandler).
    Build()

// Access shared data in handlers
func createOrderHandler(group *web.HandlerGroup) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        orderService := group.GetSharedData("orderService").(*OrderService)
        emailService := group.GetSharedData("emailService").(*EmailService)
        
        // Use services...
    })
}
```

#### Composable Handler Functions

```go
// Build complex handlers from simple functions
handler := web.NewHandlerComposer().
    Add(validateAPIKey).
    Add(parseJSONBody).
    Add(validateOrder).
    Add(processOrder).
    Add(sendConfirmation).
    Build()

// Conditional composition
handler := web.NewHandlerComposer().
    Add(authenticate).
    AddIf(config.EnableRateLimit, rateLimitHandler).
    AddIf(config.EnableMetrics, metricsHandler).
    Add(mainLogic).
    Build()
```

### Custom Middleware Development

#### Middleware Best Practices

```go
// 1. Always call next handler
func BadMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if someCondition {
            http.Error(w, "Forbidden", 403)
            // BAD: Not calling return after error
        }
        next.ServeHTTP(w, r)
    })
}

func GoodMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if someCondition {
            http.Error(w, "Forbidden", 403)
            return // GOOD: Return after handling error
        }
        next.ServeHTTP(w, r)
    })
}

// 2. Use context for passing data
func ContextMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        value := computeValue(r)
        ctx := context.WithValue(r.Context(), "myKey", value)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// 3. Wrap ResponseWriter for intercepting responses
type responseRecorder struct {
    http.ResponseWriter
    status int
    size   int
}

func (r *responseRecorder) WriteHeader(status int) {
    r.status = status
    r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
    size, err := r.ResponseWriter.Write(b)
    r.size += size
    return size, err
}

func MetricsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        rec := &responseRecorder{ResponseWriter: w, status: 200}
        
        start := time.Now()
        next.ServeHTTP(rec, r)
        duration := time.Since(start)
        
        // Record metrics
        recordMetric(r.Method, r.URL.Path, rec.status, duration, rec.size)
    })
}
```

### Extending the Framework

#### Custom Session Backend

```go
// Implement sessions.Store interface
type RedisStore struct {
    client *redis.Client
    prefix string
}

func (s *RedisStore) Get(r *http.Request, name string) (*sessions.Session, error) {
    // Implementation
}

func (s *RedisStore) New(r *http.Request, name string) (*sessions.Session, error) {
    // Implementation
}

func (s *RedisStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
    // Implementation
}

// Use custom store
app := guardian.New(guardian.Config{
    SessionKey: []byte("secret"),
    CustomSessionStore: NewRedisStore(redisClient),
})
```

#### Custom Authentication Provider

```go
// Implement auth.Provider interface
type LDAPProvider struct {
    conn *ldap.Conn
}

func (p *LDAPProvider) Authenticate(email, password string) (*auth.User, error) {
    // LDAP authentication logic
}

func (p *LDAPProvider) GetUser(id string) (*auth.User, error) {
    // Fetch user from LDAP
}

// Register provider
app.Auth().RegisterProvider("ldap", &LDAPProvider{conn: ldapConn})
```

### Performance Optimization

#### Database Query Optimization

```go
// Use connection pooling
app := guardian.New(guardian.Config{
    DatabaseType:    "mysql",
    MaxOpenConns:    25,
    MaxIdleConns:    5,
    ConnMaxLifetime: 5 * time.Minute,
})

// Batch operations
users := []User{...}
tx, _ := app.DB().Begin()
for _, user := range users {
    tx.Query().Insert("users", user)
}
tx.Commit()

// Prepared statements for repeated queries
stmt, err := app.DB().Prepare("SELECT * FROM users WHERE email = ?")
defer stmt.Close()

for _, email := range emails {
    var user User
    err := stmt.QueryRow(email).Scan(&user.ID, &user.Email)
}
```

#### Caching Strategies

```go
// Template caching
app.Use(middleware.Template(middleware.TemplateConfig{
    EnableCache: true,
    CacheTTL:    10 * time.Minute,
}))

// Response caching
func CacheMiddleware(duration time.Duration) func(http.Handler) http.Handler {
    cache := make(map[string]cachedResponse)
    mu := sync.RWMutex{}
    
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if r.Method != "GET" {
                next.ServeHTTP(w, r)
                return
            }
            
            key := r.URL.String()
            
            // Check cache
            mu.RLock()
            if cached, ok := cache[key]; ok && time.Now().Before(cached.expiry) {
                mu.RUnlock()
                w.Header().Set("X-Cache", "HIT")
                w.WriteHeader(cached.status)
                w.Write(cached.body)
                return
            }
            mu.RUnlock()
            
            // Record response
            rec := newResponseRecorder(w)
            next.ServeHTTP(rec, r)
            
            // Cache successful responses
            if rec.status < 300 {
                mu.Lock()
                cache[key] = cachedResponse{
                    body:   rec.body,
                    status: rec.status,
                    expiry: time.Now().Add(duration),
                }
                mu.Unlock()
            }
        })
    }
}
```

### Testing Strategies

#### Unit Testing Handlers

```go
func TestCreateUser(t *testing.T) {
    // Create test Guardian instance
    app := guardian.New(guardian.Config{
        SessionKey:   []byte("test-key-exactly-32-bytes-long!!"),
        DatabaseType: "sqlite",
        DatabasePath: ":memory:",
    })
    
    // Test handler
    handler := createUserHandler(app)
    
    // Create request
    body := strings.NewReader(`{"email":"test@example.com","password":"SecurePass123"}`)
    req := httptest.NewRequest("POST", "/users", body)
    req.Header.Set("Content-Type", "application/json")
    
    // Record response
    w := httptest.NewRecorder()
    handler.ServeHTTP(w, req)
    
    // Assert
    assert.Equal(t, http.StatusCreated, w.Code)
    
    var response map[string]interface{}
    json.Unmarshal(w.Body.Bytes(), &response)
    assert.Equal(t, "test@example.com", response["email"])
}
```

#### Integration Testing

```go
func TestAuthenticationFlow(t *testing.T) {
    app := setupTestApp(t)
    
    // Register user
    user, err := app.Auth().Register("test@example.com", "password123")
    require.NoError(t, err)
    
    // Login
    req := httptest.NewRequest("POST", "/login", strings.NewReader("email=test@example.com&password=password123"))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    w := httptest.NewRecorder()
    
    err = app.Auth().Login(w, req, "test@example.com", "password123")
    require.NoError(t, err)
    
    // Check session
    cookies := w.Result().Cookies()
    require.Len(t, cookies, 1)
    
    // Make authenticated request
    authReq := httptest.NewRequest("GET", "/protected", nil)
    authReq.AddCookie(cookies[0])
    
    authenticated := app.Auth().IsAuthenticated(authReq)
    assert.True(t, authenticated)
}
```

#### Security Testing

```go
func TestXSSPrevention(t *testing.T) {
    app := setupTestApp(t)
    
    // Attempt XSS
    malicious := `<script>alert('xss')</script>`
    sanitized := security.SanitizeHTML(malicious)
    
    assert.NotContains(t, sanitized, "<script>")
    assert.NotContains(t, sanitized, "alert")
}

func TestSQLInjection(t *testing.T) {
    app := setupTestApp(t)
    
    // Attempt SQL injection
    malicious := "admin' OR '1'='1"
    
    var users []User
    err := app.DB().Query().
        Select("users", "id", "email").
        Where("email", "=", malicious).
        QueryAll(&users)
    
    require.NoError(t, err)
    assert.Empty(t, users) // No results, injection prevented
}
```

## Production Deployment

### Pre-Deployment Checklist

- [ ] **Environment Configuration**
  ```go
  app := guardian.New(guardian.Config{
      Environment: "production", // Enable production defaults
  })
  ```

- [ ] **Secure Session Key**
  ```bash
  # Generate secure key
  openssl rand -base64 32
  ```
  ```go
  sessionKey := os.Getenv("SESSION_KEY")
  if len(sessionKey) != 32 {
      log.Fatal("SESSION_KEY must be exactly 32 bytes")
  }
  ```

- [ ] **Database Configuration**
  ```go
  app := guardian.New(guardian.Config{
      DatabaseType:    "mysql",
      DatabaseDSN:     os.Getenv("DATABASE_URL"),
      MaxOpenConns:    25,
      MaxIdleConns:    5,
      ConnMaxLifetime: 5 * time.Minute,
  })
  ```

- [ ] **HTTPS Configuration**
  ```go
  // Enforce HTTPS
  app.Use(middleware.ForceHTTPS)
  
  // Secure cookies
  app := guardian.New(guardian.Config{
      SessionOptions: &sessions.Options{
          Secure: true, // HTTPS only
          HttpOnly: true,
          SameSite: http.SameSiteStrictMode,
      },
  })
  ```

- [ ] **CORS Configuration**
  ```go
  app.Use(middleware.CORS(middleware.CORSConfig{
      AllowedOrigins: []string{
          "https://app.example.com",
          "https://www.example.com",
      },
      AllowCredentials: true,
  }))
  ```

- [ ] **Rate Limiting**
  ```go
  // Global rate limit
  app.Use(middleware.RateLimit(middleware.RateLimitConfig{
      RequestsPerMinute: 100,
      BurstSize:        10,
  }))
  
  // Stricter limits for sensitive endpoints
  app.POST("/login", 
      middleware.RateLimit(middleware.RateLimitConfig{
          RequestsPerMinute: 5,
          BurstSize:        2,
      }),
      loginHandler,
  )
  ```

- [ ] **Error Handling**
  ```go
  // Don't expose internal errors in production
  app.Use(middleware.ErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
      log.Printf("Error: %v", err)
      
      if app.Config.Environment == "production" {
          http.Error(w, "Internal Server Error", 500)
      } else {
          http.Error(w, err.Error(), 500)
      }
  }))
  ```

- [ ] **Logging Configuration**
  ```go
  // Structured logging for production
  logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
  app.Use(middleware.StructuredLogger(logger))
  ```

- [ ] **Health Checks**
  ```go
  app.GET("/health", func(w http.ResponseWriter, r *http.Request) {
      // Check database
      if err := app.DB().Ping(); err != nil {
          w.WriteHeader(http.StatusServiceUnavailable)
          json.NewEncoder(w).Encode(map[string]string{
              "status": "unhealthy",
              "db":     "down",
          })
          return
      }
      
      json.NewEncoder(w).Encode(map[string]string{
          "status": "healthy",
          "db":     "up",
      })
  })
  ```

### Deployment Options

#### Systemd Service

```ini
[Unit]
Description=Guardian Web Application
After=network.target

[Service]
Type=simple
User=webapp
WorkingDirectory=/var/www/app
ExecStart=/var/www/app/guardian
Restart=always
RestartSec=5
Environment="SESSION_KEY=your-secret-key"
Environment="DATABASE_URL=user:pass@tcp(localhost:3306)/app"

[Install]
WantedBy=multi-user.target
```

#### Docker Deployment

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o guardian .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/guardian .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
EXPOSE 8080
CMD ["./guardian"]
```

#### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guardian-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: guardian
  template:
    metadata:
      labels:
        app: guardian
    spec:
      containers:
      - name: guardian
        image: guardian:latest
        ports:
        - containerPort: 8080
        env:
        - name: SESSION_KEY
          valueFrom:
            secretKeyRef:
              name: guardian-secrets
              key: session-key
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: guardian-secrets
              key: database-url
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

### Monitoring and Observability

#### Prometheus Metrics

```go
// Add metrics middleware
app.Use(middleware.Prometheus())

// Custom metrics
var (
    requestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "http_request_duration_seconds",
            Help: "HTTP request latencies",
        },
        []string{"method", "path", "status"},
    )
)

func MetricsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        rec := middleware.WrapResponseWriter(w)
        
        next.ServeHTTP(rec, r)
        
        duration := time.Since(start).Seconds()
        requestDuration.WithLabelValues(
            r.Method,
            r.URL.Path,
            strconv.Itoa(rec.Status()),
        ).Observe(duration)
    })
}
```

#### Structured Logging

```go
// Configure structured logging
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

// Log with context
logger.Info("user action",
    "user_id", user.ID,
    "action", "login",
    "ip", r.RemoteAddr,
)
```

#### OpenTelemetry Tracing

```go
// Initialize tracer
tp, err := tracerProvider()
otel.SetTracerProvider(tp)

// Trace middleware
app.Use(middleware.OpenTelemetry())

// Manual spans
func processOrder(ctx context.Context, order Order) error {
    tr := otel.Tracer("guardian")
    ctx, span := tr.Start(ctx, "processOrder")
    defer span.End()
    
    span.SetAttributes(
        attribute.String("order.id", order.ID),
        attribute.Float64("order.total", order.Total),
    )
    
    // Process order...
    
    return nil
}
```

### Security Best Practices

1. **Regular Updates**
   ```bash
   go get -u github.com/flyzard/go-guardian
   go mod tidy
   ```

2. **Security Scanning**
   ```bash
   # Vulnerability scanning
   go install golang.org/x/vuln/cmd/govulncheck@latest
   govulncheck ./...
   
   # Static analysis
   go install github.com/securego/gosec/v2/cmd/gosec@latest
   gosec ./...
   ```

3. **Secrets Management**
   - Never commit secrets to version control
   - Use environment variables or secret management services
   - Rotate keys regularly

4. **Database Security**
   - Use least privilege database users
   - Enable SSL/TLS for database connections
   - Regular backups with encryption

5. **Application Security**
   - Keep all middleware enabled in production
   - Monitor for suspicious activity
   - Implement proper access controls
   - Regular security audits

## API Reference

### Core Types

#### Guardian

```go
type Guardian struct {
    *router.Router
    // Methods
    New(config Config) *Guardian
    Auth() *auth.Auth
    DB() *database.DB
    Sessions() sessions.Store
    Listen(addr string) error
    ListenTLS(addr, certFile, keyFile string) error
}
```

#### Config

```go
type Config struct {
    SessionKey          []byte
    Environment         string
    DatabaseType        string
    DatabasePath        string
    DatabaseDSN         string
    MaxOpenConns        int
    MaxIdleConns        int
    ConnMaxLifetime     time.Duration
    Features            Features
    TableNames          TableNames
    ColumnNames         ColumnNames
    SessionBackend      SessionBackend
    SessionOptions      *sessions.Options
    AutoMigrate         bool
    ValidateSchema      bool
    CustomSessionStore  sessions.Store
}
```

### Auth Interface

```go
type Auth interface {
    // User Management
    Register(email, password string) (*User, error)
    RegisterExternalUser(email string) (*User, error)
    GetUser(r *http.Request) (*User, error)
    GetUserByID(id int64) (*User, error)
    GetUserByEmail(email string) (*User, error)
    UpdatePassword(userID int64, newPassword string) error
    VerifyUserEmail(userID int64) error
    
    // Authentication
    Login(w http.ResponseWriter, r *http.Request, email, password string) error
    LoginWithoutPassword(w http.ResponseWriter, r *http.Request, email string) error
    Logout(w http.ResponseWriter, r *http.Request) error
    IsAuthenticated(r *http.Request) bool
    
    // Sessions
    CreateSession(w http.ResponseWriter, r *http.Request, userID int64, email string) error
    RefreshSession(w http.ResponseWriter, r *http.Request) error
    InvalidateSession(sessionID string) error
    InvalidateAllSessions(userID int64) error
    RegenerateSession(w http.ResponseWriter, r *http.Request) error
    
    // Tokens
    CreateVerificationToken(userID int64) (*Token, error)
    CreatePasswordResetToken(email string) (*Token, error)
    ValidateToken(token, purpose string) (*Token, error)
    
    // Remember Me
    CreateRememberToken(w http.ResponseWriter, userID int64) error
    ValidateRememberToken(r *http.Request) (*User, error)
    
    // RBAC
    UserHasPermission(userID int64, permission string) bool
    UserHasRole(userID int64, roleName string) bool
    AssignRole(userID, roleID int64) error
    RemoveRole(userID, roleID int64) error
    CreateRole(name, description string) (*Role, error)
    AssignPermissionToRole(roleID int64, permission string) error
}
```

### Database Interface

```go
type DB interface {
    // Query Builder
    Query() *QueryBuilder
    Raw(query string, args ...interface{}) (*sql.Rows, error)
    
    // Transactions
    Begin() (*Tx, error)
    
    // Migrations
    RunMigrations() error
    RunMigration(id string) error
    GetMigrationStatus() ([]MigrationStatus, error)
    
    // Schema
    ValidateSchema() []error
    
    // Connection
    Ping() error
    Stats() sql.DBStats
    Close() error
}
```

### Middleware Functions

```go
// Security
func SecurityHeaders(next http.Handler) http.Handler
func CSRF(next http.Handler) http.Handler
func ForceHTTPS(next http.Handler) http.Handler

// Authentication
func RequireAuth(store sessions.Store) func(http.Handler) http.Handler
func OptionalAuth(store sessions.Store) func(http.Handler) http.Handler
func RequirePermission(permission string) func(http.Handler) http.Handler

// Request Processing
func Logger(next http.Handler) http.Handler
func RateLimit(config RateLimitConfig) func(http.Handler) http.Handler
func CORS(config CORSConfig) func(http.Handler) http.Handler
func ValidateJSON(schema interface{}) func(http.Handler) http.Handler

// Response
func HTMX(config HTMXConfig) func(http.Handler) http.Handler
func Template(config TemplateConfig) func(http.Handler) http.Handler
func Static(prefix string, config StaticConfig) func(http.Handler) http.Handler
func Compress(next http.Handler) http.Handler
```

## Examples

### Complete Application Example

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
    
    "github.com/flyzard/go-guardian"
    "github.com/flyzard/go-guardian/middleware"
    "github.com/flyzard/go-guardian/web"
)

func main() {
    // Configuration from environment
    config := guardian.Config{
        SessionKey:   []byte(os.Getenv("SESSION_KEY")),
        Environment:  os.Getenv("ENVIRONMENT"),
        DatabaseType: "mysql",
        DatabaseDSN:  os.Getenv("DATABASE_URL"),
    }
    
    // Create application
    app := guardian.New(config)
    
    // Global middleware
    app.Use(middleware.SecurityHeaders)
    app.Use(middleware.Logger)
    app.Use(middleware.CORS(middleware.CORSConfig{
        AllowedOrigins: []string{os.Getenv("FRONTEND_URL")},
        AllowCredentials: true,
    }))
    app.Use(middleware.RateLimit(middleware.RateLimitConfig{
        RequestsPerMinute: 100,
    }))
    app.Use(middleware.CSRF)
    
    // Static files
    app.Use("/static", middleware.Static("/static", middleware.StaticConfig{
        Root: "./public",
        MaxAge: 86400,
    }))
    
    // Public routes
    app.GET("/", homeHandler)
    app.GET("/about", aboutHandler)
    
    // Auth routes
    app.POST("/register", registerHandler(app))
    app.POST("/login", loginHandler(app))
    app.POST("/logout", logoutHandler(app))
    
    // API routes
    api := app.Group("/api/v1")
    api.Use(middleware.RequireAuth(app.Sessions()))
    
    // User routes
    userHandlers := web.NewHandlerFacade("/api/v1/users").
        WithHandler("list", listUsersHandler(app)).
        WithHandler("create", createUserHandler(app)).
        WithHandler("update", updateUserHandler(app)).
        WithHandler("delete", deleteUserHandler(app)).
        WithMiddleware(middleware.RequirePermission("users.manage")).
        Build()
    
    api.Mount("/users", userHandlers)
    
    // Admin routes
    admin := app.Group("/admin")
    admin.Use(middleware.RequireAuth(app.Sessions()))
    admin.Use(middleware.RequirePermission("admin.access"))
    admin.GET("/dashboard", adminDashboardHandler)
    
    // Start server
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    
    log.Printf("Server starting on port %s", port)
    log.Fatal(app.Listen(":" + port))
}

// Handler implementations...
func homeHandler(w http.ResponseWriter, r *http.Request) {
    web.NewResponse(w).HTML("home", map[string]interface{}{
        "Title": "Welcome to Guardian",
    })
}

func registerHandler(app *guardian.Guardian) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var input struct {
            Email    string `json:"email" validate:"required,email"`
            Password string `json:"password" validate:"required,min=8"`
        }
        
        if err := web.ParseJSON(r, &input); err != nil {
            web.NewResponse(w).Error("Invalid input", err)
            return
        }
        
        user, err := app.Auth().Register(input.Email, input.Password)
        if err != nil {
            web.NewResponse(w).Error("Registration failed", err)
            return
        }
        
        // Auto-login
        err = app.Auth().CreateSession(w, r, user.ID, user.Email)
        if err != nil {
            web.NewResponse(w).Error("Login failed", err)
            return
        }
        
        web.NewResponse(w).JSON(map[string]interface{}{
            "message": "Registration successful",
            "user": map[string]interface{}{
                "id":    user.ID,
                "email": user.Email,
            },
        })
    }
}
```

### Migration from Other Frameworks

#### From Gin

```go
// Gin style
r := gin.Default()
r.GET("/users/:id", getUser)
r.POST("/users", createUser)

// Guardian style
app := guardian.New(config)
app.GET("/users/{id}", getUser)
app.POST("/users", createUser)

// Middleware translation
r.Use(gin.Logger()) // Gin
app.Use(middleware.Logger) // Guardian

// Groups
v1 := r.Group("/api/v1") // Gin
v1 := app.Group("/api/v1") // Guardian
```

#### From Echo

```go
// Echo style
e := echo.New()
e.GET("/users/:id", getUser)
e.Use(echo.Logger())

// Guardian style
app := guardian.New(config)
app.GET("/users/{id}", getUser)
app.Use(middleware.Logger)

// Context handling
func echoHandler(c echo.Context) error {
    return c.JSON(200, data)
}

func guardianHandler(w http.ResponseWriter, r *http.Request) {
    web.NewResponse(w).JSON(data)
}
```

#### From Standard Library

```go
// Standard library
mux := http.NewServeMux()
mux.HandleFunc("/users", usersHandler)
http.ListenAndServe(":8080", mux)

// Guardian
app := guardian.New(config)
app.GET("/users", usersHandler)
app.Listen(":8080")

// With middleware
handler := loggingMiddleware(csrfMiddleware(mux)) // Standard
app.Use(middleware.Logger)                        // Guardian
app.Use(middleware.CSRF)
```

### Common Patterns

#### RESTful API

```go
// Define resource handlers
type TodoHandler struct {
    app *guardian.Guardian
}

func (h *TodoHandler) Index(w http.ResponseWriter, r *http.Request) {
    todos := h.fetchTodos()
    web.NewResponse(w).JSON(todos)
}

func (h *TodoHandler) Create(w http.ResponseWriter, r *http.Request) {
    var todo Todo
    if err := web.ParseJSON(r, &todo); err != nil {
        web.NewResponse(w).Error("Invalid input", err)
        return
    }
    
    created := h.createTodo(todo)
    web.NewResponse(w).Status(201).JSON(created)
}

func (h *TodoHandler) Show(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    todo := h.getTodo(id)
    web.NewResponse(w).JSON(todo)
}

func (h *TodoHandler) Update(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    var updates Todo
    web.ParseJSON(r, &updates)
    
    updated := h.updateTodo(id, updates)
    web.NewResponse(w).JSON(updated)
}

func (h *TodoHandler) Delete(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    h.deleteTodo(id)
    web.NewResponse(w).Status(204).Empty()
}

// Register routes
handlers := web.NewHandlerFacade("/api/v1").
    WithRESTHandler("todos", &TodoHandler{app: app}).
    Build()

app.Mount("/api/v1", handlers)
```

#### WebSocket Chat

```go
type Hub struct {
    clients    map[*Client]bool
    broadcast  chan []byte
    register   chan *Client
    unregister chan *Client
}

func (h *Hub) run() {
    for {
        select {
        case client := <-h.register:
            h.clients[client] = true
            
        case client := <-h.unregister:
            if _, ok := h.clients[client]; ok {
                delete(h.clients, client)
                close(client.send)
            }
            
        case message := <-h.broadcast:
            for client := range h.clients {
                select {
                case client.send <- message:
                default:
                    close(client.send)
                    delete(h.clients, client)
                }
            }
        }
    }
}

func wsHandler(hub *Hub, app *guardian.Guardian) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Require authentication
        user, err := app.Auth().GetUser(r)
        if err != nil {
            http.Error(w, "Unauthorized", 401)
            return
        }
        
        conn, err := middleware.UpgradeWebSocket(w, r)
        if err != nil {
            return
        }
        
        client := &Client{
            hub:  hub,
            conn: conn,
            send: make(chan []byte, 256),
            user: user,
        }
        
        client.hub.register <- client
        
        go client.writePump()
        go client.readPump()
    }
}
```

#### HTMX Todo App

```go
// Todo list page
app.GET("/todos", func(w http.ResponseWriter, r *http.Request) {
    ctx := router.NewContext(w, r)
    todos := getTodos()
    
    if ctx.IsHTMX() {
        ctx.HTML(200, "partials/todo-list", todos)
    } else {
        ctx.HTML(200, "pages/todos", map[string]interface{}{
            "Todos": todos,
            "Title": "My Todos",
        })
    }
})

// Add todo
app.POST("/todos", func(w http.ResponseWriter, r *http.Request) {
    ctx := router.NewContext(w, r)
    
    title := r.FormValue("title")
    todo := createTodo(title)
    
    // Return just the new todo item
    ctx.HTML(200, "partials/todo-item", todo)
    
    // Trigger event for other updates
    ctx.HXTrigger("todo-added")
    
    // Clear the form
    ctx.HXTriggerAfterSwap("reset-form")
})

// Toggle todo
app.PUT("/todos/{id}/toggle", func(w http.ResponseWriter, r *http.Request) {
    ctx := router.NewContext(w, r)
    
    id := chi.URLParam(r, "id")
    todo := toggleTodo(id)
    
    // Return updated todo item
    ctx.HTML(200, "partials/todo-item", todo)
    
    // Update counter out-of-band
    count := getActiveTodoCount()
    ctx.HXOOBSwap("partials/todo-count", count, "#todo-count")
})

// Delete todo  
app.DELETE("/todos/{id}", func(w http.ResponseWriter, r *http.Request) {
    ctx := router.NewContext(w, r)
    
    id := chi.URLParam(r, "id")
    deleteTodo(id)
    
    // Return empty response (HTMX will remove the element)
    ctx.Status(200).Empty()
    
    // Update counter
    count := getActiveTodoCount()
    ctx.HXOOBSwap("partials/todo-count", count, "#todo-count")
})
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Support

- Documentation: [https://guardian.example.com/docs](https://guardian.example.com/docs)
- Issues: [https://github.com/flyzard/go-guardian/issues](https://github.com/flyzard/go-guardian/issues)
- Discussions: [https://github.com/flyzard/go-guardian/discussions](https://github.com/flyzard/go-guardian/discussions)

## Acknowledgments

Guardian is built on the shoulders of giants:
- [Chi Router](https://github.com/go-chi/chi) - High-performance HTTP router
- [Gorilla Sessions](https://github.com/gorilla/sessions) - Session management
- [Gorilla WebSocket](https://github.com/gorilla/websocket) - WebSocket implementation
- [Validator](https://github.com/go-playground/validator) - Struct validation
- [Argon2](https://github.com/alexedwards/argon2id) - Password hashing

Special thanks to all contributors who have helped make Guardian better!