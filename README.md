# Go-Guardian

A secure, lightweight web framework for Go that prioritizes security and simplicity. Built with a security-first approach, Go-Guardian provides essential features for building secure web applications without unnecessary complexity.

## Features

- 🔐 **Security First**: CSRF protection, XSS prevention, SQL injection prevention, secure sessions
- 🚀 **Fast & Lightweight**: Built on [chi router](https://github.com/go-chi/chi) with minimal dependencies
- 🔧 **Flexible Configuration**: Enable only the features you need
- 📦 **Multiple Database Support**: SQLite (default) and MySQL
- 🎯 **Modular Design**: Use as a full framework or just the parts you need
- 🔑 **Authentication System**: Complete auth with registration, login, sessions, and optional features
- 🛡️ **Built-in Middleware**: Security headers, CSRF, CORS, logging, rate limiting ready
- 🌐 **HTMX Support**: First-class support for hypermedia applications

## Installation

```bash
go get github.com/flyzard/go-guardian
```

## Quick Start

```go
package main

import (
    "net/http"
    "github.com/flyzard/go-guardian"
    "github.com/flyzard/go-guardian/middleware"
)

func main() {
    // Initialize with minimal configuration
    app := guardian.New(guardian.Config{
        SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    })
    
    // Apply security middleware
    app.Use(middleware.SecurityHeaders)
    app.Use(middleware.CSRF)
    
    // Define routes
    app.GET("/", homeHandler)
    
    app.Listen(":8080")
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Welcome to Go-Guardian!"))
}
```

## Configuration Options

### Basic Configuration

```go
app := guardian.New(guardian.Config{
    SessionKey:   []byte("your-32-byte-secret-key-here!!!"),
    Environment:  "development", // or "production"
    DatabaseType: "sqlite",      // or "mysql"
    DatabasePath: "app.db",      // for SQLite
})
```

### MySQL Configuration

```go
app := guardian.New(guardian.Config{
    SessionKey:      []byte("your-32-byte-secret-key-here!!!"),
    DatabaseType:    "mysql",
    DatabaseDSN:     "user:password@tcp(localhost:3306)/dbname?parseTime=true",
    MaxOpenConns:    25,
    MaxIdleConns:    5,
    ConnMaxLifetime: 5 * time.Minute,
})
```

### Feature Flags

Enable only the features you need to minimize database requirements:

```go
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    Features: guardian.Features{
        EmailVerification: false, // No tokens table needed
        PasswordReset:     false, // No tokens table needed  
        RememberMe:        false, // No remember_tokens table needed
        RBAC:              false, // No roles/permissions tables needed
        ExternalAuth:      true,  // Enable SSO/LDAP integration
    },
})
```

### Custom Table Names

Use existing database schema with custom table/column names:

```go
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    TableNames: guardian.TableNames{
        Users:  "app_users",
        Tokens: "auth_tokens",
        Roles:  "user_roles",
    },
    ColumnNames: guardian.ColumnNames{
        UserEmail:    "email_address",
        UserPassword: "pwd_hash",
        UserVerified: "is_verified",
    },
})
```

### Session Backends

Choose from different session storage options:

```go
// Cookie sessions (default) - encrypted client-side storage
app := guardian.New(guardian.Config{
    SessionKey:     []byte("your-32-byte-secret-key-here!!!"),
    SessionBackend: guardian.SessionBackendCookie,
})

// In-memory sessions - server-side, lost on restart
app := guardian.New(guardian.Config{
    SessionKey:     []byte("your-32-byte-secret-key-here!!!"),
    SessionBackend: guardian.SessionBackendMemory,
})
```

## Authentication

### Basic Authentication Flow

```go
// Registration endpoint
app.POST("/register", func(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    user, err := app.Auth().Register(email, password)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    w.Write([]byte("Registration successful"))
})

// Login endpoint
app.POST("/login", func(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    err := app.Auth().Login(w, r, email, password)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    
    w.Write([]byte("Login successful"))
})

// Protected routes
protected := app.Group("/admin")
protected.Use(middleware.RequireAuth(app.Sessions()))
protected.GET("/dashboard", func(w http.ResponseWriter, r *http.Request) {
    user, _ := app.Auth().GetUser(r)
    w.Write([]byte("Welcome " + user.Email))
})
```

### External Authentication (SSO/LDAP)

```go
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    Features: guardian.Features{
        ExternalAuth: true,
    },
})

// Register user without password
user, err := app.Auth().RegisterExternalUser("user@example.com")

// Login without password check (after external validation)
err := app.Auth().LoginWithoutPassword(w, r, "user@example.com")

// Create session for already authenticated user
err := app.Auth().CreateSessionForUser(w, r, userID, email)
```

### Email Verification

```go
// With email verification enabled (default)
user, _ := app.Auth().Register(email, password)

// Create verification token
token, _ := app.Auth().CreateVerificationToken(user.ID)

// Send email with token (implement your email sending)
sendVerificationEmail(user.Email, token.Value)

// Verify email
verified, _ := app.Auth().ValidateToken(tokenValue, "email_verification")
app.Auth().VerifyUserEmail(verified.UserID)
```

### Password Reset

```go
// Create reset token
token, _ := app.Auth().CreatePasswordResetToken("user@example.com")

// Validate token and reset password
validated, _ := app.Auth().ValidateToken(tokenValue, "password_reset")
// Update user password...
```

## Middleware

### Built-in Middleware

```go
// Security headers (CSP, X-Frame-Options, etc.)
app.Use(middleware.SecurityHeaders)

// CSRF protection (double-submit cookie)
app.Use(middleware.CSRF)

// Request logging
app.Use(middleware.Logger)

// CORS support
app.Use(middleware.CORS(middleware.CORSConfig{
    AllowedOrigins: []string{"https://example.com"},
    AllowedMethods: []string{"GET", "POST"},
    AllowCredentials: true,
}))

// HTMX support
app.Use(middleware.HTMX(middleware.HTMXConfig{
    PushURL: true,
    IncludeCSRFHeader: true,
}))
```

### Middleware Chains

```go
// Chain multiple middleware
publicAPI := app.Group("/api/v1")
publicAPI.Use(
    middleware.Logger,
    middleware.CORS(corsConfig),
    middleware.RateLimit(100), // 100 requests per minute
)

// Protected API
protectedAPI := app.Group("/api/v1/admin")
protectedAPI.Use(
    middleware.Logger,
    middleware.RequireAuth(app.Sessions()),
    middleware.RequirePermission("admin.access"),
)
```

## Database Operations

### Query Builder

```go
// Safe parameterized queries
var user User
err := app.DB().Query().
    Select("users", "id", "email").
    Where("email", "=", email).
    QueryRow().
    Scan(&user.ID, &user.Email)

// Insert
result, err := app.DB().Query().Insert("users", map[string]interface{}{
    "email": email,
    "password_hash": hash,
    "created_at": time.Now(),
})

// Update
result, err := app.DB().Query().Update("users",
    map[string]interface{}{"verified": true},
    map[string]interface{}{"id": userID},
)
```

### Migrations

```go
// Auto-migrate on startup (default)
app := guardian.New(guardian.Config{
    SessionKey:  []byte("secret"),
    AutoMigrate: true,
})

// Or run migrations manually
app := guardian.New(guardian.Config{
    SessionKey:  []byte("secret"),
    AutoMigrate: false,
})
app.RunMigrations()

// Run specific migrations
app.RunSpecificMigrations("001", "002")
```

## Security Features

### Input Validation

```go
import "github.com/flyzard/go-guardian/security"

// Validate and sanitize input
input := security.RegisterInput{
    Email:    r.FormValue("email"),
    Password: r.FormValue("password"),
}

if err := security.ValidateInput(input); err != nil {
    http.Error(w, err.Error(), http.StatusBadRequest)
    return
}

// Sanitize output
safe := security.SanitizeHTML(userInput)
```

### CSRF Protection for AJAX

```html
<!-- Include CSRF token in meta tag -->
<meta name="csrf-token" content="{{.CSRFToken}}">

<script>
// Add to all AJAX requests
fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
    },
    body: data
})
</script>
```

### HTMX Integration

```go
// In your handler
ctx := router.NewContext(w, r)

if ctx.IsHTMX() {
    // Return partial HTML
    ctx.HTML(200, "<div>Updated content</div>")
    ctx.HXTrigger("contentUpdated")
} else {
    // Return full page
    ctx.HTML(200, fullPageHTML)
}
```

## Advanced Configurations

### Minimal Setup (External Auth Only)

```go
// For apps using SSO/LDAP with minimal Guardian features
app := guardian.New(guardian.Config{
    SessionKey:   []byte("your-32-byte-secret-key-here!!!"),
    DatabaseType: "sqlite",
    DatabasePath: "users.db",
    Features: guardian.Features{
        EmailVerification: false,
        PasswordReset:     false,
        RememberMe:        false,
        RBAC:              false,
        ExternalAuth:      true,
    },
})

// Only requires users table with basic columns
```

### Full-Featured Setup

```go
// All features enabled (default)
app := guardian.New(guardian.Config{
    SessionKey:   []byte("your-32-byte-secret-key-here!!!"),
    Environment:  "production",
    DatabaseType: "mysql",
    DatabaseDSN:  "user:password@tcp(localhost:3306)/myapp?parseTime=true",
    
    // Custom session options
    SessionOptions: &sessions.Options{
        Path:     "/",
        Domain:   "example.com",
        MaxAge:   86400 * 7, // 1 week
        Secure:   true,
        HttpOnly: true,
        SameSite: http.SameSiteStrictMode,
    },
    
    // All features enabled by default
})
```

### Role-Based Access Control

```go
// With RBAC enabled
app := guardian.New(guardian.Config{
    SessionKey: []byte("your-32-byte-secret-key-here!!!"),
    Features: guardian.Features{
        RBAC: true,
    },
})

// Check permissions
if app.Auth().UserHasPermission(userID, "admin.users.edit") {
    // Allow action
}

// Assign role
app.Auth().AssignRole(userID, adminRoleID)

// Get user role
role, _ := app.Auth().GetUserRole(userID)
```

### Remember Me Functionality

```go
// Login with remember me
app.POST("/login", func(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    rememberMe := r.FormValue("remember_me") == "on"
    
    err := app.Auth().LoginWithRememberMe(w, r, email, password, rememberMe)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
})
```

## Testing

```bash
# Run all tests
./test.sh

# Run security tests only
go test -run "TestSQL|TestCSRF|TestXSS|TestPassword" ./...
```

## Migration from Other Frameworks

### From Standard Library

```go
// Before: http.HandleFunc
http.HandleFunc("/", handler)

// After: Guardian
app.GET("/", handler)
```

### From Gin/Echo

```go
// Similar routing API
app.GET("/users/:id", getUser)
app.POST("/users", createUser)

// Middleware
app.Use(middleware.Logger)
```

## Production Checklist

- [ ] Use production environment: `Environment: "production"`
- [ ] Generate secure session key: `openssl rand -base64 32`
- [ ] Enable HTTPS (sets Secure cookie flag)
- [ ] Configure proper CORS origins
- [ ] Set up database connection pooling
- [ ] Enable only needed features
- [ ] Validate database schema: `ValidateSchema: true`
- [ ] Configure session timeout appropriately
- [ ] Set up proper logging
- [ ] Implement rate limiting for public endpoints

## License

MIT License - see LICENSE file for details