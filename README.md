# Go-Guardian

A secure, lightweight web framework for Go that prioritizes security and simplicity over feature bloat.

## Philosophy

Go-Guardian follows four core principles:
- **Security First**: Every feature is designed with security as the primary concern
- **Simplicity**: Choose simple, proven solutions over complex patterns
- **Minimal Dependencies**: Use only essential, well-maintained packages
- **No Magic**: Explicit, readable code over clever abstractions

## Features

### 🔐 Security
- **CSRF Protection**: Double-submit cookie pattern
- **XSS Prevention**: Automatic HTML escaping and Content Security Policy headers
- **SQL Injection Prevention**: Parameterized queries only
- **Session Security**: Secure, HttpOnly, SameSite cookies with regeneration
- **Password Security**: bcrypt hashing with secure defaults
- **Security Headers**: X-Frame-Options, X-Content-Type-Options, etc.

### 🚀 Core Features
- **Fast Routing**: Built on [chi router](https://github.com/go-chi/chi)
- **Middleware Pipeline**: Simple, composable middleware
- **Session Management**: Secure session handling with [gorilla/sessions](https://github.com/gorilla/sessions)
- **Database Support**: SQLite (default) and MySQL with migration system
- **Input Validation**: Powered by [validator/v10](https://github.com/go-playground/validator)
- **HTMX Support**: Built-in middleware for modern hypermedia applications

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
    // Initialize app with secure session key
    app := guardian.New(guardian.Config{
        SessionKey:   []byte("your-32-byte-secret-key-here!!!"),
        DatabaseType: "sqlite",
        DatabasePath: "app.db",
    })
    
    // Apply security middleware
    app.Use(middleware.Logger)
    app.Use(middleware.SecurityHeaders)
    app.Use(middleware.CSRF)
    
    // Define routes
    app.GET("/", homeHandler)
    app.POST("/login", loginHandler)
    
    // Protected routes
    admin := app.Group("/admin")
    admin.Use(middleware.RequireAuth(app.Sessions()))
    admin.GET("/dashboard", dashboardHandler)
    
    app.Listen(":8080")
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Welcome to Go-Guardian!"))
}
```

## Security Features

### CSRF Protection
Automatically protects all state-changing operations:
```go
// CSRF token automatically validated for POST/PUT/DELETE
app.POST("/api/users", createUser)
```

### SQL Injection Prevention
Use the query builder for safe database operations:
```go
user, err := app.DB().Query().
    Select("users", "id", "email").
    Where("email", "=", email).
    QueryRow().
    Scan(&id, &email)
```

### XSS Protection
All output is automatically escaped:
```go
sanitized := security.SanitizeHTML(userInput)
```

### Authentication
Built-in secure authentication:
```go
// Register
user, err := app.Auth().Register(email, password)

// Login
err := app.Auth().Login(w, r, email, password)

// Get current user
user, err := app.Auth().GetUser(r)

// Logout
err := app.Auth().Logout(w, r)
```

## Middleware

### Built-in Middleware
- `Logger` - Request logging with request IDs
- `SecurityHeaders` - Security headers (CSP, X-Frame-Options, etc.)
- `CSRF` - CSRF protection using double-submit cookies
- `RequireAuth` - Authentication enforcement
- `CORS` - Configurable CORS support
- `HTMX` - HTMX request handling

### Custom Middleware
```go
func RateLimit(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Your middleware logic
        next.ServeHTTP(w, r)
    })
}

app.Use(RateLimit)
```

## Database

### Migrations
SQL-based migrations with up/down support:
```go
// Migrations run automatically on startup
// Add new migrations to database/migration.go
```

### Query Builder
Safe, parameterized queries:
```go
// Insert
result, err := app.DB().Query().Insert("users", map[string]interface{}{
    "email": email,
    "password_hash": hash,
})

// Update
result, err := app.DB().Query().Update("users", 
    map[string]interface{}{"verified": true},
    map[string]interface{}{"id": userID},
)
```

## Testing

The framework includes comprehensive security tests:
```bash
# Run all tests
./test.sh

# Run security tests only
go test -run "TestSQL|TestCSRF|TestXSS|TestPassword" ./...
```

## Configuration

### Environment-based Settings
```go
app := guardian.New(guardian.Config{
    SessionKey:      []byte(os.Getenv("SESSION_KEY")),
    Environment:     os.Getenv("APP_ENV"), // "development" or "production"
    DatabaseType:    "mysql",
    DatabaseDSN:     os.Getenv("DATABASE_URL"),
    MaxOpenConns:    25,
    MaxIdleConns:    5,
    ConnMaxLifetime: 5 * time.Minute,
})
```

## Security Checklist

Go-Guardian automatically handles:
- [x] SQL injection prevention via parameterized queries
- [x] XSS prevention via auto-escaping
- [x] CSRF protection on state-changing operations  
- [x] Secure password hashing (bcrypt cost 12)
- [x] Session fixation prevention
- [x] Secure cookie settings
- [x] Security headers on all responses
- [x] Input validation and sanitization

## Contributing

1. Follow the security-first philosophy
2. Keep dependencies minimal
3. Write clear, explicit code
4. Add security tests for new features

## License

MIT License - see LICENSE file for details
