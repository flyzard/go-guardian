# Handler Composition Framework

The Handler Composition Framework provides a clean and efficient way to organize related HTTP handlers, eliminating boilerplate code and providing shared data management.

## Problem it Solves

Traditional handler organization often requires:
- Multiple delegation methods that just forward calls
- Manual route registration for each handler
- No standard way to share data between related handlers
- Repetitive middleware application

## Key Features

1. **Automatic Route Delegation** - No more manual delegation methods
2. **Shared Data Store** - Thread-safe data sharing between handlers
3. **Fluent API** - Clean, chainable configuration
4. **Middleware Support** - Apply middleware to entire handler groups
5. **Multiple Handlers per Route** - Support different HTTP methods on same path

## Quick Start

### Basic Usage

```go
// Create a handler group
group := web.NewHandlerGroup("/api/users")

// Add handlers
group.Add("list", listHandler).Route("/", "list", "GET")
group.Add("create", createHandler).Route("/", "create", "POST")
group.Add("detail", detailHandler).Route("/{id}", "detail", "GET")

// Use the group
http.Handle("/api/users/", group)
```

### Using the Facade (Recommended)

```go
group := web.NewHandlerFacade("/api/users").
    WithHandler("list", listHandler).
    WithHandler("create", createHandler).
    WithHandler("detail", detailHandler).
    WithSharedData("db", database).
    WithMiddleware(authMiddleware).
    Build()
```

### Simple Handler Group

For basic use cases:

```go
group := web.SimpleHandlerGroup("/api").
    Handle("/users", usersHandler).
    Handle("/posts", postsHandler).
    HandlePrefix("/admin", adminHandler).
    Group()
```

## Advanced Features

### Shared Data

Handlers in a group can share data:

```go
// In setup
group.ShareData("config", appConfig)

// In any handler
config, ok := group.GetSharedData("config")
```

### RESTful Handlers

Automatically set up REST routes:

```go
type UserHandler struct{}

func (h *UserHandler) Index(w http.ResponseWriter, r *http.Request) {}
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {}
func (h *UserHandler) Show(w http.ResponseWriter, r *http.Request) {}

// Setup
group := web.NewHandlerFacade("/api").
    WithRESTHandler("users", &UserHandler{}).
    Build()
```

### Handler Composition

Compose multiple handler functions:

```go
composed := web.NewHandlerComposer().
    Add(validateRequest).
    Add(processRequest).
    AddIf(debug, logRequest).
    Build()
```

## Migration Example

### Before (VaultServer style)

```go
type VaultHandler struct {
    listHandler    *VaultListHandler
    statusHandler  *VaultStatusHandler
    // ... more handlers
}

func (h *VaultHandler) List(w http.ResponseWriter, r *http.Request) {
    h.listHandler.List(w, r)
}

func (h *VaultHandler) Status(w http.ResponseWriter, r *http.Request) {
    h.statusHandler.Status(w, r)
}

// ... many more delegation methods
```

### After

```go
vaultGroup := web.NewHandlerFacade("/vault").
    WithHandler("list", vaultListHandler).
    WithHandler("status", vaultStatusHandler).
    Route("/{id}/status", "status", "GET").
    Build()

// No delegation methods needed!
```

## Benefits

1. **Less Code** - Eliminates delegation boilerplate
2. **Clearer Organization** - Related handlers grouped together
3. **Better Testing** - Groups can be tested in isolation
4. **Flexible Routing** - Automatic and manual routing options
5. **Performance** - Efficient routing with proper method handling

## API Reference

### HandlerGroup

- `Add(name string, handler http.Handler)` - Register a handler
- `Route(pattern, handlerName string, methods ...string)` - Map route to handler
- `Use(middleware ...func(http.Handler) http.Handler)` - Add middleware
- `ShareData(key string, value interface{})` - Store shared data
- `GetSharedData(key string) (interface{}, bool)` - Retrieve shared data
- `Delegate(name string) http.HandlerFunc` - Get delegating function

### HandlerFacade

- `WithHandler(name string, handler http.Handler, options...)` - Add handler
- `WithRESTHandler(resource string, handler RESTHandler)` - Add REST handler
- `WithMiddleware(middleware...)` - Add middleware
- `WithSharedData(key string, value interface{})` - Add shared data
- `Route(pattern, handlerName string, methods...)` - Custom routing
- `Build() *HandlerGroup` - Build the handler group

### SimpleHandlerGroup

- `Handle(pattern string, handler http.HandlerFunc)` - Add route handler
- `HandlePrefix(prefix string, handler http.HandlerFunc)` - Add prefix handler
- `Group() *HandlerGroup` - Get the handler group