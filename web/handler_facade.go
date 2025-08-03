package web

import (
	"net/http"
	"strings"
)

// HandlerFacade provides a fluent interface for building handler groups
type HandlerFacade struct {
	group      *HandlerGroup
	autoRoutes map[string][]string // Maps handler names to their auto-generated routes
}

// NewHandlerFacade creates a new handler facade with fluent API
func NewHandlerFacade(prefix string) *HandlerFacade {
	return &HandlerFacade{
		group:      NewHandlerGroup(prefix),
		autoRoutes: make(map[string][]string),
	}
}

// WithHandler adds a handler with optional auto-routing based on common patterns
func (hf *HandlerFacade) WithHandler(name string, handler http.Handler, options ...HandlerOption) *HandlerFacade {
	// Apply options
	opts := &handlerOptions{
		autoRoute: true,
		methods:   []string{},
	}
	for _, opt := range options {
		opt(opts)
	}
	
	// Add the handler
	hf.group.Add(name, handler)
	
	// Auto-generate routes if enabled
	if opts.autoRoute {
		routes := hf.generateRoutes(name, opts)
		hf.autoRoutes[name] = routes
		
		for _, route := range routes {
			hf.group.Route(route, name, opts.methods...)
		}
	}
	
	return hf
}

// WithRESTHandler adds a handler with RESTful routes
func (hf *HandlerFacade) WithRESTHandler(resourceName string, handler RESTHandler) *HandlerFacade {
	basePath := "/" + resourceName
	
	// Add individual method handlers
	if h, ok := handler.(interface{ Index(http.ResponseWriter, *http.Request) }); ok {
		hf.group.Add(resourceName+".index", http.HandlerFunc(h.Index))
		hf.group.Route(basePath, resourceName+".index", "GET")
	}
	
	if h, ok := handler.(interface{ Create(http.ResponseWriter, *http.Request) }); ok {
		hf.group.Add(resourceName+".create", http.HandlerFunc(h.Create))
		hf.group.Route(basePath, resourceName+".create", "POST")
	}
	
	if h, ok := handler.(interface{ Show(http.ResponseWriter, *http.Request) }); ok {
		hf.group.Add(resourceName+".show", http.HandlerFunc(h.Show))
		hf.group.Route(basePath+"/{id}", resourceName+".show", "GET")
	}
	
	if h, ok := handler.(interface{ Update(http.ResponseWriter, *http.Request) }); ok {
		hf.group.Add(resourceName+".update", http.HandlerFunc(h.Update))
		hf.group.Route(basePath+"/{id}", resourceName+".update", "PUT", "PATCH")
	}
	
	if h, ok := handler.(interface{ Delete(http.ResponseWriter, *http.Request) }); ok {
		hf.group.Add(resourceName+".delete", http.HandlerFunc(h.Delete))
		hf.group.Route(basePath+"/{id}", resourceName+".delete", "DELETE")
	}
	
	return hf
}

// WithMiddleware adds middleware to all handlers in the group
func (hf *HandlerFacade) WithMiddleware(middleware ...func(http.Handler) http.Handler) *HandlerFacade {
	hf.group.Use(middleware...)
	return hf
}

// WithSharedData adds initial shared data
func (hf *HandlerFacade) WithSharedData(key string, value interface{}) *HandlerFacade {
	hf.group.ShareData(key, value)
	return hf
}

// Route adds a custom route mapping
func (hf *HandlerFacade) Route(pattern, handlerName string, methods ...string) *HandlerFacade {
	hf.group.Route(pattern, handlerName, methods...)
	return hf
}

// Build returns the configured handler group
func (hf *HandlerFacade) Build() *HandlerGroup {
	return hf.group
}

// generateRoutes creates common route patterns based on handler name
func (hf *HandlerFacade) generateRoutes(name string, opts *handlerOptions) []string {
	routes := []string{}
	
	// Common patterns
	switch name {
	case "list", "index":
		routes = append(routes, "/")
	case "create", "new":
		routes = append(routes, "/new")
	case "show", "view", "detail", "details":
		routes = append(routes, "/{id}")
	case "edit":
		routes = append(routes, "/{id}/edit")
	case "update":
		routes = append(routes, "/{id}")
	case "delete", "destroy":
		routes = append(routes, "/{id}")
	default:
		// Use handler name as route
		routes = append(routes, "/"+name)
	}
	
	// Apply custom routes from options
	if len(opts.customRoutes) > 0 {
		routes = opts.customRoutes
	}
	
	return routes
}

// HandlerOption configures handler registration
type HandlerOption func(*handlerOptions)

type handlerOptions struct {
	autoRoute    bool
	methods      []string
	customRoutes []string
}

// NoAutoRoute disables automatic route generation
func NoAutoRoute() HandlerOption {
	return func(o *handlerOptions) {
		o.autoRoute = false
	}
}

// WithMethods restricts the handler to specific HTTP methods
func WithMethods(methods ...string) HandlerOption {
	return func(o *handlerOptions) {
		o.methods = methods
	}
}

// WithRoutes specifies custom routes for the handler
func WithRoutes(routes ...string) HandlerOption {
	return func(o *handlerOptions) {
		o.customRoutes = routes
		o.autoRoute = true
	}
}

// RESTHandler interface for RESTful handlers
type RESTHandler interface{}

// RESTMethods are optional interfaces that RESTHandler implementations can satisfy
type (
	RESTIndex  interface{ Index(http.ResponseWriter, *http.Request) }
	RESTCreate interface{ Create(http.ResponseWriter, *http.Request) }
	RESTShow   interface{ Show(http.ResponseWriter, *http.Request) }
	RESTUpdate interface{ Update(http.ResponseWriter, *http.Request) }
	RESTDelete interface{ Delete(http.ResponseWriter, *http.Request) }
)

// HandlerComposer helps compose multiple handler functions into a single handler
type HandlerComposer struct {
	funcs []http.HandlerFunc
}

// NewHandlerComposer creates a new handler composer
func NewHandlerComposer() *HandlerComposer {
	return &HandlerComposer{
		funcs: make([]http.HandlerFunc, 0),
	}
}

// Add adds a handler function to the composition
func (hc *HandlerComposer) Add(fn http.HandlerFunc) *HandlerComposer {
	hc.funcs = append(hc.funcs, fn)
	return hc
}

// AddIf conditionally adds a handler function
func (hc *HandlerComposer) AddIf(condition bool, fn http.HandlerFunc) *HandlerComposer {
	if condition {
		hc.funcs = append(hc.funcs, fn)
	}
	return hc
}

// ServeHTTP implements http.Handler by calling all composed functions in order
func (hc *HandlerComposer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, fn := range hc.funcs {
		fn(w, r)
		
		// Check if response was already written
		if w.Header().Get("Content-Type") != "" {
			break
		}
	}
}

// Build returns the composed handler
func (hc *HandlerComposer) Build() http.Handler {
	return hc
}

// SimpleHandlerGroup provides a minimal API for common use cases
func SimpleHandlerGroup(prefix string) *SimpleGroup {
	return &SimpleGroup{
		facade: NewHandlerFacade(prefix),
		group:  nil,
	}
}

// SimpleGroup provides a simplified API for handler groups
type SimpleGroup struct {
	facade *HandlerFacade
	group  *HandlerGroup
}

// Handle adds a handler function with a specific route
func (sg *SimpleGroup) Handle(pattern string, handler http.HandlerFunc) *SimpleGroup {
	// Extract handler name from pattern
	name := pattern
	if pattern != "/" {
		name = strings.TrimPrefix(pattern, "/")
		name = strings.ReplaceAll(name, "/", ".")
	} else {
		name = "index"
	}
	
	sg.facade.WithHandler(name, handler, WithRoutes(pattern))
	return sg
}

// HandlePrefix adds a handler that matches all routes with a prefix
func (sg *SimpleGroup) HandlePrefix(prefix string, handler http.HandlerFunc) *SimpleGroup {
	name := strings.TrimPrefix(prefix, "/") + ".prefix"
	pattern := prefix + "/*"
	
	sg.facade.WithHandler(name, handler, WithRoutes(pattern))
	return sg
}

// Group returns the built handler group
func (sg *SimpleGroup) Group() *HandlerGroup {
	if sg.group == nil {
		sg.group = sg.facade.Build()
	}
	return sg.group
}