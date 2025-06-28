// Package router provides a custom router for handling HTTP routes
package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Router is a custom router that extends chi.Router
type Router struct {
	chi.Router
	routes map[string]*Route
}

// Route represents a single route in the router
type Route struct {
	Pattern   string
	Method    string
	Handler   http.HandlerFunc
	RouteName string
}

// New creates a new Router
func New() *Router {
	return &Router{
		Router: chi.NewRouter(),
		routes: make(map[string]*Route),
	}
}

// GET adds a GET route to the router
func (r *Router) GET(pattern string, handler http.HandlerFunc) *Route {
	r.Router.Get(pattern, handler)
	route := &Route{Pattern: pattern, Method: "GET", Handler: handler}
	return route
}

// POST adds a POST route to the router
func (r *Router) POST(pattern string, handler http.HandlerFunc) *Route {
	r.Router.Post(pattern, handler)
	route := &Route{Pattern: pattern, Method: "POST", Handler: handler}
	return route
}

// PUT adds a PUT route to the router
func (r *Router) PUT(pattern string, handler http.HandlerFunc) *Route {
	r.Router.Put(pattern, handler)
	route := &Route{Pattern: pattern, Method: "PUT", Handler: handler}
	return route
}

// DELETE adds a DELETE route to the router
func (r *Router) DELETE(pattern string, handler http.HandlerFunc) *Route {
	r.Router.Delete(pattern, handler)
	route := &Route{Pattern: pattern, Method: "DELETE", Handler: handler}
	return route
}

// PATCH adds a PATCH route to the router
func (r *Router) PATCH(pattern string, handler http.HandlerFunc) *Route {
	r.Router.Patch(pattern, handler)
	route := &Route{Pattern: pattern, Method: "PATCH", Handler: handler}
	return route
}

// Group creates a new route Group
func (r *Router) Group(pattern string) *Group {
	return &Group{
		router:  r,
		pattern: pattern,
	}
}

// SetName sets the name of the route
func (route *Route) SetName(name string) *Route {
	route.RouteName = name
	return route
}

// URL generates a URL for a named route
func (r *Router) URL(name string, params ...string) string {
	if route, ok := r.routes[name]; ok {
		// Simple URL generation - can be enhanced
		url := route.Pattern
		for i := 0; i < len(params); i += 2 {
			if i+1 < len(params) {
				url = replaceParam(url, params[i], params[i+1])
			}
		}
		return url
	}
	return ""
}

func replaceParam(pattern, _, _ string) string {
	// Simple parameter replacement
	return pattern // TODO: Implement actual replacement
}
