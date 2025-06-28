package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Router struct {
	chi.Router
	routes map[string]*Route
}

type Route struct {
	Pattern   string
	Method    string
	Handler   http.HandlerFunc
	RouteName string
	router    *Router // Reference to parent router
}

func New() *Router {
	return &Router{
		Router: chi.NewRouter(),
		routes: make(map[string]*Route),
	}
}

func (r *Router) GET(pattern string, handler http.HandlerFunc) *Route {
	r.Router.Get(pattern, handler)
	route := &Route{Pattern: pattern, Method: "GET", Handler: handler, router: r}
	return route
}

func (r *Router) POST(pattern string, handler http.HandlerFunc) *Route {
	r.Router.Post(pattern, handler)
	route := &Route{Pattern: pattern, Method: "POST", Handler: handler, router: r}
	return route
}

func (r *Router) PUT(pattern string, handler http.HandlerFunc) *Route {
	r.Router.Put(pattern, handler)
	route := &Route{Pattern: pattern, Method: "PUT", Handler: handler, router: r}
	return route
}

func (r *Router) DELETE(pattern string, handler http.HandlerFunc) *Route {
	r.Router.Delete(pattern, handler)
	route := &Route{Pattern: pattern, Method: "DELETE", Handler: handler, router: r}
	return route
}

func (r *Router) PATCH(pattern string, handler http.HandlerFunc) *Route {
	r.Router.Patch(pattern, handler)
	route := &Route{Pattern: pattern, Method: "PATCH", Handler: handler, router: r}
	return route
}

func (r *Router) Group(pattern string) *Group {
	return &Group{
		router:  r,
		pattern: pattern,
	}
}

func (route *Route) Name(name string) *Route {
	route.RouteName = name
	if route.router != nil {
		route.router.routes[name] = route
	}
	return route
}

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
