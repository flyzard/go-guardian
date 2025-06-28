package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Group represents a group of routes with a common pattern and middlewares
type Group struct {
	router      *Router
	pattern     string
	middlewares []func(http.Handler) http.Handler
}

// Use adds middleware to the group
func (g *Group) Use(middleware ...func(http.Handler) http.Handler) {
	g.middlewares = append(g.middlewares, middleware...)
}

// GET adds a GET route to the group
func (g *Group) GET(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern
	g.router.Route(g.pattern, func(r chi.Router) {
		for _, mw := range g.middlewares {
			r.Use(mw)
		}
		r.Get(pattern, handler)
	})
	return &Route{Pattern: fullPattern, Method: "GET", Handler: handler}
}

// POST adds a POST route to the group
func (g *Group) POST(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern
	g.router.Route(g.pattern, func(r chi.Router) {
		for _, mw := range g.middlewares {
			r.Use(mw)
		}
		r.Post(pattern, handler)
	})
	return &Route{Pattern: fullPattern, Method: "POST", Handler: handler}
}

// PUT adds a PUT route to the group
func (g *Group) PUT(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern
	g.router.Route(g.pattern, func(r chi.Router) {
		for _, mw := range g.middlewares {
			r.Use(mw)
		}
		r.Put(pattern, handler)
	})
	return &Route{Pattern: fullPattern, Method: "PUT", Handler: handler}
}

// DELETE adds a DELETE route to the group
func (g *Group) DELETE(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern
	g.router.Route(g.pattern, func(r chi.Router) {
		for _, mw := range g.middlewares {
			r.Use(mw)
		}
		r.Delete(pattern, handler)
	})
	return &Route{Pattern: fullPattern, Method: "DELETE", Handler: handler}
}
