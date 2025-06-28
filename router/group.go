package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Group struct {
	router      *Router
	pattern     string
	middlewares []func(http.Handler) http.Handler
}

func (g *Group) Use(middleware ...func(http.Handler) http.Handler) {
	g.middlewares = append(g.middlewares, middleware...)
}

func (g *Group) GET(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern
	g.router.Route(g.pattern, func(r chi.Router) {
		for _, mw := range g.middlewares {
			r.Use(mw)
		}
		r.Get(pattern, handler)
	})
	route := &Route{Pattern: fullPattern, Method: "GET", Handler: handler, router: g.router}
	return route
}

func (g *Group) POST(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern
	g.router.Route(g.pattern, func(r chi.Router) {
		for _, mw := range g.middlewares {
			r.Use(mw)
		}
		r.Post(pattern, handler)
	})
	route := &Route{Pattern: fullPattern, Method: "POST", Handler: handler, router: g.router}
	return route
}

func (g *Group) PUT(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern
	g.router.Route(g.pattern, func(r chi.Router) {
		for _, mw := range g.middlewares {
			r.Use(mw)
		}
		r.Put(pattern, handler)
	})
	route := &Route{Pattern: fullPattern, Method: "PUT", Handler: handler, router: g.router}
	return route
}

func (g *Group) DELETE(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern
	g.router.Route(g.pattern, func(r chi.Router) {
		for _, mw := range g.middlewares {
			r.Use(mw)
		}
		r.Delete(pattern, handler)
	})
	route := &Route{Pattern: fullPattern, Method: "DELETE", Handler: handler, router: g.router}
	return route
}
