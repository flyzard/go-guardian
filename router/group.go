package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Group struct {
	router      *Router
	pattern     string
	middlewares []func(http.Handler) http.Handler
	chiRouter   chi.Router
}

func (r *Router) Group(pattern string) *Group {
	// Create a sub-router for this group
	var chiRouter chi.Router
	if pattern == "/" {
		// For root pattern, use the main router with a middleware group
		chiRouter = r.Router
	} else {
		// For other patterns, create a proper sub-router
		chiRouter = chi.NewRouter()
		r.Router.Mount(pattern, chiRouter)
	}

	return &Group{
		router:    r,
		pattern:   pattern,
		chiRouter: chiRouter,
	}
}

func (g *Group) Use(middleware ...func(http.Handler) http.Handler) {
	g.middlewares = append(g.middlewares, middleware...)
}

func (g *Group) GET(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern

	// Wrap handler with group middlewares
	h := http.Handler(handler)
	for i := len(g.middlewares) - 1; i >= 0; i-- {
		h = g.middlewares[i](h)
	}

	g.chiRouter.Get(pattern, h.ServeHTTP)

	route := &Route{
		Pattern: fullPattern,
		Method:  "GET",
		Handler: handler,
		router:  g.router,
	}
	return route
}

func (g *Group) POST(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern

	// Wrap handler with group middlewares
	h := http.Handler(handler)
	for i := len(g.middlewares) - 1; i >= 0; i-- {
		h = g.middlewares[i](h)
	}

	g.chiRouter.Post(pattern, h.ServeHTTP)

	route := &Route{
		Pattern: fullPattern,
		Method:  "POST",
		Handler: handler,
		router:  g.router,
	}
	return route
}

func (g *Group) PUT(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern

	// Wrap handler with group middlewares
	h := http.Handler(handler)
	for i := len(g.middlewares) - 1; i >= 0; i-- {
		h = g.middlewares[i](h)
	}

	g.chiRouter.Put(pattern, h.ServeHTTP)

	route := &Route{
		Pattern: fullPattern,
		Method:  "PUT",
		Handler: handler,
		router:  g.router,
	}
	return route
}

func (g *Group) DELETE(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern

	// Wrap handler with group middlewares
	h := http.Handler(handler)
	for i := len(g.middlewares) - 1; i >= 0; i-- {
		h = g.middlewares[i](h)
	}

	g.chiRouter.Delete(pattern, h.ServeHTTP)

	route := &Route{
		Pattern: fullPattern,
		Method:  "DELETE",
		Handler: handler,
		router:  g.router,
	}
	return route
}

func (g *Group) PATCH(pattern string, handler http.HandlerFunc) *Route {
	fullPattern := g.pattern + pattern

	// Wrap handler with group middlewares
	h := http.Handler(handler)
	for i := len(g.middlewares) - 1; i >= 0; i-- {
		h = g.middlewares[i](h)
	}

	g.chiRouter.Patch(pattern, h.ServeHTTP)

	route := &Route{
		Pattern: fullPattern,
		Method:  "PATCH",
		Handler: handler,
		router:  g.router,
	}
	return route
}
