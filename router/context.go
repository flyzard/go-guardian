package router

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Context is a wrapper around http.ResponseWriter and http.Request
type Context struct {
	w http.ResponseWriter
	r *http.Request
}

// NewContext creates a new Context
func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	return &Context{w: w, r: r}
}

// Param retrieves a URL parameter by name
func (c *Context) Param(key string) string {
	return chi.URLParam(c.r, key)
}

// Query retrieves a query parameter by name
func (c *Context) Query(key string) string {
	return c.r.URL.Query().Get(key)
}

// JSON sends a JSON response
func (c *Context) JSON(status int, data interface{}) error {
	c.w.Header().Set("Content-Type", "application/json")
	c.w.WriteHeader(status)
	return json.NewEncoder(c.w).Encode(data)
}

// String sends a plain text response
func (c *Context) String(status int, format string, values ...interface{}) {
	c.w.WriteHeader(status)
	c.w.Write([]byte(format))
}

// Redirect sends a redirect response
func (c *Context) Redirect(status int, url string) {
	http.Redirect(c.w, c.r, url, status)
}

// SetCookie sets a cookie
func (c *Context) SetCookie(cookie *http.Cookie) {
	http.SetCookie(c.w, cookie)
}

// Cookie retrieves a cookie by name
func (c *Context) Cookie(name string) (*http.Cookie, error) {
	return c.r.Cookie(name)
}

// Request returns the underlying http.Request
func (c *Context) Request() *http.Request {
	return c.r
}

// ResponseWriter returns the underlying http.ResponseWriter
func (c *Context) ResponseWriter() http.ResponseWriter {
	return c.w
}

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

// Set sets a value in the context
func (c *Context) Set(key string, value interface{}) {
	ctx := context.WithValue(c.r.Context(), contextKey(key), value)
	c.r = c.r.WithContext(ctx)
}

// Get retrieves a value from the context
func (c *Context) Get(key string) interface{} {
	return c.r.Context().Value(contextKey(key))
}
