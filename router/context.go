package router

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Context struct {
	w http.ResponseWriter
	r *http.Request
}

func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	return &Context{w: w, r: r}
}


// Existing methods...
func (c *Context) Param(key string) string {
	return chi.URLParam(c.r, key)
}

func (c *Context) Query(key string) string {
	return c.r.URL.Query().Get(key)
}

func (c *Context) JSON(status int, data interface{}) error {
	c.w.Header().Set("Content-Type", "application/json")
	c.w.WriteHeader(status)
	return json.NewEncoder(c.w).Encode(data)
}

func (c *Context) HTML(status int, html string) {
	c.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	c.w.WriteHeader(status)
	c.w.Write([]byte(html))
}

func (c *Context) String(status int, format string, values ...interface{}) {
	c.w.WriteHeader(status)
	c.w.Write([]byte(format))
}

func (c *Context) Redirect(status int, url string) {
	http.Redirect(c.w, c.r, url, status)
}

func (c *Context) SetCookie(cookie *http.Cookie) {
	http.SetCookie(c.w, cookie)
}

func (c *Context) Cookie(name string) (*http.Cookie, error) {
	return c.r.Cookie(name)
}

func (c *Context) Request() *http.Request {
	return c.r
}

func (c *Context) ResponseWriter() http.ResponseWriter {
	return c.w
}

func (c *Context) Set(key string, value interface{}) {
	ctx := context.WithValue(c.r.Context(), key, value)
	c.r = c.r.WithContext(ctx)
}

func (c *Context) Get(key string) interface{} {
	return c.r.Context().Value(key)
}
