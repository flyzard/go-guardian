// Package web provides HTTP utilities and helpers for the Guardian framework.
package web

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// HandlerGroup manages a collection of related handlers with shared data and automatic routing
type HandlerGroup struct {
	handlers map[string]http.Handler     // Named handlers in the group
	routes   map[string][]routeMapping   // Route pattern to handler mappings (multiple per pattern)
	shared   sync.Map                    // Thread-safe shared data store
	prefix   string                      // URL prefix for the group
	mu       sync.RWMutex               // Protects handlers and routes maps
	
	// Middleware to apply to all handlers in the group
	middleware []func(http.Handler) http.Handler
}

// routeMapping stores the handler name and allowed methods for a route
type routeMapping struct {
	handlerName string
	methods     []string // Empty means all methods allowed
}

// NewHandlerGroup creates a new handler group with optional URL prefix
func NewHandlerGroup(prefix string) *HandlerGroup {
	return &HandlerGroup{
		handlers:   make(map[string]http.Handler),
		routes:     make(map[string][]routeMapping),
		prefix:     strings.TrimSuffix(prefix, "/"),
		middleware: make([]func(http.Handler) http.Handler, 0),
	}
}

// Add registers a named handler in the group
func (hg *HandlerGroup) Add(name string, handler http.Handler) *HandlerGroup {
	hg.mu.Lock()
	defer hg.mu.Unlock()
	
	// Apply group middleware to the handler
	finalHandler := handler
	for i := len(hg.middleware) - 1; i >= 0; i-- {
		finalHandler = hg.middleware[i](finalHandler)
	}
	
	hg.handlers[name] = finalHandler
	return hg
}

// Route maps a URL pattern to a named handler with optional method restrictions
func (hg *HandlerGroup) Route(pattern, handlerName string, methods ...string) *HandlerGroup {
	hg.mu.Lock()
	defer hg.mu.Unlock()
	
	// Normalize the pattern
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	
	fullPattern := hg.prefix + pattern
	
	// Append to existing mappings for this pattern
	if hg.routes[fullPattern] == nil {
		hg.routes[fullPattern] = make([]routeMapping, 0)
	}
	
	hg.routes[fullPattern] = append(hg.routes[fullPattern], routeMapping{
		handlerName: handlerName,
		methods:     methods,
	})
	
	return hg
}

// Use adds middleware that will be applied to all handlers in the group
func (hg *HandlerGroup) Use(middleware ...func(http.Handler) http.Handler) *HandlerGroup {
	hg.mu.Lock()
	defer hg.mu.Unlock()
	
	hg.middleware = append(hg.middleware, middleware...)
	
	// Re-apply middleware to existing handlers
	for name, handler := range hg.handlers {
		// Strip existing middleware by getting the original handler
		// This is a simplified approach - in production you'd track original handlers
		finalHandler := handler
		for i := len(middleware) - 1; i >= 0; i-- {
			finalHandler = middleware[i](finalHandler)
		}
		hg.handlers[name] = finalHandler
	}
	
	return hg
}

// Delegate returns a handler function that delegates to the named handler
// This is useful for backward compatibility with existing routing
func (hg *HandlerGroup) Delegate(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hg.mu.RLock()
		handler, exists := hg.handlers[name]
		hg.mu.RUnlock()
		
		if !exists {
			http.Error(w, fmt.Sprintf("Handler '%s' not found", name), http.StatusInternalServerError)
			return
		}
		
		handler.ServeHTTP(w, r)
	}
}

// ServeHTTP implements http.Handler interface for automatic routing
func (hg *HandlerGroup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hg.mu.RLock()
	defer hg.mu.RUnlock()
	
	// Try to match the request path to a route
	for pattern, mappings := range hg.routes {
		if matchesPattern(r.URL.Path, pattern) {
			// Try to find a mapping that matches the request method
			var matchedMapping *routeMapping
			var methodAllowed bool
			
			for _, mapping := range mappings {
				// If no methods specified, this mapping handles all methods
				if len(mapping.methods) == 0 {
					matchedMapping = &mapping
					methodAllowed = true
					break
				}
				
				// Check if the request method is in the allowed methods
				if contains(mapping.methods, r.Method) {
					matchedMapping = &mapping
					methodAllowed = true
					break
				}
			}
			
			// If we found a route match but no method match, return 405
			if !methodAllowed && len(mappings) > 0 {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			
			if matchedMapping != nil {
				handler, exists := hg.handlers[matchedMapping.handlerName]
				if !exists {
					http.Error(w, fmt.Sprintf("Handler '%s' not found", matchedMapping.handlerName), http.StatusInternalServerError)
					return
				}
				
				handler.ServeHTTP(w, r)
				return
			}
		}
	}
	
	// No route matched
	http.NotFound(w, r)
}

// ShareData stores data that can be accessed by all handlers in the group
func (hg *HandlerGroup) ShareData(key string, value interface{}) {
	hg.shared.Store(key, value)
}

// GetSharedData retrieves shared data by key
func (hg *HandlerGroup) GetSharedData(key string) (interface{}, bool) {
	return hg.shared.Load(key)
}

// GetSharedString retrieves shared data as string
func (hg *HandlerGroup) GetSharedString(key string) (string, bool) {
	val, ok := hg.shared.Load(key)
	if !ok {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}

// GetSharedInt retrieves shared data as int
func (hg *HandlerGroup) GetSharedInt(key string) (int, bool) {
	val, ok := hg.shared.Load(key)
	if !ok {
		return 0, false
	}
	i, ok := val.(int)
	return i, ok
}

// DeleteSharedData removes shared data by key
func (hg *HandlerGroup) DeleteSharedData(key string) {
	hg.shared.Delete(key)
}

// ClearSharedData removes all shared data
func (hg *HandlerGroup) ClearSharedData() {
	hg.shared.Range(func(key, value interface{}) bool {
		hg.shared.Delete(key)
		return true
	})
}

// Mount attaches this handler group to a router at the specified pattern
func (hg *HandlerGroup) Mount(pattern string, router interface{ Handle(string, http.Handler) }) {
	if !strings.HasSuffix(pattern, "/*") {
		pattern = strings.TrimSuffix(pattern, "/") + "/*"
	}
	
	// Type assertion for chi router
	type chiRouter interface {
		Handle(pattern string, h http.Handler)
	}
	
	if r, ok := router.(chiRouter); ok {
		r.Handle(pattern, hg)
	}
}

// Handlers returns a copy of the registered handlers map
func (hg *HandlerGroup) Handlers() map[string]http.Handler {
	hg.mu.RLock()
	defer hg.mu.RUnlock()
	
	result := make(map[string]http.Handler, len(hg.handlers))
	for k, v := range hg.handlers {
		result[k] = v
	}
	return result
}

// Routes returns a copy of the registered routes
func (hg *HandlerGroup) Routes() map[string]string {
	hg.mu.RLock()
	defer hg.mu.RUnlock()
	
	result := make(map[string]string)
	for pattern, mappings := range hg.routes {
		// For simplicity, just show the first handler for each pattern
		if len(mappings) > 0 {
			result[pattern] = mappings[0].handlerName
		}
	}
	return result
}

// Helper functions

// matchesPattern checks if a path matches a pattern (simple implementation)
// In production, you'd use a more sophisticated pattern matching
func matchesPattern(path, pattern string) bool {
	// Exact match
	if path == pattern {
		return true
	}
	
	// Pattern with wildcard
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}
	
	// Pattern with parameter (e.g., /vault/{id})
	if strings.Contains(pattern, "{") && strings.Contains(pattern, "}") {
		// Simple parameter matching - in production use a proper router
		patternParts := strings.Split(pattern, "/")
		pathParts := strings.Split(path, "/")
		
		if len(patternParts) != len(pathParts) {
			return false
		}
		
		for i, part := range patternParts {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				// This is a parameter, any value matches
				continue
			}
			if part != pathParts[i] {
				return false
			}
		}
		return true
	}
	
	return false
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}