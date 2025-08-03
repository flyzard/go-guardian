package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"
	
	"github.com/flyzard/go-guardian/web"
	"github.com/flyzard/go-guardian/web/template"
)

// templateContextKey is the context key for template manager
type templateContextKey struct{}

// TemplateConfig holds template middleware configuration
type TemplateConfig struct {
	Manager           *template.Manager
	ComponentRegistry *template.ComponentRegistry
	HTMXExtensions    *template.HTMXExtensions
	EnableCache       bool
	CacheTTL          time.Duration
}

// Template middleware adds template management to the request context
func Template(config TemplateConfig) func(http.Handler) http.Handler {
	// Initialize template manager if not provided
	if config.Manager == nil {
		config.Manager = template.NewManager(template.Config{
			Development: true,
		})
	}

	// Initialize component registry
	if config.ComponentRegistry == nil {
		config.ComponentRegistry = template.NewComponentRegistry(config.Manager)
		config.ComponentRegistry.RegisterBuiltinComponents()
	}

	// Initialize HTMX extensions
	if config.HTMXExtensions == nil {
		config.HTMXExtensions = template.NewHTMXExtensions(config.ComponentRegistry)
	}

	// Create cached manager if caching is enabled
	var manager interface{} = config.Manager
	if config.EnableCache {
		cachedManager := template.NewCachedManager(
			template.Config{
				Development: false, // Caching typically used in production
			},
			template.CacheConfig{
				TTL:     config.CacheTTL,
				MaxSize: 100 * 1024 * 1024, // 100MB
			},
		)
		manager = cachedManager
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add template manager to context
			ctx := context.WithValue(r.Context(), templateContextKey{}, manager)
			r = r.WithContext(ctx)

			// Wrap response writer to add template support
			wrappedWriter := &templateResponseWriter{
				ResponseWriter:    w,
				templateManager:   config.Manager,
				componentRegistry: config.ComponentRegistry,
			}

			next.ServeHTTP(wrappedWriter, r)
		})
	}
}

// GetTemplateManager retrieves the template manager from context
func GetTemplateManager(r *http.Request) *template.Manager {
	if manager, ok := r.Context().Value(templateContextKey{}).(*template.Manager); ok {
		return manager
	}
	if cachedManager, ok := r.Context().Value(templateContextKey{}).(*template.CachedManager); ok {
		return cachedManager.Manager
	}
	return nil
}

// templateResponseWriter wraps http.ResponseWriter to add template support
type templateResponseWriter struct {
	http.ResponseWriter
	templateManager   *template.Manager
	componentRegistry *template.ComponentRegistry
}

// NewResponseBuilder creates a response builder with template support
func (w *templateResponseWriter) NewResponseBuilder() *web.ResponseBuilder {
	return web.NewResponse(w.ResponseWriter).WithTemplateManager(w.templateManager)
}

// Helper functions for common template operations

// RenderTemplate renders a template directly to the response
func RenderTemplate(w http.ResponseWriter, r *http.Request, name string, data interface{}) error {
	manager := GetTemplateManager(r)
	if manager == nil {
		http.Error(w, "Template manager not configured", http.StatusInternalServerError)
		return fmt.Errorf("template manager not found in context")
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return manager.Render(w, name, data)
}

// RenderPartial renders a partial template
func RenderPartial(w http.ResponseWriter, r *http.Request, templateSet, partialName string, data interface{}) error {
	manager := GetTemplateManager(r)
	if manager == nil {
		http.Error(w, "Template manager not configured", http.StatusInternalServerError)
		return fmt.Errorf("template manager not found in context")
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return manager.RenderPartial(w, templateSet, partialName, data)
}

// RenderComponent renders a component
func RenderComponent(w http.ResponseWriter, r *http.Request, name string, props map[string]interface{}) error {
	// This would need access to component registry from context
	// For now, return an error
	return fmt.Errorf("component rendering not yet implemented in middleware")
}