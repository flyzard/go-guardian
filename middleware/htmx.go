package middleware

import (
	"context"
	"net/http"
)

// HTMXConfig holds HTMX middleware configuration
type HTMXConfig struct {
	// Set HX-Push-Url header based on current URL for non-boosted requests
	PushURL bool
	// Include CSRF token in response headers
	IncludeCSRFHeader bool
}

// HTMX middleware that adds HTMX-friendly features
func HTMX(config HTMXConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add HTMX indicator to context
			if r.Header.Get("HX-Request") == "true" {
				ctx := context.WithValue(r.Context(), "htmx", true)
				r = r.WithContext(ctx)
			}

			// Include CSRF token in response headers for HTMX requests
			if config.IncludeCSRFHeader && r.Header.Get("HX-Request") == "true" {
				if cookie, err := r.Cookie("csrf_token"); err == nil {
					w.Header().Set("X-CSRF-Token", cookie.Value)
				}
			}

			// Auto push URL for non-boosted HTMX requests
			if config.PushURL && r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Boosted") != "true" {
				w.Header().Set("HX-Push-Url", r.URL.Path)
			}

			next.ServeHTTP(w, r)
		})
	}
}
