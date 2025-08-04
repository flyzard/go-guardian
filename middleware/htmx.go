package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/flyzard/go-guardian/htmx"
	"github.com/flyzard/go-guardian/response"
	"github.com/flyzard/go-guardian/web"
)


// HTMXConfig holds HTMX middleware configuration
type HTMXConfig struct {
	// Set HX-Push-Url header based on current URL for non-boosted requests
	PushURL bool
	// Include CSRF token in response headers
	IncludeCSRFHeader bool
	// Auto-retarget errors to body for partial requests
	AutoRetargetErrors bool
	// Default swap method for errors
	ErrorSwapMethod string
}

// DefaultHTMXConfig returns a default HTMX configuration
func DefaultHTMXConfig() HTMXConfig {
	return HTMXConfig{
		PushURL:            true,
		IncludeCSRFHeader:  true,
		AutoRetargetErrors: true,
		ErrorSwapMethod:    "innerHTML",
	}
}

// HTMX middleware that adds HTMX-friendly features
func HTMX(config HTMXConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Parse HTMX request information using centralized package
			info := htmx.GetRequestInfo(r)

			// Add HTMX info to context
			if info.IsHTMX {
				ctx := context.WithValue(r.Context(), htmx.RequestInfoKey, info)
				r = r.WithContext(ctx)
			}

			// Include CSRF token in response headers for HTMX requests
			if config.IncludeCSRFHeader && info.IsHTMX {
				if cookie, err := r.Cookie("csrf_token"); err == nil {
					htmx.SetCSRFToken(w, cookie.Value)
				}
			}

			// Auto push URL for non-boosted HTMX requests
			if config.PushURL && info.IsHTMX && !info.IsBoosted {
				htmx.SetPushURL(w, r.URL.Path)
			}

			// Wrap response writer for error handling
			if config.AutoRetargetErrors && info.IsHTMX && !info.IsBoosted {
				w = &htmxResponseWriter{
					ResponseWriter: w,
					config:         config,
					isHTMX:         true,
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// htmxResponseWriter wraps http.ResponseWriter to intercept error responses
type htmxResponseWriter struct {
	http.ResponseWriter
	config      HTMXConfig
	isHTMX      bool
	wroteHeader bool
}

func (w *htmxResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader && w.isHTMX && code >= 400 {
		// Auto-retarget errors to body for HTMX requests
		htmx.SetRetarget(w, "body")
		htmx.SetReswap(w, w.config.ErrorSwapMethod)
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *htmxResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}


// RequireHTMX ensures the request is from HTMX, otherwise returns an error
func RequireHTMX() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !htmx.IsRequest(r) {
				response.New(w, r).ErrorWithStatus(
					web.BadRequest("This endpoint requires an HTMX request"),
					http.StatusBadRequest,
				).Send()
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// HTMXOnly is an alias for RequireHTMX
var HTMXOnly = RequireHTMX

// PartialOnly ensures the request is a non-boosted HTMX request
func PartialOnly() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !htmx.IsPartialRequest(r) {
				response.New(w, r).ErrorWithStatus(
					web.BadRequest("This endpoint only serves partial content"),
					http.StatusBadRequest,
				).Send()
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// HTMXTrigger creates a middleware that only allows specific HTMX triggers
func HTMXTrigger(allowedTriggers ...string) func(http.Handler) http.Handler {
	triggerMap := make(map[string]bool)
	for _, trigger := range allowedTriggers {
		triggerMap[trigger] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, ok := htmx.FromContext(r.Context())
			if !ok || !info.IsHTMX {
				response.New(w, r).ErrorWithStatus(
					web.BadRequest("This endpoint requires an HTMX request"),
					http.StatusBadRequest,
				).Send()
				return
			}

			// Check both trigger name and ID
			if !triggerMap[info.TriggerName] && !triggerMap[info.TriggerID] {
				response.New(w, r).ErrorWithStatus(
					web.BadRequest("Invalid trigger for this endpoint"),
					http.StatusBadRequest,
				).Send()
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HTMXTarget creates a middleware that only allows specific HTMX targets
func HTMXTarget(allowedTargets ...string) func(http.Handler) http.Handler {
	targetMap := make(map[string]bool)
	for _, target := range allowedTargets {
		targetMap[target] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, ok := htmx.FromContext(r.Context())
			if !ok || !info.IsHTMX {
				response.New(w, r).ErrorWithStatus(
					web.BadRequest("This endpoint requires an HTMX request"),
					http.StatusBadRequest,
				).Send()
				return
			}

			if !targetMap[info.Target] {
				response.New(w, r).ErrorWithStatus(
					web.BadRequest("Invalid target for this endpoint"),
					http.StatusBadRequest,
				).Send()
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// VaryHTMX adds appropriate Vary headers for HTMX caching
func VaryHTMX(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add HTMX headers to Vary to ensure proper caching
		existing := w.Header().Get("Vary")
		htmxHeaders := []string{htmx.HeaderRequest, htmx.HeaderBoosted, htmx.HeaderTarget}
		
		if existing == "" {
			w.Header().Set("Vary", strings.Join(htmxHeaders, ", "))
		} else {
			w.Header().Set("Vary", existing + ", " + strings.Join(htmxHeaders, ", "))
		}

		next.ServeHTTP(w, r)
	})
}
