package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/flyzard/go-guardian/web"
)

// HTMXContextKey is the context key for HTMX request data
type HTMXContextKey string

const (
	// HTMXRequestKey is the context key for HTMX request information
	HTMXRequestKey HTMXContextKey = "htmx_request"
)

// HTMXRequestInfo contains information about an HTMX request
type HTMXRequestInfo struct {
	IsHTMX         bool
	IsBoosted      bool
	Target         string
	TriggerName    string
	TriggerID      string
	CurrentURL     string
	Prompt         string
	HistoryRestore bool
}

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
			// Parse HTMX request information
			info := &HTMXRequestInfo{
				IsHTMX:         r.Header.Get("HX-Request") == "true",
				IsBoosted:      r.Header.Get("HX-Boosted") == "true",
				Target:         r.Header.Get("HX-Target"),
				TriggerName:    r.Header.Get("HX-Trigger-Name"),
				TriggerID:      r.Header.Get("HX-Trigger"),
				CurrentURL:     r.Header.Get("HX-Current-URL"),
				Prompt:         r.Header.Get("HX-Prompt"),
				HistoryRestore: r.Header.Get("HX-History-Restore-Request") == "true",
			}

			// Add HTMX info to context
			if info.IsHTMX {
				ctx := context.WithValue(r.Context(), HTMXRequestKey, info)
				r = r.WithContext(ctx)
			}

			// Include CSRF token in response headers for HTMX requests
			if config.IncludeCSRFHeader && info.IsHTMX {
				if cookie, err := r.Cookie("csrf_token"); err == nil {
					w.Header().Set("X-CSRF-Token", cookie.Value)
				}
			}

			// Auto push URL for non-boosted HTMX requests
			if config.PushURL && info.IsHTMX && !info.IsBoosted {
				w.Header().Set("HX-Push-Url", r.URL.Path)
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
		w.Header().Set("HX-Retarget", "body")
		w.Header().Set("HX-Reswap", w.config.ErrorSwapMethod)
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

// GetHTMXInfo retrieves HTMX request information from context
func GetHTMXInfo(r *http.Request) (*HTMXRequestInfo, bool) {
	info, ok := r.Context().Value(HTMXRequestKey).(*HTMXRequestInfo)
	return info, ok
}

// RequireHTMX ensures the request is from HTMX, otherwise returns an error
func RequireHTMX() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !web.IsHTMX(r) {
				web.NewResponse(w).WebError(
					web.BadRequest("This endpoint requires an HTMX request"),
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
			if !web.IsHTMX(r) || web.IsBoosted(r) {
				web.NewResponse(w).WebError(
					web.BadRequest("This endpoint only serves partial content"),
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
			info, ok := GetHTMXInfo(r)
			if !ok || !info.IsHTMX {
				web.NewResponse(w).WebError(
					web.BadRequest("This endpoint requires an HTMX request"),
				).Send()
				return
			}

			// Check both trigger name and ID
			if !triggerMap[info.TriggerName] && !triggerMap[info.TriggerID] {
				web.NewResponse(w).WebError(
					web.BadRequest("Invalid trigger for this endpoint"),
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
			info, ok := GetHTMXInfo(r)
			if !ok || !info.IsHTMX {
				web.NewResponse(w).WebError(
					web.BadRequest("This endpoint requires an HTMX request"),
				).Send()
				return
			}

			if !targetMap[info.Target] {
				web.NewResponse(w).WebError(
					web.BadRequest("Invalid target for this endpoint"),
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
		htmxHeaders := []string{"HX-Request", "HX-Boosted", "HX-Target"}
		
		if existing == "" {
			w.Header().Set("Vary", strings.Join(htmxHeaders, ", "))
		} else {
			w.Header().Set("Vary", existing + ", " + strings.Join(htmxHeaders, ", "))
		}

		next.ServeHTTP(w, r)
	})
}
