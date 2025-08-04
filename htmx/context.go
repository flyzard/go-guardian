package htmx

import (
	"context"
	"net/http"
)

// ContextKey is the type for HTMX context keys
type ContextKey string

const (
	// RequestInfoKey is the context key for HTMX request information
	RequestInfoKey ContextKey = "htmx:request_info"
)

// FromContext retrieves HTMX request info from context
func FromContext(ctx context.Context) (*RequestInfo, bool) {
	info, ok := ctx.Value(RequestInfoKey).(*RequestInfo)
	return info, ok
}

// NewContext adds HTMX request info to context
func NewContext(ctx context.Context, r *http.Request) context.Context {
	info := GetRequestInfo(r)
	return context.WithValue(ctx, RequestInfoKey, info)
}

// WithContext adds HTMX request info to the request's context
func WithContext(r *http.Request) *http.Request {
	return r.WithContext(NewContext(r.Context(), r))
}

// MustFromContext retrieves HTMX request info from context, panics if not found
func MustFromContext(ctx context.Context) *RequestInfo {
	info, ok := FromContext(ctx)
	if !ok {
		panic("htmx: request info not found in context")
	}
	return info
}

// Middleware adds HTMX request info to context for all requests
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only add to context if it's an HTMX request
		if IsRequest(r) {
			r = WithContext(r)
		}
		next.ServeHTTP(w, r)
	})
}

// IsRequestFromContext checks if the request in context is from HTMX
func IsRequestFromContext(ctx context.Context) bool {
	info, ok := FromContext(ctx)
	return ok && info.IsHTMX
}

// GetTargetFromContext gets the target from context
func GetTargetFromContext(ctx context.Context) string {
	info, ok := FromContext(ctx)
	if !ok {
		return ""
	}
	return info.Target
}

// GetTriggerFromContext gets the trigger from context
func GetTriggerFromContext(ctx context.Context) string {
	info, ok := FromContext(ctx)
	if !ok {
		return ""
	}
	return info.TriggerID
}