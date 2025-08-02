package web

import (
	"encoding/json"
	"html/template"
	"net/http"
	"sync"

	"github.com/flyzard/go-guardian/auth"
	"github.com/gorilla/sessions"
)

// Handler provides common web handler functionality
type Handler struct {
	Auth        *auth.Service
	Sessions    sessions.Store
	templatesMu sync.RWMutex
	templates   map[string]*template.Template
	development bool
}

// NewHandler creates a new base handler
func NewHandler(authService *auth.Service, sessions sessions.Store, development bool) *Handler {
	return &Handler{
		Auth:        authService,
		Sessions:    sessions,
		templates:   make(map[string]*template.Template),
		development: development,
	}
}

// GetUser retrieves the current user from request context
func (h *Handler) GetUser(r *http.Request) (*auth.User, error) {
	// First check context (set by middleware)
	if user, ok := r.Context().Value(auth.UserContextKey).(*auth.User); ok {
		return user, nil
	}

	// Fallback to session
	return h.Auth.GetUser(r)
}

// JSON sends a JSON response
func (h *Handler) JSON(w http.ResponseWriter, status int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

// Error sends an error response (HTMX-aware)
// Deprecated: Use WebError method for structured error handling
func (h *Handler) Error(w http.ResponseWriter, r *http.Request, err error, message string, status int) {
	if h.IsHTMX(r) {
		w.Header().Set("HX-Retarget", "body")
		w.Header().Set("HX-Reswap", "innerHTML")
		http.Error(w, `<div class="alert alert-error">`+message+`</div>`, status)
		return
	}
	http.Error(w, message, status)
}

// WebError sends a structured error response using the response builder
func (h *Handler) WebError(w http.ResponseWriter, r *http.Request, err error) {
	if IsHTMX(r) && !IsBoosted(r) {
		NewResponse(w).
			HTMXRetarget("body").
			HTMXReswap("innerHTML").
			WebError(err).
			Send()
		return
	}
	NewResponse(w).WebError(err).Send()
}

// Redirect performs an HTMX-aware redirect
func (h *Handler) Redirect(w http.ResponseWriter, r *http.Request, url string, status int) {
	if h.IsHTMX(r) {
		w.Header().Set("HX-Redirect", url)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, url, status)
}

// IsHTMX checks if request is from HTMX
func (h *Handler) IsHTMX(r *http.Request) bool {
	return IsHTMX(r)
}

// IsBoosted checks if request is HTMX boosted
func (h *Handler) IsBoosted(r *http.Request) bool {
	return IsBoosted(r)
}

// RequireHTMX ensures the request is from HTMX
func (h *Handler) RequireHTMX(w http.ResponseWriter, r *http.Request, redirectTo string) bool {
	if !h.IsHTMX(r) {
		http.Redirect(w, r, redirectTo, http.StatusSeeOther)
		return false
	}
	return true
}

// Response creates a new response builder
func (h *Handler) Response(w http.ResponseWriter) *ResponseBuilder {
	return NewResponse(w)
}
