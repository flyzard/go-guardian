package web

import (
	"html/template"
	"net/http"
	"sync"

	"github.com/flyzard/go-guardian/auth"
	"github.com/flyzard/go-guardian/htmx"
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


// IsHTMX checks if request is from HTMX
func (h *Handler) IsHTMX(r *http.Request) bool {
	return htmx.IsRequest(r)
}

// IsBoosted checks if request is HTMX boosted
func (h *Handler) IsBoosted(r *http.Request) bool {
	return htmx.IsBoosted(r)
}

// RequireHTMX ensures the request is from HTMX
func (h *Handler) RequireHTMX(w http.ResponseWriter, r *http.Request, redirectTo string) bool {
	if !h.IsHTMX(r) {
		http.Redirect(w, r, redirectTo, http.StatusSeeOther)
		return false
	}
	return true
}

