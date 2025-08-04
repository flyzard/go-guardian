package middleware

import (
	"net/http"

	"github.com/flyzard/go-guardian/auth"
	"github.com/flyzard/go-guardian/htmx"
	"github.com/gorilla/sessions"
)

type contextKey string

const userContextKey contextKey = "user"

// RequireAuth ensures user is authenticated
func RequireAuth(store sessions.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := store.Get(r, "auth-session")
			if err != nil {
				handleUnauthorized(w, r)
				return
			}

			userID, ok := session.Values["user_id"]
			if !ok || userID == nil {
				handleUnauthorized(w, r)
				return
			}

			// Add user data to context
			user := &auth.User{
				ID:    userID.(int64),
				Email: getStringValue(session.Values["email"]),
			}

			ctx := auth.WithUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID retrieves user ID from context
func GetUserID(r *http.Request) (int64, bool) {
	userID, ok := r.Context().Value(userContextKey).(int64)
	return userID, ok
}

// OptionalAuth allows access without authentication
func OptionalAuth(store sessions.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := store.Get(r, "auth-session")

			if userID, ok := session.Values["user_id"]; ok && userID != nil {
				user := &auth.User{
					ID:    userID.(int64),
					Email: getStringValue(session.Values["email"]),
				}

				ctx := auth.WithUser(r.Context(), user)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func handleUnauthorized(w http.ResponseWriter, r *http.Request) {
	// HTMX-aware unauthorized handling
	if htmx.IsRequest(r) {
		htmx.SetRedirect(w, "/login")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func getStringValue(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
