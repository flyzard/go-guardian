package middleware

import (
	"context"
	"net/http"

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
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			userID, ok := session.Values["user_id"]
			if !ok || userID == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Add user ID to context
			ctx := context.WithValue(r.Context(), userContextKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID retrieves user ID from context
func GetUserID(r *http.Request) (int64, bool) {
	userID, ok := r.Context().Value(userContextKey).(int64)
	return userID, ok
}
