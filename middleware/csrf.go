package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

const (
	csrfCookieName = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
)

// CSRF implements double-submit cookie pattern
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF for safe methods
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			// Ensure CSRF cookie exists
			if _, err := r.Cookie(csrfCookieName); err != nil {
				token := generateCSRFToken()
				http.SetCookie(w, &http.Cookie{
					Name:     csrfCookieName,
					Value:    token,
					Path:     "/",
					HttpOnly: false, // Must be readable by JS
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
					MaxAge:   86400, // 24 hours
				})
			}
			next.ServeHTTP(w, r)
			return
		}

		// Verify CSRF token for state-changing methods
		cookie, err := r.Cookie(csrfCookieName)
		if err != nil {
			http.Error(w, "CSRF cookie missing", http.StatusForbidden)
			return
		}

		header := r.Header.Get(csrfHeaderName)
		if header == "" {
			// Try form value as fallback
			header = r.FormValue("csrf_token")
		}

		if cookie.Value == "" || cookie.Value != header {
			http.Error(w, "CSRF token mismatch", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
