package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
)

const (
	csrfCookieName = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	CSRFTokenKey   = "_csrf" // Form field name for CSRF token
)

// CSRFConfig holds CSRF middleware configuration
type CSRFConfig struct {
	Secure bool // Whether to use secure cookies (HTTPS only)
}

// CSRF implements double-submit cookie pattern
func CSRF(next http.Handler) http.Handler {
	return CSRFWithConfig(CSRFConfig{Secure: true})(next)
}

// CSRFWithConfig creates CSRF middleware with custom config
func CSRFWithConfig(config CSRFConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF for safe methods
			if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
				// Ensure CSRF cookie exists
				if _, err := r.Cookie(csrfCookieName); err != nil {
					token := generateCSRFToken()
					cookie := &http.Cookie{
						Name:     csrfCookieName,
						Value:    token,
						Path:     "/",
						HttpOnly: false, // Must be readable by JS
						Secure:   config.Secure,
						SameSite: http.SameSiteLaxMode,
						MaxAge:   86400, // 24 hours
					}
					http.SetCookie(w, cookie)

					// For HTMX requests, also set the token in response header
					if r.Header.Get("HX-Request") == "true" {
						w.Header().Set("X-CSRF-Token", token)
					}

					log.Printf("CSRF: Set new token for %s", r.URL.Path)
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

			// Check header first (supports both X-CSRF-Token and HX-Trigger for HTMX)
			token := r.Header.Get(csrfHeaderName)

			// If no header, check form value
			if token == "" {
				token = r.FormValue("csrf_token")
			}

			if cookie.Value == "" || cookie.Value != token {
				log.Printf("CSRF mismatch - Cookie: %s, Token: %s", cookie.Value, token)

				// For HTMX requests, return a more helpful error
				if r.Header.Get("HX-Request") == "true" {
					w.Header().Set("HX-Retarget", "body")
					w.Header().Set("HX-Reswap", "innerHTML")
					http.Error(w, `<div class="alert alert-error">Security error: Please refresh the page and try again.</div>`, http.StatusForbidden)
					return
				}

				http.Error(w, "CSRF token mismatch", http.StatusForbidden)
				return
			}

			// For HTMX requests, include the token in response
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("X-CSRF-Token", cookie.Value)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// GetCSRFToken retrieves the CSRF token from the request
func GetCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}
