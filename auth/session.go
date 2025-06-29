package auth

import (
	"net/http"

	"github.com/gorilla/sessions"
)

// NewSessionStore creates a secure session store
func NewSessionStore(secret []byte) *sessions.CookieStore {
	store := sessions.NewCookieStore(secret)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   1800, // 30 minutes
		HttpOnly: true,
		Secure:   true, // HTTPS only in production
		SameSite: http.SameSiteLaxMode,
	}
	return store
}

// RegenerateSession creates a new session ID
func RegenerateSession(w http.ResponseWriter, r *http.Request, store sessions.Store) error {
	session, err := store.Get(r, "auth-session")
	if err != nil {
		return err
	}

	// Save values
	values := make(map[interface{}]interface{})
	for k, v := range session.Values {
		values[k] = v
	}

	// Delete old session
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Create new session
	newSession, _ := store.New(r, "auth-session")
	for k, v := range values {
		newSession.Values[k] = v
	}

	return newSession.Save(r, w)
}
