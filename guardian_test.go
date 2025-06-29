// File: guardian_test.go
package guardian

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/flyzard/go-guardian/middleware"
)

func TestFullAuthenticationFlow(t *testing.T) {
	// Setup Guardian app
	app := New(Config{
		SessionKey:     []byte("test-secret-key-32-bytes-long!!!"),
		DatabaseType:   "sqlite",
		DatabasePath:   ":memory:",
		Environment:    "development",
		AutoMigrate:    true,
		ValidateSchema: true,
	})
	defer app.DB().Close()

	// Add middleware
	app.Use(middleware.Logger)
	app.Use(middleware.SecurityHeaders)
	app.Use(middleware.CSRF)

	// Setup routes
	app.POST("/register", func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")
		password := r.FormValue("password")

		user, err := app.Auth().Register(email, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("User created: " + user.Email))
	})

	app.POST("/login", func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")
		password := r.FormValue("password")

		// For testing, mark user as verified
		app.DB().Exec("UPDATE users SET verified = 1 WHERE email = ?", email)

		err := app.Auth().Login(w, r, email, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.Write([]byte("Logged in"))
	})

	protected := app.Group("/admin")
	protected.Use(middleware.RequireAuth(app.Sessions()))
	protected.GET("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Admin Dashboard"))
	})

	// First, make a GET request to obtain CSRF token
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	app.router.ServeHTTP(rec, req)

	var csrfToken string
	var csrfCookie *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "csrf_token" {
			csrfToken = cookie.Value
			csrfCookie = cookie
			break
		}
	}

	if csrfToken == "" {
		t.Fatal("No CSRF token received")
	}

	// Test registration with CSRF token
	form := url.Values{}
	form.Add("email", "test@example.com")
	form.Add("password", "SecurePass123")

	req = httptest.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(csrfCookie)
	rec = httptest.NewRecorder()
	app.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Registration failed: %d - %s", rec.Code, rec.Body.String())
	}

	// Test login with CSRF token
	form = url.Values{}
	form.Add("email", "test@example.com")
	form.Add("password", "SecurePass123")

	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(csrfCookie)
	rec = httptest.NewRecorder()
	app.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Login failed: %d - %s", rec.Code, rec.Body.String())
	}

	// Get session cookie
	var sessionCookie *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "auth-session" {
			sessionCookie = cookie
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("No session cookie set after login")
	}

	// Test protected route access
	req = httptest.NewRequest("GET", "/admin/dashboard", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	app.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Protected route access failed: %d", rec.Code)
	}

	if rec.Body.String() != "Admin Dashboard" {
		t.Errorf("Unexpected response: %s", rec.Body.String())
	}
}

func TestSessionSecurity(t *testing.T) {
	app := New(Config{
		SessionKey:     []byte("test-secret-key-32-bytes-long!!!"),
		DatabaseType:   "sqlite",
		DatabasePath:   ":memory:",
		Environment:    "production", // Test secure cookies
		AutoMigrate:    true,
		ValidateSchema: true,
	})
	defer app.DB().Close()

	// Create and login user
	user, _ := app.Auth().Register("test@example.com", "password123")
	app.DB().Exec("UPDATE users SET verified = 1 WHERE id = ?", user.ID)

	// Get CSRF token first
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	// We need a handler that serves the root
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Apply CSRF middleware
	csrfHandler := middleware.CSRFWithConfig(middleware.CSRFConfig{
		Secure: true,
	})(handler)

	csrfHandler.ServeHTTP(rec, req)

	var csrfToken string
	var csrfCookie *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "csrf_token" {
			csrfToken = cookie.Value
			csrfCookie = cookie
			break
		}
	}

	// Now test login
	req = httptest.NewRequest("POST", "/login", nil)
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(csrfCookie)
	rec = httptest.NewRecorder()

	app.Auth().Login(rec, req, "test@example.com", "password123")

	// Check session cookie security attributes
	var sessionCookie *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "auth-session" {
			sessionCookie = cookie
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("No session cookie found")
	}

	if !sessionCookie.HttpOnly {
		t.Error("Session cookie should be HttpOnly")
	}

	if !sessionCookie.Secure {
		t.Error("Session cookie should be Secure in production")
	}

	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Error("Session cookie should have SameSite=Lax")
	}
}
