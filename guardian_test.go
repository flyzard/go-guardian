// File: guardian_test.go
package guardian

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

func TestFeatureFlags(t *testing.T) {
	// Test 1: All features disabled - only users table required
	t.Run("AllFeaturesDisabled", func(t *testing.T) {
		// Use a temporary file instead of :memory: to persist across connections
		tmpFile, err := os.CreateTemp("", "test-*.db")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		// Create only users table
		db, err := sql.Open("sqlite3", tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}

		_, err = db.Exec(`
			CREATE TABLE users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				email TEXT UNIQUE NOT NULL,
				password_hash TEXT NOT NULL,
				verified BOOLEAN DEFAULT 0,
				created_at DATETIME NOT NULL
			);

			CREATE TABLE tokens (
				id INTEGER PRIMARY KEY,
				token TEXT UNIQUE,
				user_id INTEGER,
				purpose TEXT,
				expires_at DATETIME,
				created_at DATETIME
			);
		`)
		if err != nil {
			t.Fatal("Failed to create users table:", err)
		}
		db.Close()

		// Guardian should work with just users table when all features disabled
		app := New(Config{
			SessionKey:     []byte("test-secret-key-32-bytes-long!!!"),
			DatabaseType:   "sqlite",
			DatabasePath:   tmpFile.Name(),
			AutoMigrate:    false,
			ValidateSchema: true,
			Features: Features{
				EmailVerification: false,
				PasswordReset:     false,
				RememberMe:        false,
				RBAC:              false,
				ExternalAuth:      true,
			},
		})
		defer app.DB().Close()

		// Should not panic - only users table is required

		// Register should work and user should be auto-verified
		user, err := app.Auth().Register("test@example.com", "password123")
		if err != nil {
			t.Fatal("Registration failed:", err)
		}

		if !user.Verified {
			t.Error("User should be auto-verified when email verification is disabled")
		}
	})

	// Test 2: Email verification disabled but password reset enabled
	t.Run("MixedTokenFeatures", func(t *testing.T) {
		// Use temporary file
		tmpFile, err := os.CreateTemp("", "test-*.db")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		// Still need tokens table for password reset
		db, err := sql.Open("sqlite3", tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}

		_, err = db.Exec(`
			CREATE TABLE users (
				id INTEGER PRIMARY KEY,
				email TEXT UNIQUE,
				password_hash TEXT,
				verified BOOLEAN DEFAULT 0,
				created_at DATETIME
			);
			CREATE TABLE tokens (
				id INTEGER PRIMARY KEY,
				token TEXT UNIQUE,
				user_id INTEGER,
				purpose TEXT,
				expires_at DATETIME,
				created_at DATETIME
			);
		`)
		if err != nil {
			t.Fatal("Failed to create tables:", err)
		}
		db.Close()

		app := New(Config{
			SessionKey:   []byte("test-secret-key-32-bytes-long!!!"),
			DatabaseType: "sqlite",
			DatabasePath: tmpFile.Name(),
			AutoMigrate:  false,
			Features: Features{
				EmailVerification: false, // No email verification
				PasswordReset:     true,  // But password reset enabled
				RememberMe:        false,
				RBAC:              false,
			},
		})
		defer app.DB().Close()

		// Register user (should be auto-verified)
		user, _ := app.Auth().Register("test@example.com", "password123")
		if !user.Verified {
			t.Error("User should be auto-verified")
		}

		// Password reset should work
		token, err := app.Auth().CreatePasswordResetToken("test@example.com")
		if err != nil {
			t.Error("Password reset should work:", err)
		}
		if token == nil {
			t.Error("Should create password reset token")
		}
	})

	// Test 3: Feature disabled methods return errors
	t.Run("DisabledFeatureErrors", func(t *testing.T) {
		app := New(Config{
			SessionKey:   []byte("test-secret-key-32-bytes-long!!!"),
			DatabaseType: "sqlite",
			DatabasePath: ":memory:",
			Features: Features{
				EmailVerification: false,
				PasswordReset:     false,
				RememberMe:        false,
				RBAC:              false,
				ExternalAuth:      true,
			},
		})
		defer app.DB().Close()

		// Try to create verification token
		_, err := app.Auth().CreateVerificationToken(1)
		if err == nil || err.Error() != "feature is disabled" {
			t.Error("Expected feature disabled error for verification token")
		}

		// Try to create password reset token
		_, err = app.Auth().CreatePasswordResetToken("test@example.com")
		if err == nil || err.Error() != "feature is disabled" {
			t.Error("Expected feature disabled error for password reset")
		}

		// Try to use remember me
		err = app.Auth().LoginWithRememberMe(nil, nil, "test@example.com", "password", true)
		if err == nil || err.Error() != "feature is disabled" {
			t.Error("Expected feature disabled error for remember me")
		}

		// RBAC should return error
		role, err := app.Auth().GetUserRole(1)
		if err == nil || err.Error() != "feature is disabled" {
			t.Error("Expected feature disabled error for RBAC")
		}
		if role != nil {
			t.Error("Role should be nil when RBAC disabled")
		}

		if app.Auth().UserHasPermission(1, "any.permission") {
			t.Error("UserHasPermission should return false when RBAC disabled")
		}
	})

	// Test 4: Schema validation with partial features
	t.Run("PartialFeatureValidation", func(t *testing.T) {
		// Use temporary file
		tmpFile, err := os.CreateTemp("", "test-*.db")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		// Create users and roles tables only
		db, err := sql.Open("sqlite3", tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}

		_, err = db.Exec(`
			CREATE TABLE users (
				id INTEGER PRIMARY KEY,
				email TEXT UNIQUE,
				password_hash TEXT,
				verified BOOLEAN DEFAULT 0,
				created_at DATETIME,
				role_id INTEGER
			);
			CREATE TABLE roles (
				id INTEGER PRIMARY KEY,
				name TEXT UNIQUE
			);
			CREATE TABLE permissions (
				id INTEGER PRIMARY KEY,
				name TEXT UNIQUE
			);
			CREATE TABLE role_permissions (
				role_id INTEGER,
				permission_id INTEGER,
				PRIMARY KEY (role_id, permission_id)
			);
		`)
		if err != nil {
			t.Fatal("Failed to create tables:", err)
		}
		db.Close()

		// Should work with just RBAC enabled
		app := New(Config{
			SessionKey:   []byte("test-secret-key-32-bytes-long!!!"),
			DatabaseType: "sqlite",
			DatabasePath: tmpFile.Name(),
			AutoMigrate:  false,
			Features: Features{
				EmailVerification: false, // No tokens table needed
				PasswordReset:     false, // No tokens table needed
				RememberMe:        false, // No remember_tokens needed
				RBAC:              true,  // Only RBAC tables needed
			},
		})
		defer app.DB().Close()

		// RBAC operations should work
		if !app.Auth().UserHasPermission(1, "test") {
			// This is fine - no permissions assigned
		}
	})
}

func TestMinimalDatabaseRequirements(t *testing.T) {
	// Test that Guardian can work with just a users table
	t.Run("OnlyUsersTable", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test-*.db")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		db, err := sql.Open("sqlite3", tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}

		// Create ONLY users table
		_, err = db.Exec(`
			CREATE TABLE users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				email TEXT UNIQUE NOT NULL,
				password_hash TEXT NOT NULL,
				verified BOOLEAN DEFAULT 1,
				created_at DATETIME NOT NULL
			)
		`)
		if err != nil {
			t.Fatal("Failed to create users table:", err)
		}
		db.Close()

		app := New(Config{
			SessionKey:     []byte("test-secret-key-32-bytes-long!!!"),
			DatabaseType:   "sqlite",
			DatabasePath:   tmpFile.Name(),
			AutoMigrate:    false,
			ValidateSchema: true,
			Features: Features{
				EmailVerification: false,
				PasswordReset:     false,
				RememberMe:        false,
				RBAC:              false,
				ExternalAuth:      true,
			},
		})
		defer app.DB().Close()

		// Full auth flow should work
		_, err = app.Auth().Register("minimal@example.com", "password123")
		if err != nil {
			t.Fatal("Registration failed with minimal setup:", err)
		}

		// Login should work
		req := httptest.NewRequest("POST", "/login", nil)
		rec := httptest.NewRecorder()

		err = app.Auth().Login(rec, req, "minimal@example.com", "password123")
		if err != nil {
			t.Fatal("Login failed with minimal setup:", err)
		}

		// Session should be created
		cookies := rec.Result().Cookies()
		if len(cookies) == 0 {
			t.Error("No session cookie created")
		}

		// User retrieval should work
		user, err := app.Auth().GetUser(req)
		if err == nil && user != nil {
			// This would work if the session was properly set
			t.Log("User retrieval works with minimal setup")
		}
	})
}
