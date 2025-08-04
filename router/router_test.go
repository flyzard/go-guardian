package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/flyzard/go-guardian/htmx"
)

func TestRouterParameterInjection(t *testing.T) {
	r := New()

	// Test route parameter extraction doesn't allow injection
	r.GET("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		ctx := NewContext(w, r)
		id := ctx.Param("id")

		// Write back the extracted ID
		w.Write([]byte("User ID: " + id))
	})

	// Test with valid requests first
	validTests := []struct {
		path     string
		expected string
	}{
		{"/users/123", "User ID: 123"},
		{"/users/abc", "User ID: abc"},
	}

	for _, tt := range validTests {
		req := httptest.NewRequest("GET", tt.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Valid path %s returned %d", tt.path, rec.Code)
		}

		if rec.Body.String() != tt.expected {
			t.Errorf("Expected %q, got %q", tt.expected, rec.Body.String())
		}
	}

	// Test potentially dangerous paths - these should be handled safely
	// The router should either extract them as-is or return 404
	dangerousPaths := []string{
		"/users/1%27%20OR%20%271%27%3D%271",       // URL encoded: 1' OR '1'='1
		"/users/1%3B%20DROP%20TABLE%20users%3B--", // URL encoded: 1; DROP TABLE users;--
		"/users/..%2F..%2Fetc%2Fpasswd",           // Path traversal attempt
		"/users/1%00.php",                         // Null byte injection
	}

	for _, path := range dangerousPaths {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		// Should either 404 or safely handle the parameter
		if rec.Code == http.StatusInternalServerError {
			t.Errorf("Potential security issue with path: %s", path)
		}
	}
}

func TestContextHTMXHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("HX-Request", "true")
	r.Header.Set("HX-Trigger", "button-1")

	// Use htmx package directly instead of deprecated Context methods
	// Context is still created but not used for HTMX operations
	_ = NewContext(w, r)
	if !htmx.IsRequest(r) {
		t.Error("Failed to detect HTMX request")
	}

	if htmx.GetTrigger(r) != "button-1" {
		t.Error("Failed to get HTMX trigger")
	}

	// Test HTMX response headers using htmx package
	htmx.SetRedirect(w, "/new-page")
	htmx.SetTrigger(w, "event1")

	if w.Header().Get("HX-Redirect") != "/new-page" {
		t.Error("Failed to set HX-Redirect header")
	}

	if w.Header().Get("HX-Trigger") != "event1" {
		t.Error("Failed to set HX-Trigger header")
	}
}
