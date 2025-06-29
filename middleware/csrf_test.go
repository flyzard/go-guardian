// File: middleware/csrf_test.go
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFProtection(t *testing.T) {
	handler := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test GET request sets CSRF cookie
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Check cookie was set
	cookies := rec.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}

	if csrfCookie == nil {
		t.Fatal("CSRF cookie not set on GET request")
	}

	if csrfCookie.HttpOnly {
		t.Fatal("CSRF cookie should not be HttpOnly (needs JS access)")
	}

	// Test POST without CSRF token
	req = httptest.NewRequest("POST", "/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", rec.Code)
	}

	// Test POST with mismatched CSRF token
	req = httptest.NewRequest("POST", "/", nil)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", "wrong-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatal("CSRF protection failed with mismatched token")
	}

	// Test POST with correct CSRF token
	req = httptest.NewRequest("POST", "/", nil)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}
}

func TestCSRFWithHTMX(t *testing.T) {
	handler := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Get CSRF token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}

	// Check token in response header for HTMX
	if rec.Header().Get("X-CSRF-Token") != csrfCookie.Value {
		t.Fatal("CSRF token not in response header for HTMX request")
	}
}
