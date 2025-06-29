package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// This test is for a future rate limiting implementation
func TestRateLimitingStub(t *testing.T) {
	t.Skip("Rate limiting not yet implemented")

	// TODO: Implement rate limiting middleware and tests
	// Example of what should be tested:
	// 1. Allow normal request rate
	// 2. Block excessive requests
	// 3. Reset after time window
	// 4. Per-IP tracking
	// 5. Exemption for authenticated users
}

func TestConcurrentCSRFRequests(t *testing.T) {
	handler := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Get initial CSRF token
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var csrfToken string
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "csrf_token" {
			csrfToken = cookie.Value
			break
		}
	}

	// Test concurrent POST requests with same token
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := httptest.NewRequest("POST", "/", nil)
			req.Header.Set("X-CSRF-Token", csrfToken)
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				errors <- http.ErrAbortHandler
			}
		}()
	}

	wg.Wait()
	close(errors)

	errorCount := 0
	for range errors {
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("CSRF failed under concurrent load: %d errors", errorCount)
	}
}
