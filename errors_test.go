package guardian

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

// Test standard error variables
func TestStandardErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"Invalid credentials", ErrInvalidCredentials, "invalid credentials provided"},
		{"Account locked", ErrAccountLocked, "account is locked due to security policy"},
		{"Session expired", ErrSessionExpired, "session has expired"},
		{"Token invalid", ErrTokenInvalid, "invalid token"},
		{"User not found", ErrUserNotFound, "user not found"},
		{"Rate limit exceeded", ErrRateLimitExceeded, "rate limit exceeded"},
		{"Validation failed", ErrValidationFailed, "validation failed"},
		{"Storage unavailable", ErrStorageUnavailable, "storage service unavailable"},
		{"Internal error", ErrInternal, "internal server error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("Expected error message %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

// Test APIError creation and methods
func TestAPIError(t *testing.T) {
	t.Run("NewAPIError", func(t *testing.T) {
		err := NewAPIError(ErrorTypeAuthentication, "Authentication Failed", http.StatusUnauthorized)

		if err.Type != "authentication" {
			t.Errorf("Expected type 'authentication', got %q", err.Type)
		}
		if err.Title != "Authentication Failed" {
			t.Errorf("Expected title 'Authentication Failed', got %q", err.Title)
		}
		if err.Status != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, err.Status)
		}
		if err.Timestamp.IsZero() {
			t.Error("Expected timestamp to be set")
		}
	})

	t.Run("NewAPIErrorWithDetail", func(t *testing.T) {
		err := NewAPIErrorWithDetail(ErrorTypeValidation, "Validation Error", "Email is required", http.StatusBadRequest)

		if err.Detail != "Email is required" {
			t.Errorf("Expected detail 'Email is required', got %q", err.Detail)
		}
	})

	t.Run("WrapError", func(t *testing.T) {
		originalErr := errors.New("database connection failed")
		wrappedErr := WrapError(originalErr, ErrorTypeStorage, "Storage Error", http.StatusInternalServerError)

		if wrappedErr.Detail != originalErr.Error() {
			t.Errorf("Expected detail to be original error message")
		}
		if wrappedErr.Unwrap() != originalErr {
			t.Error("Expected unwrap to return original error")
		}
	})

	t.Run("Error method", func(t *testing.T) {
		// Test with detail
		err1 := NewAPIErrorWithDetail(ErrorTypeValidation, "Title", "Detail message", http.StatusBadRequest)
		if err1.Error() != "Detail message" {
			t.Errorf("Expected error message to be detail, got %q", err1.Error())
		}

		// Test without detail
		err2 := NewAPIError(ErrorTypeAuthentication, "Title only", http.StatusUnauthorized)
		if err2.Error() != "Title only" {
			t.Errorf("Expected error message to be title, got %q", err2.Error())
		}
	})

	t.Run("SetContext", func(t *testing.T) {
		err := NewAPIError(ErrorTypeValidation, "Test", http.StatusBadRequest)
		err.SetContext("field", "email").SetContext("value", "invalid@")

		if err.Context["field"] != "email" {
			t.Error("Expected context field to be set")
		}
		if err.Context["value"] != "invalid@" {
			t.Error("Expected context value to be set")
		}
	})

	t.Run("SetRequestID", func(t *testing.T) {
		err := NewAPIError(ErrorTypeInternal, "Test", http.StatusInternalServerError)
		requestID := "req-123-456"
		err.SetRequestID(requestID)

		if err.RequestID != requestID {
			t.Errorf("Expected request ID %q, got %q", requestID, err.RequestID)
		}
	})
}

// Test JSON marshaling
func TestAPIErrorJSON(t *testing.T) {
	t.Run("Basic marshaling", func(t *testing.T) {
		err := NewAPIErrorWithDetail(ErrorTypeAuthentication, "Auth Failed", "Invalid password", http.StatusUnauthorized)
		err.SetRequestID("req-123")
		err.SetContext("user_id", "user123")

		data, jsonErr := json.Marshal(err)
		if jsonErr != nil {
			t.Fatalf("Failed to marshal APIError: %v", jsonErr)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("Failed to unmarshal JSON: %v", err)
		}

		if result["type"] != "authentication" {
			t.Errorf("Expected type 'authentication', got %v", result["type"])
		}
		if result["title"] != "Auth Failed" {
			t.Errorf("Expected title 'Auth Failed', got %v", result["title"])
		}
		if result["detail"] != "Invalid password" {
			t.Errorf("Expected detail 'Invalid password', got %v", result["detail"])
		}
		if result["status"] != float64(401) {
			t.Errorf("Expected status 401, got %v", result["status"])
		}
		if result["request_id"] != "req-123" {
			t.Errorf("Expected request_id 'req-123', got %v", result["request_id"])
		}

		// Check context
		context, ok := result["context"].(map[string]interface{})
		if !ok {
			t.Error("Expected context to be an object")
		} else if context["user_id"] != "user123" {
			t.Errorf("Expected context user_id 'user123', got %v", context["user_id"])
		}

		// Ensure cause is not included in JSON
		if _, exists := result["cause"]; exists {
			t.Error("Expected cause to be excluded from JSON")
		}
	})

	t.Run("RFC 7807 compliance", func(t *testing.T) {
		err := NewAPIErrorWithDetail(ErrorTypeValidation, "Validation Failed", "Email format is invalid", http.StatusBadRequest)
		err.Instance = "/users/123"

		data, jsonErr := json.Marshal(err)
		if jsonErr != nil {
			t.Fatalf("Failed to marshal APIError: %v", jsonErr)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("Failed to unmarshal JSON: %v", err)
		}

		// Check RFC 7807 required fields
		requiredFields := []string{"type", "title", "status"}
		for _, field := range requiredFields {
			if _, exists := result[field]; !exists {
				t.Errorf("Missing required RFC 7807 field: %s", field)
			}
		}

		// Check optional fields
		if result["instance"] != "/users/123" {
			t.Errorf("Expected instance '/users/123', got %v", result["instance"])
		}
	})
}

// Test error creation helpers
func TestErrorHelpers(t *testing.T) {
	t.Run("NewAuthenticationError", func(t *testing.T) {
		err := NewAuthenticationError("Login Failed", "Invalid username or password")

		if err.Type != "authentication" {
			t.Errorf("Expected type 'authentication', got %q", err.Type)
		}
		if err.Status != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, err.Status)
		}
	})

	t.Run("NewAuthorizationError", func(t *testing.T) {
		err := NewAuthorizationError("Access Denied", "Insufficient permissions")

		if err.Type != "authorization" {
			t.Errorf("Expected type 'authorization', got %q", err.Type)
		}
		if err.Status != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d", http.StatusForbidden, err.Status)
		}
	})

	t.Run("NewValidationError", func(t *testing.T) {
		err := NewValidationError("Invalid Input", "Email is required")

		if err.Type != "validation" {
			t.Errorf("Expected type 'validation', got %q", err.Type)
		}
		if err.Status != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, err.Status)
		}
	})

	t.Run("NewNotFoundError", func(t *testing.T) {
		err := NewNotFoundError("user")

		if err.Status != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, err.Status)
		}
		if err.Detail != "The requested user was not found" {
			t.Errorf("Expected specific detail message, got %q", err.Detail)
		}
	})

	t.Run("NewInternalError", func(t *testing.T) {
		err := NewInternalError("Database connection failed")

		if err.Type != "internal" {
			t.Errorf("Expected type 'internal', got %q", err.Type)
		}
		if err.Status != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, err.Status)
		}
	})

	t.Run("NewRateLimitError", func(t *testing.T) {
		retryAfter := 30 * time.Second
		err := NewRateLimitError(retryAfter)

		if err.Type != "rate_limit" {
			t.Errorf("Expected type 'rate_limit', got %q", err.Type)
		}
		if err.Status != http.StatusTooManyRequests {
			t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, err.Status)
		}
		if err.Context["retry_after"] != 30 {
			t.Errorf("Expected retry_after context to be 30, got %v", err.Context["retry_after"])
		}
	})
}

// Test error checking utilities
func TestErrorChecking(t *testing.T) {
	t.Run("IsType", func(t *testing.T) {
		authErr := NewAuthenticationError("Test", "Test detail")
		_ = NewValidationError("Test", "Test detail")
		regularErr := errors.New("regular error")

		if !IsType(authErr, ErrorTypeAuthentication) {
			t.Error("Expected IsType to return true for authentication error")
		}
		if IsType(authErr, ErrorTypeValidation) {
			t.Error("Expected IsType to return false for different error type")
		}
		if IsType(regularErr, ErrorTypeAuthentication) {
			t.Error("Expected IsType to return false for non-APIError")
		}
	})

	t.Run("Specific type checkers", func(t *testing.T) {
		authErr := NewAuthenticationError("Test", "Test")
		authzErr := NewAuthorizationError("Test", "Test")
		valErr := NewValidationError("Test", "Test")
		rateErr := NewRateLimitError(time.Minute)

		if !IsAuthenticationError(authErr) {
			t.Error("Expected IsAuthenticationError to return true")
		}
		if IsAuthenticationError(authzErr) {
			t.Error("Expected IsAuthenticationError to return false for authorization error")
		}

		if !IsAuthorizationError(authzErr) {
			t.Error("Expected IsAuthorizationError to return true")
		}
		if !IsValidationError(valErr) {
			t.Error("Expected IsValidationError to return true")
		}
		if !IsRateLimitError(rateErr) {
			t.Error("Expected IsRateLimitError to return true")
		}
	})

	t.Run("GetHTTPStatus", func(t *testing.T) {
		apiErr := NewAuthenticationError("Test", "Test")
		regularErr := errors.New("regular error")

		if GetHTTPStatus(apiErr) != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, GetHTTPStatus(apiErr))
		}
		if GetHTTPStatus(regularErr) != http.StatusInternalServerError {
			t.Errorf("Expected default status %d, got %d", http.StatusInternalServerError, GetHTTPStatus(regularErr))
		}
	})

	t.Run("GetErrorType", func(t *testing.T) {
		apiErr := NewValidationError("Test", "Test")
		regularErr := errors.New("regular error")

		if GetErrorType(apiErr) != ErrorTypeValidation {
			t.Errorf("Expected type %s, got %s", ErrorTypeValidation, GetErrorType(apiErr))
		}
		if GetErrorType(regularErr) != ErrorTypeInternal {
			t.Errorf("Expected default type %s, got %s", ErrorTypeInternal, GetErrorType(regularErr))
		}
	})
}

// Test ValidationErrors
func TestValidationErrors(t *testing.T) {
	t.Run("Basic operations", func(t *testing.T) {
		ve := NewValidationErrors()

		if ve.HasErrors() {
			t.Error("Expected no errors initially")
		}

		ve.Add("email", "Email is required")
		ve.AddWithCode("password", "Password too weak", "WEAK_PASSWORD")

		if !ve.HasErrors() {
			t.Error("Expected errors after adding")
		}

		if len(ve.Errors) != 2 {
			t.Errorf("Expected 2 errors, got %d", len(ve.Errors))
		}

		// Check first error
		if ve.Errors[0].Field != "email" {
			t.Errorf("Expected field 'email', got %q", ve.Errors[0].Field)
		}
		if ve.Errors[0].Message != "Email is required" {
			t.Errorf("Expected message 'Email is required', got %q", ve.Errors[0].Message)
		}

		// Check second error with code
		if ve.Errors[1].Code != "WEAK_PASSWORD" {
			t.Errorf("Expected code 'WEAK_PASSWORD', got %q", ve.Errors[1].Code)
		}
	})

	t.Run("Error method", func(t *testing.T) {
		// No errors
		ve1 := NewValidationErrors()
		if ve1.Error() != "validation failed" {
			t.Errorf("Expected default message, got %q", ve1.Error())
		}

		// Single error
		ve2 := NewValidationErrors()
		ve2.Add("email", "Email is invalid")
		expected := "validation failed: Email is invalid"
		if ve2.Error() != expected {
			t.Errorf("Expected %q, got %q", expected, ve2.Error())
		}

		// Multiple errors
		ve3 := NewValidationErrors()
		ve3.Add("email", "Email is invalid")
		ve3.Add("password", "Password is required")
		expected = "validation failed: 2 errors"
		if ve3.Error() != expected {
			t.Errorf("Expected %q, got %q", expected, ve3.Error())
		}
	})

	t.Run("ToAPIError", func(t *testing.T) {
		// No errors
		ve1 := NewValidationErrors()
		apiErr1 := ve1.ToAPIError()
		if apiErr1 != nil {
			t.Error("Expected nil APIError for empty validation errors")
		}

		// With errors
		ve2 := NewValidationErrors()
		ve2.Add("email", "Email is required")
		ve2.Add("password", "Password too short")

		apiErr2 := ve2.ToAPIError()
		if apiErr2 == nil {
			t.Fatal("Expected APIError to be created")
		}

		if apiErr2.Type != "validation" {
			t.Errorf("Expected type 'validation', got %q", apiErr2.Type)
		}
		if apiErr2.Status != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, apiErr2.Status)
		}

		// Check context contains field errors
		fieldErrors, ok := apiErr2.Context["field_errors"].([]FieldError)
		if !ok {
			t.Error("Expected field_errors in context")
		} else if len(fieldErrors) != 2 {
			t.Errorf("Expected 2 field errors in context, got %d", len(fieldErrors))
		}
	})
}

// Test error assertion helpers
func TestErrorAssertions(t *testing.T) {
	t.Run("AsAPIError", func(t *testing.T) {
		apiErr := NewAuthenticationError("Test", "Test")
		regularErr := errors.New("regular error")

		// Test with APIError
		result1, ok1 := AsAPIError(apiErr)
		if !ok1 {
			t.Error("Expected AsAPIError to return true for APIError")
		}
		if result1 != apiErr {
			t.Error("Expected same APIError instance")
		}

		// Test with regular error
		result2, ok2 := AsAPIError(regularErr)
		if ok2 {
			t.Error("Expected AsAPIError to return false for regular error")
		}
		if result2 != nil {
			t.Error("Expected nil result for regular error")
		}
	})

	t.Run("MustAPIError", func(t *testing.T) {
		apiErr := NewAuthenticationError("Test", "Test")
		regularErr := errors.New("regular error")

		// Test with APIError
		result1 := MustAPIError(apiErr)
		if result1 != apiErr {
			t.Error("Expected same APIError instance")
		}

		// Test with regular error
		result2 := MustAPIError(regularErr)
		if result2 == nil {
			t.Fatal("Expected APIError to be created")
		}
		if result2.Type != "internal" {
			t.Errorf("Expected type 'internal', got %q", result2.Type)
		}
		if result2.Status != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, result2.Status)
		}
		if result2.Unwrap() != regularErr {
			t.Error("Expected wrapped error to be the original error")
		}
	})
}

// Test error wrapping and unwrapping
func TestErrorWrapping(t *testing.T) {
	t.Run("Error unwrapping", func(t *testing.T) {
		originalErr := errors.New("original database error")
		wrappedErr := WrapError(originalErr, ErrorTypeStorage, "Database Error", http.StatusInternalServerError)

		// Test that it unwraps correctly
		if !errors.Is(wrappedErr, originalErr) {
			t.Error("Expected errors.Is to return true for wrapped error")
		}

		// Test direct unwrap
		if wrappedErr.Unwrap() != originalErr {
			t.Error("Expected Unwrap to return original error")
		}
	})

	t.Run("Chain unwrapping", func(t *testing.T) {
		baseErr := errors.New("base error")
		level1Err := WrapError(baseErr, ErrorTypeStorage, "Level 1", http.StatusInternalServerError)
		level2Err := WrapError(level1Err, ErrorTypeInternal, "Level 2", http.StatusInternalServerError)

		// Should be able to find the base error through the chain
		if !errors.Is(level2Err, baseErr) {
			t.Error("Expected errors.Is to find base error through chain")
		}

		// Should be able to find intermediate error
		if !errors.Is(level2Err, level1Err) {
			t.Error("Expected errors.Is to find intermediate error")
		}
	})
}

// Benchmark tests
func BenchmarkAPIErrorCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewAPIError(ErrorTypeAuthentication, "Test Error", http.StatusUnauthorized)
	}
}

func BenchmarkAPIErrorJSON(b *testing.B) {
	err := NewAPIErrorWithDetail(ErrorTypeValidation, "Test", "Test detail", http.StatusBadRequest)
	err.SetContext("field", "email")
	err.SetRequestID("req-123")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(err)
	}
}

func BenchmarkErrorTypeChecking(b *testing.B) {
	err := NewAuthenticationError("Test", "Test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsAuthenticationError(err)
	}
}

// Test comprehensive error scenarios
func TestRealWorldScenarios(t *testing.T) {
	t.Run("Login flow errors", func(t *testing.T) {
		// User not found
		userErr := NewNotFoundError("user")
		if !IsType(userErr, ErrorTypeUser) {
			t.Error("Expected user error type")
		}

		// Invalid password
		authErr := NewAuthenticationError("Login Failed", "Invalid password")
		if authErr.Status != http.StatusUnauthorized {
			t.Error("Expected 401 status for authentication error")
		}

		// Account locked
		lockedErr := WrapError(ErrAccountLocked, ErrorTypeAuthentication, "Account Locked", http.StatusUnauthorized)
		if !errors.Is(lockedErr, ErrAccountLocked) {
			t.Error("Expected wrapped error to be detectable")
		}
	})

	t.Run("API validation scenario", func(t *testing.T) {
		ve := NewValidationErrors()
		ve.Add("email", "Email is required")
		ve.Add("password", "Password must be at least 8 characters")
		ve.AddWithCode("terms", "Must accept terms of service", "TERMS_REQUIRED")

		apiErr := ve.ToAPIError()

		// Convert to JSON as would happen in API response
		data, err := json.Marshal(apiErr)
		if err != nil {
			t.Fatalf("Failed to marshal: %v", err)
		}

		// Verify JSON structure
		var response map[string]interface{}
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}

		// Should have RFC 7807 structure
		if response["type"] != "validation" {
			t.Error("Expected validation type in JSON")
		}
		if response["status"] != float64(400) {
			t.Error("Expected 400 status in JSON")
		}

		// Should include field errors in context
		context := response["context"].(map[string]interface{})
		fieldErrors := context["field_errors"].([]interface{})
		if len(fieldErrors) != 3 {
			t.Errorf("Expected 3 field errors in JSON, got %d", len(fieldErrors))
		}
	})
}
