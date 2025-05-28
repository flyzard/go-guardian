// Package go-guardian provides a comprehensive error handling system.
// All errors follow RFC 7807 Problem Details for HTTP APIs and support
// error wrapping for better debugging and context preservation.
package guardian

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Standard error variables used throughout the library.
// These provide consistent error handling and allow for easy error type checking.
var (
	// Authentication errors
	ErrInvalidCredentials   = errors.New("invalid credentials provided")
	ErrAccountLocked        = errors.New("account is locked due to security policy")
	ErrAccountNotVerified   = errors.New("account email not verified")
	ErrPasswordExpired      = errors.New("password has expired")
	ErrTwoFactorRequired    = errors.New("two-factor authentication required")
	ErrInvalidTwoFactorCode = errors.New("invalid two-factor authentication code")
	ErrAuthenticationFailed = errors.New("authentication failed")

	// Authorization errors
	ErrUnauthorized       = errors.New("unauthorized access")
	ErrInsufficientPerms  = errors.New("insufficient permissions")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrResourceNotAllowed = errors.New("resource access not allowed")
	ErrRoleNotFound       = errors.New("role not found")
	ErrPermissionNotFound = errors.New("permission not found")

	// Session errors
	ErrSessionExpired    = errors.New("session has expired")
	ErrSessionNotFound   = errors.New("session not found")
	ErrSessionInvalid    = errors.New("invalid session")
	ErrSessionRevoked    = errors.New("session has been revoked")
	ErrConcurrentSession = errors.New("concurrent session limit exceeded")

	// Token errors
	ErrTokenExpired          = errors.New("token has expired")
	ErrTokenInvalid          = errors.New("invalid token")
	ErrTokenMalformed        = errors.New("malformed token")
	ErrTokenNotFound         = errors.New("token not found")
	ErrTokenRevoked          = errors.New("token has been revoked")
	ErrTokenGenerationFailed = errors.New("token generation failed")

	// User management errors
	ErrUserNotFound    = errors.New("user not found")
	ErrUserExists      = errors.New("user already exists")
	ErrUserDisabled    = errors.New("user account is disabled")
	ErrInvalidUserData = errors.New("invalid user data")
	ErrPasswordTooWeak = errors.New("password does not meet security requirements")
	ErrPasswordReuse   = errors.New("password was recently used")
	ErrEmailInvalid    = errors.New("invalid email format")
	ErrEmailExists     = errors.New("email already registered")

	// Rate limiting errors
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	ErrTooManyRequests   = errors.New("too many requests")
	ErrQuotaExceeded     = errors.New("quota exceeded")

	// Validation errors
	ErrValidationFailed = errors.New("validation failed")
	ErrInvalidInput     = errors.New("invalid input provided")
	ErrMissingRequired  = errors.New("required field missing")
	ErrInvalidFormat    = errors.New("invalid format")
	ErrValueOutOfRange  = errors.New("value out of acceptable range")

	// Storage errors
	ErrStorageUnavailable = errors.New("storage service unavailable")
	ErrStorageTimeout     = errors.New("storage operation timeout")
	ErrDataCorrupted      = errors.New("data corruption detected")
	ErrConnectionFailed   = errors.New("database connection failed")
	ErrTransactionFailed  = errors.New("transaction failed")

	// Configuration errors
	ErrConfigInvalid        = errors.New("invalid configuration")
	ErrConfigMissing        = errors.New("required configuration missing")
	ErrInitializationFailed = errors.New("initialization failed")

	// General errors
	ErrInternal           = errors.New("internal server error")
	ErrServiceUnavailable = errors.New("service temporarily unavailable")
	ErrTimeout            = errors.New("operation timeout")
	ErrCancelled          = errors.New("operation cancelled")
	ErrNotImplemented     = errors.New("feature not implemented")
)

// ErrorType represents the category of error for consistent handling.
type ErrorType string

const (
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeAuthorization  ErrorType = "authorization"
	ErrorTypeValidation     ErrorType = "validation"
	ErrorTypeSession        ErrorType = "session"
	ErrorTypeToken          ErrorType = "token"
	ErrorTypeUser           ErrorType = "user"
	ErrorTypeRateLimit      ErrorType = "rate_limit"
	ErrorTypeStorage        ErrorType = "storage"
	ErrorTypeConfiguration  ErrorType = "configuration"
	ErrorTypeInternal       ErrorType = "internal"
	ErrorTypeNetwork        ErrorType = "network"
)

// APIError represents an RFC 7807 compliant error response.
// It provides structured error information suitable for HTTP APIs.
type APIError struct {
	// RFC 7807 fields
	Type     string `json:"type"`               // URI reference identifying the problem type
	Title    string `json:"title"`              // Short, human-readable summary
	Status   int    `json:"status"`             // HTTP status code
	Detail   string `json:"detail,omitempty"`   // Human-readable explanation
	Instance string `json:"instance,omitempty"` // URI reference identifying the problem occurrence

	// Additional fields for enhanced debugging
	Timestamp time.Time              `json:"timestamp"`            // When the error occurred
	RequestID string                 `json:"request_id,omitempty"` // Request identifier for tracing
	Code      string                 `json:"code,omitempty"`       // Application-specific error code
	Context   map[string]interface{} `json:"context,omitempty"`    // Additional context

	// Internal fields (not serialized)
	cause error `json:"-"` // Original error for unwrapping
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Title
}

// Unwrap returns the underlying error for error unwrapping.
func (e *APIError) Unwrap() error {
	return e.cause
}

// MarshalJSON implements custom JSON marshaling.
func (e *APIError) MarshalJSON() ([]byte, error) {
	type Alias APIError
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(e),
	})
}

// SetContext adds context information to the error.
func (e *APIError) SetContext(key string, value interface{}) *APIError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// SetRequestID sets the request ID for tracing.
func (e *APIError) SetRequestID(requestID string) *APIError {
	e.RequestID = requestID
	return e
}

// NewAPIError creates a new APIError with the given parameters.
func NewAPIError(errorType ErrorType, title string, status int) *APIError {
	return &APIError{
		Type:      string(errorType),
		Title:     title,
		Status:    status,
		Timestamp: time.Now().UTC(),
	}
}

// NewAPIErrorWithDetail creates a new APIError with detailed information.
func NewAPIErrorWithDetail(errorType ErrorType, title, detail string, status int) *APIError {
	return &APIError{
		Type:      string(errorType),
		Title:     title,
		Detail:    detail,
		Status:    status,
		Timestamp: time.Now().UTC(),
	}
}

// WrapError wraps an existing error as an APIError.
func WrapError(err error, errorType ErrorType, title string, status int) *APIError {
	return &APIError{
		Type:      string(errorType),
		Title:     title,
		Detail:    err.Error(),
		Status:    status,
		Timestamp: time.Now().UTC(),
		cause:     err,
	}
}

// Error creation helpers for common scenarios

// NewAuthenticationError creates an authentication-related API error.
func NewAuthenticationError(title, detail string) *APIError {
	return NewAPIErrorWithDetail(ErrorTypeAuthentication, title, detail, http.StatusUnauthorized)
}

// NewAuthorizationError creates an authorization-related API error.
func NewAuthorizationError(title, detail string) *APIError {
	return NewAPIErrorWithDetail(ErrorTypeAuthorization, title, detail, http.StatusForbidden)
}

// NewValidationError creates a validation-related API error.
func NewValidationError(title, detail string) *APIError {
	return NewAPIErrorWithDetail(ErrorTypeValidation, title, detail, http.StatusBadRequest)
}

// NewNotFoundError creates a not found API error.
func NewNotFoundError(resource string) *APIError {
	return NewAPIErrorWithDetail(ErrorTypeUser, "Resource Not Found",
		fmt.Sprintf("The requested %s was not found", resource), http.StatusNotFound)
}

// NewInternalError creates an internal server error.
func NewInternalError(detail string) *APIError {
	return NewAPIErrorWithDetail(ErrorTypeInternal, "Internal Server Error", detail, http.StatusInternalServerError)
}

// NewRateLimitError creates a rate limit exceeded error.
func NewRateLimitError(retryAfter time.Duration) *APIError {
	err := NewAPIErrorWithDetail(ErrorTypeRateLimit, "Rate Limit Exceeded",
		"Too many requests. Please try again later.", http.StatusTooManyRequests)
	if retryAfter > 0 {
		err.SetContext("retry_after", int(retryAfter.Seconds()))
	}
	return err
}

// Error checking utilities

// IsType checks if an error is of a specific type.
func IsType(err error, errorType ErrorType) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Type == string(errorType)
	}
	return false
}

// IsAuthenticationError checks if an error is authentication-related.
func IsAuthenticationError(err error) bool {
	return IsType(err, ErrorTypeAuthentication)
}

// IsAuthorizationError checks if an error is authorization-related.
func IsAuthorizationError(err error) bool {
	return IsType(err, ErrorTypeAuthorization)
}

// IsValidationError checks if an error is validation-related.
func IsValidationError(err error) bool {
	return IsType(err, ErrorTypeValidation)
}

// IsRateLimitError checks if an error is rate limit-related.
func IsRateLimitError(err error) bool {
	return IsType(err, ErrorTypeRateLimit)
}

// GetHTTPStatus extracts the HTTP status code from an error.
func GetHTTPStatus(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	// Default to 500 for unknown errors
	return http.StatusInternalServerError
}

// GetErrorType extracts the error type from an error.
func GetErrorType(err error) ErrorType {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return ErrorType(apiErr.Type)
	}
	return ErrorTypeInternal
}

// Multi-error handling for validation scenarios

// ValidationErrors represents multiple validation errors.
type ValidationErrors struct {
	Errors []FieldError `json:"errors"`
}

// FieldError represents a validation error for a specific field.
type FieldError struct {
	Field   string      `json:"field"`
	Message string      `json:"message"`
	Code    string      `json:"code,omitempty"`
	Value   interface{} `json:"value,omitempty"`
}

// Error implements the error interface for ValidationErrors.
func (ve *ValidationErrors) Error() string {
	if len(ve.Errors) == 0 {
		return "validation failed"
	}
	if len(ve.Errors) == 1 {
		return fmt.Sprintf("validation failed: %s", ve.Errors[0].Message)
	}
	return fmt.Sprintf("validation failed: %d errors", len(ve.Errors))
}

// Add adds a field error to the validation errors.
func (ve *ValidationErrors) Add(field, message string) {
	ve.Errors = append(ve.Errors, FieldError{
		Field:   field,
		Message: message,
	})
}

// AddWithCode adds a field error with a specific error code.
func (ve *ValidationErrors) AddWithCode(field, message, code string) {
	ve.Errors = append(ve.Errors, FieldError{
		Field:   field,
		Message: message,
		Code:    code,
	})
}

// HasErrors returns true if there are any validation errors.
func (ve *ValidationErrors) HasErrors() bool {
	return len(ve.Errors) > 0
}

// NewValidationErrors creates a new ValidationErrors instance.
func NewValidationErrors() *ValidationErrors {
	return &ValidationErrors{
		Errors: make([]FieldError, 0),
	}
}

// ToAPIError converts ValidationErrors to an APIError.
func (ve *ValidationErrors) ToAPIError() *APIError {
	if !ve.HasErrors() {
		return nil
	}

	err := NewValidationError("Validation Failed", ve.Error())
	err.SetContext("field_errors", ve.Errors)
	return err
}

// Error assertion helpers

// AsAPIError attempts to convert an error to an APIError.
func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	return apiErr, errors.As(err, &apiErr)
}

// MustAPIError converts an error to an APIError, creating a new one if necessary.
func MustAPIError(err error) *APIError {
	if apiErr, ok := AsAPIError(err); ok {
		return apiErr
	}
	return WrapError(err, ErrorTypeInternal, "Internal Error", http.StatusInternalServerError)
}
