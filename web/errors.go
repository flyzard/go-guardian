package web

import (
	"fmt"
	"net/http"
)

// ErrorType represents different categories of web errors
type ErrorType string

const (
	ErrorTypeValidation   ErrorType = "validation"
	ErrorTypeUnauthorized ErrorType = "unauthorized"
	ErrorTypeForbidden    ErrorType = "forbidden"
	ErrorTypeNotFound     ErrorType = "not_found"
	ErrorTypeConflict     ErrorType = "conflict"
	ErrorTypeInternal     ErrorType = "internal"
	ErrorTypeBadRequest   ErrorType = "bad_request"
	ErrorTypeTimeout      ErrorType = "timeout"
)

// WebError represents a structured web error with additional context
type WebError struct {
	Type       ErrorType
	Message    string
	Details    string
	StatusCode int
	Field      string // For validation errors
	Value      any    // The invalid value (for debugging)
}

// Error implements the error interface
func (e *WebError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Details)
	}
	return e.Message
}


// WithDetails adds details to the error
func (e *WebError) WithDetails(details string) *WebError {
	e.Details = details
	return e
}

// WithField adds field information (useful for validation errors)
func (e *WebError) WithField(field string, value any) *WebError {
	e.Field = field
	e.Value = value
	return e
}

// IsWebError checks if an error is a WebError and returns it
func IsWebError(err error) (*WebError, bool) {
	webErr, ok := err.(*WebError)
	return webErr, ok
}

// Common error constructors

// Validation creates a validation error
func Validation(message string) *WebError {
	return &WebError{
		Type:       ErrorTypeValidation,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// Unauthorized creates an unauthorized error
func Unauthorized(message string) *WebError {
	return &WebError{
		Type:       ErrorTypeUnauthorized,
		Message:    message,
		StatusCode: http.StatusUnauthorized,
	}
}

// Forbidden creates a forbidden error
func Forbidden(message string) *WebError {
	return &WebError{
		Type:       ErrorTypeForbidden,
		Message:    message,
		StatusCode: http.StatusForbidden,
	}
}

// NotFound creates a not found error
func NotFound(message string) *WebError {
	return &WebError{
		Type:       ErrorTypeNotFound,
		Message:    message,
		StatusCode: http.StatusNotFound,
	}
}

// Conflict creates a conflict error
func Conflict(message string) *WebError {
	return &WebError{
		Type:       ErrorTypeConflict,
		Message:    message,
		StatusCode: http.StatusConflict,
	}
}

// Internal creates an internal server error
func Internal(message string) *WebError {
	return &WebError{
		Type:       ErrorTypeInternal,
		Message:    message,
		StatusCode: http.StatusInternalServerError,
	}
}

// BadRequest creates a bad request error
func BadRequest(message string) *WebError {
	return &WebError{
		Type:       ErrorTypeBadRequest,
		Message:    message,
		StatusCode: http.StatusBadRequest,
	}
}

// Timeout creates a timeout error
func Timeout(message string) *WebError {
	return &WebError{
		Type:       ErrorTypeTimeout,
		Message:    message,
		StatusCode: http.StatusRequestTimeout,
	}
}

// WrapError wraps a standard error with a WebError
func WrapError(err error, errorType ErrorType, message string) *WebError {
	return &WebError{
		Type:       errorType,
		Message:    message,
		Details:    err.Error(),
		StatusCode: statusCodeForType(errorType),
	}
}

// statusCodeForType returns the appropriate HTTP status code for an error type
func statusCodeForType(errorType ErrorType) int {
	switch errorType {
	case ErrorTypeValidation, ErrorTypeBadRequest:
		return http.StatusBadRequest
	case ErrorTypeUnauthorized:
		return http.StatusUnauthorized
	case ErrorTypeForbidden:
		return http.StatusForbidden
	case ErrorTypeNotFound:
		return http.StatusNotFound
	case ErrorTypeConflict:
		return http.StatusConflict
	case ErrorTypeTimeout:
		return http.StatusRequestTimeout
	default:
		return http.StatusInternalServerError
	}
}