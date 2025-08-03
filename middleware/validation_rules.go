package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/flyzard/go-guardian/web"
	"github.com/go-chi/chi/v5"
)

// ValidateIDInRange creates a validator for numeric ID parameters within a specified range
func ValidateIDInRange(paramName string, min, max int64) ValidationFunc {
	return func(r *http.Request) error {
		value := chi.URLParam(r, paramName)
		if value == "" {
			return web.Validation(fmt.Sprintf("%s is required", paramName)).
				WithField(paramName, "")
		}

		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return web.Validation(fmt.Sprintf("Invalid %s format", paramName)).
				WithDetails("Must be a valid integer").
				WithField(paramName, value)
		}

		if id < min || id > max {
			return web.Validation(fmt.Sprintf("%s out of valid range", paramName)).
				WithDetails(fmt.Sprintf("Must be between %d and %d", min, max)).
				WithField(paramName, value)
		}

		return nil
	}
}

// ValidateSearchQuery creates a validator for search query parameters
func ValidateSearchQuery(paramName string, maxLength int, allowedChars string) ValidationFunc {
	return func(r *http.Request) error {
		value := r.URL.Query().Get(paramName)
		
		// Empty search is valid
		if value == "" {
			return nil
		}

		// Check length
		if len(value) > maxLength {
			return web.Validation(fmt.Sprintf("%s too long", paramName)).
				WithDetails(fmt.Sprintf("Maximum length is %d characters", maxLength)).
				WithField(paramName, value)
		}

		// Check for allowed characters
		if allowedChars != "" {
			for _, char := range value {
				if !strings.ContainsRune(allowedChars, char) {
					return web.Validation(fmt.Sprintf("Invalid characters in %s", paramName)).
						WithDetails(fmt.Sprintf("Only these characters are allowed: %s", allowedChars)).
						WithField(paramName, value)
				}
			}
		}

		return nil
	}
}

// ValidateEnum creates a validator that ensures a parameter value is one of the allowed values
func ValidateEnum(paramName string, validValues ...string) ValidationFunc {
	return func(r *http.Request) error {
		// Try URL param first, then query param
		value := chi.URLParam(r, paramName)
		if value == "" {
			value = r.URL.Query().Get(paramName)
		}

		// Empty value might be valid if it's in the list
		if value == "" && !contains(validValues, "") {
			return nil
		}

		if !contains(validValues, value) {
			return web.Validation(fmt.Sprintf("Invalid %s value", paramName)).
				WithDetails(fmt.Sprintf("Must be one of: %s", strings.Join(validValues, ", "))).
				WithField(paramName, value)
		}

		return nil
	}
}

// ValidateChain creates a validator that runs multiple validators in sequence
// It stops at the first validation error
func ValidateChain(validators ...ValidationFunc) ValidationFunc {
	return func(r *http.Request) error {
		for _, validator := range validators {
			if err := validator(r); err != nil {
				return err
			}
		}
		return nil
	}
}

// ValidateURLParam creates a validator for URL parameters with a custom validation function
func ValidateURLParam(paramName string, validator func(string) error) ValidationFunc {
	return func(r *http.Request) error {
		value := chi.URLParam(r, paramName)
		if err := validator(value); err != nil {
			return web.Validation(fmt.Sprintf("Invalid %s", paramName)).
				WithDetails(err.Error()).
				WithField(paramName, value)
		}
		return nil
	}
}

// ValidateURLParamInt creates a validator for integer URL parameters within a range
func ValidateURLParamInt(paramName string, min, max int64) ValidationFunc {
	return ValidateURLParam(paramName, func(value string) error {
		if value == "" {
			return fmt.Errorf("value is required")
		}

		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("must be a valid integer")
		}

		if intVal < min || intVal > max {
			return fmt.Errorf("must be between %d and %d", min, max)
		}

		return nil
	})
}

// ValidateQueryParam creates a validator for query parameters with a custom validation function
func ValidateQueryParam(paramName string, validator func(string) error) ValidationFunc {
	return func(r *http.Request) error {
		value := r.URL.Query().Get(paramName)
		if err := validator(value); err != nil {
			return web.Validation(fmt.Sprintf("Invalid %s", paramName)).
				WithDetails(err.Error()).
				WithField(paramName, value)
		}
		return nil
	}
}

// ValidateQueryParamInt creates a validator for integer query parameters within a range
func ValidateQueryParamInt(paramName string, min, max int64) ValidationFunc {
	return ValidateQueryParam(paramName, func(value string) error {
		// Empty query param is allowed
		if value == "" {
			return nil
		}

		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("must be a valid integer")
		}

		if intVal < min || intVal > max {
			return fmt.Errorf("must be between %d and %d", min, max)
		}

		return nil
	})
}

// ValidateFormValue creates a validator for form values with a custom validation function
func ValidateFormValue(fieldName string, validator func(string) error) ValidationFunc {
	return func(r *http.Request) error {
		value := r.FormValue(fieldName)
		if err := validator(value); err != nil {
			return web.Validation(fmt.Sprintf("Invalid %s", fieldName)).
				WithDetails(err.Error()).
				WithField(fieldName, value)
		}
		return nil
	}
}

// Helper function to check if a string is in a slice
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}