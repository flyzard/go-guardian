package middleware

import (
	"net/http"

	"github.com/flyzard/go-guardian/response"
	"github.com/flyzard/go-guardian/web"
)

// ValidationFunc is a function that validates a request and returns an error if invalid
type ValidationFunc func(r *http.Request) error

// ParamValidation creates a middleware that validates request parameters
func ParamValidation(validators ...ValidationFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Run all validators
			for _, validator := range validators {
				if err := validator(r); err != nil {
					// Check if it's already a WebError
					if webErr, ok := web.IsWebError(err); ok {
						response.New(w, r).ErrorWithStatus(webErr, webErr.StatusCode).Send()
					} else {
						// Wrap in a validation error
						response.New(w, r).ErrorWithStatus(
							web.Validation("Invalid request parameters").WithDetails(err.Error()),
							http.StatusBadRequest,
						).Send()
					}
					return
				}
			}

			// All validations passed, continue to next handler
			next.ServeHTTP(w, r)
		})
	}
}

// QueryValidation creates a middleware that validates query parameters
func QueryValidation(paramName string, validator func(value string) error) func(http.Handler) http.Handler {
	return ParamValidation(func(r *http.Request) error {
		value := r.URL.Query().Get(paramName)
		if err := validator(value); err != nil {
			return web.Validation("Invalid query parameter").
				WithDetails(err.Error()).
				WithField(paramName, value)
		}
		return nil
	})
}

// HeaderValidation creates a middleware that validates request headers
func HeaderValidation(headerName string, validator func(value string) error) func(http.Handler) http.Handler {
	return ParamValidation(func(r *http.Request) error {
		value := r.Header.Get(headerName)
		if err := validator(value); err != nil {
			return web.Validation("Invalid header").
				WithDetails(err.Error()).
				WithField(headerName, value)
		}
		return nil
	})
}

// RequiredParam creates a validator that ensures a parameter is present
func RequiredParam(paramName string, getValue func(r *http.Request) string) ValidationFunc {
	return func(r *http.Request) error {
		value := getValue(r)
		if value == "" {
			return web.Validation("Required parameter missing").
				WithField(paramName, "")
		}
		return nil
	}
}

// RequiredQuery creates a validator that ensures a query parameter is present
func RequiredQuery(paramName string) ValidationFunc {
	return RequiredParam(paramName, func(r *http.Request) string {
		return r.URL.Query().Get(paramName)
	})
}

// RequiredHeader creates a validator that ensures a header is present
func RequiredHeader(headerName string) ValidationFunc {
	return RequiredParam(headerName, func(r *http.Request) string {
		return r.Header.Get(headerName)
	})
}

// ContentTypeValidation creates a middleware that validates the Content-Type header
func ContentTypeValidation(expectedType string) func(http.Handler) http.Handler {
	return HeaderValidation("Content-Type", func(value string) error {
		if value != expectedType {
			return web.BadRequest("Invalid content type").
				WithDetails("Expected: " + expectedType + ", Got: " + value)
		}
		return nil
	})
}

// JSONContentType is a middleware that ensures the request has JSON content type
func JSONContentType(next http.Handler) http.Handler {
	return ContentTypeValidation("application/json")(next)
}

// FormContentType is a middleware that ensures the request has form content type
func FormContentType(next http.Handler) http.Handler {
	return ContentTypeValidation("application/x-www-form-urlencoded")(next)
}

// ChainValidators combines multiple validation functions into one
func ChainValidators(validators ...ValidationFunc) ValidationFunc {
	return func(r *http.Request) error {
		for _, validator := range validators {
			if err := validator(r); err != nil {
				return err
			}
		}
		return nil
	}
}