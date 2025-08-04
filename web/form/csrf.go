package form

import (
	"net/http"
	
	"github.com/flyzard/go-guardian/middleware"
)

// WithCSRFFromRequest extracts CSRF token from request and adds it to the form
func (b *Builder) WithCSRFFromRequest(r *http.Request) *Builder {
	token := middleware.GetCSRFToken(r)
	if token != "" {
		b.csrf = &CSRFConfig{
			Token:     token,
			FieldName: middleware.CSRFTokenKey,
		}
	}
	return b
}

// WithCSRFFieldName sets a custom CSRF field name
func (b *Builder) WithCSRFFieldName(fieldName string) *Builder {
	if b.csrf != nil {
		b.csrf.FieldName = fieldName
	}
	return b
}

// GetCSRFToken returns the CSRF token if configured
func (b *Builder) GetCSRFToken() string {
	if b.csrf != nil {
		return b.csrf.Token
	}
	return ""
}

// HasCSRF checks if CSRF protection is enabled
func (b *Builder) HasCSRF() bool {
	return b.csrf != nil && b.csrf.Token != ""
}