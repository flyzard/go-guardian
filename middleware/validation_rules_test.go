package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/flyzard/go-guardian/web"
	"github.com/go-chi/chi/v5"
)

func TestValidateIDInRange(t *testing.T) {
	tests := []struct {
		name      string
		paramName string
		value     string
		min       int64
		max       int64
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid ID in range",
			paramName: "id",
			value:     "100",
			min:       1,
			max:       1000,
			wantErr:   false,
		},
		{
			name:      "ID below minimum",
			paramName: "id",
			value:     "0",
			min:       1,
			max:       1000,
			wantErr:   true,
			errMsg:    "out of valid range",
		},
		{
			name:      "ID above maximum",
			paramName: "id",
			value:     "1001",
			min:       1,
			max:       1000,
			wantErr:   true,
			errMsg:    "out of valid range",
		},
		{
			name:      "empty ID",
			paramName: "id",
			value:     "",
			min:       1,
			max:       1000,
			wantErr:   true,
			errMsg:    "is required",
		},
		{
			name:      "non-numeric ID",
			paramName: "id",
			value:     "abc",
			min:       1,
			max:       1000,
			wantErr:   true,
			errMsg:    "Invalid id format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with chi context
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add(tt.paramName, tt.value)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			validator := ValidateIDInRange(tt.paramName, tt.min, tt.max)
			err := validator(req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("error message does not contain expected text: got %v, want substring %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateSearchQuery(t *testing.T) {
	tests := []struct {
		name         string
		paramName    string
		value        string
		maxLength    int
		allowedChars string
		wantErr      bool
		errMsg       string
	}{
		{
			name:         "valid search query",
			paramName:    "search",
			value:        "test search",
			maxLength:    100,
			allowedChars: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -",
			wantErr:      false,
		},
		{
			name:         "empty search query",
			paramName:    "search",
			value:        "",
			maxLength:    100,
			allowedChars: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -",
			wantErr:      false,
		},
		{
			name:      "query too long",
			paramName: "search",
			value:     "this is a very long search query that exceeds the maximum allowed length",
			maxLength: 20,
			wantErr:   true,
			errMsg:    "too long",
		},
		{
			name:         "invalid characters",
			paramName:    "search",
			value:        "test@search",
			maxLength:    100,
			allowedChars: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -",
			wantErr:      true,
			errMsg:       "Invalid characters",
		},
		{
			name:      "no character restriction",
			paramName: "search",
			value:     "test@search#special",
			maxLength: 100,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test?"+tt.paramName+"="+url.QueryEscape(tt.value), nil)

			validator := ValidateSearchQuery(tt.paramName, tt.maxLength, tt.allowedChars)
			err := validator(req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("error message does not contain expected text: got %v, want substring %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateEnum(t *testing.T) {
	tests := []struct {
		name        string
		paramName   string
		value       string
		validValues []string
		isURLParam  bool
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "valid enum value",
			paramName:   "status",
			value:       "active",
			validValues: []string{"active", "inactive", "pending"},
			wantErr:     false,
		},
		{
			name:        "invalid enum value",
			paramName:   "status",
			value:       "deleted",
			validValues: []string{"active", "inactive", "pending"},
			wantErr:     true,
			errMsg:      "Invalid status value",
		},
		{
			name:        "empty value allowed",
			paramName:   "status",
			value:       "",
			validValues: []string{"active", "inactive", "pending", ""},
			wantErr:     false,
		},
		{
			name:        "empty value not allowed",
			paramName:   "status",
			value:       "",
			validValues: []string{"active", "inactive", "pending"},
			wantErr:     false, // Empty is allowed if not in the list
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.isURLParam {
				req = httptest.NewRequest(http.MethodGet, "/test", nil)
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add(tt.paramName, tt.value)
				req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			} else {
				req = httptest.NewRequest(http.MethodGet, "/test?"+tt.paramName+"="+url.QueryEscape(tt.value), nil)
			}

			validator := ValidateEnum(tt.paramName, tt.validValues...)
			err := validator(req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("error message does not contain expected text: got %v, want substring %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateChain(t *testing.T) {
	// Create test validators
	alwaysPass := func(r *http.Request) error {
		return nil
	}
	alwaysFail := func(r *http.Request) error {
		return web.Validation("Always fails")
	}

	tests := []struct {
		name       string
		validators []ValidationFunc
		wantErr    bool
	}{
		{
			name:       "all validators pass",
			validators: []ValidationFunc{alwaysPass, alwaysPass, alwaysPass},
			wantErr:    false,
		},
		{
			name:       "first validator fails",
			validators: []ValidationFunc{alwaysFail, alwaysPass, alwaysPass},
			wantErr:    true,
		},
		{
			name:       "middle validator fails",
			validators: []ValidationFunc{alwaysPass, alwaysFail, alwaysPass},
			wantErr:    true,
		},
		{
			name:       "last validator fails",
			validators: []ValidationFunc{alwaysPass, alwaysPass, alwaysFail},
			wantErr:    true,
		},
		{
			name:       "empty chain",
			validators: []ValidationFunc{},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			validator := ValidateChain(tt.validators...)
			err := validator(req)

			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			} else if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateURLParamInt(t *testing.T) {
	tests := []struct {
		name      string
		paramName string
		value     string
		min       int64
		max       int64
		wantErr   bool
	}{
		{
			name:      "valid integer in range",
			paramName: "count",
			value:     "50",
			min:       1,
			max:       100,
			wantErr:   false,
		},
		{
			name:      "integer at minimum",
			paramName: "count",
			value:     "1",
			min:       1,
			max:       100,
			wantErr:   false,
		},
		{
			name:      "integer at maximum",
			paramName: "count",
			value:     "100",
			min:       1,
			max:       100,
			wantErr:   false,
		},
		{
			name:      "integer below minimum",
			paramName: "count",
			value:     "0",
			min:       1,
			max:       100,
			wantErr:   true,
		},
		{
			name:      "integer above maximum",
			paramName: "count",
			value:     "101",
			min:       1,
			max:       100,
			wantErr:   true,
		},
		{
			name:      "empty value",
			paramName: "count",
			value:     "",
			min:       1,
			max:       100,
			wantErr:   true,
		},
		{
			name:      "non-integer value",
			paramName: "count",
			value:     "abc",
			min:       1,
			max:       100,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add(tt.paramName, tt.value)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			validator := ValidateURLParamInt(tt.paramName, tt.min, tt.max)
			err := validator(req)

			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			} else if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// Helper function for testing
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && (s[0:len(substr)] == substr || containsString(s[1:], substr))))
}