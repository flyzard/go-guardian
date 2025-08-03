package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResponseBuilder_Info(t *testing.T) {
	tests := []struct {
		name     string
		icon     string
		message  string
		expected string
	}{
		{
			name:     "info with search icon",
			icon:     "🔍",
			message:  "Searching...",
			expected: `<div class="alert alert-info">`,
		},
		{
			name:     "info with custom icon",
			icon:     "⚙️",
			message:  "Processing request",
			expected: `<strong>⚙️</strong> Processing request`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			b := NewResponse(rec)
			
			b.Info(tt.icon, tt.message).Send()
			
			body := rec.Body.String()
			if !strings.Contains(body, tt.expected) {
				t.Errorf("expected body to contain %q, got %q", tt.expected, body)
			}
		})
	}
}

func TestResponseBuilder_SuccessWithDetails(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		details  string
		expected []string
	}{
		{
			name:    "success with details",
			title:   "Operation Complete",
			details: "All items have been processed successfully",
			expected: []string{
				`<div class="alert alert-success">`,
				`<strong>✓ Operation Complete</strong>`,
				`<p class="alert-details">All items have been processed successfully</p>`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			b := NewResponse(rec)
			
			b.SuccessWithDetails(tt.title, tt.details).Send()
			
			body := rec.Body.String()
			for _, exp := range tt.expected {
				if !strings.Contains(body, exp) {
					t.Errorf("expected body to contain %q, got %q", exp, body)
				}
			}
		})
	}
}

func TestResponseBuilder_HTMXPartial(t *testing.T) {
	// Create a mock template manager for testing
	// Note: This test would require a proper template manager setup
	// For now, we'll test the HTMX headers being set correctly
	
	rec := httptest.NewRecorder()
	b := NewResponse(rec)
	
	// HTMXPartial without template manager should error
	// But headers should still be set before the error
	b.HTMXPartial("test.html", nil)
	
	// Check that headers were set in the builder (not sent yet)
	if b.headers["HX-Retarget"] != "this" {
		t.Errorf("expected HX-Retarget to be set to 'this' in builder")
	}
	if b.headers["HX-Reswap"] != "outerHTML" {
		t.Errorf("expected HX-Reswap to be set to 'outerHTML' in builder")
	}
	
	// Now send and check the response
	b.Send()
	
	// Check error message
	body := rec.Body.String()
	if !strings.Contains(body, "Template manager not configured") {
		t.Errorf("expected error about template manager, got %q", body)
	}
	
	// Headers should be present even with error
	if got := rec.Header().Get("HX-Retarget"); got != "this" {
		t.Errorf("expected HX-Retarget header to be 'this', got %q", got)
	}
	if got := rec.Header().Get("HX-Reswap"); got != "outerHTML" {
		t.Errorf("expected HX-Reswap header to be 'outerHTML', got %q", got)
	}
}

func TestResponseBuilder_Toast(t *testing.T) {
	tests := []struct {
		name      string
		toastType string
		message   string
		duration  int
		checks    []string
	}{
		{
			name:      "success toast",
			toastType: "success",
			message:   "Operation completed!",
			duration:  3000,
			checks: []string{
				`class="toast toast-success"`,
				`style="animation-duration: 3000ms"`,
				`<div class="toast-content">Operation completed!</div>`,
				`setTimeout`,
				`.remove()`,
				`}, 3000);`,
			},
		},
		{
			name:      "error toast",
			toastType: "error",
			message:   "Something went wrong",
			duration:  5000,
			checks: []string{
				`class="toast toast-error"`,
				`style="animation-duration: 5000ms"`,
				`<div class="toast-content">Something went wrong</div>`,
				`}, 5000);`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			b := NewResponse(rec)
			
			// Add small delay to ensure unique IDs
			time.Sleep(1 * time.Millisecond)
			
			b.Toast(tt.toastType, tt.message, tt.duration).Send()
			
			body := rec.Body.String()
			
			// Check all expected strings
			for _, check := range tt.checks {
				if !strings.Contains(body, check) {
					t.Errorf("expected body to contain %q, got %q", check, body)
				}
			}
			
			// Check HTMX headers
			if got := rec.Header().Get("HX-Retarget"); got != "#toast-container" {
				t.Errorf("expected HX-Retarget to be '#toast-container', got %q", got)
			}
			if got := rec.Header().Get("HX-Reswap"); got != "beforeend" {
				t.Errorf("expected HX-Reswap to be 'beforeend', got %q", got)
			}
			
			// Check that toast has unique ID
			if !strings.Contains(body, `id="toast-`) {
				t.Error("expected toast to have unique ID starting with 'toast-'")
			}
		})
	}
}

func TestResponseBuilder_AlertWithIcon(t *testing.T) {
	tests := []struct {
		name      string
		alertType AlertType
		icon      string
		message   string
		expected  []string
	}{
		{
			name:      "warning with icon",
			alertType: AlertWarning,
			icon:      "⚠️",
			message:   "Please review your changes",
			expected: []string{
				`<div class="alert alert-warning">`,
				`<strong>⚠️</strong> Please review your changes`,
			},
		},
		{
			name:      "danger with icon",
			alertType: AlertDanger,
			icon:      "🚫",
			message:   "Access denied",
			expected: []string{
				`<div class="alert alert-danger">`,
				`<strong>🚫</strong> Access denied`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			b := NewResponse(rec)
			
			b.AlertWithIcon(tt.alertType, tt.icon, tt.message).Send()
			
			body := rec.Body.String()
			for _, exp := range tt.expected {
				if !strings.Contains(body, exp) {
					t.Errorf("expected body to contain %q, got %q", exp, body)
				}
			}
		})
	}
}