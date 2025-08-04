package response

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponseBuilder(t *testing.T) {
	tests := []struct {
		name     string
		build    func(Response) Response
		wantCode int
		wantType string
		wantBody string
	}{
		{
			name: "JSON response",
			build: func(r Response) Response {
				return r.Status(http.StatusCreated).JSON(map[string]string{"message": "success"})
			},
			wantCode: http.StatusCreated,
			wantType: "application/json",
			wantBody: `{"message":"success"}`,
		},
		{
			name: "HTML response",
			build: func(r Response) Response {
				return r.HTML("<h1>Hello</h1>")
			},
			wantCode: http.StatusOK,
			wantType: "text/html; charset=utf-8",
			wantBody: "<h1>Hello</h1>",
		},
		{
			name: "Text response",
			build: func(r Response) Response {
				return r.Text("Hello World")
			},
			wantCode: http.StatusOK,
			wantType: "text/plain; charset=utf-8",
			wantBody: "Hello World",
		},
		{
			name: "Error response",
			build: func(r Response) Response {
				return r.Error(errors.New("something went wrong"))
			},
			wantCode: http.StatusInternalServerError,
			wantType: "text/html; charset=utf-8",
			wantBody: `<div class="alert alert-danger"><strong>something went wrong</strong></div>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			
			resp := New(w, r)
			tt.build(resp).Send()
			
			if w.Code != tt.wantCode {
				t.Errorf("got status %d, want %d", w.Code, tt.wantCode)
			}
			
			contentType := w.Header().Get("Content-Type")
			if contentType != tt.wantType {
				t.Errorf("got content-type %q, want %q", contentType, tt.wantType)
			}
			
			body := strings.TrimSpace(w.Body.String())
			if body != tt.wantBody {
				t.Errorf("got body %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestHTMXAutoDetection(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("HX-Request", "true")
	
	builder := New(w, r).(*Builder)
	
	if builder.htmxWriter == nil {
		t.Error("expected HTMX writer to be initialized for HTMX request")
	}
}

func TestJSONAutoDetection(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "application/json")
	
	builder := New(w, r).(*Builder)
	
	if !builder.isJSON {
		t.Error("expected JSON mode to be enabled for JSON accept header")
	}
	
	if builder.headers["Content-Type"] != "application/json" {
		t.Errorf("expected JSON content type, got %s", builder.headers["Content-Type"])
	}
}

// Mock WebError-like struct
type mockWebError struct {
	Type       string
	Message    string
	Details    string
	StatusCode int
	Field      string
}

func (e *mockWebError) Error() string {
	return e.Message
}

func TestErrorWithWebError(t *testing.T) {
	
	err := &mockWebError{
		Type:       "validation",
		Message:    "Invalid input",
		Details:    "Email is required",
		StatusCode: http.StatusBadRequest,
		Field:      "email",
	}
	
	// Test JSON response
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "application/json")
	
	New(w, r).ErrorWithStatus(err, http.StatusBadRequest).Send()
	
	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", w.Code, http.StatusBadRequest)
	}
	
	// Should contain error fields in JSON
	body := w.Body.String()
	if !strings.Contains(body, `"error":"`) {
		t.Error("JSON response should contain error field")
	}
}

func TestNotificationMethods(t *testing.T) {
	tests := []struct {
		name     string
		build    func(NotificationResponse) Response
		wantBody string
	}{
		{
			name: "Success alert",
			build: func(r NotificationResponse) Response {
				return r.Success("Operation completed")
			},
			wantBody: `<div class="alert alert-success">Operation completed</div>`,
		},
		{
			name: "Warning alert",
			build: func(r NotificationResponse) Response {
				return r.Warning("Be careful")
			},
			wantBody: `<div class="alert alert-warning">Be careful</div>`,
		},
		{
			name: "Info alert",
			build: func(r NotificationResponse) Response {
				return r.Info("FYI")
			},
			wantBody: `<div class="alert alert-info">FYI</div>`,
		},
		{
			name: "Danger alert",
			build: func(r NotificationResponse) Response {
				return r.Danger("Error occurred")
			},
			wantBody: `<div class="alert alert-danger">Error occurred</div>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			
			resp := New(w, r).(NotificationResponse)
			tt.build(resp).Send()
			
			body := strings.TrimSpace(w.Body.String())
			if body != tt.wantBody {
				t.Errorf("got body %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestBuilderPooling(t *testing.T) {
	// Get a builder
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/", nil)
	b1 := New(w1, r1).(*Builder)
	
	// Set some custom headers
	b1.Header("X-Custom", "value")
	b1.Status(http.StatusCreated)
	b1.Send()
	
	// Get another builder (should be reused from pool)
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/", nil)
	b2 := New(w2, r2).(*Builder)
	
	// Check that it was properly reset
	if b2.status != http.StatusOK {
		t.Errorf("expected status to be reset to 200, got %d", b2.status)
	}
	
	if _, exists := b2.headers["X-Custom"]; exists {
		t.Error("expected custom header to be cleared")
	}
	
	if b2.content.Len() != 0 {
		t.Error("expected content to be cleared")
	}
}