package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerFacade_Basic(t *testing.T) {
	facade := NewHandlerFacade("/api")
	
	// Build a simple handler group
	listCalled := false
	listHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		listCalled = true
		w.Write([]byte("list"))
	})
	
	detailCalled := false
	detailHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		detailCalled = true
		w.Write([]byte("detail"))
	})
	
	group := facade.
		WithHandler("list", listHandler).
		WithHandler("detail", detailHandler).
		Build()
	
	// Test auto-routing
	t.Run("Auto-route for list", func(t *testing.T) {
		listCalled = false
		req := httptest.NewRequest("GET", "/api/", nil)
		rec := httptest.NewRecorder()
		
		group.ServeHTTP(rec, req)
		
		if !listCalled {
			t.Error("list handler was not called")
		}
	})
	
	t.Run("Auto-route for detail", func(t *testing.T) {
		detailCalled = false
		req := httptest.NewRequest("GET", "/api/123", nil)
		rec := httptest.NewRecorder()
		
		group.ServeHTTP(rec, req)
		
		if !detailCalled {
			t.Error("detail handler was not called")
		}
	})
}

func TestHandlerFacade_CustomRoutes(t *testing.T) {
	facade := NewHandlerFacade("/api")
	
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.Write([]byte("custom"))
	})
	
	group := facade.
		WithHandler("custom", handler, WithRoutes("/my-custom-route", "/another-route")).
		Build()
	
	tests := []struct {
		path   string
		expect bool
	}{
		{"/api/my-custom-route", true},
		{"/api/another-route", true},
		{"/api/custom", false}, // Auto-route should be overridden
	}
	
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			handlerCalled = false
			req := httptest.NewRequest("GET", tt.path, nil)
			rec := httptest.NewRecorder()
			
			group.ServeHTTP(rec, req)
			
			if handlerCalled != tt.expect {
				t.Errorf("handler called = %v, want %v", handlerCalled, tt.expect)
			}
		})
	}
}

func TestHandlerFacade_NoAutoRoute(t *testing.T) {
	facade := NewHandlerFacade("/api")
	
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("no auto"))
	})
	
	group := facade.
		WithHandler("test", handler, NoAutoRoute()).
		Route("/manual", "test").
		Build()
	
	// Should work with manual route
	req := httptest.NewRequest("GET", "/api/manual", nil)
	rec := httptest.NewRecorder()
	group.ServeHTTP(rec, req)
	
	if rec.Code != 200 {
		t.Error("manual route did not work")
	}
	
	// Should not work with auto route
	req = httptest.NewRequest("GET", "/api/test", nil)
	rec = httptest.NewRecorder()
	group.ServeHTTP(rec, req)
	
	if rec.Code != 404 {
		t.Error("auto route was not disabled")
	}
}

func TestHandlerFacade_Methods(t *testing.T) {
	facade := NewHandlerFacade("/api")
	
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	
	group := facade.
		WithHandler("users", handler, WithMethods("GET", "POST")).
		Build()
	
	tests := []struct {
		method       string
		expectedCode int
	}{
		{"GET", 200},
		{"POST", 200},
		{"PUT", 405},
		{"DELETE", 405},
	}
	
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/users", nil)
			rec := httptest.NewRecorder()
			
			group.ServeHTTP(rec, req)
			
			if rec.Code != tt.expectedCode {
				t.Errorf("expected %d, got %d", tt.expectedCode, rec.Code)
			}
		})
	}
}

func TestHandlerFacade_REST(t *testing.T) {
	facade := NewHandlerFacade("/api")
	
	// Mock REST handler
	handler := &mockRESTHandler{
		responses: make(map[string]string),
	}
	handler.responses["index"] = "user list"
	handler.responses["show"] = "user detail"
	handler.responses["create"] = "user created"
	
	group := facade.
		WithRESTHandler("users", handler).
		Build()
	
	tests := []struct {
		method       string
		path         string
		expectedBody string
		expectedCode int
	}{
		{"GET", "/api/users", "user list", 200},
		{"GET", "/api/users/123", "user detail", 200},
		{"POST", "/api/users", "user created", 200},
		{"DELETE", "/api/users/123", "", 405}, // Not implemented - returns Method Not Allowed
	}
	
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			
			group.ServeHTTP(rec, req)
			
			if rec.Code != tt.expectedCode {
				t.Errorf("expected status %d, got %d", tt.expectedCode, rec.Code)
			}
			
			if tt.expectedBody != "" && rec.Body.String() != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, rec.Body.String())
			}
		})
	}
}

func TestHandlerFacade_SharedData(t *testing.T) {
	facade := NewHandlerFacade("/api")
	
	group := facade.
		WithSharedData("config", "value1").
		WithSharedData("count", 42).
		Build()
	
	val, ok := group.GetSharedData("config")
	if !ok || val != "value1" {
		t.Errorf("expected value1, got %v", val)
	}
	
	count, ok := group.GetSharedInt("count")
	if !ok || count != 42 {
		t.Errorf("expected 42, got %v", count)
	}
}

func TestHandlerComposer(t *testing.T) {
	composer := NewHandlerComposer()
	
	var calls []string
	
	handler1 := func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "handler1")
	}
	
	handler2 := func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "handler2")
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("response"))
	}
	
	handler3 := func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "handler3") // Should not be called
	}
	
	composed := composer.
		Add(handler1).
		Add(handler2).
		AddIf(true, handler3).
		Build()
	
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	
	composed.ServeHTTP(rec, req)
	
	// Only first two handlers should be called
	if len(calls) != 2 {
		t.Errorf("expected 2 calls, got %d", len(calls))
	}
	
	if calls[0] != "handler1" || calls[1] != "handler2" {
		t.Errorf("unexpected call order: %v", calls)
	}
	
	if rec.Body.String() != "response" {
		t.Errorf("unexpected response: %s", rec.Body.String())
	}
}

func TestSimpleHandlerGroup(t *testing.T) {
	simple := SimpleHandlerGroup("/api")
	
	handler1Called := false
	handler1 := func(w http.ResponseWriter, r *http.Request) {
		handler1Called = true
		w.Write([]byte("users"))
	}
	
	handler2Called := false
	handler2 := func(w http.ResponseWriter, r *http.Request) {
		handler2Called = true
		w.Write([]byte("posts"))
	}
	
	prefixCalled := false
	prefixHandler := func(w http.ResponseWriter, r *http.Request) {
		prefixCalled = true
		w.Write([]byte("admin"))
	}
	
	group := simple.
		Handle("/users", handler1).
		Handle("/posts", handler2).
		HandlePrefix("/admin", prefixHandler).
		Group()
	
	tests := []struct {
		path           string
		expectedCalled *bool
	}{
		{"/api/users", &handler1Called},
		{"/api/posts", &handler2Called},
		{"/api/admin/settings", &prefixCalled},
	}
	
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			*tt.expectedCalled = false
			
			req := httptest.NewRequest("GET", tt.path, nil)
			rec := httptest.NewRecorder()
			
			group.ServeHTTP(rec, req)
			
			if !*tt.expectedCalled {
				t.Errorf("handler for %s was not called", tt.path)
			}
		})
	}
}

// Test helpers

type mockRESTHandler struct {
	responses map[string]string
}

func (m *mockRESTHandler) Index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(m.responses["index"]))
}

func (m *mockRESTHandler) Show(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(m.responses["show"]))
}

func (m *mockRESTHandler) Create(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(m.responses["create"]))
}