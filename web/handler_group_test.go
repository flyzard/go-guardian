package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestHandlerGroup_Basic(t *testing.T) {
	group := NewHandlerGroup("/api")
	
	// Add handlers
	handler1Called := false
	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler1Called = true
		w.Write([]byte("handler1"))
	})
	
	handler2Called := false
	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler2Called = true
		w.Write([]byte("handler2"))
	})
	
	group.Add("users", handler1)
	group.Add("posts", handler2)
	
	// Test delegation
	t.Run("Delegate to handler1", func(t *testing.T) {
		handler1Called = false
		req := httptest.NewRequest("GET", "/api/users", nil)
		rec := httptest.NewRecorder()
		
		group.Delegate("users")(rec, req)
		
		if !handler1Called {
			t.Error("handler1 was not called")
		}
		if rec.Body.String() != "handler1" {
			t.Errorf("unexpected response: %s", rec.Body.String())
		}
	})
	
	t.Run("Delegate to handler2", func(t *testing.T) {
		handler2Called = false
		req := httptest.NewRequest("GET", "/api/posts", nil)
		rec := httptest.NewRecorder()
		
		group.Delegate("posts")(rec, req)
		
		if !handler2Called {
			t.Error("handler2 was not called")
		}
		if rec.Body.String() != "handler2" {
			t.Errorf("unexpected response: %s", rec.Body.String())
		}
	})
	
	t.Run("Delegate to non-existent handler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/invalid", nil)
		rec := httptest.NewRecorder()
		
		group.Delegate("invalid")(rec, req)
		
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rec.Code)
		}
	})
}

func TestHandlerGroup_Routing(t *testing.T) {
	group := NewHandlerGroup("/api")
	
	// Add handlers with routes
	userListCalled := false
	userList := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userListCalled = true
		w.Write([]byte("user list"))
	})
	
	userDetailCalled := false
	userDetail := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userDetailCalled = true
		w.Write([]byte("user detail"))
	})
	
	group.Add("user.list", userList).Route("/users", "user.list", "GET")
	group.Add("user.detail", userDetail).Route("/users/{id}", "user.detail", "GET")
	
	tests := []struct {
		name           string
		path           string
		method         string
		expectedBody   string
		expectedCode   int
		expectedCalled *bool
	}{
		{
			name:           "GET /api/users",
			path:           "/api/users",
			method:         "GET",
			expectedBody:   "user list",
			expectedCode:   200,
			expectedCalled: &userListCalled,
		},
		{
			name:           "GET /api/users/123",
			path:           "/api/users/123",
			method:         "GET",
			expectedBody:   "user detail",
			expectedCode:   200,
			expectedCalled: &userDetailCalled,
		},
		{
			name:         "POST /api/users (method not allowed)",
			path:         "/api/users",
			method:       "POST",
			expectedBody: "Method not allowed",
			expectedCode: 405,
		},
		{
			name:         "GET /api/invalid",
			path:         "/api/invalid",
			method:       "GET",
			expectedBody: "404 page not found",
			expectedCode: 404,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectedCalled != nil {
				*tt.expectedCalled = false
			}
			
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			
			group.ServeHTTP(rec, req)
			
			if rec.Code != tt.expectedCode {
				t.Errorf("expected status %d, got %d", tt.expectedCode, rec.Code)
			}
			
			body := rec.Body.String()
			if !strings.Contains(body, strings.TrimSpace(tt.expectedBody)) {
				t.Errorf("expected body to contain %q, got %q", tt.expectedBody, body)
			}
			
			if tt.expectedCalled != nil && !*tt.expectedCalled {
				t.Error("expected handler was not called")
			}
		})
	}
}

func TestHandlerGroup_SharedData(t *testing.T) {
	group := NewHandlerGroup("/api")
	
	// Test basic operations
	t.Run("Store and retrieve", func(t *testing.T) {
		group.ShareData("key1", "value1")
		group.ShareData("key2", 42)
		
		val1, ok := group.GetSharedData("key1")
		if !ok || val1 != "value1" {
			t.Errorf("expected value1, got %v", val1)
		}
		
		val2, ok := group.GetSharedData("key2")
		if !ok || val2 != 42 {
			t.Errorf("expected 42, got %v", val2)
		}
	})
	
	t.Run("Type-specific getters", func(t *testing.T) {
		group.ShareData("string", "hello")
		group.ShareData("int", 123)
		
		str, ok := group.GetSharedString("string")
		if !ok || str != "hello" {
			t.Errorf("expected hello, got %v", str)
		}
		
		i, ok := group.GetSharedInt("int")
		if !ok || i != 123 {
			t.Errorf("expected 123, got %v", i)
		}
		
		// Wrong type
		_, ok = group.GetSharedString("int")
		if ok {
			t.Error("expected false for wrong type")
		}
	})
	
	t.Run("Delete and clear", func(t *testing.T) {
		group.ShareData("temp1", "value1")
		group.ShareData("temp2", "value2")
		
		group.DeleteSharedData("temp1")
		_, ok := group.GetSharedData("temp1")
		if ok {
			t.Error("expected temp1 to be deleted")
		}
		
		_, ok = group.GetSharedData("temp2")
		if !ok {
			t.Error("expected temp2 to still exist")
		}
		
		group.ClearSharedData()
		_, ok = group.GetSharedData("temp2")
		if ok {
			t.Error("expected all data to be cleared")
		}
	})
}

func TestHandlerGroup_Middleware(t *testing.T) {
	group := NewHandlerGroup("/api")
	
	// Middleware that adds headers
	middleware1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Middleware-1", "true")
			next.ServeHTTP(w, r)
		})
	}
	
	middleware2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Middleware-2", "true")
			next.ServeHTTP(w, r)
		})
	}
	
	group.Use(middleware1, middleware2)
	
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	})
	
	group.Add("test", handler).Route("/test", "test")
	
	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	
	group.ServeHTTP(rec, req)
	
	if rec.Header().Get("X-Middleware-1") != "true" {
		t.Error("middleware1 was not applied")
	}
	if rec.Header().Get("X-Middleware-2") != "true" {
		t.Error("middleware2 was not applied")
	}
	if rec.Body.String() != "response" {
		t.Errorf("unexpected response: %s", rec.Body.String())
	}
}

func TestHandlerGroup_Concurrency(t *testing.T) {
	group := NewHandlerGroup("/api")
	
	// Test concurrent operations
	var wg sync.WaitGroup
	errors := make(chan error, 100)
	
	// Concurrent adds
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			})
			group.Add(string(rune('a'+i)), handler)
		}(i)
	}
	
	// Concurrent data operations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := string(rune('A' + i))
			group.ShareData(key, i)
			
			val, ok := group.GetSharedData(key)
			if !ok || val != i {
				errors <- &testError{msg: "data mismatch"}
			}
		}(i)
	}
	
	// Concurrent reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = group.Handlers()
			_ = group.Routes()
		}()
	}
	
	wg.Wait()
	close(errors)
	
	for err := range errors {
		t.Error(err)
	}
}

func TestHandlerGroup_Mount(t *testing.T) {
	group := NewHandlerGroup("")
	
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mounted"))
	})
	
	group.Add("test", handler).Route("/test", "test")
	
	// Mock chi router
	router := &mockChiRouter{
		handlers: make(map[string]http.Handler),
	}
	
	group.Mount("/api/v1", router)
	
	if len(router.handlers) != 1 {
		t.Errorf("expected 1 handler, got %d", len(router.handlers))
	}
	
	if _, ok := router.handlers["/api/v1/*"]; !ok {
		t.Error("handler was not mounted at expected path")
	}
}

// Test helpers

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

type mockChiRouter struct {
	handlers map[string]http.Handler
}

func (m *mockChiRouter) Handle(pattern string, h http.Handler) {
	m.handlers[pattern] = h
}