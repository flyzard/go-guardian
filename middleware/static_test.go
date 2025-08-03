package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatic(t *testing.T) {
	// Create temporary directory structure for tests
	tmpDir := t.TempDir()
	
	// Create test files
	createTestFile(t, tmpDir, "index.html", "<html><body>Index</body></html>")
	createTestFile(t, tmpDir, "test.css", "body { color: red; }")
	createTestFile(t, tmpDir, "test.js", "console.log('test');")
	createTestFile(t, tmpDir, "test.txt", "Hello, World!")
	createTestFile(t, tmpDir, "404.html", "<html><body>Not Found</body></html>")
	createTestFile(t, tmpDir, "subdir/test.html", "<html><body>Subdir</body></html>")
	createTestFile(t, tmpDir, ".git/config", "secret")

	tests := []struct {
		name           string
		config         StaticConfig
		path           string
		expectedStatus int
		expectedBody   string
		checkHeaders   map[string]string
		acceptEncoding string
	}{
		{
			name: "serve index file",
			config: StaticConfig{
				Root:  tmpDir,
				Index: "index.html",
			},
			path:           "/static/",
			expectedStatus: http.StatusOK,
			expectedBody:   "<html><body>Index</body></html>",
			checkHeaders: map[string]string{
				"Content-Type":              "text/html",
				"X-Content-Type-Options":    "nosniff",
			},
		},
		{
			name: "serve CSS file",
			config: StaticConfig{
				Root: tmpDir,
			},
			path:           "/static/test.css",
			expectedStatus: http.StatusOK,
			expectedBody:   "body { color: red; }",
			checkHeaders: map[string]string{
				"Content-Type": "text/css",
			},
		},
		{
			name: "serve JS file",
			config: StaticConfig{
				Root: tmpDir,
			},
			path:           "/static/test.js",
			expectedStatus: http.StatusOK,
			expectedBody:   "console.log('test');",
			checkHeaders: map[string]string{
				"Content-Type": "application/javascript",
			},
		},
		{
			name: "serve with cache headers",
			config: StaticConfig{
				Root:   tmpDir,
				MaxAge: 3600,
			},
			path:           "/static/test.txt",
			expectedStatus: http.StatusOK,
			expectedBody:   "Hello, World!",
			checkHeaders: map[string]string{
				"Cache-Control": "public, max-age=3600",
			},
		},
		{
			name: "serve compressed content",
			config: StaticConfig{
				Root:          tmpDir,
				Compress:      true,
				CompressTypes: []string{"text/css"},
			},
			path:           "/static/test.css",
			expectedStatus: http.StatusOK,
			expectedBody:   "body { color: red; }",
			acceptEncoding: "gzip",
			checkHeaders: map[string]string{
				"Content-Encoding": "gzip",
			},
		},
		{
			name: "file not found with custom 404",
			config: StaticConfig{
				Root:         tmpDir,
				NotFoundFile: "404.html",
			},
			path:           "/static/nonexistent.html",
			expectedStatus: http.StatusOK,
			expectedBody:   "<html><body>Not Found</body></html>",
		},
		{
			name: "prevent directory traversal",
			config: StaticConfig{
				Root: tmpDir,
			},
			path:           "/static/../../../etc/passwd",
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "ignore patterns",
			config: StaticConfig{
				Root:           tmpDir,
				IgnorePatterns: []string{".git/*"},
			},
			path:           "/static/.git/config",
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "serve subdirectory file",
			config: StaticConfig{
				Root: tmpDir,
			},
			path:           "/static/subdir/test.html",
			expectedStatus: http.StatusOK,
			expectedBody:   "<html><body>Subdir</body></html>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler
			handler := Static("/static", tt.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("next handler should not be called")
			}))

			// Create request
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}

			// Record response
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// Check status code
			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			// Check body
			body := rec.Body.String()
			if rec.Header().Get("Content-Encoding") == "gzip" {
				// Decompress gzip content
				reader, err := gzip.NewReader(strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				decompressed, err := io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				body = string(decompressed)
			}

			if tt.expectedStatus == http.StatusOK && body != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, body)
			}

			// Check headers
			for header, expected := range tt.checkHeaders {
				if got := rec.Header().Get(header); got != expected {
					t.Errorf("expected header %s=%q, got %q", header, expected, got)
				}
			}
		})
	}
}

func TestStaticETag(t *testing.T) {
	tmpDir := t.TempDir()
	createTestFile(t, tmpDir, "test.txt", "Hello, World!")

	handler := Static("/static", StaticConfig{Root: tmpDir})(nil)

	// First request
	req1 := httptest.NewRequest("GET", "/static/test.txt", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec1.Code)
	}

	etag := rec1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag header")
	}

	// Second request with If-None-Match
	req2 := httptest.NewRequest("GET", "/static/test.txt", nil)
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNotModified {
		t.Errorf("expected status 304, got %d", rec2.Code)
	}

	if rec2.Body.Len() != 0 {
		t.Error("expected empty body for 304 response")
	}
}

func TestStaticLastModified(t *testing.T) {
	tmpDir := t.TempDir()
	createTestFile(t, tmpDir, "test.txt", "Hello, World!")

	handler := Static("/static", StaticConfig{Root: tmpDir})(nil)

	// First request
	req1 := httptest.NewRequest("GET", "/static/test.txt", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	lastMod := rec1.Header().Get("Last-Modified")
	if lastMod == "" {
		t.Fatal("expected Last-Modified header")
	}

	// Second request with If-Modified-Since in the future
	futureTime := time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)
	req2 := httptest.NewRequest("GET", "/static/test.txt", nil)
	req2.Header.Set("If-Modified-Since", futureTime)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNotModified {
		t.Errorf("expected status 304, got %d", rec2.Code)
	}
}

func TestStaticFallthrough(t *testing.T) {
	tmpDir := t.TempDir()
	createTestFile(t, tmpDir, "test.txt", "Hello")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := Static("/static", StaticConfig{Root: tmpDir})(next)

	// Request to non-static path
	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called")
	}
}

func TestStaticRangeRequest(t *testing.T) {
	tmpDir := t.TempDir()
	content := strings.Repeat("Hello, World! ", 100)
	createTestFile(t, tmpDir, "large.txt", content)

	handler := Static("/static", StaticConfig{Root: tmpDir})(nil)

	// Range request
	req := httptest.NewRequest("GET", "/static/large.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Errorf("expected status 206, got %d", rec.Code)
	}

	if got := rec.Body.String(); got != "Hello, Wor" {
		t.Errorf("expected partial content, got %q", got)
	}
}

// Helper function to create test files
func createTestFile(t *testing.T, dir, name, content string) {
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}