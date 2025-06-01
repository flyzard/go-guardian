package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	guardian "github.com/flyzard/go-guardian"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := guardian.New()
	r := gin.New()

	r.Use(g.Security().SecurityHeadersMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "test"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
}

func TestRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := guardian.New()
	r := gin.New()

	r.Use(g.Security().RateLimitMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "test"})
	})

	// Make multiple requests
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestCSRFProtection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := guardian.New().WithDatabase("test_csrf.db")
	err := g.Initialize()
	assert.NoError(t, err)
	defer g.Close()
	defer os.Remove("test_csrf.db")

	r := gin.New()

	// Set up session store (required for CSRF middleware)
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	r.Use(g.Security().CSRFMiddleware())
	r.POST("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "test"})
	})

	req, _ := http.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should fail without CSRF token
	assert.Equal(t, http.StatusForbidden, w.Code)
}
