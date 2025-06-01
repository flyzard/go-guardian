// Package security provides security middleware for web applications
package security

import (
	"time"

	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	csrf "github.com/utrack/gin-csrf"
)

// Manager handles security middleware
type Manager struct {
	config *Config
}

// Config holds security configuration
type Config struct {
	CSRFConfig         *CSRFConfig
	SecurityHeaders    *SecurityHeadersConfig
	RateLimitConfig    *RateLimitConfig
	CORSConfig         *CORSConfig
	ContentTypeOptions bool
	FrameOptions       string
	XSSProtection      bool
}

// CSRFConfig holds CSRF protection configuration
type CSRFConfig struct {
	Secret     string
	TokenName  string
	HeaderName string
}

// SecurityHeadersConfig holds security headers configuration
type SecurityHeadersConfig struct {
	ContentTypeNosniff      bool
	BrowserXSSFilter        bool
	ContentSecurityPolicy   string
	FrameDeny               bool
	CustomFrameOptionsValue string
	HTTPSRedirect           bool
	STSSeconds              int64
	STSIncludeSubdomains    bool
	STSPreload              bool
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Rate   int
	Period time.Duration
	Store  limiter.Store
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           time.Duration
}

// NewManager creates a new security manager
func NewManager() *Manager {
	config := &Config{
		CSRFConfig: &CSRFConfig{
			Secret:     "default-csrf-secret-change-in-production",
			TokenName:  "_token",
			HeaderName: "X-CSRF-Token",
		},
		SecurityHeaders: &SecurityHeadersConfig{
			ContentTypeNosniff:    true,
			BrowserXSSFilter:      true,
			ContentSecurityPolicy: "default-src 'self'",
			FrameDeny:             true,
			HTTPSRedirect:         false,
			STSSeconds:            31536000,
			STSIncludeSubdomains:  true,
			STSPreload:            true,
		},
		RateLimitConfig: &RateLimitConfig{
			Rate:   100,
			Period: time.Minute,
			Store:  memory.NewStore(),
		},
		ContentTypeOptions: true,
		FrameOptions:       "DENY",
		XSSProtection:      true,
	}

	return &Manager{
		config: config,
	}
}

// EnableCSRF enables CSRF protection
func (m *Manager) EnableCSRF() *Manager {
	// CSRF is enabled by default
	return m
}

// WithCSRFSecret sets the CSRF secret
func (m *Manager) WithCSRFSecret(secret string) *Manager {
	m.config.CSRFConfig.Secret = secret
	return m
}

// EnableSecurityHeaders enables security headers
func (m *Manager) EnableSecurityHeaders() *Manager {
	// Security headers are enabled by default
	return m
}

// WithContentSecurityPolicy sets the CSP header
func (m *Manager) WithContentSecurityPolicy(policy string) *Manager {
	m.config.SecurityHeaders.ContentSecurityPolicy = policy
	return m
}

// EnableRateLimit enables rate limiting
func (m *Manager) EnableRateLimit(rate int, period time.Duration) *Manager {
	m.config.RateLimitConfig.Rate = rate
	m.config.RateLimitConfig.Period = period
	return m
}

// CSRFMiddleware returns CSRF protection middleware
func (m *Manager) CSRFMiddleware() gin.HandlerFunc {
	return csrf.Middleware(csrf.Options{
		Secret: m.config.CSRFConfig.Secret,
		ErrorFunc: func(c *gin.Context) {
			c.JSON(403, gin.H{"error": "CSRF token mismatch"})
			c.Abort()
		},
	})
}

// SecurityHeadersMiddleware returns security headers middleware
func (m *Manager) SecurityHeadersMiddleware() gin.HandlerFunc {
	return secure.New(secure.Config{
		ContentTypeNosniff:      m.config.SecurityHeaders.ContentTypeNosniff,
		BrowserXssFilter:        m.config.SecurityHeaders.BrowserXSSFilter,
		ContentSecurityPolicy:   m.config.SecurityHeaders.ContentSecurityPolicy,
		FrameDeny:               m.config.SecurityHeaders.FrameDeny,
		CustomFrameOptionsValue: m.config.SecurityHeaders.CustomFrameOptionsValue,
		SSLRedirect:             m.config.SecurityHeaders.HTTPSRedirect,
		STSSeconds:              m.config.SecurityHeaders.STSSeconds,
		STSIncludeSubdomains:    m.config.SecurityHeaders.STSIncludeSubdomains,
		STSPreload:              m.config.SecurityHeaders.STSPreload,
	})
}

// RateLimitMiddleware returns rate limiting middleware
func (m *Manager) RateLimitMiddleware() gin.HandlerFunc {
	rate := limiter.Rate{
		Period: m.config.RateLimitConfig.Period,
		Limit:  int64(m.config.RateLimitConfig.Rate),
	}

	lmt := limiter.New(m.config.RateLimitConfig.Store, rate)

	return func(c *gin.Context) {
		context, err := lmt.Get(c, c.ClientIP())
		if err != nil {
			c.JSON(500, gin.H{"error": "Internal server error"})
			c.Abort()
			return
		}

		if context.Reached {
			c.JSON(429, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// XSSProtectionMiddleware returns XSS protection middleware
func (m *Manager) XSSProtectionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Next()
	}
}

// ContentTypeOptionsMiddleware returns content type options middleware
func (m *Manager) ContentTypeOptionsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Next()
	}
}

// FrameOptionsMiddleware returns frame options middleware
func (m *Manager) FrameOptionsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", m.config.FrameOptions)
		c.Next()
	}
}

// CORSMiddleware returns CORS middleware
func (m *Manager) CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Set CORS headers
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// Bundle returns a middleware bundle with all security features
func (m *Manager) Bundle() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		m.SecurityHeadersMiddleware(),
		m.XSSProtectionMiddleware(),
		m.ContentTypeOptionsMiddleware(),
		m.FrameOptionsMiddleware(),
		m.CORSMiddleware(),
		m.RateLimitMiddleware(),
		m.CSRFMiddleware(),
	}
}

// Apply applies all security middleware to a router
func (m *Manager) Apply(r *gin.Engine) {
	middlewares := m.Bundle()
	for _, middleware := range middlewares {
		r.Use(middleware)
	}
}
