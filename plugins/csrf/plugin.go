package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"

	"github.com/flyzard/go-guardian/database"
	"github.com/flyzard/go-guardian/htmx"
	"github.com/flyzard/go-guardian/plugin"
)

const (
	csrfCookieName = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	CSRFTokenKey   = "_csrf" // Form field name for CSRF token
)

// Config holds CSRF plugin configuration
type Config struct {
	Secure         bool     // Whether to use secure cookies (HTTPS only)
	ExemptPaths    []string // Paths to exempt from CSRF protection
	TokenLength    int      // Length of CSRF tokens (default: 32)
	CookieMaxAge   int      // Cookie max age in seconds (default: 86400)
	CookiePath     string   // Cookie path (default: "/")
	CookieDomain   string   // Cookie domain (default: "")
	SameSiteMode   http.SameSite // SameSite mode (default: Lax)
}

// DefaultConfig returns the default CSRF configuration
func DefaultConfig() Config {
	return Config{
		Secure:       true,
		TokenLength:  32,
		CookieMaxAge: 86400, // 24 hours
		CookiePath:   "/",
		SameSiteMode: http.SameSiteLaxMode,
	}
}

// CSRFPlugin implements CSRF protection as a plugin
type CSRFPlugin struct {
	config Config
}

// New creates a new CSRF plugin with default configuration
func New() *CSRFPlugin {
	return &CSRFPlugin{
		config: DefaultConfig(),
	}
}

// NewWithConfig creates a new CSRF plugin with custom configuration
func NewWithConfig(config Config) *CSRFPlugin {
	// Apply defaults for zero values
	if config.TokenLength == 0 {
		config.TokenLength = 32
	}
	if config.CookieMaxAge == 0 {
		config.CookieMaxAge = 86400
	}
	if config.CookiePath == "" {
		config.CookiePath = "/"
	}
	
	return &CSRFPlugin{
		config: config,
	}
}

// Name returns the plugin name
func (p *CSRFPlugin) Name() string {
	return "csrf"
}

// Description returns the plugin description
func (p *CSRFPlugin) Description() string {
	return "Provides CSRF protection using double-submit cookie pattern"
}

// Init initializes the plugin
func (p *CSRFPlugin) Init(ctx *plugin.Context) error {
	// Update config if provided in context
	if cfg, ok := ctx.Config["csrf"]; ok {
		if csrfConfig, ok := cfg.(Config); ok {
			p.config = csrfConfig
		}
	}
	
	log.Printf("CSRF plugin initialized with secure=%v", p.config.Secure)
	return nil
}

// Routes returns no routes - CSRF is middleware only
func (p *CSRFPlugin) Routes() []plugin.Route {
	return nil
}

// Middleware returns the CSRF middleware
func (p *CSRFPlugin) Middleware() []plugin.Middleware {
	return []plugin.Middleware{
		{
			Handler:     p.csrfMiddleware(),
			Priority:    10, // Run early in the chain
			Description: "CSRF protection middleware",
		},
	}
}

// Migrations returns no migrations - CSRF doesn't need database tables
func (p *CSRFPlugin) Migrations() []database.Migration {
	return nil
}

// RequiredTables returns no tables - CSRF doesn't use database
func (p *CSRFPlugin) RequiredTables() []string {
	return nil
}

// Cleanup performs any cleanup when plugin is disabled
func (p *CSRFPlugin) Cleanup() error {
	return nil
}

// DefaultConfig implements ConfigurablePlugin interface
func (p *CSRFPlugin) DefaultConfig() interface{} {
	return DefaultConfig()
}

// ValidateConfig implements ConfigurablePlugin interface
func (p *CSRFPlugin) ValidateConfig(config interface{}) error {
	_, ok := config.(Config)
	if !ok {
		return plugin.ErrInvalidConfig
	}
	return nil
}

// csrfMiddleware returns the actual middleware handler
func (p *CSRFPlugin) csrfMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path is exempt
			if p.isExemptPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			
			// Skip CSRF for safe methods
			if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
				// Ensure CSRF cookie exists
				if _, err := r.Cookie(csrfCookieName); err != nil {
					token := p.generateToken()
					p.setCSRFCookie(w, token)
					
					// For HTMX requests, also set the token in response header
					if htmx.IsRequest(r) {
						htmx.SetCSRFToken(w, token)
					}
					
					log.Printf("CSRF: Set new token for %s", r.URL.Path)
				}
				next.ServeHTTP(w, r)
				return
			}
			
			// Verify CSRF token for state-changing methods
			cookie, err := r.Cookie(csrfCookieName)
			if err != nil {
				p.handleCSRFError(w, r, "CSRF cookie missing")
				return
			}
			
			// Check header first (supports CSRF token in header for HTMX)
			token := r.Header.Get(csrfHeaderName)
			
			// If no header, check form value
			if token == "" {
				token = r.FormValue("csrf_token")
			}
			
			if cookie.Value == "" || cookie.Value != token {
				log.Printf("CSRF mismatch - Cookie: %s, Token: %s", cookie.Value, token)
				p.handleCSRFError(w, r, "CSRF token mismatch")
				return
			}
			
			// For HTMX requests, include the token in response
			if htmx.IsRequest(r) {
				htmx.SetCSRFToken(w, cookie.Value)
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// generateToken generates a new CSRF token
func (p *CSRFPlugin) generateToken() string {
	b := make([]byte, p.config.TokenLength)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// setCSRFCookie sets the CSRF cookie
func (p *CSRFPlugin) setCSRFCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     p.config.CookiePath,
		Domain:   p.config.CookieDomain,
		HttpOnly: false, // Must be readable by JS
		Secure:   p.config.Secure,
		SameSite: p.config.SameSiteMode,
		MaxAge:   p.config.CookieMaxAge,
	}
	http.SetCookie(w, cookie)
}

// handleCSRFError handles CSRF validation errors
func (p *CSRFPlugin) handleCSRFError(w http.ResponseWriter, r *http.Request, message string) {
	// For HTMX requests, return a more helpful error
	if htmx.IsRequest(r) {
		htmx.SetRetarget(w, "body")
		htmx.SetReswap(w, htmx.SwapInnerHTML)
		http.Error(w, `<div class="alert alert-error">Security error: Please refresh the page and try again.</div>`, http.StatusForbidden)
		return
	}
	
	http.Error(w, message, http.StatusForbidden)
}

// isExemptPath checks if a path is exempt from CSRF protection
func (p *CSRFPlugin) isExemptPath(path string) bool {
	for _, exempt := range p.config.ExemptPaths {
		if path == exempt {
			return true
		}
	}
	return false
}

// GetCSRFToken is a helper function to retrieve the CSRF token from a request
func GetCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}