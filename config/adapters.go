package config

import (
	"log"
	"os"
	"sync"
)

var (
	deprecationWarnings     = true
	deprecationWarningsOnce sync.Once
	deprecationWarningsMu   sync.Mutex
)

// DisableDeprecationWarnings disables deprecation warnings globally
func DisableDeprecationWarnings() {
	deprecationWarningsMu.Lock()
	defer deprecationWarningsMu.Unlock()
	deprecationWarnings = false
}

// EnableDeprecationWarnings enables deprecation warnings globally
func EnableDeprecationWarnings() {
	deprecationWarningsMu.Lock()
	defer deprecationWarningsMu.Unlock()
	deprecationWarnings = true
}

// LogDeprecation logs a deprecation warning once per message
func LogDeprecation(message string) {
	deprecationWarningsMu.Lock()
	defer deprecationWarningsMu.Unlock()
	
	if !deprecationWarnings {
		return
	}
	
	// Check if we should suppress deprecations via environment variable
	if os.Getenv("GUARDIAN_SUPPRESS_DEPRECATIONS") == "true" {
		return
	}
	
	deprecationWarningsOnce.Do(func() {
		log.Printf("DEPRECATION WARNING: %s\nSet GUARDIAN_SUPPRESS_DEPRECATIONS=true to disable these warnings.", message)
	})
}

// GuardianConfig provides backward compatibility for guardian.Config
type GuardianConfig struct {
	SessionKey              []byte
	SessionCookieName       string
	SessionDomain           string
	SessionSecure           bool
	SessionHTTPOnly         bool
	SessionSameSite         string
	SessionPath             string
	DatabaseSession         bool
	SessionBackend          string
	Development             bool
	SecretKey               []byte
	RememberMeDuration      int
	PasswordResetExpiration int
	LoginURL                string
	AuthenticatedURL        string
	AfterLogoutURL          string
	AfterVerifyURL          string
	AfterResetURL           string
	CacheExpiration         int
	TableNames              TableNames
	ColumnNames             FlatColumnNames
	Features                Features
	TemplatePath            string
	TemplateFS              interface{}
	StaticPath              string
	RateLimitRequests       int
	RateLimitWindow         int
	PreloadPermissions      bool
	CacheDuration           int
	DebugMode               bool
}

// AuthConfig provides backward compatibility for auth.Config
type AuthConfig struct {
	DB                           interface{}
	LDAP                         interface{}
	Logger                       interface{}
	Tables                       TableNames
	Columns                      FlatColumnNames
	Features                     Features
	BcryptCost                   int
	RememberTokenLength          int
	TokenExpiration              int
	SessionTimeout               int
	MaxLoginAttempts             int
	LockoutDuration              int
	EmailVerificationTokenLength int
	PasswordResetTokenLength     int
	AllowUnverifiedLogin         bool
	EnableRememberMe             bool
	RequireEmailVerification     bool
	SessionBackend               string
	CacheBackend                 string
	CacheDuration                int
	DefaultRole                  string
	PreloadPermissions           bool
	EnablePasswordlessAuth       bool
}

// DatabaseConfig provides backward compatibility for database.Config
type DatabaseConfig struct {
	DSN          string
	Driver       string
	MaxOpenConns int
	MaxIdleConns int
	MaxLifetime  int
	Tables       TableNames
	Columns      FlatColumnNames
	Logger       interface{}
	DebugMode    bool
}

// MiddlewareConfig provides a common configuration interface for middleware
type MiddlewareConfig interface {
	// Validate validates the configuration
	Validate() error
	// Defaults returns the default configuration
	Defaults() interface{}
}