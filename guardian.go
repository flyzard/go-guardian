// Package guardian provides comprehensive security features for Gin-Gonic applications
package guardian

import (
	"log/slog"

	"github.com/flyzard/go-guardian/audit"
	"github.com/flyzard/go-guardian/auth"
	"github.com/flyzard/go-guardian/captcha"
	"github.com/flyzard/go-guardian/encryption"
	"github.com/flyzard/go-guardian/oauth"
	"github.com/flyzard/go-guardian/protection"
	"github.com/flyzard/go-guardian/rbac"
	"github.com/flyzard/go-guardian/security"
	"github.com/flyzard/go-guardian/sessions"
	"github.com/flyzard/go-guardian/tokens"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Guardian is the main security package instance
type Guardian struct {
	db         *gorm.DB
	config     *Config
	auth       *auth.Manager
	security   *security.Manager
	sessions   *sessions.Manager
	rbac       *rbac.Manager
	tokens     *tokens.Manager
	protection *protection.Manager
	captcha    *captcha.Manager
	audit      *audit.Manager
	oauth      *oauth.Manager
	encryption *encryption.Manager
	logger     *slog.Logger
}

// Config holds the main configuration for Guardian
type Config struct {
	DatabasePath   string
	JWTSecret      []byte
	SessionSecret  []byte
	EncryptionKey  []byte
	Debug          bool
	LogLevel       slog.Level
	EmailConfig    *auth.EmailConfig
	OAuthProviders map[string]*oauth.ProviderConfig
}

// New creates a new Guardian instance with default configuration
func New() *Guardian {
	config := &Config{
		DatabasePath:  "guardian.db",
		Debug:         false,
		LogLevel:      slog.LevelInfo,
		JWTSecret:     []byte("default-jwt-secret-change-in-production"),
		SessionSecret: []byte("default-session-secret-change-in-production"),
		EncryptionKey: []byte("default-encryption-key-32-bytes!!"),
	}

	return &Guardian{
		config: config,
		logger: slog.Default(),
	}
}

// WithDatabase sets the database path
func (g *Guardian) WithDatabase(path string) *Guardian {
	g.config.DatabasePath = path
	return g
}

// WithJWTSecret sets the JWT secret
func (g *Guardian) WithJWTSecret(secret string) *Guardian {
	g.config.JWTSecret = []byte(secret)
	return g
}

// WithSessionSecret sets the session secret
func (g *Guardian) WithSessionSecret(secret string) *Guardian {
	g.config.SessionSecret = []byte(secret)
	return g
}

// WithEncryptionKey sets the encryption key
func (g *Guardian) WithEncryptionKey(key string) *Guardian {
	if len(key) != 32 {
		panic("encryption key must be exactly 32 bytes")
	}
	g.config.EncryptionKey = []byte(key)
	return g
}

// WithEmailConfig sets the email configuration
func (g *Guardian) WithEmailConfig(config *auth.EmailConfig) *Guardian {
	g.config.EmailConfig = config
	return g
}

// WithOAuthProvider adds an OAuth provider configuration
func (g *Guardian) WithOAuthProvider(name string, config *oauth.ProviderConfig) *Guardian {
	if g.config.OAuthProviders == nil {
		g.config.OAuthProviders = make(map[string]*oauth.ProviderConfig)
	}
	g.config.OAuthProviders[name] = config
	return g
}

// WithDebug enables debug mode
func (g *Guardian) WithDebug(debug bool) *Guardian {
	g.config.Debug = debug
	if debug {
		g.config.LogLevel = slog.LevelDebug
	}
	return g
}

// Initialize initializes the Guardian instance
func (g *Guardian) Initialize() error {
	// Initialize database
	if err := g.initDatabase(); err != nil {
		return err
	}

	// Initialize components
	g.initComponents()

	return nil
}

// initDatabase initializes the database connection
func (g *Guardian) initDatabase() error {
	db, err := gorm.Open(sqlite.Open(g.config.DatabasePath), &gorm.Config{})
	if err != nil {
		return err
	}

	g.db = db
	return g.runMigrations()
}

// runMigrations runs database migrations
func (g *Guardian) runMigrations() error {
	// Run migrations for all models
	return g.db.AutoMigrate(
		&auth.User{},
		&auth.PasswordReset{},
		&auth.EmailVerification{},
		&auth.MFASecret{},
		&auth.BackupCode{},
		&sessions.Session{},
		&rbac.Role{},
		&rbac.Permission{},
		&rbac.UserRole{},
		&rbac.RolePermission{},
		&tokens.APIKey{},
		&tokens.RefreshToken{},
		&audit.AuditLog{},
		&oauth.OAuthState{},
		&oauth.OAuthToken{},
	)
}

// initComponents initializes all components
func (g *Guardian) initComponents() {
	g.auth = auth.NewManager(g.db, g.config.JWTSecret, g.config.EmailConfig)
	g.security = security.NewManager()
	g.sessions = sessions.NewManager(g.db, g.config.SessionSecret)
	g.rbac = rbac.NewManager(g.db)
	g.tokens = tokens.NewManager(g.db, g.config.JWTSecret)
	g.protection = protection.NewManager(g.db)
	g.captcha = captcha.NewManager()
	g.audit = audit.NewManager(g.db)
	g.oauth = oauth.NewManager(g.db, g.config.OAuthProviders)
	g.encryption = encryption.NewManager(g.config.EncryptionKey)
}

// Auth returns the authentication manager
func (g *Guardian) Auth() *auth.Manager {
	if g.auth == nil {
		g.Initialize()
	}
	return g.auth
}

// Security returns the security manager
func (g *Guardian) Security() *security.Manager {
	if g.security == nil {
		g.Initialize()
	}
	return g.security
}

// Sessions returns the sessions manager
func (g *Guardian) Sessions() *sessions.Manager {
	if g.sessions == nil {
		g.Initialize()
	}
	return g.sessions
}

// RBAC returns the RBAC manager
func (g *Guardian) RBAC() *rbac.Manager {
	if g.rbac == nil {
		g.Initialize()
	}
	return g.rbac
}

// Tokens returns the tokens manager
func (g *Guardian) Tokens() *tokens.Manager {
	if g.tokens == nil {
		g.Initialize()
	}
	return g.tokens
}

// Protection returns the protection manager
func (g *Guardian) Protection() *protection.Manager {
	if g.protection == nil {
		g.Initialize()
	}
	return g.protection
}

// Captcha returns the captcha manager
func (g *Guardian) Captcha() *captcha.Manager {
	if g.captcha == nil {
		g.Initialize()
	}
	return g.captcha
}

// Audit returns the audit manager
func (g *Guardian) Audit() *audit.Manager {
	if g.audit == nil {
		g.Initialize()
	}
	return g.audit
}

// OAuth returns the OAuth manager
func (g *Guardian) OAuth() *oauth.Manager {
	if g.oauth == nil {
		g.Initialize()
	}
	return g.oauth
}

// Encryption returns the encryption manager
func (g *Guardian) Encryption() *encryption.Manager {
	if g.encryption == nil {
		g.Initialize()
	}
	return g.encryption
}

// RequireAuth is a middleware that requires authentication
func (g *Guardian) RequireAuth() gin.HandlerFunc {
	return g.Auth().RequireAuth()
}

// RequireRole is a middleware that requires a specific role
func (g *Guardian) RequireRole(role string) gin.HandlerFunc {
	return g.RBAC().RequireRole(role)
}

// RequirePermission is a middleware that requires a specific permission
func (g *Guardian) RequirePermission(permission string) gin.HandlerFunc {
	return g.RBAC().RequirePermission(permission)
}

// DB returns the database instance
func (g *Guardian) DB() *gorm.DB {
	return g.db
}

// Config returns the configuration
func (g *Guardian) Config() *Config {
	return g.config
}

// Close closes the Guardian instance and its database connection
func (g *Guardian) Close() error {
	if g.db != nil {
		sqlDB, err := g.db.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

// GetCurrentUser returns the current authenticated user from context
// This is a convenience function that wraps auth.GetCurrentUser
func GetCurrentUser(c *gin.Context) (*auth.User, bool) {
	return auth.GetCurrentUser(c)
}

// GetCurrentUserID returns the current authenticated user ID from context
// This is a convenience function that wraps auth.GetCurrentUserID
func GetCurrentUserID(c *gin.Context) (uuid.UUID, bool) {
	return auth.GetCurrentUserID(c)
}
