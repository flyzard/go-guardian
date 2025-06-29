package guardian

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/flyzard/go-guardian/auth"
	"github.com/flyzard/go-guardian/database"
	"github.com/flyzard/go-guardian/router"
	"github.com/gorilla/sessions"
)

// SessionBackend defines the type of session storage
type SessionBackend string

const (
	SessionBackendCookie   SessionBackend = "cookie"   // Default: encrypted cookies
	SessionBackendMemory   SessionBackend = "memory"   // In-memory store
	SessionBackendDatabase SessionBackend = "database" // Database-backed sessions
)

// TableNames allows customizing table names
type TableNames struct {
	Users           string
	Tokens          string // Only required if using email verification or password reset
	Sessions        string // Only required if using database sessions
	Roles           string
	Permissions     string
	RolePermissions string
	RememberTokens  string
}

// DefaultTableNames returns the default table names
func DefaultTableNames() TableNames {
	return TableNames{
		Users:           "users",
		Tokens:          "tokens",
		Sessions:        "sessions",
		Roles:           "roles",
		Permissions:     "permissions",
		RolePermissions: "role_permissions",
		RememberTokens:  "remember_tokens",
	}
}

// ColumnNames allows customizing column names
type ColumnNames struct {
	// Users table columns
	UserID       string
	UserEmail    string
	UserPassword string
	UserVerified string
	UserCreated  string
	UserRoleID   string

	// Tokens table columns
	TokenID      string
	TokenValue   string
	TokenUserID  string
	TokenPurpose string
	TokenExpires string
	TokenCreated string
}

// DefaultColumnNames returns the default column names
func DefaultColumnNames() ColumnNames {
	return ColumnNames{
		UserID:       "id",
		UserEmail:    "email",
		UserPassword: "password_hash",
		UserVerified: "verified",
		UserCreated:  "created_at",
		UserRoleID:   "role_id",

		TokenID:      "id",
		TokenValue:   "token",
		TokenUserID:  "user_id",
		TokenPurpose: "purpose",
		TokenExpires: "expires_at",
		TokenCreated: "created_at",
	}
}

// Features allows disabling optional features
type Features struct {
	EmailVerification bool // Requires tokens table
	PasswordReset     bool // Requires tokens table
	RememberMe        bool // Requires remember_tokens table
	RBAC              bool // Requires roles, permissions tables
	ExternalAuth      bool // Enable external authentication (SSO, LDAP, etc.)
}

// DefaultFeatures returns all features enabled
// This maintains backward compatibility - existing apps get all features
func DefaultFeatures() Features {
	return Features{
		EmailVerification: true,
		PasswordReset:     true,
		RememberMe:        true,
		RBAC:              true,
		ExternalAuth:      false,
	}
}

type Config struct {
	SessionKey  []byte
	Environment string // "development" or "production"

	// Database configuration
	DatabaseType    string // "sqlite" or "mysql"
	DatabasePath    string // For SQLite
	DatabaseDSN     string // For MySQL: "user:pass@tcp(localhost:3306)/dbname?parseTime=true"
	MaxOpenConns    int    // Max open connections
	MaxIdleConns    int    // Max idle connections
	ConnMaxLifetime time.Duration

	// Migration configuration
	AutoMigrate    bool   // Whether to run migrations automatically (default: true)
	ValidateSchema bool   // Whether to validate required tables exist (default: true)
	MigrationTable string // Custom migration table name (default: "migrations")

	// Table name mapping
	TableNames TableNames // Custom table names (default: standard names)

	// Column name mapping
	ColumnNames ColumnNames // Custom column names (default: standard names)

	// Session configuration
	SessionBackend SessionBackend    // Type of session storage (default: "cookie")
	SessionOptions *sessions.Options // Session cookie options

	// Feature flags
	Features Features // Which features to enable (default: all)
}

type Guardian struct {
	router   *router.Router
	db       *database.DB
	auth     *auth.Service
	sessions sessions.Store
	config   Config
}

// InMemoryStore implements a simple in-memory session store
type InMemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*sessions.Session
	options  *sessions.Options
}

func NewInMemoryStore(keyPairs ...[]byte) *InMemoryStore {
	return &InMemoryStore{
		sessions: make(map[string]*sessions.Session),
		options: &sessions.Options{
			Path:     "/",
			MaxAge:   1800, // 30 minutes
			HttpOnly: true,
		},
	}
}

func (s *InMemoryStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

func (s *InMemoryStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	opts := *s.options
	session.Options = &opts
	session.IsNew = true

	// Try to get existing session from cookie
	if cookie, err := r.Cookie(name); err == nil {
		s.mu.RLock()
		if existing, exists := s.sessions[cookie.Value]; exists {
			s.mu.RUnlock()
			// Return the existing session
			existing.IsNew = false
			return existing, nil
		}
		s.mu.RUnlock()
	}

	return session, nil
}

func (s *InMemoryStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Delete session
	if session.Options.MaxAge <= 0 {
		s.mu.Lock()
		delete(s.sessions, session.ID)
		s.mu.Unlock()

		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	// Generate session ID if new
	if session.ID == "" {
		session.ID = generateSessionID()
	}

	// Store in memory
	s.mu.Lock()
	s.sessions[session.ID] = session
	s.mu.Unlock()

	// Set cookie with session ID
	http.SetCookie(w, sessions.NewCookie(session.Name(), session.ID, session.Options))

	return nil
}

func (s *InMemoryStore) cleanup() {
	// Simple cleanup - in production, use a proper scheduler
	// This is a placeholder for a more sophisticated implementation
	// that would periodically clean up expired sessions
}

func (s *InMemoryStore) Options(options *sessions.Options) {
	s.options = options
}

func generateSessionID() string {
	// Use the same token generation as auth
	return auth.GenerateToken()
}

func New(cfg Config) *Guardian {
	// Validate configuration
	if len(cfg.SessionKey) < 32 {
		panic("session key must be at least 32 bytes")
	}

	if cfg.Environment == "" {
		cfg.Environment = "development"
	}

	// Set defaults for database
	if cfg.DatabaseType == "" {
		cfg.DatabaseType = "sqlite"
	}

	if cfg.DatabaseType == "sqlite" && cfg.DatabasePath == "" {
		cfg.DatabasePath = "guardian.db"
	}

	// Set defaults for sessions
	if cfg.SessionBackend == "" {
		cfg.SessionBackend = SessionBackendCookie
	}

	// Set defaults for migrations
	if cfg.MigrationTable == "" {
		cfg.MigrationTable = "migrations"
	}

	// Set default features if not provided
	if cfg.Features == (Features{}) {
		cfg.Features = DefaultFeatures()
	}

	// Set default table names if not provided
	if cfg.TableNames == (TableNames{}) {
		cfg.TableNames = DefaultTableNames()
	} else {
		// Fill in any missing table names with defaults
		defaults := DefaultTableNames()
		if cfg.TableNames.Users == "" {
			cfg.TableNames.Users = defaults.Users
		}
		if cfg.TableNames.Tokens == "" {
			cfg.TableNames.Tokens = defaults.Tokens
		}
		if cfg.TableNames.Sessions == "" {
			cfg.TableNames.Sessions = defaults.Sessions
		}
		if cfg.TableNames.Roles == "" {
			cfg.TableNames.Roles = defaults.Roles
		}
		if cfg.TableNames.Permissions == "" {
			cfg.TableNames.Permissions = defaults.Permissions
		}
		if cfg.TableNames.RolePermissions == "" {
			cfg.TableNames.RolePermissions = defaults.RolePermissions
		}
		if cfg.TableNames.RememberTokens == "" {
			cfg.TableNames.RememberTokens = defaults.RememberTokens
		}
	}

	// Set default column names if not provided
	if cfg.ColumnNames == (ColumnNames{}) {
		cfg.ColumnNames = DefaultColumnNames()
	} else {
		// Fill in any missing column names with defaults
		defaults := DefaultColumnNames()
		if cfg.ColumnNames.UserID == "" {
			cfg.ColumnNames.UserID = defaults.UserID
		}
		if cfg.ColumnNames.UserEmail == "" {
			cfg.ColumnNames.UserEmail = defaults.UserEmail
		}
		if cfg.ColumnNames.UserPassword == "" {
			cfg.ColumnNames.UserPassword = defaults.UserPassword
		}
		if cfg.ColumnNames.UserVerified == "" {
			cfg.ColumnNames.UserVerified = defaults.UserVerified
		}
		if cfg.ColumnNames.UserCreated == "" {
			cfg.ColumnNames.UserCreated = defaults.UserCreated
		}
		if cfg.ColumnNames.UserRoleID == "" {
			cfg.ColumnNames.UserRoleID = defaults.UserRoleID
		}
		if cfg.ColumnNames.TokenID == "" {
			cfg.ColumnNames.TokenID = defaults.TokenID
		}
		if cfg.ColumnNames.TokenValue == "" {
			cfg.ColumnNames.TokenValue = defaults.TokenValue
		}
		if cfg.ColumnNames.TokenUserID == "" {
			cfg.ColumnNames.TokenUserID = defaults.TokenUserID
		}
		if cfg.ColumnNames.TokenPurpose == "" {
			cfg.ColumnNames.TokenPurpose = defaults.TokenPurpose
		}
		if cfg.ColumnNames.TokenExpires == "" {
			cfg.ColumnNames.TokenExpires = defaults.TokenExpires
		}
		if cfg.ColumnNames.TokenCreated == "" {
			cfg.ColumnNames.TokenCreated = defaults.TokenCreated
		}
	}

	// Default to true for backward compatibility
	if !cfg.AutoMigrate && cfg.ValidateSchema == false {
		cfg.ValidateSchema = true
	}

	// Initialize database based on type
	var db *database.DB
	var err error

	switch cfg.DatabaseType {
	case "sqlite":
		db, err = database.NewSQLiteWithConfig(database.SQLiteConfig{
			Path:           cfg.DatabasePath,
			AutoMigrate:    cfg.AutoMigrate,
			MigrationTable: cfg.MigrationTable,
			TableNames: database.TableMapping{
				Users:           cfg.TableNames.Users,
				Tokens:          cfg.TableNames.Tokens,
				Sessions:        cfg.TableNames.Sessions,
				Roles:           cfg.TableNames.Roles,
				Permissions:     cfg.TableNames.Permissions,
				RolePermissions: cfg.TableNames.RolePermissions,
				RememberTokens:  cfg.TableNames.RememberTokens,
			},
		})
	case "mysql":
		if cfg.DatabaseDSN == "" {
			panic("MySQL DSN is required")
		}
		db, err = database.NewMySQLWithConfig(database.MySQLConfig{
			DSN:             cfg.DatabaseDSN,
			MaxOpenConns:    cfg.MaxOpenConns,
			MaxIdleConns:    cfg.MaxIdleConns,
			ConnMaxLifetime: cfg.ConnMaxLifetime,
			AutoMigrate:     cfg.AutoMigrate,
			MigrationTable:  cfg.MigrationTable,
			TableNames: database.TableMapping{
				Users:           cfg.TableNames.Users,
				Tokens:          cfg.TableNames.Tokens,
				Sessions:        cfg.TableNames.Sessions,
				Roles:           cfg.TableNames.Roles,
				Permissions:     cfg.TableNames.Permissions,
				RolePermissions: cfg.TableNames.RolePermissions,
				RememberTokens:  cfg.TableNames.RememberTokens,
			},
		})
	default:
		panic("unsupported database type: " + cfg.DatabaseType)
	}

	if err != nil {
		panic("failed to initialize database: " + err.Error())
	}

	// Validate schema if requested
	if cfg.ValidateSchema {
		validator := database.NewSchemaValidator(db)

		// Build mapping based on enabled features
		mapping := database.TableMapping{
			Users: cfg.TableNames.Users, // Always required
		}

		// Only require tokens table if email verification or password reset is enabled
		if cfg.Features.EmailVerification || cfg.Features.PasswordReset {
			mapping.Tokens = cfg.TableNames.Tokens
		}

		// Only require sessions table if using database sessions
		if cfg.SessionBackend == SessionBackendDatabase {
			mapping.Sessions = cfg.TableNames.Sessions
		}

		// Only require RBAC tables if RBAC is enabled
		if cfg.Features.RBAC {
			mapping.Roles = cfg.TableNames.Roles
			mapping.Permissions = cfg.TableNames.Permissions
			mapping.RolePermissions = cfg.TableNames.RolePermissions
		}

		// Only require remember tokens table if remember me is enabled
		if cfg.Features.RememberMe {
			mapping.RememberTokens = cfg.TableNames.RememberTokens
		}

		// Skip full validation if external auth is enabled and no Guardian-specific features are used
		if cfg.Features.ExternalAuth &&
			!cfg.Features.EmailVerification &&
			!cfg.Features.PasswordReset &&
			!cfg.Features.RBAC &&
			!cfg.Features.RememberMe {
			// For external auth with minimal features, only check that users table exists
			// Don't validate column names as they might be completely different
			log.Println("✓ External auth mode - skipping full schema validation")
		} else {
			if err := validator.ValidateWithMapping(mapping); err != nil {
				panic("schema validation failed: " + err.Error() +
					"\nPlease ensure all required tables and columns exist. " +
					"See database/SCHEMA.md for requirements.")
			}
			log.Println("✓ Database schema validated successfully")
		}
	}

	// Initialize session store based on backend
	var sessionStore sessions.Store

	// Set default session options if not provided
	if cfg.SessionOptions == nil {
		cfg.SessionOptions = &sessions.Options{
			Path:     "/",
			MaxAge:   1800, // 30 minutes
			HttpOnly: true,
			Secure:   cfg.Environment == "production",
			SameSite: http.SameSiteLaxMode,
		}
	}

	switch cfg.SessionBackend {
	case SessionBackendCookie:
		sessionStore = sessions.NewCookieStore(cfg.SessionKey)
		sessionStore.(*sessions.CookieStore).Options = cfg.SessionOptions

	case SessionBackendMemory:
		store := NewInMemoryStore(cfg.SessionKey)
		store.options = cfg.SessionOptions
		sessionStore = store
		log.Println("⚠️  Using in-memory sessions - sessions will be lost on restart")
		log.Println("⚠️  Not suitable for production multi-server deployments")

	case SessionBackendDatabase:
		// For database sessions, we'd need to implement a custom store
		// This would require:
		// 1. Implementing sessions.Store interface
		// 2. Storing session data in the sessions table
		// 3. Handling session cleanup/expiration
		// 4. Proper serialization of session values
		panic("Database session backend not yet implemented. Please use 'cookie' or 'memory' backends.")

	default:
		panic("unsupported session backend: " + string(cfg.SessionBackend))
	}

	// Initialize auth service with table names and features
	authService := auth.NewServiceWithConfig(auth.ServiceConfig{
		Store: sessionStore,
		DB:    db.DB,
		TableNames: auth.TableConfig{
			Users:           cfg.TableNames.Users,
			Tokens:          cfg.TableNames.Tokens,
			Sessions:        cfg.TableNames.Sessions,
			Roles:           cfg.TableNames.Roles,
			Permissions:     cfg.TableNames.Permissions,
			RolePermissions: cfg.TableNames.RolePermissions,
			RememberTokens:  cfg.TableNames.RememberTokens,
		},
		ColumnNames: auth.ColumnConfig{
			UserID:       cfg.ColumnNames.UserID,
			UserEmail:    cfg.ColumnNames.UserEmail,
			UserPassword: cfg.ColumnNames.UserPassword,
			UserVerified: cfg.ColumnNames.UserVerified,
			UserCreated:  cfg.ColumnNames.UserCreated,
			UserRoleID:   cfg.ColumnNames.UserRoleID,

			TokenID:      cfg.ColumnNames.TokenID,
			TokenValue:   cfg.ColumnNames.TokenValue,
			TokenUserID:  cfg.ColumnNames.TokenUserID,
			TokenPurpose: cfg.ColumnNames.TokenPurpose,
			TokenExpires: cfg.ColumnNames.TokenExpires,
			TokenCreated: cfg.ColumnNames.TokenCreated,
		},
		Features: auth.FeatureConfig{
			EmailVerification: cfg.Features.EmailVerification,
			PasswordReset:     cfg.Features.PasswordReset,
			RememberMe:        cfg.Features.RememberMe,
			RBAC:              cfg.Features.RBAC,
			ExternalAuth:      cfg.Features.ExternalAuth,
		},
	})

	// Initialize router
	r := router.New()

	return &Guardian{
		router:   r,
		db:       db,
		auth:     authService,
		sessions: sessionStore,
		config:   cfg,
	}
}

// Router methods delegation
func (g *Guardian) GET(pattern string, handler http.HandlerFunc) *router.Route {
	return g.router.GET(pattern, handler)
}

func (g *Guardian) POST(pattern string, handler http.HandlerFunc) *router.Route {
	return g.router.POST(pattern, handler)
}

func (g *Guardian) PUT(pattern string, handler http.HandlerFunc) *router.Route {
	return g.router.PUT(pattern, handler)
}

func (g *Guardian) DELETE(pattern string, handler http.HandlerFunc) *router.Route {
	return g.router.DELETE(pattern, handler)
}

func (g *Guardian) PATCH(pattern string, handler http.HandlerFunc) *router.Route {
	return g.router.PATCH(pattern, handler)
}

func (g *Guardian) Use(middleware ...func(http.Handler) http.Handler) {
	g.router.Use(middleware...)
}

func (g *Guardian) Group(pattern string) *router.Group {
	return g.router.Group(pattern)
}

func (g *Guardian) Auth() *auth.Service {
	return g.auth
}

func (g *Guardian) DB() *database.DB {
	return g.db
}

func (g *Guardian) Sessions() sessions.Store {
	return g.sessions
}

func (g *Guardian) Config() Config {
	return g.config
}

// Features returns the enabled features configuration
func (g *Guardian) Features() Features {
	return g.config.Features
}

// IsFeatureEnabled checks if a specific feature is enabled
func (g *Guardian) IsFeatureEnabled(feature string) bool {
	switch feature {
	case "email_verification":
		return g.config.Features.EmailVerification
	case "password_reset":
		return g.config.Features.PasswordReset
	case "remember_me":
		return g.config.Features.RememberMe
	case "rbac":
		return g.config.Features.RBAC
	case "external_auth":
		return g.config.Features.ExternalAuth
	default:
		return false
	}
}

func (g *Guardian) Listen(addr string) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      g.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		srv.Shutdown(ctx)
		g.db.Close()
	}()

	log.Printf("Guardian server starting on %s", addr)
	return srv.ListenAndServe()
}

// RunMigrations manually runs Guardian's migrations
// This is useful if you want to run migrations separately from app initialization
func (g *Guardian) RunMigrations() error {
	return g.db.Migrate()
}

// RunSpecificMigrations runs only specific migrations by version
func (g *Guardian) RunSpecificMigrations(versions ...string) error {
	return g.db.MigrateUp(versions...)
}

// GetAvailableMigrations returns all Guardian migrations for inspection
func GetAvailableMigrations() []database.Migration {
	return database.GetMigrations()
}
