package guardian

import (
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/flyzard/go-guardian/auth"
	"github.com/flyzard/go-guardian/config"
	"github.com/flyzard/go-guardian/database"
	"github.com/flyzard/go-guardian/plugin"
	authPlugin "github.com/flyzard/go-guardian/plugins/auth"
	csrfPlugin "github.com/flyzard/go-guardian/plugins/csrf"
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

// TableNames is an alias to config.TableNames for backward compatibility
type TableNames = config.TableNames


// ColumnNames is an alias to config.FlatColumnNames for backward compatibility
type ColumnNames = config.FlatColumnNames


// Features is an alias to config.Features for backward compatibility
type Features = config.Features


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

	// Plugin system (new in v2)
	EnablePluginSystem bool // Enable the new plugin architecture (default: false)
	Plugins            []string // List of plugins to enable (when EnablePluginSystem is true)

	OAuth *auth.OAuthConfig
}

type Guardian struct {
	router         *router.Router
	db             *database.DB
	auth           *auth.Service
	sessions       sessions.Store
	config         Config
	pluginRegistry *plugin.Registry // New: plugin registry
	routesSetup    bool             // Track if routes have been setup
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
		session.ID = auth.GenerateToken()
	}

	// Store in memory
	s.mu.Lock()
	s.sessions[session.ID] = session
	s.mu.Unlock()

	// Set cookie with session ID
	http.SetCookie(w, sessions.NewCookie(session.Name(), session.ID, session.Options))

	return nil
}

// func (s *InMemoryStore) cleanup() {
// 	// Simple cleanup - in production, use a proper scheduler
// 	// This is a placeholder for a more sophisticated implementation
// 	// that would periodically clean up expired sessions
// }

func (s *InMemoryStore) Options(options *sessions.Options) {
	s.options = options
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

	// Only set default features if NO features were specified at all
	// We check if all fields are false AND ExternalAuth is also false, which indicates
	// the user didn't set any features explicitly
	allFeaturesZero := !cfg.Features.EmailVerification && 
		!cfg.Features.PasswordReset && 
		!cfg.Features.RememberMe && 
		!cfg.Features.RBAC && 
		!cfg.Features.ExternalAuth
	
	if allFeaturesZero {
		// User didn't specify any features, use defaults
		cfg.Features = config.DefaultFeatures()
	}
	// Otherwise, respect the user's explicit feature configuration

	// Set default table names based on enabled features
	defaults := config.DefaultTableNames()
	if cfg.TableNames == (TableNames{}) {
		// Only set defaults for tables that are actually needed
		cfg.TableNames.Users = defaults.Users // Always needed
		
		if cfg.Features.EmailVerification || cfg.Features.PasswordReset {
			cfg.TableNames.Tokens = defaults.Tokens
		}
		if cfg.SessionBackend == SessionBackendDatabase {
			cfg.TableNames.Sessions = defaults.Sessions
		}
		if cfg.Features.RBAC {
			cfg.TableNames.Roles = defaults.Roles
			cfg.TableNames.Permissions = defaults.Permissions
			cfg.TableNames.RolePermissions = defaults.RolePermissions
		}
		if cfg.Features.RememberMe {
			cfg.TableNames.RememberTokens = defaults.RememberTokens
		}
	} else {
		// Apply defaults to missing fields
		if cfg.TableNames.Users == "" {
			cfg.TableNames.Users = defaults.Users
		}
		// Only set defaults for tables that are needed based on features
		if cfg.Features.EmailVerification || cfg.Features.PasswordReset {
			if cfg.TableNames.Tokens == "" {
				cfg.TableNames.Tokens = defaults.Tokens
			}
		}
		if cfg.SessionBackend == SessionBackendDatabase {
			if cfg.TableNames.Sessions == "" {
				cfg.TableNames.Sessions = defaults.Sessions
			}
		}
		if cfg.Features.RBAC {
			if cfg.TableNames.Roles == "" {
				cfg.TableNames.Roles = defaults.Roles
			}
			if cfg.TableNames.Permissions == "" {
				cfg.TableNames.Permissions = defaults.Permissions
			}
			if cfg.TableNames.RolePermissions == "" {
				cfg.TableNames.RolePermissions = defaults.RolePermissions
			}
		}
		if cfg.Features.RememberMe {
			if cfg.TableNames.RememberTokens == "" {
				cfg.TableNames.RememberTokens = defaults.RememberTokens
			}
		}
	}

	// Set default column names if not provided
	if cfg.ColumnNames == (ColumnNames{}) {
		cfg.ColumnNames = config.DefaultFlatColumnNames()
	} else {
		// Apply defaults to missing fields
		config.ApplyDefaults(&cfg.ColumnNames, config.DefaultFlatColumnNames())
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
		OAuth: cfg.OAuth,
	})

	// Initialize router
	r := router.New()

	// Initialize plugin system if enabled
	var pluginRegistry *plugin.Registry
	if cfg.EnablePluginSystem {
		// Create plugin context
		pluginContext := &plugin.Context{
			DB:           db,
			SessionStore: sessionStore,
			Config:       make(map[string]interface{}),
		}
		
		// Create registry
		pluginRegistry = plugin.NewRegistry(pluginContext)
		
		// Register built-in plugins
		registerBuiltinPlugins(pluginRegistry)
		
		// Enable plugins based on configuration
		if len(cfg.Plugins) > 0 {
			// Use explicit plugin list
			loader := plugin.NewLoader(pluginRegistry)
			if err := loader.EnableList(cfg.Plugins); err != nil {
				log.Printf("Warning: Some plugins failed to load: %v", err)
			}
		} else {
			// Map features to plugins for backward compatibility
			loader := plugin.NewLoader(pluginRegistry)
			featureMap := map[string]bool{
				"csrf":              true, // Always enable CSRF
				"email_verification": cfg.Features.EmailVerification,
				"password_reset":    cfg.Features.PasswordReset,
				"remember_me":       cfg.Features.RememberMe,
				"rbac":              cfg.Features.RBAC,
				"external_auth":     cfg.Features.ExternalAuth,
			}
			
			if err := loader.EnableFromFeatures(featureMap); err != nil {
				log.Printf("Warning: Some plugins failed to load from features: %v", err)
			}
		}
		
		// Apply plugin middleware
		for _, mw := range pluginRegistry.CollectMiddleware() {
			r.Use(mw)
		}
		
		// Don't register plugin routes yet - wait until after user middleware
		// Routes will be registered on first route definition or ServeHTTP
		
		log.Printf("Plugin system enabled with %d active plugins", len(pluginRegistry.EnabledPlugins()))
	}

	return &Guardian{
		router:         r,
		db:             db,
		auth:           authService,
		sessions:       sessionStore,
		config:         cfg,
		pluginRegistry: pluginRegistry,
	}
}

// setupPluginRoutes sets up plugin routes if not already done
func (g *Guardian) setupPluginRoutes() {
	if g.routesSetup || !g.config.EnablePluginSystem || g.pluginRegistry == nil {
		return
	}
	
	// Register plugin routes
	for _, route := range g.pluginRegistry.CollectRoutes() {
		// Apply route-specific middleware first
		handler := route.Handler
		for i := len(route.Middleware) - 1; i >= 0; i-- {
			handler = route.Middleware[i](handler).ServeHTTP
		}
		
		// Register with router
		switch route.Method {
		case "GET":
			g.router.GET(route.Path, handler)
		case "POST":
			g.router.POST(route.Path, handler)
		case "PUT":
			g.router.PUT(route.Path, handler)
		case "DELETE":
			g.router.DELETE(route.Path, handler)
		case "PATCH":
			g.router.PATCH(route.Path, handler)
		}
	}
	
	g.routesSetup = true
}

// Router methods delegation
func (g *Guardian) GET(pattern string, handler http.HandlerFunc) *router.Route {
	g.setupPluginRoutes()
	return g.router.GET(pattern, handler)
}

func (g *Guardian) POST(pattern string, handler http.HandlerFunc) *router.Route {
	g.setupPluginRoutes()
	return g.router.POST(pattern, handler)
}

func (g *Guardian) PUT(pattern string, handler http.HandlerFunc) *router.Route {
	g.setupPluginRoutes()
	return g.router.PUT(pattern, handler)
}

func (g *Guardian) DELETE(pattern string, handler http.HandlerFunc) *router.Route {
	g.setupPluginRoutes()
	return g.router.DELETE(pattern, handler)
}

func (g *Guardian) PATCH(pattern string, handler http.HandlerFunc) *router.Route {
	g.setupPluginRoutes()
	return g.router.PATCH(pattern, handler)
}

func (g *Guardian) Use(middleware ...func(http.Handler) http.Handler) {
	g.router.Use(middleware...)
}

func (g *Guardian) Group(pattern string) *router.Group {
	g.setupPluginRoutes()
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
	// If plugin system is enabled, check plugin registry
	if g.config.EnablePluginSystem && g.pluginRegistry != nil {
		// Map feature names to plugin names
		featureToPlugin := map[string]string{
			"csrf":              "csrf",
			"email_verification": "auth",
			"password_reset":    "auth", 
			"remember_me":       "auth",
			"rbac":              "rbac",
			"external_auth":     "external_auth",
		}
		
		if pluginName, ok := featureToPlugin[feature]; ok {
			return g.pluginRegistry.IsEnabled(pluginName)
		}
		return false
	}
	
	// Legacy feature flag checking
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

// Plugin returns the plugin registry (nil if plugin system is not enabled)
func (g *Guardian) Plugin() *plugin.Registry {
	return g.pluginRegistry
}

// EnablePlugin enables a plugin by name (only works if plugin system is enabled)
func (g *Guardian) EnablePlugin(name string) error {
	if !g.config.EnablePluginSystem {
		return errors.New("plugin system is not enabled")
	}
	if g.pluginRegistry == nil {
		return errors.New("plugin registry not initialized")
	}
	return g.pluginRegistry.Enable(name)
}

// DisablePlugin disables a plugin by name (only works if plugin system is enabled)  
func (g *Guardian) DisablePlugin(name string) error {
	if !g.config.EnablePluginSystem {
		return errors.New("plugin system is not enabled")
	}
	if g.pluginRegistry == nil {
		return errors.New("plugin registry not initialized")
	}
	return g.pluginRegistry.Disable(name)
}

// registerBuiltinPlugins registers all built-in plugins with the registry
func registerBuiltinPlugins(registry *plugin.Registry) {
	// Register CSRF plugin
	if err := registry.Register(csrfPlugin.New()); err != nil {
		log.Printf("Failed to register CSRF plugin: %v", err)
	}
	
	// Register Auth plugin
	if err := registry.Register(authPlugin.New()); err != nil {
		log.Printf("Failed to register Auth plugin: %v", err)
	}
	
	// Future plugins can be registered here
	// Example:
	// registry.Register(rbacPlugin.New())
	// registry.Register(rateLimitPlugin.New())
}

func (g *Guardian) Listen(addr string) error {
	// Ensure plugin routes are setup before serving
	g.setupPluginRoutes()
	
	srv := &http.Server{
		Addr:         addr,
		Handler:      g.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	// go func() {
	// 	sigChan := make(chan os.Signal, 1)
	// 	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	// 	<-sigChan

	// 	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// 	defer cancel()

	// 	srv.Shutdown(ctx)
	// 	g.db.Close()
	// }()

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
