// File: guardian.go
package guardian

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flyzard/go-guardian/auth"
	"github.com/flyzard/go-guardian/database"
	"github.com/flyzard/go-guardian/router"
	"github.com/gorilla/sessions"
)

// TableNames allows customizing table names
type TableNames struct {
	Users           string
	Tokens          string
	Sessions        string
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
}

type Guardian struct {
	router   *router.Router
	db       *database.DB
	auth     *auth.Service
	sessions sessions.Store
	config   Config
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

	// Set defaults for migrations
	if cfg.MigrationTable == "" {
		cfg.MigrationTable = "migrations"
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
			TableNames:     database.TableMapping(cfg.TableNames),
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
			TableNames:      database.TableMapping(cfg.TableNames),
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
		if err := validator.ValidateWithMapping(database.TableMapping(cfg.TableNames)); err != nil {
			panic("schema validation failed: " + err.Error() +
				"\nPlease ensure all required tables and columns exist. " +
				"See database/SCHEMA.md for requirements.")
		}
		log.Println("✓ Database schema validated successfully")
	}

	// Initialize session store
	sessionStore := sessions.NewCookieStore(cfg.SessionKey)
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   1800, // 30 minutes
		HttpOnly: true,
		Secure:   cfg.Environment == "production",
		SameSite: http.SameSiteLaxMode,
	}

	// Initialize auth service with table names
	authService := auth.NewServiceWithConfig(auth.ServiceConfig{
		Store:      sessionStore,
		DB:         db.DB,
		TableNames: auth.TableConfig(cfg.TableNames),
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
