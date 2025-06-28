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

	// Initialize database based on type
	var db *database.DB
	var err error

	switch cfg.DatabaseType {
	case "sqlite":
		db, err = database.NewSQLite(cfg.DatabasePath)
	case "mysql":
		if cfg.DatabaseDSN == "" {
			panic("MySQL DSN is required")
		}
		db, err = database.NewMySQL(database.MySQLConfig{
			DSN:             cfg.DatabaseDSN,
			MaxOpenConns:    cfg.MaxOpenConns,
			MaxIdleConns:    cfg.MaxIdleConns,
			ConnMaxLifetime: cfg.ConnMaxLifetime,
		})
	default:
		panic("unsupported database type: " + cfg.DatabaseType)
	}

	if err != nil {
		panic("failed to initialize database: " + err.Error())
	}

	// Initialize session store
	sessionStore := sessions.NewCookieStore(cfg.SessionKey)
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   1800, // 30 minutes
		HttpOnly: true,
		Secure:   cfg.Environment == "production",
		SameSite: http.SameSiteStrictMode,
	}

	// Initialize auth service
	authService := auth.NewService(sessionStore, db.DB)

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
