package auth

import (
	"errors"
	"log"
	"net/http"

	"github.com/flyzard/go-guardian/auth"
	"github.com/flyzard/go-guardian/database"
	"github.com/flyzard/go-guardian/middleware"
	"github.com/flyzard/go-guardian/plugin"
	"github.com/flyzard/go-guardian/response"
	"github.com/gorilla/sessions"
)

// Config holds auth plugin configuration
type Config struct {
	EnableEmailVerification bool
	EnablePasswordReset     bool
	EnableRememberMe        bool
	SessionName            string
	LoginPath              string
	LogoutPath             string
	RegisterPath           string
}

// DefaultConfig returns default auth configuration
func DefaultConfig() Config {
	return Config{
		EnableEmailVerification: true,
		EnablePasswordReset:     true,
		EnableRememberMe:        true,
		SessionName:            "auth-session",
		LoginPath:              "/auth/login",
		LogoutPath:             "/auth/logout",
		RegisterPath:           "/auth/register",
	}
}

// AuthPlugin implements authentication as a plugin
type AuthPlugin struct {
	config  Config
	service *auth.Service
	store   sessions.Store
}

// New creates a new auth plugin
func New() *AuthPlugin {
	return &AuthPlugin{
		config: DefaultConfig(),
	}
}

// NewWithConfig creates a new auth plugin with custom configuration
func NewWithConfig(config Config) *AuthPlugin {
	return &AuthPlugin{
		config: config,
	}
}

// Name returns the plugin name
func (p *AuthPlugin) Name() string {
	return "auth"
}

// Description returns the plugin description
func (p *AuthPlugin) Description() string {
	return "Provides user authentication with sessions, registration, and password management"
}

// Init initializes the plugin
func (p *AuthPlugin) Init(ctx *plugin.Context) error {
	// Get session store from context
	store, ok := ctx.SessionStore.(sessions.Store)
	if !ok {
		return plugin.ErrInvalidConfig
	}
	p.store = store
	
	// Update config if provided in context
	if cfg, ok := ctx.Config["auth"]; ok {
		if authConfig, ok := cfg.(Config); ok {
			p.config = authConfig
		}
	}
	
	// Create auth service
	p.service = auth.NewService(store, ctx.DB.DB)
	
	log.Printf("Auth plugin initialized with email verification=%v, password reset=%v", 
		p.config.EnableEmailVerification, p.config.EnablePasswordReset)
	return nil
}

// Routes returns authentication routes
func (p *AuthPlugin) Routes() []plugin.Route {
	routes := []plugin.Route{
		{
			Method:      "POST",
			Path:        p.config.LoginPath,
			Handler:     p.handleLogin,
			Description: "User login endpoint",
		},
		{
			Method:      "POST",
			Path:        p.config.LogoutPath,
			Handler:     p.handleLogout,
			Middleware:  []func(http.Handler) http.Handler{middleware.RequireAuth(p.store)},
			Description: "User logout endpoint",
		},
	}
	
	if p.config.EnableEmailVerification || p.config.EnablePasswordReset {
		routes = append(routes, plugin.Route{
			Method:      "POST",
			Path:        p.config.RegisterPath,
			Handler:     p.handleRegister,
			Description: "User registration endpoint",
		})
	}
	
	if p.config.EnablePasswordReset {
		routes = append(routes, []plugin.Route{
			{
				Method:      "POST",
				Path:        "/auth/password/reset",
				Handler:     p.handlePasswordResetRequest,
				Description: "Request password reset",
			},
			{
				Method:      "POST",
				Path:        "/auth/password/reset/confirm",
				Handler:     p.handlePasswordResetConfirm,
				Description: "Confirm password reset with token",
			},
		}...)
	}
	
	if p.config.EnableEmailVerification {
		routes = append(routes, plugin.Route{
			Method:      "GET",
			Path:        "/auth/verify",
			Handler:     p.handleEmailVerification,
			Description: "Email verification endpoint",
		})
	}
	
	return routes
}

// Middleware returns auth-related middleware
func (p *AuthPlugin) Middleware() []plugin.Middleware {
	return []plugin.Middleware{
		{
			Handler:     middleware.OptionalAuth(p.store),
			Priority:    20, // Run after CSRF
			Description: "Optional authentication middleware - adds user to context if authenticated",
		},
	}
}

// Migrations returns database migrations for auth
func (p *AuthPlugin) Migrations() []database.Migration {
	migrations := []database.Migration{
		{
			Version: "auth_001",
			Name:    "create_users_table",
			UpSQLite: `
				CREATE TABLE IF NOT EXISTS users (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					email TEXT UNIQUE NOT NULL,
					password_hash TEXT NOT NULL,
					verified BOOLEAN DEFAULT FALSE,
					created_at DATETIME NOT NULL,
					updated_at DATETIME
				);
				CREATE INDEX idx_users_email ON users(email);
			`,
			DownSQLite: `DROP TABLE IF EXISTS users;`,
			UpMySQL: `
				CREATE TABLE IF NOT EXISTS users (
					id BIGINT PRIMARY KEY AUTO_INCREMENT,
					email VARCHAR(255) UNIQUE NOT NULL,
					password_hash VARCHAR(255) NOT NULL,
					verified TINYINT(1) DEFAULT 0,
					created_at DATETIME NOT NULL,
					updated_at DATETIME NULL,
					INDEX idx_users_email (email)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
			`,
			DownMySQL: `DROP TABLE IF EXISTS users;`,
		},
	}
	
	if p.config.EnableEmailVerification || p.config.EnablePasswordReset {
		migrations = append(migrations, database.Migration{
			Version: "auth_002",
			Name:    "create_tokens_table",
			UpSQLite: `
				CREATE TABLE IF NOT EXISTS tokens (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					token TEXT UNIQUE NOT NULL,
					user_id INTEGER NOT NULL,
					purpose TEXT NOT NULL,
					expires_at DATETIME NOT NULL,
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
					FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
				);
				CREATE INDEX idx_tokens_token ON tokens(token);
				CREATE INDEX idx_tokens_expires ON tokens(expires_at);
			`,
			DownSQLite: `DROP TABLE IF EXISTS tokens;`,
			UpMySQL: `
				CREATE TABLE IF NOT EXISTS tokens (
					id BIGINT PRIMARY KEY AUTO_INCREMENT,
					token VARCHAR(255) UNIQUE NOT NULL,
					user_id BIGINT NOT NULL,
					purpose VARCHAR(50) NOT NULL,
					expires_at DATETIME NOT NULL,
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
					INDEX idx_tokens_token (token),
					INDEX idx_tokens_expires (expires_at),
					FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
				) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
			`,
			DownMySQL: `DROP TABLE IF EXISTS tokens;`,
		})
	}
	
	if p.config.EnableRememberMe {
		migrations = append(migrations, database.Migration{
			Version: "auth_003",
			Name:    "create_remember_tokens_table",
			UpSQLite: `
				CREATE TABLE IF NOT EXISTS remember_tokens (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					user_id INTEGER NOT NULL,
					token TEXT UNIQUE NOT NULL,
					expires_at DATETIME NOT NULL,
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
					FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
				);
				CREATE INDEX idx_remember_tokens_token ON remember_tokens(token);
			`,
			DownSQLite: `DROP TABLE IF EXISTS remember_tokens;`,
			UpMySQL: `
				CREATE TABLE IF NOT EXISTS remember_tokens (
					id BIGINT PRIMARY KEY AUTO_INCREMENT,
					user_id BIGINT NOT NULL,
					token VARCHAR(255) UNIQUE NOT NULL,
					expires_at DATETIME NOT NULL,
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
					INDEX idx_remember_tokens_token (token),
					FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
				) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
			`,
			DownMySQL: `DROP TABLE IF EXISTS remember_tokens;`,
		})
	}
	
	return migrations
}

// RequiredTables returns tables required by auth
func (p *AuthPlugin) RequiredTables() []string {
	tables := []string{"users"}
	
	if p.config.EnableEmailVerification || p.config.EnablePasswordReset {
		tables = append(tables, "tokens")
	}
	
	if p.config.EnableRememberMe {
		tables = append(tables, "remember_tokens")
	}
	
	return tables
}

// Cleanup performs cleanup when plugin is disabled
func (p *AuthPlugin) Cleanup() error {
	// Nothing to cleanup for auth
	return nil
}

// DefaultConfig implements ConfigurablePlugin interface
func (p *AuthPlugin) DefaultConfig() interface{} {
	return DefaultConfig()
}

// ValidateConfig implements ConfigurablePlugin interface  
func (p *AuthPlugin) ValidateConfig(config interface{}) error {
	_, ok := config.(Config)
	if !ok {
		return plugin.ErrInvalidConfig
	}
	return nil
}

// Handler implementations

func (p *AuthPlugin) handleLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")
	rememberMe := r.FormValue("remember_me") == "on"
	
	// Use the appropriate login method based on remember me feature
	var err error
	if rememberMe && p.config.EnableRememberMe {
		err = p.service.LoginWithRememberMe(w, r, email, password, true)
	} else {
		err = p.service.Login(w, r, email, password)
	}
	
	if err != nil {
		response.New(w, r).ErrorWithStatus(err, http.StatusUnauthorized).Send()
		return
	}
	
	response.New(w, r).JSON(map[string]interface{}{
		"success": true,
		"message": "Login successful",
	}).Send()
}

func (p *AuthPlugin) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := p.store.Get(r, p.config.SessionName)
	session.Options.MaxAge = -1
	session.Save(r, w)
	
	response.New(w, r).JSON(map[string]interface{}{
		"success": true,
		"message": "Logged out successfully",
	}).Send()
}

func (p *AuthPlugin) handleRegister(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")
	
	user, err := p.service.Register(email, password)
	if err != nil {
		response.New(w, r).ErrorWithStatus(err, http.StatusBadRequest).Send()
		return
	}
	
	response.New(w, r).Status(http.StatusCreated).JSON(map[string]interface{}{
		"success": true,
		"user":    user,
		"message": "Registration successful",
	}).Send()
}

func (p *AuthPlugin) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement password reset request
	// This would require adding the RequestPasswordReset method to auth.Service
	response.New(w, r).ErrorWithStatus(
		errors.New("password reset not yet implemented in plugin system"), 
		http.StatusNotImplemented,
	).Send()
}

func (p *AuthPlugin) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement password reset confirmation
	// This would require adding the ResetPassword method to auth.Service
	response.New(w, r).ErrorWithStatus(
		errors.New("password reset not yet implemented in plugin system"), 
		http.StatusNotImplemented,
	).Send()
}

func (p *AuthPlugin) handleEmailVerification(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement email verification
	// This would require adding the VerifyEmail method to auth.Service
	response.New(w, r).ErrorWithStatus(
		errors.New("email verification not yet implemented in plugin system"), 
		http.StatusNotImplemented,
	).Send()
}