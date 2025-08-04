package plugin

import (
	"errors"
	"net/http"

	"github.com/flyzard/go-guardian/database"
)

// Common errors
var (
	ErrInvalidConfig = errors.New("invalid plugin configuration")
	ErrNotFound      = errors.New("plugin not found")
	ErrAlreadyEnabled = errors.New("plugin already enabled")
	ErrDependencyFailed = errors.New("plugin dependency failed")
)

// Plugin defines the interface for Guardian plugins
type Plugin interface {
	// Name returns the unique name of the plugin
	Name() string
	
	// Description returns a brief description of what the plugin does
	Description() string
	
	// Init initializes the plugin with Guardian instance
	// This is called when the plugin is enabled
	Init(ctx *Context) error
	
	// Routes returns HTTP routes to be registered
	Routes() []Route
	
	// Middleware returns HTTP middleware to be applied globally
	Middleware() []Middleware
	
	// Migrations returns database migrations for this plugin
	Migrations() []database.Migration
	
	// RequiredTables returns table names this plugin requires
	RequiredTables() []string
	
	// Cleanup is called when the plugin is disabled
	Cleanup() error
}

// Context provides access to Guardian services for plugins
type Context struct {
	// DB provides database access
	DB *database.DB
	
	// SessionStore provides session management
	SessionStore interface{}
	
	// Config provides access to plugin-specific configuration
	Config map[string]interface{}
}

// Route represents an HTTP route
type Route struct {
	Method      string
	Path        string
	Handler     http.HandlerFunc
	Middleware  []func(http.Handler) http.Handler
	Description string
}

// Middleware represents HTTP middleware with metadata
type Middleware struct {
	Handler     func(http.Handler) http.Handler
	Priority    int    // Lower values are executed first
	Description string
}

// ConfigurablePlugin is an optional interface for plugins that support configuration
type ConfigurablePlugin interface {
	Plugin
	
	// DefaultConfig returns the default configuration for this plugin
	DefaultConfig() interface{}
	
	// ValidateConfig validates the provided configuration
	ValidateConfig(config interface{}) error
}

// LifecyclePlugin is an optional interface for plugins that need lifecycle hooks
type LifecyclePlugin interface {
	Plugin
	
	// OnStart is called when the server starts
	OnStart() error
	
	// OnStop is called when the server stops
	OnStop() error
}

// DependentPlugin is an optional interface for plugins with dependencies
type DependentPlugin interface {
	Plugin
	
	// Dependencies returns names of plugins this plugin depends on
	Dependencies() []string
}