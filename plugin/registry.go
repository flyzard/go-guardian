package plugin

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"

	"github.com/flyzard/go-guardian/database"
)

// Registry manages plugins and their lifecycle
type Registry struct {
	mu       sync.RWMutex
	plugins  map[string]Plugin
	enabled  map[string]bool
	order    []string // Maintains registration order
	context  *Context
}

// NewRegistry creates a new plugin registry
func NewRegistry(ctx *Context) *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
		enabled: make(map[string]bool),
		order:   make([]string, 0),
		context: ctx,
	}
}

// Register adds a plugin to the registry
func (r *Registry) Register(p Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	name := p.Name()
	if name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}
	
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}
	
	// Check dependencies if applicable
	if dp, ok := p.(DependentPlugin); ok {
		for _, dep := range dp.Dependencies() {
			if _, exists := r.plugins[dep]; !exists {
				return fmt.Errorf("plugin %s depends on %s which is not registered", name, dep)
			}
		}
	}
	
	r.plugins[name] = p
	r.order = append(r.order, name)
	
	log.Printf("Plugin registered: %s - %s", name, p.Description())
	return nil
}

// Enable activates a plugin
func (r *Registry) Enable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	p, exists := r.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}
	
	if r.enabled[name] {
		return fmt.Errorf("plugin %s already enabled", name)
	}
	
	// Enable dependencies first
	if dp, ok := p.(DependentPlugin); ok {
		for _, dep := range dp.Dependencies() {
			if !r.enabled[dep] {
				if err := r.enableInternal(dep); err != nil {
					return fmt.Errorf("failed to enable dependency %s: %w", dep, err)
				}
			}
		}
	}
	
	// Initialize the plugin
	if err := p.Init(r.context); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
	}
	
	// Call OnStart if implemented
	if lp, ok := p.(LifecyclePlugin); ok {
		if err := lp.OnStart(); err != nil {
			// Cleanup on failure
			p.Cleanup()
			return fmt.Errorf("plugin %s OnStart failed: %w", name, err)
		}
	}
	
	r.enabled[name] = true
	log.Printf("Plugin enabled: %s", name)
	return nil
}

// enableInternal enables a plugin without locking (used internally)
func (r *Registry) enableInternal(name string) error {
	p, exists := r.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}
	
	if r.enabled[name] {
		return nil
	}
	
	if err := p.Init(r.context); err != nil {
		return err
	}
	
	if lp, ok := p.(LifecyclePlugin); ok {
		if err := lp.OnStart(); err != nil {
			p.Cleanup()
			return err
		}
	}
	
	r.enabled[name] = true
	return nil
}

// Disable deactivates a plugin
func (r *Registry) Disable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if !r.enabled[name] {
		return fmt.Errorf("plugin %s not enabled", name)
	}
	
	// Check if other enabled plugins depend on this one
	for pname, plugin := range r.plugins {
		if !r.enabled[pname] || pname == name {
			continue
		}
		
		if dp, ok := plugin.(DependentPlugin); ok {
			for _, dep := range dp.Dependencies() {
				if dep == name {
					return fmt.Errorf("cannot disable %s: plugin %s depends on it", name, pname)
				}
			}
		}
	}
	
	p := r.plugins[name]
	
	// Call OnStop if implemented
	if lp, ok := p.(LifecyclePlugin); ok {
		if err := lp.OnStop(); err != nil {
			log.Printf("Warning: plugin %s OnStop failed: %v", name, err)
		}
	}
	
	// Cleanup
	if err := p.Cleanup(); err != nil {
		log.Printf("Warning: plugin %s cleanup failed: %v", name, err)
	}
	
	r.enabled[name] = false
	log.Printf("Plugin disabled: %s", name)
	return nil
}

// Get returns a plugin by name
func (r *Registry) Get(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	p, exists := r.plugins[name]
	return p, exists
}

// IsEnabled checks if a plugin is enabled
func (r *Registry) IsEnabled(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	return r.enabled[name]
}

// EnabledPlugins returns all enabled plugins in registration order
func (r *Registry) EnabledPlugins() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	result := make([]Plugin, 0)
	for _, name := range r.order {
		if r.enabled[name] {
			result = append(result, r.plugins[name])
		}
	}
	
	return result
}

// AllPlugins returns all registered plugins
func (r *Registry) AllPlugins() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	result := make([]Plugin, 0, len(r.plugins))
	for _, name := range r.order {
		result = append(result, r.plugins[name])
	}
	
	return result
}

// CollectRoutes gathers all routes from enabled plugins
func (r *Registry) CollectRoutes() []Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var routes []Route
	for _, name := range r.order {
		if r.enabled[name] {
			routes = append(routes, r.plugins[name].Routes()...)
		}
	}
	
	return routes
}

// CollectMiddleware gathers all middleware from enabled plugins, sorted by priority
func (r *Registry) CollectMiddleware() []func(http.Handler) http.Handler {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var middlewares []Middleware
	for _, name := range r.order {
		if r.enabled[name] {
			middlewares = append(middlewares, r.plugins[name].Middleware()...)
		}
	}
	
	// Sort by priority
	sort.Slice(middlewares, func(i, j int) bool {
		return middlewares[i].Priority < middlewares[j].Priority
	})
	
	// Extract handlers
	handlers := make([]func(http.Handler) http.Handler, len(middlewares))
	for i, m := range middlewares {
		handlers[i] = m.Handler
	}
	
	return handlers
}

// CollectMigrations gathers all migrations from enabled plugins
func (r *Registry) CollectMigrations() []database.Migration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var migrations []database.Migration
	for _, name := range r.order {
		if r.enabled[name] {
			migrations = append(migrations, r.plugins[name].Migrations()...)
		}
	}
	
	return migrations
}

// CollectRequiredTables gathers all required tables from enabled plugins
func (r *Registry) CollectRequiredTables() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	tableMap := make(map[string]bool)
	for _, name := range r.order {
		if r.enabled[name] {
			for _, table := range r.plugins[name].RequiredTables() {
				tableMap[table] = true
			}
		}
	}
	
	// Convert to slice
	tables := make([]string, 0, len(tableMap))
	for table := range tableMap {
		tables = append(tables, table)
	}
	
	sort.Strings(tables)
	return tables
}