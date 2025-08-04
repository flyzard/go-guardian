package plugin

import (
	"fmt"
	"log"
)

// Loader handles plugin loading and configuration
type Loader struct {
	registry *Registry
	config   map[string]interface{}
}

// NewLoader creates a new plugin loader
func NewLoader(registry *Registry) *Loader {
	return &Loader{
		registry: registry,
		config:   make(map[string]interface{}),
	}
}

// LoadConfig sets configuration for a plugin
func (l *Loader) LoadConfig(pluginName string, config interface{}) error {
	p, exists := l.registry.Get(pluginName)
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}
	
	// Validate config if plugin supports it
	if cp, ok := p.(ConfigurablePlugin); ok {
		if err := cp.ValidateConfig(config); err != nil {
			return fmt.Errorf("invalid config for plugin %s: %w", pluginName, err)
		}
	}
	
	l.config[pluginName] = config
	return nil
}

// GetConfig retrieves configuration for a plugin
func (l *Loader) GetConfig(pluginName string) (interface{}, bool) {
	config, exists := l.config[pluginName]
	return config, exists
}

// EnableFromFeatures enables plugins based on feature flags
// This provides backward compatibility with the existing feature system
func (l *Loader) EnableFromFeatures(features map[string]bool) error {
	// Map old feature flags to new plugins
	featureToPlugin := map[string]string{
		"csrf":              "csrf",
		"email_verification": "auth",
		"password_reset":    "auth",
		"remember_me":       "auth",
		"rbac":              "rbac",
		"external_auth":     "external_auth",
	}
	
	enabledPlugins := make(map[string]bool)
	
	// Determine which plugins to enable based on features
	for feature, enabled := range features {
		if enabled {
			if pluginName, ok := featureToPlugin[feature]; ok {
				enabledPlugins[pluginName] = true
			}
		}
	}
	
	// Enable plugins
	for pluginName := range enabledPlugins {
		if err := l.registry.Enable(pluginName); err != nil {
			// Log warning but continue with other plugins
			log.Printf("Warning: failed to enable plugin %s: %v", pluginName, err)
		}
	}
	
	return nil
}

// EnableList enables multiple plugins by name
func (l *Loader) EnableList(plugins []string) error {
	var errors []error
	
	for _, name := range plugins {
		if err := l.registry.Enable(name); err != nil {
			errors = append(errors, fmt.Errorf("plugin %s: %w", name, err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("failed to enable %d plugins", len(errors))
	}
	
	return nil
}

// AutoDiscover would be used for dynamic plugin loading in the future
// For now, plugins must be explicitly registered
func (l *Loader) AutoDiscover(path string) error {
	// This is a placeholder for future functionality
	// Could scan a directory for plugin files or use build tags
	log.Printf("Auto-discovery not yet implemented")
	return nil
}