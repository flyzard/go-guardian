package plugin_test

import (
	"testing"

	"github.com/flyzard/go-guardian/plugin"
)

func TestLoader(t *testing.T) {
	ctx := &plugin.Context{
		Config: make(map[string]interface{}),
	}
	registry := plugin.NewRegistry(ctx)
	loader := plugin.NewLoader(registry)

	// Register some mock plugins
	registry.Register(NewMockPlugin("csrf"))
	registry.Register(NewMockPlugin("auth"))
	registry.Register(NewMockPlugin("rbac"))

	t.Run("LoadConfig", func(t *testing.T) {
		config := map[string]interface{}{
			"secure": true,
			"paths":  []string{"/api", "/admin"},
		}

		err := loader.LoadConfig("csrf", config)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Try to load config for non-existent plugin
		err = loader.LoadConfig("nonexistent", config)
		if err == nil {
			t.Fatal("Expected error when loading config for non-existent plugin")
		}
	})

	t.Run("GetConfig", func(t *testing.T) {
		config, exists := loader.GetConfig("csrf")
		if !exists {
			t.Fatal("Config should exist for csrf plugin")
		}

		if config == nil {
			t.Fatal("Config should not be nil")
		}

		_, exists = loader.GetConfig("auth")
		if exists {
			t.Fatal("Config should not exist for auth plugin")
		}
	})

	t.Run("EnableList", func(t *testing.T) {
		plugins := []string{"csrf", "auth"}
		err := loader.EnableList(plugins)
		if err != nil {
			t.Fatalf("Failed to enable plugins: %v", err)
		}

		if !registry.IsEnabled("csrf") {
			t.Fatal("CSRF plugin should be enabled")
		}

		if !registry.IsEnabled("auth") {
			t.Fatal("Auth plugin should be enabled")
		}

		if registry.IsEnabled("rbac") {
			t.Fatal("RBAC plugin should not be enabled")
		}
	})

	t.Run("EnableFromFeatures", func(t *testing.T) {
		// Create new registry for clean test
		registry2 := plugin.NewRegistry(ctx)
		loader2 := plugin.NewLoader(registry2)

		// Register plugins
		registry2.Register(NewMockPlugin("csrf"))
		registry2.Register(NewMockPlugin("auth"))
		registry2.Register(NewMockPlugin("rbac"))

		features := map[string]bool{
			"csrf":              true,
			"email_verification": true,  // Maps to auth
			"password_reset":    true,  // Maps to auth
			"rbac":              false, // Should not enable
		}

		err := loader2.EnableFromFeatures(features)
		if err != nil {
			t.Fatalf("Failed to enable from features: %v", err)
		}

		if !registry2.IsEnabled("csrf") {
			t.Fatal("CSRF plugin should be enabled")
		}

		if !registry2.IsEnabled("auth") {
			t.Fatal("Auth plugin should be enabled (via email_verification)")
		}

		if registry2.IsEnabled("rbac") {
			t.Fatal("RBAC plugin should not be enabled")
		}
	})
}

// ConfigurableMockPlugin implements ConfigurablePlugin interface
type ConfigurableMockPlugin struct {
	MockPlugin
	defaultConfig interface{}
}

func NewConfigurableMockPlugin(name string) *ConfigurableMockPlugin {
	return &ConfigurableMockPlugin{
		MockPlugin: MockPlugin{name: name},
		defaultConfig: map[string]interface{}{
			"enabled": true,
			"timeout": 30,
		},
	}
}

func (p *ConfigurableMockPlugin) DefaultConfig() interface{} {
	return p.defaultConfig
}

func (p *ConfigurableMockPlugin) ValidateConfig(config interface{}) error {
	// Simple validation - just check it's a map
	_, ok := config.(map[string]interface{})
	if !ok {
		return plugin.ErrInvalidConfig
	}
	return nil
}

func TestLoaderWithConfigurablePlugin(t *testing.T) {
	ctx := &plugin.Context{
		Config: make(map[string]interface{}),
	}
	registry := plugin.NewRegistry(ctx)
	loader := plugin.NewLoader(registry)

	// Register configurable plugin
	cp := NewConfigurableMockPlugin("configurable")
	registry.Register(cp)

	t.Run("ValidateConfig", func(t *testing.T) {
		// Valid config
		validConfig := map[string]interface{}{
			"enabled": false,
			"timeout": 60,
		}
		err := loader.LoadConfig("configurable", validConfig)
		if err != nil {
			t.Fatalf("Failed to load valid config: %v", err)
		}

		// Invalid config
		invalidConfig := "not a map"
		err = loader.LoadConfig("configurable", invalidConfig)
		if err == nil {
			t.Fatal("Expected error when loading invalid config")
		}
	})
}