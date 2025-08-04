package plugin_test

import (
	"net/http"
	"testing"

	"github.com/flyzard/go-guardian/database"
	"github.com/flyzard/go-guardian/plugin"
)

// MockPlugin implements a basic plugin for testing
type MockPlugin struct {
	name        string
	initialized bool
	enabled     bool
	cleanedUp   bool
}

func NewMockPlugin(name string) *MockPlugin {
	return &MockPlugin{name: name}
}

func (p *MockPlugin) Name() string        { return p.name }
func (p *MockPlugin) Description() string { return "Mock plugin for testing" }

func (p *MockPlugin) Init(ctx *plugin.Context) error {
	p.initialized = true
	return nil
}

func (p *MockPlugin) Routes() []plugin.Route {
	return []plugin.Route{
		{
			Method:      "GET",
			Path:        "/test",
			Handler:     http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			Description: "Test route",
		},
	}
}

func (p *MockPlugin) Middleware() []plugin.Middleware {
	return []plugin.Middleware{
		{
			Handler:     func(next http.Handler) http.Handler { return next },
			Priority:    50,
			Description: "Test middleware",
		},
	}
}

func (p *MockPlugin) Migrations() []database.Migration {
	return nil
}

func (p *MockPlugin) RequiredTables() []string {
	return []string{"test_table"}
}

func (p *MockPlugin) Cleanup() error {
	p.cleanedUp = true
	return nil
}

func TestRegistry(t *testing.T) {
	ctx := &plugin.Context{
		Config: make(map[string]interface{}),
	}
	registry := plugin.NewRegistry(ctx)

	t.Run("Register", func(t *testing.T) {
		p1 := NewMockPlugin("test1")
		err := registry.Register(p1)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}

		// Try to register again
		err = registry.Register(p1)
		if err == nil {
			t.Fatal("Expected error when registering duplicate plugin")
		}
	})

	t.Run("Enable", func(t *testing.T) {
		p2 := NewMockPlugin("test2")
		registry.Register(p2)

		err := registry.Enable("test2")
		if err != nil {
			t.Fatalf("Failed to enable plugin: %v", err)
		}

		if !p2.initialized {
			t.Fatal("Plugin was not initialized")
		}

		if !registry.IsEnabled("test2") {
			t.Fatal("Plugin should be enabled")
		}

		// Try to enable non-existent plugin
		err = registry.Enable("nonexistent")
		if err == nil {
			t.Fatal("Expected error when enabling non-existent plugin")
		}
	})

	t.Run("Disable", func(t *testing.T) {
		p3 := NewMockPlugin("test3")
		registry.Register(p3)
		registry.Enable("test3")

		err := registry.Disable("test3")
		if err != nil {
			t.Fatalf("Failed to disable plugin: %v", err)
		}

		if !p3.cleanedUp {
			t.Fatal("Plugin was not cleaned up")
		}

		if registry.IsEnabled("test3") {
			t.Fatal("Plugin should be disabled")
		}
	})

	t.Run("CollectRoutes", func(t *testing.T) {
		routes := registry.CollectRoutes()
		// Only test2 should be enabled from previous tests
		if len(routes) != 1 {
			t.Fatalf("Expected 1 route, got %d", len(routes))
		}
	})

	t.Run("CollectMiddleware", func(t *testing.T) {
		middleware := registry.CollectMiddleware()
		// Only test2 should be enabled from previous tests
		if len(middleware) != 1 {
			t.Fatalf("Expected 1 middleware, got %d", len(middleware))
		}
	})

	t.Run("CollectRequiredTables", func(t *testing.T) {
		tables := registry.CollectRequiredTables()
		// Only test2 should be enabled from previous tests
		if len(tables) != 1 || tables[0] != "test_table" {
			t.Fatalf("Expected [test_table], got %v", tables)
		}
	})
}

// DependentMockPlugin implements a plugin with dependencies
type DependentMockPlugin struct {
	MockPlugin
	deps []string
}

func NewDependentMockPlugin(name string, deps []string) *DependentMockPlugin {
	return &DependentMockPlugin{
		MockPlugin: MockPlugin{name: name},
		deps:       deps,
	}
}

func (p *DependentMockPlugin) Dependencies() []string {
	return p.deps
}

func TestRegistryDependencies(t *testing.T) {
	ctx := &plugin.Context{
		Config: make(map[string]interface{}),
	}
	registry := plugin.NewRegistry(ctx)

	t.Run("RegisterWithDependencies", func(t *testing.T) {
		// Register base plugin
		base := NewMockPlugin("base")
		registry.Register(base)

		// Register dependent plugin
		dep := NewDependentMockPlugin("dependent", []string{"base"})
		err := registry.Register(dep)
		if err != nil {
			t.Fatalf("Failed to register dependent plugin: %v", err)
		}

		// Try to register plugin with missing dependency
		bad := NewDependentMockPlugin("bad", []string{"missing"})
		err = registry.Register(bad)
		if err == nil {
			t.Fatal("Expected error when registering plugin with missing dependency")
		}
	})

	t.Run("EnableWithDependencies", func(t *testing.T) {
		// Enable dependent plugin - should enable base first
		err := registry.Enable("dependent")
		if err != nil {
			t.Fatalf("Failed to enable dependent plugin: %v", err)
		}

		if !registry.IsEnabled("base") {
			t.Fatal("Base plugin should be enabled as dependency")
		}

		if !registry.IsEnabled("dependent") {
			t.Fatal("Dependent plugin should be enabled")
		}
	})

	t.Run("DisableWithDependents", func(t *testing.T) {
		// Try to disable base plugin while dependent is enabled
		err := registry.Disable("base")
		if err == nil {
			t.Fatal("Expected error when disabling plugin with active dependents")
		}

		// Disable dependent first
		err = registry.Disable("dependent")
		if err != nil {
			t.Fatalf("Failed to disable dependent plugin: %v", err)
		}

		// Now should be able to disable base
		err = registry.Disable("base")
		if err != nil {
			t.Fatalf("Failed to disable base plugin: %v", err)
		}
	})
}