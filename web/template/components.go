package template

import (
	"fmt"
	"html/template"
	"strings"
)

// Component represents a reusable UI component
type Component struct {
	Name     string
	Template string
	Props    map[string]interface{}
	Slots    map[string]template.HTML
	registry *ComponentRegistry // Add reference to registry
}

// ComponentRegistry manages reusable components
type ComponentRegistry struct {
	components map[string]*ComponentDefinition
	manager    *Manager
}

// ComponentDefinition defines a component template
type ComponentDefinition struct {
	Name         string
	Template     string
	DefaultProps map[string]interface{}
	RequiredProps []string
}

// NewComponentRegistry creates a new component registry
func NewComponentRegistry(manager *Manager) *ComponentRegistry {
	registry := &ComponentRegistry{
		components: make(map[string]*ComponentDefinition),
		manager:    manager,
	}

	// Register component helper functions
	manager.AddFunc("component", registry.renderComponent)
	manager.AddFunc("slot", registry.renderSlot)

	return registry
}

// Register registers a new component
func (r *ComponentRegistry) Register(name string, definition ComponentDefinition) error {
	definition.Name = name
	r.components[name] = &definition

	// Register the component template
	return r.manager.RegisterString("component:"+name, definition.Template)
}

// Component creates a component instance
func (r *ComponentRegistry) Component(name string, props ...map[string]interface{}) *Component {
	def, exists := r.components[name]
	if !exists {
		return nil
	}

	component := &Component{
		Name:     name,
		Props:    make(map[string]interface{}),
		Slots:    make(map[string]template.HTML),
		registry: r, // Set registry reference
	}

	// Apply default props
	for k, v := range def.DefaultProps {
		component.Props[k] = v
	}

	// Apply provided props
	if len(props) > 0 {
		for k, v := range props[0] {
			component.Props[k] = v
		}
	}

	return component
}

// Slot adds a slot to the component
func (c *Component) Slot(name string, content string) *Component {
	c.Slots[name] = template.HTML(content)
	return c
}

// Render renders the component
func (c *Component) Render() (template.HTML, error) {
	data := map[string]interface{}{
		"Props": c.Props,
		"Slots": c.Slots,
	}

	rendered, err := c.registry.manager.RenderToString("component:"+c.Name, data)
	if err != nil {
		return "", err
	}

	return template.HTML(rendered), nil
}

// renderComponent is a template function for rendering components
func (r *ComponentRegistry) renderComponent(name string, props ...interface{}) (template.HTML, error) {
	component := r.Component(name)
	if component == nil {
		return "", fmt.Errorf("component %s not found", name)
	}

	// Parse props if provided
	if len(props) > 0 {
		if propsMap, ok := props[0].(map[string]interface{}); ok {
			for k, v := range propsMap {
				component.Props[k] = v
			}
		}
	}

	return component.Render()
}

// renderSlot is a template function for rendering slots
func (r *ComponentRegistry) renderSlot(name string, slots map[string]template.HTML) template.HTML {
	if content, exists := slots[name]; exists {
		return content
	}
	return ""
}

// Built-in Components

// RegisterBuiltinComponents registers common UI components
func (r *ComponentRegistry) RegisterBuiltinComponents() error {
	// Alert component
	err := r.Register("alert", ComponentDefinition{
		Template: `<div class="alert alert-{{ .Props.type }} {{ .Props.class }}" role="alert">
			{{ if .Props.dismissible }}
			<button type="button" class="close" data-dismiss="alert" aria-label="Close">
				<span aria-hidden="true">&times;</span>
			</button>
			{{ end }}
			{{ if .Props.icon }}<i class="fas fa-{{ .Props.icon }} mr-2"></i>{{ end }}
			{{ if .Props.title }}<strong>{{ .Props.title }}</strong>{{ if .Props.message }}: {{ end }}{{ end }}
			{{ .Props.message }}
			{{ slot "content" .Slots }}
		</div>`,
		DefaultProps: map[string]interface{}{
			"type":        "info",
			"dismissible": false,
			"class":       "",
		},
	})
	if err != nil {
		return err
	}

	// Card component
	err = r.Register("card", ComponentDefinition{
		Template: `<div class="card {{ .Props.class }}">
			{{ if or .Props.title (slot "header" .Slots) }}
			<div class="card-header">
				{{ if .Props.title }}<h5 class="card-title mb-0">{{ .Props.title }}</h5>{{ end }}
				{{ slot "header" .Slots }}
			</div>
			{{ end }}
			<div class="card-body">
				{{ slot "body" .Slots }}
			</div>
			{{ if slot "footer" .Slots }}
			<div class="card-footer">
				{{ slot "footer" .Slots }}
			</div>
			{{ end }}
		</div>`,
		DefaultProps: map[string]interface{}{
			"class": "",
		},
	})
	if err != nil {
		return err
	}

	// Modal component
	err = r.Register("modal", ComponentDefinition{
		Template: `<div class="modal fade" id="{{ .Props.id }}" tabindex="-1" role="dialog">
			<div class="modal-dialog {{ .Props.size }}" role="document">
				<div class="modal-content">
					<div class="modal-header">
						<h5 class="modal-title">{{ .Props.title }}</h5>
						<button type="button" class="close" data-dismiss="modal" aria-label="Close">
							<span aria-hidden="true">&times;</span>
						</button>
					</div>
					<div class="modal-body">
						{{ slot "body" .Slots }}
					</div>
					{{ if slot "footer" .Slots }}
					<div class="modal-footer">
						{{ slot "footer" .Slots }}
					</div>
					{{ end }}
				</div>
			</div>
		</div>`,
		RequiredProps: []string{"id", "title"},
		DefaultProps: map[string]interface{}{
			"size": "",
		},
	})
	if err != nil {
		return err
	}

	// Badge component
	err = r.Register("badge", ComponentDefinition{
		Template: `<span class="badge badge-{{ .Props.type }} {{ .Props.class }}">
			{{ if .Props.icon }}<i class="fas fa-{{ .Props.icon }} mr-1"></i>{{ end }}
			{{ .Props.text }}
		</span>`,
		DefaultProps: map[string]interface{}{
			"type":  "secondary",
			"class": "",
		},
		RequiredProps: []string{"text"},
	})
	if err != nil {
		return err
	}

	// Button component
	err = r.Register("button", ComponentDefinition{
		Template: `<button type="{{ .Props.type }}" 
			class="btn btn-{{ .Props.variant }} {{ .Props.size }} {{ .Props.class }}"
			{{ if .Props.disabled }}disabled{{ end }}
			{{ if .Props.loading }}disabled{{ end }}
			{{ range $k, $v := .Props.attrs }}{{ $k }}="{{ $v }}" {{ end }}>
			{{ if .Props.loading }}
				<span class="spinner-border spinner-border-sm mr-2" role="status" aria-hidden="true"></span>
			{{ else if .Props.icon }}
				<i class="fas fa-{{ .Props.icon }} {{ if .Props.text }}mr-2{{ end }}"></i>
			{{ end }}
			{{ .Props.text }}
			{{ slot "content" .Slots }}
		</button>`,
		DefaultProps: map[string]interface{}{
			"type":     "button",
			"variant":  "primary",
			"size":     "",
			"class":    "",
			"disabled": false,
			"loading":  false,
			"attrs":    map[string]string{},
		},
	})
	if err != nil {
		return err
	}

	// Progress component
	err = r.Register("progress", ComponentDefinition{
		Template: `<div class="progress {{ .Props.class }}" style="height: {{ .Props.height }};">
			<div class="progress-bar {{ .Props.barClass }} {{ if .Props.striped }}progress-bar-striped{{ end }} {{ if .Props.animated }}progress-bar-animated{{ end }}"
				role="progressbar" 
				style="width: {{ .Props.value }}%"
				aria-valuenow="{{ .Props.value }}" 
				aria-valuemin="0" 
				aria-valuemax="100">
				{{ if .Props.showLabel }}{{ .Props.value }}%{{ end }}
			</div>
		</div>`,
		DefaultProps: map[string]interface{}{
			"value":     0,
			"height":    "1rem",
			"class":     "",
			"barClass":  "",
			"striped":   false,
			"animated":  false,
			"showLabel": false,
		},
	})
	if err != nil {
		return err
	}

	// Dropdown component
	err = r.Register("dropdown", ComponentDefinition{
		Template: `<div class="dropdown {{ if .Props.dropup }}dropup{{ end }} {{ .Props.class }}">
			<button class="btn btn-{{ .Props.variant }} dropdown-toggle" 
				type="button" 
				id="{{ .Props.id }}" 
				data-toggle="dropdown" 
				aria-haspopup="true" 
				aria-expanded="false">
				{{ if .Props.icon }}<i class="fas fa-{{ .Props.icon }} mr-2"></i>{{ end }}
				{{ .Props.text }}
			</button>
			<div class="dropdown-menu {{ .Props.menuClass }}" aria-labelledby="{{ .Props.id }}">
				{{ slot "items" .Slots }}
			</div>
		</div>`,
		RequiredProps: []string{"id", "text"},
		DefaultProps: map[string]interface{}{
			"variant":   "secondary",
			"class":     "",
			"menuClass": "",
			"dropup":    false,
		},
	})
	if err != nil {
		return err
	}

	// Tabs component
	err = r.Register("tabs", ComponentDefinition{
		Template: `<div class="{{ .Props.class }}">
			<ul class="nav nav-{{ .Props.type }}" id="{{ .Props.id }}" role="tablist">
				{{ range $i, $tab := .Props.tabs }}
				<li class="nav-item">
					<a class="nav-link {{ if eq $i 0 }}active{{ end }}" 
						id="{{ $.Props.id }}-{{ $tab.id }}-tab" 
						data-toggle="tab" 
						href="#{{ $.Props.id }}-{{ $tab.id }}" 
						role="tab">
						{{ if $tab.icon }}<i class="fas fa-{{ $tab.icon }} mr-2"></i>{{ end }}
						{{ $tab.title }}
					</a>
				</li>
				{{ end }}
			</ul>
			<div class="tab-content {{ .Props.contentClass }}" id="{{ .Props.id }}-content">
				{{ slot "content" .Slots }}
			</div>
		</div>`,
		RequiredProps: []string{"id", "tabs"},
		DefaultProps: map[string]interface{}{
			"type":         "tabs",
			"class":        "",
			"contentClass": "pt-3",
		},
	})

	return err
}

// ComponentBuilder provides a fluent API for building components
type ComponentBuilder struct {
	registry *ComponentRegistry
	name     string
	props    map[string]interface{}
	slots    map[string]string
}

// NewComponentBuilder creates a new component builder
func (r *ComponentRegistry) NewComponentBuilder(name string) *ComponentBuilder {
	return &ComponentBuilder{
		registry: r,
		name:     name,
		props:    make(map[string]interface{}),
		slots:    make(map[string]string),
	}
}

// Prop sets a component property
func (b *ComponentBuilder) Prop(key string, value interface{}) *ComponentBuilder {
	b.props[key] = value
	return b
}

// Props sets multiple properties
func (b *ComponentBuilder) Props(props map[string]interface{}) *ComponentBuilder {
	for k, v := range props {
		b.props[k] = v
	}
	return b
}

// Slot sets a component slot
func (b *ComponentBuilder) Slot(name, content string) *ComponentBuilder {
	b.slots[name] = content
	return b
}

// Build builds and returns the component HTML
func (b *ComponentBuilder) Build() (template.HTML, error) {
	component := b.registry.Component(b.name, b.props)
	if component == nil {
		return "", fmt.Errorf("component %s not found", b.name)
	}

	for name, content := range b.slots {
		component.Slot(name, content)
	}

	return component.Render()
}

// String implements Stringer interface
func (b *ComponentBuilder) String() string {
	html, err := b.Build()
	if err != nil {
		return fmt.Sprintf("<!-- Error building component: %s -->", err)
	}
	return string(html)
}

// Helper function to create CSS classes
func Classes(classes ...string) string {
	var validClasses []string
	for _, class := range classes {
		class = strings.TrimSpace(class)
		if class != "" {
			validClasses = append(validClasses, class)
		}
	}
	return strings.Join(validClasses, " ")
}