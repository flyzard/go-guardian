package template

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"strings"
	"sync"
)

// Manager provides advanced template management for web applications
type Manager struct {
	templates   map[string]*template.Template
	funcMap     template.FuncMap
	baseDir     string
	extension   string
	delims      Delimiters
	mu          sync.RWMutex
	development bool
	cache       map[string]*cachedRender
}

// Delimiters defines custom template delimiters
type Delimiters struct {
	Left  string
	Right string
}

// Config holds template manager configuration
type Config struct {
	BaseDir     string
	Extension   string
	FuncMap     template.FuncMap
	Delims      Delimiters
	Development bool // Reload templates on each request in dev mode
}

// cachedRender stores cached template renders
type cachedRender struct {
	content []byte
	modTime int64
}

// NewManager creates a new template manager
func NewManager(config Config) *Manager {
	if config.Extension == "" {
		config.Extension = ".html"
	}
	if config.Delims.Left == "" {
		config.Delims = Delimiters{Left: "{{", Right: "}}"}
	}

	m := &Manager{
		templates:   make(map[string]*template.Template),
		funcMap:     mergeFuncMaps(defaultFuncMap(), config.FuncMap),
		baseDir:     config.BaseDir,
		extension:   config.Extension,
		delims:      config.Delims,
		development: config.Development,
		cache:       make(map[string]*cachedRender),
	}

	return m
}

// Register loads and registers a template
func (m *Manager) Register(name string, patterns ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build full paths
	fullPatterns := make([]string, len(patterns))
	for i, pattern := range patterns {
		fullPatterns[i] = filepath.Join(m.baseDir, pattern)
	}

	// Create and parse template
	tmpl := template.New(name).
		Funcs(m.funcMap).
		Delims(m.delims.Left, m.delims.Right)

	tmpl, err := tmpl.ParseGlob(fullPatterns[0])
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %w", name, err)
	}

	// Parse additional patterns
	for i := 1; i < len(fullPatterns); i++ {
		tmpl, err = tmpl.ParseGlob(fullPatterns[i])
		if err != nil {
			return fmt.Errorf("failed to parse template pattern %s: %w", fullPatterns[i], err)
		}
	}

	m.templates[name] = tmpl
	return nil
}

// RegisterString registers a template from string
func (m *Manager) RegisterString(name, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tmpl := template.New(name).
		Funcs(m.funcMap).
		Delims(m.delims.Left, m.delims.Right)

	tmpl, err := tmpl.Parse(content)
	if err != nil {
		return fmt.Errorf("failed to parse template string %s: %w", name, err)
	}

	m.templates[name] = tmpl
	return nil
}

// Render renders a template with the given data
func (m *Manager) Render(w io.Writer, name string, data interface{}) error {
	// In development mode, reload template
	if m.development {
		// This would typically reload from disk
		// For now, we'll just skip caching
	}

	m.mu.RLock()
	tmpl, exists := m.templates[name]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("template %s not found", name)
	}

	return tmpl.Execute(w, data)
}

// RenderToString renders a template to a string
func (m *Manager) RenderToString(name string, data interface{}) (string, error) {
	var buf bytes.Buffer
	err := m.Render(&buf, name, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderPartial renders a specific template within a template set
func (m *Manager) RenderPartial(w io.Writer, templateSet, partialName string, data interface{}) error {
	m.mu.RLock()
	tmpl, exists := m.templates[templateSet]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("template set %s not found", templateSet)
	}

	return tmpl.ExecuteTemplate(w, partialName, data)
}

// AddFunc adds a template function
func (m *Manager) AddFunc(name string, fn interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.funcMap[name] = fn

	// Update all existing templates
	for _, tmpl := range m.templates {
		tmpl.Funcs(m.funcMap)
	}
}

// Clone creates a copy of the template manager with a new function map
func (m *Manager) Clone() *Manager {
	m.mu.RLock()
	defer m.mu.RUnlock()

	newManager := &Manager{
		templates:   make(map[string]*template.Template),
		funcMap:     make(template.FuncMap),
		baseDir:     m.baseDir,
		extension:   m.extension,
		delims:      m.delims,
		development: m.development,
		cache:       make(map[string]*cachedRender),
	}

	// Copy function map
	for k, v := range m.funcMap {
		newManager.funcMap[k] = v
	}

	// Clone templates
	for name, tmpl := range m.templates {
		cloned, _ := tmpl.Clone()
		newManager.templates[name] = cloned
	}

	return newManager
}

// Layout provides layout/partial rendering support
type Layout struct {
	manager      *Manager
	name         string
	sections     map[string]string
	sectionData  map[string]interface{}
	mainData     interface{}
}

// NewLayout creates a new layout renderer
func (m *Manager) NewLayout(name string) *Layout {
	return &Layout{
		manager:     m,
		name:        name,
		sections:    make(map[string]string),
		sectionData: make(map[string]interface{}),
	}
}

// Section defines a layout section
func (l *Layout) Section(name, content string, data ...interface{}) *Layout {
	l.sections[name] = content
	if len(data) > 0 {
		l.sectionData[name] = data[0]
	}
	return l
}

// Data sets the main data for the layout
func (l *Layout) Data(data interface{}) *Layout {
	l.mainData = data
	return l
}

// Render renders the layout
func (l *Layout) Render(w io.Writer) error {
	// Prepare layout data
	layoutData := map[string]interface{}{
		"Sections":    l.sections,
		"SectionData": l.sectionData,
		"Data":        l.mainData,
		"Yield": func(section string) template.HTML {
			content, exists := l.sections[section]
			if !exists {
				return ""
			}
			
			// Render section if it's a template name
			if strings.HasPrefix(content, "@") {
				templateName := strings.TrimPrefix(content, "@")
				rendered, err := l.manager.RenderToString(templateName, l.sectionData[section])
				if err != nil {
					return template.HTML("<!-- Error rendering section: " + err.Error() + " -->")
				}
				return template.HTML(rendered)
			}
			
			return template.HTML(content)
		},
	}

	return l.manager.Render(w, l.name, layoutData)
}

// Helper functions

func defaultFuncMap() template.FuncMap {
	return template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"title": strings.Title,
		"trim":  strings.TrimSpace,
		"join":  strings.Join,
		"split": strings.Split,
		"contains": strings.Contains,
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,
		"replace": strings.Replace,
		"replaceAll": strings.ReplaceAll,
		"html": func(s string) template.HTML {
			return template.HTML(s)
		},
		"css": func(s string) template.CSS {
			return template.CSS(s)
		},
		"js": func(s string) template.JS {
			return template.JS(s)
		},
		"attr": func(s string) template.HTMLAttr {
			return template.HTMLAttr(s)
		},
		"url": func(s string) template.URL {
			return template.URL(s)
		},
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"safeCSS": func(s string) template.CSS {
			return template.CSS(s)
		},
		"safeJS": func(s string) template.JS {
			return template.JS(s)
		},
		"dict": func(values ...interface{}) (map[string]interface{}, error) {
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("dict requires even number of arguments")
			}
			dict := make(map[string]interface{})
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				dict[key] = values[i+1]
			}
			return dict, nil
		},
		"list": func(values ...interface{}) []interface{} {
			return values
		},
	}
}

func mergeFuncMaps(maps ...template.FuncMap) template.FuncMap {
	merged := make(template.FuncMap)
	for _, m := range maps {
		for k, v := range m {
			merged[k] = v
		}
	}
	return merged
}