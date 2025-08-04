package form

import (
	"fmt"
	"html/template"
	"strings"
)

// Builder provides a fluent API for building HTML forms
type Builder struct {
	name       string
	id         string
	class      string
	method     string
	action     string
	fields     []Field
	attributes map[string]string
	htmxAttrs  map[string]string
	csrf       *CSRFConfig
	errors     map[string]string
}

// CSRFConfig holds CSRF token configuration
type CSRFConfig struct {
	Token     string
	FieldName string
}

// New creates a new form builder
func New(name string) *Builder {
	return &Builder{
		name:       name,
		id:         name + "-form",
		method:     "POST",
		fields:     []Field{},
		attributes: make(map[string]string),
		htmxAttrs:  make(map[string]string),
		errors:     make(map[string]string),
	}
}

// ID sets the form ID
func (b *Builder) ID(id string) *Builder {
	b.id = id
	return b
}

// Class sets the form CSS class
func (b *Builder) Class(class string) *Builder {
	b.class = class
	return b
}

// Method sets the form method (GET, POST, etc.)
func (b *Builder) Method(method string) *Builder {
	b.method = strings.ToUpper(method)
	return b
}

// Action sets the form action URL
func (b *Builder) Action(action string) *Builder {
	b.action = action
	return b
}

// Attr adds a custom HTML attribute
func (b *Builder) Attr(key, value string) *Builder {
	b.attributes[key] = value
	return b
}

// AddField adds a field to the form
func (b *Builder) AddField(field Field) *Builder {
	b.fields = append(b.fields, field)
	return b
}

// WithCSRF adds CSRF protection to the form
func (b *Builder) WithCSRF(token string) *Builder {
	b.csrf = &CSRFConfig{
		Token:     token,
		FieldName: "_csrf",
	}
	return b
}

// WithCSRFConfig adds CSRF protection with custom configuration
func (b *Builder) WithCSRFConfig(config *CSRFConfig) *Builder {
	b.csrf = config
	return b
}

// HTMXPost configures the form for HTMX POST requests
func (b *Builder) HTMXPost(url, target string) *Builder {
	b.htmxAttrs["hx-post"] = url
	b.htmxAttrs["hx-target"] = target
	return b
}

// HTMXGet configures the form for HTMX GET requests
func (b *Builder) HTMXGet(url, target string) *Builder {
	b.htmxAttrs["hx-get"] = url
	b.htmxAttrs["hx-target"] = target
	return b
}

// HTMXPut configures the form for HTMX PUT requests
func (b *Builder) HTMXPut(url, target string) *Builder {
	b.htmxAttrs["hx-put"] = url
	b.htmxAttrs["hx-target"] = target
	return b
}

// HTMXDelete configures the form for HTMX DELETE requests
func (b *Builder) HTMXDelete(url, target string) *Builder {
	b.htmxAttrs["hx-delete"] = url
	b.htmxAttrs["hx-target"] = target
	return b
}

// HTMXSwap sets the HTMX swap mode
func (b *Builder) HTMXSwap(swap string) *Builder {
	b.htmxAttrs["hx-swap"] = swap
	return b
}

// HTMXTrigger sets the HTMX trigger
func (b *Builder) HTMXTrigger(trigger string) *Builder {
	b.htmxAttrs["hx-trigger"] = trigger
	return b
}

// HTMXIndicator sets the HTMX loading indicator
func (b *Builder) HTMXIndicator(indicator string) *Builder {
	b.htmxAttrs["hx-indicator"] = indicator
	return b
}

// HTMXConfirm sets the HTMX confirmation message
func (b *Builder) HTMXConfirm(message string) *Builder {
	b.htmxAttrs["hx-confirm"] = message
	return b
}

// HTMXBoost enables HTMX boost for the form
func (b *Builder) HTMXBoost() *Builder {
	b.htmxAttrs["hx-boost"] = "true"
	return b
}

// HTMXPushURL configures URL pushing behavior
func (b *Builder) HTMXPushURL(value string) *Builder {
	b.htmxAttrs["hx-push-url"] = value
	return b
}

// HTMXHeaders adds custom headers to HTMX requests
func (b *Builder) HTMXHeaders(headers map[string]string) *Builder {
	pairs := make([]string, 0, len(headers))
	for k, v := range headers {
		pairs = append(pairs, fmt.Sprintf(`"%s": "%s"`, k, v))
	}
	b.htmxAttrs["hx-headers"] = fmt.Sprintf(`{%s}`, strings.Join(pairs, ", "))
	return b
}

// WithErrors sets form errors for display
func (b *Builder) WithErrors(errors map[string]string) *Builder {
	b.errors = errors
	return b
}

// WithError sets a single field error
func (b *Builder) WithError(field, message string) *Builder {
	b.errors[field] = message
	return b
}

// Render generates the HTML for the form
func (b *Builder) Render() template.HTML {
	var sb strings.Builder

	// Build form attributes
	attrs := []string{
		fmt.Sprintf(`id="%s"`, b.id),
		fmt.Sprintf(`name="%s"`, b.name),
		fmt.Sprintf(`method="%s"`, b.method),
	}

	if b.action != "" {
		attrs = append(attrs, fmt.Sprintf(`action="%s"`, b.action))
	}

	if b.class != "" {
		attrs = append(attrs, fmt.Sprintf(`class="%s"`, b.class))
	}

	// Add custom attributes
	for k, v := range b.attributes {
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, k, v))
	}

	// Add HTMX attributes
	for k, v := range b.htmxAttrs {
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, k, v))
	}

	// Start form tag
	sb.WriteString(fmt.Sprintf(`<form %s>`, strings.Join(attrs, " ")))
	sb.WriteString("\n")

	// Add CSRF token if configured
	if b.csrf != nil {
		sb.WriteString(fmt.Sprintf(`  <input type="hidden" name="%s" value="%s">`,
			b.csrf.FieldName, b.csrf.Token))
		sb.WriteString("\n")
	}

	// Render fields
	for _, field := range b.fields {
		// Check if field has an error
		fieldError := ""
		if err, ok := b.errors[field.GetName()]; ok {
			fieldError = err
		}
		
		sb.WriteString(field.Render(fieldError))
		sb.WriteString("\n")
	}

	// Close form tag
	sb.WriteString("</form>")

	return template.HTML(sb.String())
}

// RenderField renders a single field (useful for HTMX partial updates)
func (b *Builder) RenderField(fieldName string) template.HTML {
	for _, field := range b.fields {
		if field.GetName() == fieldName {
			fieldError := ""
			if err, ok := b.errors[fieldName]; ok {
				fieldError = err
			}
			return template.HTML(field.Render(fieldError))
		}
	}
	return ""
}

// GetField retrieves a field by name
func (b *Builder) GetField(name string) Field {
	for _, field := range b.fields {
		if field.GetName() == name {
			return field
		}
	}
	return nil
}

// RemoveField removes a field by name
func (b *Builder) RemoveField(name string) *Builder {
	newFields := make([]Field, 0, len(b.fields))
	for _, field := range b.fields {
		if field.GetName() != name {
			newFields = append(newFields, field)
		}
	}
	b.fields = newFields
	return b
}

// Clear removes all fields from the form
func (b *Builder) Clear() *Builder {
	b.fields = []Field{}
	b.errors = make(map[string]string)
	return b
}