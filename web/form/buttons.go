package form

import (
	"fmt"
	"html"
	"strings"
)

// Button represents a form button
type Button struct {
	Type       string // submit, button, reset
	Name       string
	Value      string
	Text       string
	Class      string
	ID         string
	Disabled   bool
	Attributes map[string]string
	HTMXAttrs  map[string]string
}

// SubmitButton creates a new submit button
func SubmitButton(text string) *Button {
	return &Button{
		Type:       "submit",
		Text:       text,
		Class:      "btn btn-primary",
		Attributes: make(map[string]string),
		HTMXAttrs:  make(map[string]string),
	}
}

// ResetButton creates a new reset button
func ResetButton(text string) *Button {
	return &Button{
		Type:       "reset",
		Text:       text,
		Class:      "btn btn-secondary",
		Attributes: make(map[string]string),
		HTMXAttrs:  make(map[string]string),
	}
}

// StandardButton creates a standard button
func StandardButton(text string) *Button {
	return &Button{
		Type:       "button",
		Text:       text,
		Class:      "btn btn-default",
		Attributes: make(map[string]string),
		HTMXAttrs:  make(map[string]string),
	}
}

// Render renders the button
func (b *Button) Render() string {
	attrs := []string{
		fmt.Sprintf(`type="%s"`, b.Type),
	}
	
	if b.Name != "" {
		attrs = append(attrs, fmt.Sprintf(`name="%s"`, b.Name))
	}
	
	if b.Value != "" {
		attrs = append(attrs, fmt.Sprintf(`value="%s"`, html.EscapeString(b.Value)))
	}
	
	if b.ID != "" {
		attrs = append(attrs, fmt.Sprintf(`id="%s"`, b.ID))
	}
	
	if b.Class != "" {
		attrs = append(attrs, fmt.Sprintf(`class="%s"`, b.Class))
	}
	
	if b.Disabled {
		attrs = append(attrs, "disabled")
	}
	
	// Add custom attributes
	for k, v := range b.Attributes {
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, k, html.EscapeString(v)))
	}
	
	// Add HTMX attributes
	for k, v := range b.HTMXAttrs {
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, k, html.EscapeString(v)))
	}
	
	return fmt.Sprintf(`<button %s>%s</button>`, 
		strings.Join(attrs, " "), 
		html.EscapeString(b.Text))
}

// WithName sets the button name
func (b *Button) WithName(name string) *Button {
	b.Name = name
	return b
}

// WithValue sets the button value
func (b *Button) WithValue(value string) *Button {
	b.Value = value
	return b
}

// WithID sets the button ID
func (b *Button) WithID(id string) *Button {
	b.ID = id
	return b
}

// WithClass sets the button class
func (b *Button) WithClass(class string) *Button {
	b.Class = class
	return b
}

// AddClass adds a CSS class to the button
func (b *Button) AddClass(class string) *Button {
	if b.Class != "" {
		b.Class += " " + class
	} else {
		b.Class = class
	}
	return b
}

// Primary styles the button as primary
func (b *Button) Primary() *Button {
	b.Class = "btn btn-primary"
	return b
}

// Secondary styles the button as secondary
func (b *Button) Secondary() *Button {
	b.Class = "btn btn-secondary"
	return b
}

// Success styles the button as success
func (b *Button) Success() *Button {
	b.Class = "btn btn-success"
	return b
}

// Danger styles the button as danger
func (b *Button) Danger() *Button {
	b.Class = "btn btn-danger"
	return b
}

// Warning styles the button as warning
func (b *Button) Warning() *Button {
	b.Class = "btn btn-warning"
	return b
}

// Info styles the button as info
func (b *Button) Info() *Button {
	b.Class = "btn btn-info"
	return b
}

// Small makes the button small
func (b *Button) Small() *Button {
	return b.AddClass("btn-sm")
}

// Large makes the button large
func (b *Button) Large() *Button {
	return b.AddClass("btn-lg")
}

// Block makes the button full width
func (b *Button) Block() *Button {
	return b.AddClass("btn-block")
}

// SetDisabled disables or enables the button
func (b *Button) SetDisabled(disabled bool) *Button {
	b.Disabled = disabled
	return b
}

// Attr adds a custom attribute
func (b *Button) Attr(key, value string) *Button {
	b.Attributes[key] = value
	return b
}

// HTMX methods

// HTMXGet adds hx-get attribute
func (b *Button) HTMXGet(url string) *Button {
	b.HTMXAttrs["hx-get"] = url
	return b
}

// HTMXPost adds hx-post attribute
func (b *Button) HTMXPost(url string) *Button {
	b.HTMXAttrs["hx-post"] = url
	return b
}

// HTMXPut adds hx-put attribute
func (b *Button) HTMXPut(url string) *Button {
	b.HTMXAttrs["hx-put"] = url
	return b
}

// HTMXDelete adds hx-delete attribute
func (b *Button) HTMXDelete(url string) *Button {
	b.HTMXAttrs["hx-delete"] = url
	return b
}

// HTMXTarget adds hx-target attribute
func (b *Button) HTMXTarget(target string) *Button {
	b.HTMXAttrs["hx-target"] = target
	return b
}

// HTMXSwap adds hx-swap attribute
func (b *Button) HTMXSwap(swap string) *Button {
	b.HTMXAttrs["hx-swap"] = swap
	return b
}

// HTMXConfirm adds hx-confirm attribute
func (b *Button) HTMXConfirm(message string) *Button {
	b.HTMXAttrs["hx-confirm"] = message
	return b
}

// HTMXIndicator adds hx-indicator attribute
func (b *Button) HTMXIndicator(indicator string) *Button {
	b.HTMXAttrs["hx-indicator"] = indicator
	return b
}

// ButtonGroup represents a group of buttons
type ButtonGroup struct {
	Buttons []Button
	Class   string
}

// NewButtonGroup creates a new button group
func NewButtonGroup() *ButtonGroup {
	return &ButtonGroup{
		Buttons: []Button{},
		Class:   "btn-group",
	}
}

// AddButton adds a button to the group
func (g *ButtonGroup) AddButton(button *Button) *ButtonGroup {
	g.Buttons = append(g.Buttons, *button)
	return g
}

// WithClass sets the group class
func (g *ButtonGroup) WithClass(class string) *ButtonGroup {
	g.Class = class
	return g
}

// Render renders the button group
func (g *ButtonGroup) Render() string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf(`<div class="%s">`, g.Class))
	
	for _, button := range g.Buttons {
		sb.WriteString(button.Render())
	}
	
	sb.WriteString(`</div>`)
	
	return sb.String()
}

// Add button support to form builder
func (b *Builder) AddButton(button *Button) *Builder {
	// Store button HTML as a special field
	b.fields = append(b.fields, &buttonField{html: button.Render()})
	return b
}

// AddButtonGroup adds a button group to the form
func (b *Builder) AddButtonGroup(group *ButtonGroup) *Builder {
	b.fields = append(b.fields, &buttonField{html: group.Render()})
	return b
}

// buttonField is a special field type for buttons
type buttonField struct {
	html string
}

func (f *buttonField) GetName() string { return "" }
func (f *buttonField) GetType() string { return "button" }
func (f *buttonField) GetValue() string { return "" }
func (f *buttonField) SetValue(value string) Field { return f }
func (f *buttonField) Render(error string) string { return f.html }