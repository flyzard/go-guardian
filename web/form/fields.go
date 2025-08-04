package form

import (
	"fmt"
	"html"
	"strings"
)

// Field represents a form field interface
type Field interface {
	GetName() string
	GetType() string
	GetValue() string
	SetValue(value string) Field
	Render(error string) string
}

// BaseField contains common field properties
type BaseField struct {
	Name        string
	Type        string
	Value       string
	ID          string
	Class       string
	Label       string
	Placeholder string
	Required    bool
	Disabled    bool
	ReadOnly    bool
	Attributes  map[string]string
	Validation  *FieldValidation
}

// FieldValidation contains validation rules for a field
type FieldValidation struct {
	MinLength   int
	MaxLength   int
	Min         string
	Max         string
	Pattern     string
	PatternMsg  string
}

// GetName returns the field name
func (f *BaseField) GetName() string {
	return f.Name
}

// GetType returns the field type
func (f *BaseField) GetType() string {
	return f.Type
}

// GetValue returns the field value
func (f *BaseField) GetValue() string {
	return f.Value
}

// SetValue sets the field value - must be implemented by concrete types
func (f *BaseField) SetValue(value string) Field {
	f.Value = value
	// This will be overridden by concrete field types
	return nil
}

// Render must be implemented by concrete field types
func (f *BaseField) Render(error string) string {
	// This is a base method that should be overridden
	return ""
}

// buildAttributes builds HTML attributes string
func (f *BaseField) buildAttributes(additionalAttrs ...string) string {
	attrs := []string{
		fmt.Sprintf(`name="%s"`, f.Name),
		fmt.Sprintf(`type="%s"`, f.Type),
	}

	if f.ID != "" {
		attrs = append(attrs, fmt.Sprintf(`id="%s"`, f.ID))
	} else {
		attrs = append(attrs, fmt.Sprintf(`id="%s"`, f.Name))
	}

	if f.Class != "" {
		attrs = append(attrs, fmt.Sprintf(`class="%s"`, f.Class))
	}

	if f.Value != "" {
		attrs = append(attrs, fmt.Sprintf(`value="%s"`, html.EscapeString(f.Value)))
	}

	if f.Placeholder != "" {
		attrs = append(attrs, fmt.Sprintf(`placeholder="%s"`, html.EscapeString(f.Placeholder)))
	}

	if f.Required {
		attrs = append(attrs, "required")
	}

	if f.Disabled {
		attrs = append(attrs, "disabled")
	}

	if f.ReadOnly {
		attrs = append(attrs, "readonly")
	}

	// Add validation attributes
	if f.Validation != nil {
		if f.Validation.MinLength > 0 {
			attrs = append(attrs, fmt.Sprintf(`minlength="%d"`, f.Validation.MinLength))
		}
		if f.Validation.MaxLength > 0 {
			attrs = append(attrs, fmt.Sprintf(`maxlength="%d"`, f.Validation.MaxLength))
		}
		if f.Validation.Min != "" {
			attrs = append(attrs, fmt.Sprintf(`min="%s"`, f.Validation.Min))
		}
		if f.Validation.Max != "" {
			attrs = append(attrs, fmt.Sprintf(`max="%s"`, f.Validation.Max))
		}
		if f.Validation.Pattern != "" {
			attrs = append(attrs, fmt.Sprintf(`pattern="%s"`, f.Validation.Pattern))
			if f.Validation.PatternMsg != "" {
				attrs = append(attrs, fmt.Sprintf(`title="%s"`, html.EscapeString(f.Validation.PatternMsg)))
			}
		}
	}

	// Add custom attributes
	for k, v := range f.Attributes {
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, k, html.EscapeString(v)))
	}

	// Add additional attributes
	attrs = append(attrs, additionalAttrs...)

	return strings.Join(attrs, " ")
}

// renderWithWrapper renders the field with a wrapper div
func (f *BaseField) renderWithWrapper(input, error string) string {
	var sb strings.Builder
	
	wrapperClass := "form-group"
	if error != "" {
		wrapperClass += " has-error"
	}
	
	sb.WriteString(fmt.Sprintf(`<div class="%s">`, wrapperClass))
	
	// Add label if present
	if f.Label != "" {
		labelFor := f.ID
		if labelFor == "" {
			labelFor = f.Name
		}
		sb.WriteString(fmt.Sprintf(`<label for="%s">%s`, labelFor, html.EscapeString(f.Label)))
		if f.Required {
			sb.WriteString(`<span class="required">*</span>`)
		}
		sb.WriteString(`</label>`)
	}
	
	// Add input
	sb.WriteString(input)
	
	// Add error message if present
	if error != "" {
		sb.WriteString(fmt.Sprintf(`<span class="error-message">%s</span>`, html.EscapeString(error)))
	}
	
	sb.WriteString(`</div>`)
	
	return sb.String()
}

// TextField represents a text input field
type TextField struct {
	BaseField
}

// Text creates a new text field
func Text(name string) *TextField {
	return &TextField{
		BaseField: BaseField{
			Name:       name,
			Type:       "text",
			Attributes: make(map[string]string),
		},
	}
}

// Render renders the text field
func (f *TextField) Render(error string) string {
	input := fmt.Sprintf(`<input %s>`, f.buildAttributes())
	return f.renderWithWrapper(input, error)
}

// SetValue sets the field value
func (f *TextField) SetValue(value string) Field {
	f.Value = value
	return f
}

// Label sets the field label
func (f *TextField) Label(label string) *TextField {
	f.BaseField.Label = label
	return f
}

// Placeholder sets the placeholder
func (f *TextField) Placeholder(placeholder string) *TextField {
	f.BaseField.Placeholder = placeholder
	return f
}

// Required makes the field required
func (f *TextField) Required() *TextField {
	f.BaseField.Required = true
	return f
}

// Class sets the CSS class
func (f *TextField) Class(class string) *TextField {
	f.BaseField.Class = class
	return f
}

// MinLength sets minimum length validation
func (f *TextField) MinLength(length int) *TextField {
	if f.Validation == nil {
		f.Validation = &FieldValidation{}
	}
	f.Validation.MinLength = length
	return f
}

// MaxLength sets maximum length validation
func (f *TextField) MaxLength(length int) *TextField {
	if f.Validation == nil {
		f.Validation = &FieldValidation{}
	}
	f.Validation.MaxLength = length
	return f
}

// Pattern sets pattern validation
func (f *TextField) Pattern(pattern, message string) *TextField {
	if f.Validation == nil {
		f.Validation = &FieldValidation{}
	}
	f.Validation.Pattern = pattern
	f.Validation.PatternMsg = message
	return f
}

// Attr adds a custom attribute
func (f *TextField) Attr(key, value string) *TextField {
	if f.Attributes == nil {
		f.Attributes = make(map[string]string)
	}
	f.Attributes[key] = value
	return f
}

// EmailField represents an email input field
type EmailField struct {
	BaseField
}

// Email creates a new email field
func Email(name string) *EmailField {
	return &EmailField{
		BaseField: BaseField{
			Name:       name,
			Type:       "email",
			Attributes: make(map[string]string),
		},
	}
}

// Render renders the email field
func (f *EmailField) Render(error string) string {
	input := fmt.Sprintf(`<input %s>`, f.buildAttributes())
	return f.renderWithWrapper(input, error)
}

// SetValue sets the field value
func (f *EmailField) SetValue(value string) Field {
	f.Value = value
	return f
}

// Label sets the field label
func (f *EmailField) Label(label string) *EmailField {
	f.BaseField.Label = label
	return f
}

// Required makes the field required
func (f *EmailField) Required() *EmailField {
	f.BaseField.Required = true
	return f
}

// Placeholder sets the placeholder
func (f *EmailField) Placeholder(placeholder string) *EmailField {
	f.BaseField.Placeholder = placeholder
	return f
}

// Class sets the CSS class
func (f *EmailField) Class(class string) *EmailField {
	f.BaseField.Class = class
	return f
}

// Attr adds a custom attribute
func (f *EmailField) Attr(key, value string) *EmailField {
	if f.Attributes == nil {
		f.Attributes = make(map[string]string)
	}
	f.Attributes[key] = value
	return f
}

// PasswordField represents a password input field
type PasswordField struct {
	BaseField
}

// Password creates a new password field
func Password(name string) *PasswordField {
	return &PasswordField{
		BaseField: BaseField{
			Name:       name,
			Type:       "password",
			Attributes: make(map[string]string),
		},
	}
}

// Render renders the password field
func (f *PasswordField) Render(error string) string {
	input := fmt.Sprintf(`<input %s>`, f.buildAttributes())
	return f.renderWithWrapper(input, error)
}

// SetValue sets the field value
func (f *PasswordField) SetValue(value string) Field {
	f.Value = value
	return f
}

// Label sets the field label
func (f *PasswordField) Label(label string) *PasswordField {
	f.BaseField.Label = label
	return f
}

// Required makes the field required
func (f *PasswordField) Required() *PasswordField {
	f.BaseField.Required = true
	return f
}

// MinLength sets minimum length validation
func (f *PasswordField) MinLength(length int) *PasswordField {
	if f.Validation == nil {
		f.Validation = &FieldValidation{}
	}
	f.Validation.MinLength = length
	return f
}

// Class sets the CSS class
func (f *PasswordField) Class(class string) *PasswordField {
	f.BaseField.Class = class
	return f
}

// TextAreaField represents a textarea field
type TextAreaField struct {
	BaseField
	Rows int
	Cols int
}

// TextArea creates a new textarea field
func TextArea(name string) *TextAreaField {
	return &TextAreaField{
		BaseField: BaseField{
			Name:       name,
			Type:       "textarea",
			Attributes: make(map[string]string),
		},
		Rows: 4,
		Cols: 50,
	}
}

// Render renders the textarea field
func (f *TextAreaField) Render(error string) string {
	id := f.ID
	if id == "" {
		id = f.Name
	}
	attrs := []string{
		fmt.Sprintf(`name="%s"`, f.Name),
		fmt.Sprintf(`id="%s"`, id),
		fmt.Sprintf(`rows="%d"`, f.Rows),
		fmt.Sprintf(`cols="%d"`, f.Cols),
	}
	
	if f.BaseField.Class != "" {
		attrs = append(attrs, fmt.Sprintf(`class="%s"`, f.BaseField.Class))
	}
	
	if f.BaseField.Placeholder != "" {
		attrs = append(attrs, fmt.Sprintf(`placeholder="%s"`, html.EscapeString(f.BaseField.Placeholder)))
	}
	
	if f.BaseField.Required {
		attrs = append(attrs, "required")
	}
	
	// Add custom attributes
	for k, v := range f.Attributes {
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, k, html.EscapeString(v)))
	}
	
	input := fmt.Sprintf(`<textarea %s>%s</textarea>`, 
		strings.Join(attrs, " "), 
		html.EscapeString(f.BaseField.Value))
	
	return f.renderWithWrapper(input, error)
}

// Label sets the field label
func (f *TextAreaField) Label(label string) *TextAreaField {
	f.BaseField.Label = label
	return f
}

// Dimensions sets rows and columns
func (f *TextAreaField) Dimensions(rows, cols int) *TextAreaField {
	f.Rows = rows
	f.Cols = cols
	return f
}

// Required makes the field required
func (f *TextAreaField) Required() *TextAreaField {
	f.BaseField.Required = true
	return f
}

// Placeholder sets the placeholder
func (f *TextAreaField) Placeholder(placeholder string) *TextAreaField {
	f.BaseField.Placeholder = placeholder
	return f
}

// Class sets the CSS class
func (f *TextAreaField) Class(class string) *TextAreaField {
	f.BaseField.Class = class
	return f
}

// SetValue sets the field value
func (f *TextAreaField) SetValue(value string) Field {
	f.BaseField.Value = value
	return f
}

// getID helper method to get ID
func (f *BaseField) getID() string {
	if f.ID != "" {
		return f.ID
	}
	return f.Name
}