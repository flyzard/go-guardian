package form

import (
	"fmt"
	"html"
	"strings"
)

// SelectOption represents an option in a select field
type SelectOption struct {
	Value    string
	Label    string
	Selected bool
	Disabled bool
}

// SelectField represents a select dropdown field
type SelectField struct {
	BaseField
	Options  []SelectOption
	Multiple bool
}

// Select creates a new select field
func Select(name string) *SelectField {
	return &SelectField{
		BaseField: BaseField{
			Name:       name,
			Type:       "select",
			Attributes: make(map[string]string),
		},
		Options: []SelectOption{},
	}
}

// Render renders the select field
func (f *SelectField) Render(error string) string {
	id := f.ID
	if id == "" {
		id = f.Name
	}
	attrs := []string{
		fmt.Sprintf(`name="%s"`, f.Name),
		fmt.Sprintf(`id="%s"`, id),
	}
	
	if f.BaseField.Class != "" {
		attrs = append(attrs, fmt.Sprintf(`class="%s"`, f.BaseField.Class))
	}
	
	if f.BaseField.Required {
		attrs = append(attrs, "required")
	}
	
	if f.BaseField.Disabled {
		attrs = append(attrs, "disabled")
	}
	
	if f.Multiple {
		attrs = append(attrs, "multiple")
	}
	
	// Add custom attributes
	for k, v := range f.Attributes {
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, k, html.EscapeString(v)))
	}
	
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<select %s>`, strings.Join(attrs, " ")))
	
	// Render options
	for _, opt := range f.Options {
		optAttrs := []string{fmt.Sprintf(`value="%s"`, html.EscapeString(opt.Value))}
		
		if opt.Selected || opt.Value == f.BaseField.Value {
			optAttrs = append(optAttrs, "selected")
		}
		
		if opt.Disabled {
			optAttrs = append(optAttrs, "disabled")
		}
		
		sb.WriteString(fmt.Sprintf(`<option %s>%s</option>`, 
			strings.Join(optAttrs, " "), 
			html.EscapeString(opt.Label)))
	}
	
	sb.WriteString(`</select>`)
	
	return f.renderWithWrapper(sb.String(), error)
}

// AddOption adds an option to the select field
func (f *SelectField) AddOption(value, label string) *SelectField {
	f.Options = append(f.Options, SelectOption{Value: value, Label: label})
	return f
}

// AddOptions adds multiple options from value/label pairs
func (f *SelectField) AddOptions(options ...string) *SelectField {
	for _, opt := range options {
		f.Options = append(f.Options, SelectOption{Value: opt, Label: opt})
	}
	return f
}

// OptionsMap adds options from a map
func (f *SelectField) OptionsMap(options map[string]string) *SelectField {
	for value, label := range options {
		f.Options = append(f.Options, SelectOption{Value: value, Label: label})
	}
	return f
}

// Default sets the default selected value
func (f *SelectField) Default(value string) *SelectField {
	f.BaseField.Value = value
	return f
}

// Label sets the field label
func (f *SelectField) Label(label string) *SelectField {
	f.BaseField.Label = label
	return f
}

// Required makes the field required
func (f *SelectField) Required() *SelectField {
	f.BaseField.Required = true
	return f
}

// EnableMultiple enables multiple selection
func (f *SelectField) EnableMultiple() *SelectField {
	f.Multiple = true
	return f
}

// SetValue sets the field value
func (f *SelectField) SetValue(value string) Field {
	f.BaseField.Value = value
	return f
}

// CheckboxField represents a checkbox input field
type CheckboxField struct {
	BaseField
	Checked bool
}

// Checkbox creates a new checkbox field
func Checkbox(name string) *CheckboxField {
	return &CheckboxField{
		BaseField: BaseField{
			Name:       name,
			Type:       "checkbox",
			Attributes: make(map[string]string),
		},
	}
}

// Render renders the checkbox field
func (f *CheckboxField) Render(error string) string {
	attrs := []string{
		fmt.Sprintf(`type="checkbox"`),
		fmt.Sprintf(`name="%s"`, f.Name),
		fmt.Sprintf(`id="%s"`, f.getID()),
	}
	
	if f.BaseField.Value != "" {
		attrs = append(attrs, fmt.Sprintf(`value="%s"`, html.EscapeString(f.BaseField.Value)))
	} else {
		attrs = append(attrs, `value="1"`)
	}
	
	if f.BaseField.Class != "" {
		attrs = append(attrs, fmt.Sprintf(`class="%s"`, f.BaseField.Class))
	}
	
	if f.Checked {
		attrs = append(attrs, "checked")
	}
	
	if f.BaseField.Required {
		attrs = append(attrs, "required")
	}
	
	if f.BaseField.Disabled {
		attrs = append(attrs, "disabled")
	}
	
	// Add custom attributes
	for k, v := range f.Attributes {
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, k, html.EscapeString(v)))
	}
	
	// For checkboxes, render label differently
	wrapperClass := "form-check"
	if error != "" {
		wrapperClass += " has-error"
	}
	
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<div class="%s">`, wrapperClass))
	sb.WriteString(fmt.Sprintf(`<input %s>`, strings.Join(attrs, " ")))
	
	if f.BaseField.Label != "" {
		id := f.ID
		if id == "" {
			id = f.Name
		}
		sb.WriteString(fmt.Sprintf(`<label for="%s" class="form-check-label">%s</label>`, 
			id, html.EscapeString(f.BaseField.Label)))
	}
	
	if error != "" {
		sb.WriteString(fmt.Sprintf(`<span class="error-message">%s</span>`, html.EscapeString(error)))
	}
	
	sb.WriteString(`</div>`)
	
	return sb.String()
}

// Label sets the field label
func (f *CheckboxField) Label(label string) *CheckboxField {
	f.BaseField.Label = label
	return f
}

// SetChecked sets the checkbox as checked
func (f *CheckboxField) SetChecked(checked bool) *CheckboxField {
	f.Checked = checked
	return f
}

// SetValue sets the field value
func (f *CheckboxField) SetValue(value string) Field {
	f.Value = value
	// If value is "true", "1", or "on", check the box
	f.Checked = value == "true" || value == "1" || value == "on"
	return f
}

// RadioField represents a group of radio buttons
type RadioField struct {
	BaseField
	Options []SelectOption
}

// Radio creates a new radio field group
func Radio(name string) *RadioField {
	return &RadioField{
		BaseField: BaseField{
			Name:       name,
			Type:       "radio",
			Attributes: make(map[string]string),
		},
		Options: []SelectOption{},
	}
}

// Render renders the radio field group
func (f *RadioField) Render(error string) string {
	wrapperClass := "form-group"
	if error != "" {
		wrapperClass += " has-error"
	}
	
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<div class="%s">`, wrapperClass))
	
	// Add label if present
	if f.BaseField.Label != "" {
		sb.WriteString(fmt.Sprintf(`<label>%s`, html.EscapeString(f.BaseField.Label)))
		if f.BaseField.Required {
			sb.WriteString(`<span class="required">*</span>`)
		}
		sb.WriteString(`</label>`)
	}
	
	sb.WriteString(`<div class="radio-group">`)
	
	// Render each radio option
	id := f.ID
	if id == "" {
		id = f.Name
	}
	for i, opt := range f.Options {
		radioID := fmt.Sprintf("%s_%d", id, i)
		attrs := []string{
			`type="radio"`,
			fmt.Sprintf(`name="%s"`, f.Name),
			fmt.Sprintf(`id="%s"`, radioID),
			fmt.Sprintf(`value="%s"`, html.EscapeString(opt.Value)),
		}
		
		if opt.Selected || opt.Value == f.BaseField.Value {
			attrs = append(attrs, "checked")
		}
		
		if opt.Disabled {
			attrs = append(attrs, "disabled")
		}
		
		if f.BaseField.Required && i == 0 {
			attrs = append(attrs, "required")
		}
		
		sb.WriteString(`<div class="form-check">`)
		sb.WriteString(fmt.Sprintf(`<input %s>`, strings.Join(attrs, " ")))
		sb.WriteString(fmt.Sprintf(`<label for="%s" class="form-check-label">%s</label>`, 
			radioID, html.EscapeString(opt.Label)))
		sb.WriteString(`</div>`)
	}
	
	sb.WriteString(`</div>`)
	
	if error != "" {
		sb.WriteString(fmt.Sprintf(`<span class="error-message">%s</span>`, html.EscapeString(error)))
	}
	
	sb.WriteString(`</div>`)
	
	return sb.String()
}

// AddOption adds an option to the radio group
func (f *RadioField) AddOption(value, label string) *RadioField {
	f.Options = append(f.Options, SelectOption{Value: value, Label: label})
	return f
}

// Label sets the field label
func (f *RadioField) Label(label string) *RadioField {
	f.BaseField.Label = label
	return f
}

// Default sets the default selected value
func (f *RadioField) Default(value string) *RadioField {
	f.BaseField.Value = value
	return f
}

// Required makes the field required
func (f *RadioField) Required() *RadioField {
	f.BaseField.Required = true
	return f
}

// SetValue sets the field value
func (f *RadioField) SetValue(value string) Field {
	f.BaseField.Value = value
	return f
}

// HiddenField represents a hidden input field
type HiddenField struct {
	BaseField
}

// Hidden creates a new hidden field
func Hidden(name string) *HiddenField {
	return &HiddenField{
		BaseField: BaseField{
			Name:       name,
			Type:       "hidden",
			Attributes: make(map[string]string),
		},
	}
}

// Render renders the hidden field
func (f *HiddenField) Render(error string) string {
	return fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, 
		f.Name, html.EscapeString(f.BaseField.Value))
}

// Value sets the field value
func (f *HiddenField) Value(value string) *HiddenField {
	f.BaseField.Value = value
	return f
}

// SetValue sets the field value
func (f *HiddenField) SetValue(value string) Field {
	f.BaseField.Value = value
	return f
}

