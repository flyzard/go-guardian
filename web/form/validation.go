package form

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	
	"github.com/flyzard/go-guardian/security"
)

// ValidationRule represents a validation rule for a field
type ValidationRule struct {
	Type    string
	Message string
	Params  map[string]interface{}
}

// Validator provides form validation functionality
type Validator struct {
	rules  map[string][]ValidationRule
	errors map[string]string
}

// NewValidator creates a new form validator
func NewValidator() *Validator {
	return &Validator{
		rules:  make(map[string][]ValidationRule),
		errors: make(map[string]string),
	}
}

// AddRule adds a validation rule for a field
func (v *Validator) AddRule(fieldName string, rule ValidationRule) *Validator {
	v.rules[fieldName] = append(v.rules[fieldName], rule)
	return v
}

// Required adds a required validation rule
func (v *Validator) Required(fieldName, message string) *Validator {
	if message == "" {
		message = fmt.Sprintf("%s is required", fieldName)
	}
	return v.AddRule(fieldName, ValidationRule{
		Type:    "required",
		Message: message,
	})
}

// Email adds an email validation rule
func (v *Validator) Email(fieldName, message string) *Validator {
	if message == "" {
		message = fmt.Sprintf("%s must be a valid email address", fieldName)
	}
	return v.AddRule(fieldName, ValidationRule{
		Type:    "email",
		Message: message,
	})
}

// MinLength adds a minimum length validation rule
func (v *Validator) MinLength(fieldName string, length int, message string) *Validator {
	if message == "" {
		message = fmt.Sprintf("%s must be at least %d characters", fieldName, length)
	}
	return v.AddRule(fieldName, ValidationRule{
		Type:    "minlength",
		Message: message,
		Params:  map[string]interface{}{"min": length},
	})
}

// MaxLength adds a maximum length validation rule
func (v *Validator) MaxLength(fieldName string, length int, message string) *Validator {
	if message == "" {
		message = fmt.Sprintf("%s must not exceed %d characters", fieldName, length)
	}
	return v.AddRule(fieldName, ValidationRule{
		Type:    "maxlength",
		Message: message,
		Params:  map[string]interface{}{"max": length},
	})
}

// Pattern adds a regex pattern validation rule
func (v *Validator) Pattern(fieldName, pattern, message string) *Validator {
	if message == "" {
		message = fmt.Sprintf("%s format is invalid", fieldName)
	}
	return v.AddRule(fieldName, ValidationRule{
		Type:    "pattern",
		Message: message,
		Params:  map[string]interface{}{"pattern": pattern},
	})
}

// InRange adds a numeric range validation rule
func (v *Validator) InRange(fieldName string, min, max float64, message string) *Validator {
	if message == "" {
		message = fmt.Sprintf("%s must be between %v and %v", fieldName, min, max)
	}
	return v.AddRule(fieldName, ValidationRule{
		Type:    "range",
		Message: message,
		Params:  map[string]interface{}{"min": min, "max": max},
	})
}

// ValidateRequest validates form data from an HTTP request
func (v *Validator) ValidateRequest(r *http.Request) bool {
	v.errors = make(map[string]string)
	
	// Parse form if not already parsed
	if err := r.ParseForm(); err != nil {
		v.errors["_form"] = "Failed to parse form data"
		return false
	}
	
	// Validate each field with rules
	for fieldName, rules := range v.rules {
		value := r.FormValue(fieldName)
		
		for _, rule := range rules {
			if !v.validateField(fieldName, value, rule) {
				break // Stop on first validation failure for this field
			}
		}
	}
	
	return len(v.errors) == 0
}

// validateField validates a single field against a rule
func (v *Validator) validateField(fieldName, value string, rule ValidationRule) bool {
	switch rule.Type {
	case "required":
		if strings.TrimSpace(value) == "" {
			v.errors[fieldName] = rule.Message
			return false
		}
		
	case "email":
		if value != "" && !security.ValidateEmail(value) {
			v.errors[fieldName] = rule.Message
			return false
		}
		
	case "minlength":
		if minLen, ok := rule.Params["min"].(int); ok {
			if len(value) < minLen {
				v.errors[fieldName] = rule.Message
				return false
			}
		}
		
	case "maxlength":
		if maxLen, ok := rule.Params["max"].(int); ok {
			if len(value) > maxLen {
				v.errors[fieldName] = rule.Message
				return false
			}
		}
		
	case "pattern":
		if pattern, ok := rule.Params["pattern"].(string); ok {
			if err := security.ValidatePattern(value, pattern); err != nil {
				v.errors[fieldName] = rule.Message
				return false
			}
		}
		
	case "range":
		if value != "" {
			num, err := strconv.ParseFloat(value, 64)
			if err != nil {
				v.errors[fieldName] = "Must be a valid number"
				return false
			}
			
			min, _ := rule.Params["min"].(float64)
			max, _ := rule.Params["max"].(float64)
			
			if num < min || num > max {
				v.errors[fieldName] = rule.Message
				return false
			}
		}
	}
	
	return true
}

// GetErrors returns all validation errors
func (v *Validator) GetErrors() map[string]string {
	return v.errors
}

// GetError returns the error for a specific field
func (v *Validator) GetError(fieldName string) string {
	return v.errors[fieldName]
}

// HasErrors checks if there are any validation errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// AddError manually adds an error for a field
func (v *Validator) AddError(fieldName, message string) *Validator {
	v.errors[fieldName] = message
	return v
}

// Integration with Form Builder

// WithValidator attaches a validator to the form
func (b *Builder) WithValidator(validator *Validator) *Builder {
	// Apply validation rules to fields
	for _, field := range b.fields {
		if rules, ok := validator.rules[field.GetName()]; ok {
			// Apply validation attributes based on rules
			for _, rule := range rules {
				b.applyValidationToField(field, rule)
			}
		}
	}
	return b
}

// applyValidationToField applies validation attributes to a field
func (b *Builder) applyValidationToField(field Field, rule ValidationRule) {
	switch f := field.(type) {
	case *TextField:
		b.applyTextFieldValidation(f, rule)
	case *EmailField:
		b.applyEmailFieldValidation(f, rule)
	case *TextAreaField:
		b.applyTextAreaValidation(f, rule)
	case *PasswordField:
		b.applyPasswordFieldValidation(f, rule)
	}
}

func (b *Builder) applyTextFieldValidation(field *TextField, rule ValidationRule) {
	switch rule.Type {
	case "required":
		field.Required()
	case "minlength":
		if min, ok := rule.Params["min"].(int); ok {
			field.MinLength(min)
		}
	case "maxlength":
		if max, ok := rule.Params["max"].(int); ok {
			field.MaxLength(max)
		}
	case "pattern":
		if pattern, ok := rule.Params["pattern"].(string); ok {
			field.Pattern(pattern, rule.Message)
		}
	}
}

func (b *Builder) applyEmailFieldValidation(field *EmailField, rule ValidationRule) {
	if rule.Type == "required" {
		field.Required()
	}
}

func (b *Builder) applyTextAreaValidation(field *TextAreaField, rule ValidationRule) {
	if rule.Type == "required" {
		field.Required()
	}
}

func (b *Builder) applyPasswordFieldValidation(field *PasswordField, rule ValidationRule) {
	switch rule.Type {
	case "required":
		field.Required()
	case "minlength":
		if min, ok := rule.Params["min"].(int); ok {
			field.MinLength(min)
		}
	}
}

// ValidateAndBind validates the form and binds values from the request
func (b *Builder) ValidateAndBind(r *http.Request, validator *Validator) bool {
	// Parse form if needed
	if err := r.ParseForm(); err != nil {
		b.WithError("_form", "Failed to parse form data")
		return false
	}
	
	// Bind values to fields
	for _, field := range b.fields {
		fieldName := field.GetName()
		if fieldName != "" {
			value := r.FormValue(fieldName)
			field.SetValue(value)
		}
	}
	
	// Validate if validator provided
	if validator != nil {
		if !validator.ValidateRequest(r) {
			b.WithErrors(validator.GetErrors())
			return false
		}
	}
	
	return true
}