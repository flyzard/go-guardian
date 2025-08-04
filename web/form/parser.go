package form

import (
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Parser provides utilities for parsing form data into structs
type Parser struct {
	tagName string
}

// NewParser creates a new form parser
func NewParser() *Parser {
	return &Parser{
		tagName: "form",
	}
}

// Parse parses form data from request into a struct
func (p *Parser) Parse(r *http.Request, dest interface{}) error {
	// Ensure we have form data
	if err := r.ParseForm(); err != nil {
		return err
	}
	
	return p.parseFormToStruct(r.Form, dest)
}

// ParseMultipart parses multipart form data
func (p *Parser) ParseMultipart(r *http.Request, dest interface{}) error {
	// Parse multipart form with 32MB limit
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return err
	}
	
	return p.parseFormToStruct(r.MultipartForm.Value, dest)
}

// parseFormToStruct fills a struct from form values
func (p *Parser) parseFormToStruct(form map[string][]string, dest interface{}) error {
	v := reflect.ValueOf(dest)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return ErrInvalidDestination
	}
	
	v = v.Elem()
	t := v.Type()
	
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)
		
		// Skip unexported fields
		if !fieldValue.CanSet() {
			continue
		}
		
		// Get form field name from tag or use field name
		formFieldName := p.getFieldName(field)
		if formFieldName == "-" {
			continue
		}
		
		// Get form values
		values, exists := form[formFieldName]
		if !exists || len(values) == 0 {
			continue
		}
		
		// Set field value based on type
		if err := p.setFieldValue(fieldValue, values); err != nil {
			return err
		}
	}
	
	return nil
}

// getFieldName extracts the form field name from struct tag
func (p *Parser) getFieldName(field reflect.StructField) string {
	tag := field.Tag.Get(p.tagName)
	if tag == "" {
		return strings.ToLower(field.Name)
	}
	
	// Handle tag options (e.g., "name,required")
	parts := strings.Split(tag, ",")
	return parts[0]
}

// setFieldValue sets the field value based on its type
func (p *Parser) setFieldValue(field reflect.Value, values []string) error {
	if len(values) == 0 {
		return nil
	}
	
	switch field.Kind() {
	case reflect.String:
		field.SetString(values[0])
		
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, err := strconv.ParseInt(values[0], 10, 64)
		if err != nil {
			return err
		}
		field.SetInt(val)
		
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		val, err := strconv.ParseUint(values[0], 10, 64)
		if err != nil {
			return err
		}
		field.SetUint(val)
		
	case reflect.Float32, reflect.Float64:
		val, err := strconv.ParseFloat(values[0], 64)
		if err != nil {
			return err
		}
		field.SetFloat(val)
		
	case reflect.Bool:
		val, err := strconv.ParseBool(values[0])
		if err != nil {
			// Handle checkbox values
			val = values[0] == "on" || values[0] == "1" || values[0] == "true"
		}
		field.SetBool(val)
		
	case reflect.Slice:
		// Handle slice types (for multi-select, checkboxes)
		p.setSliceValue(field, values)
		
	case reflect.Struct:
		// Handle special struct types
		if field.Type() == reflect.TypeOf(time.Time{}) {
			if t, err := time.Parse("2006-01-02", values[0]); err == nil {
				field.Set(reflect.ValueOf(t))
			}
		}
		
	case reflect.Ptr:
		// Create new instance if nil
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
		// Recursively set the value
		return p.setFieldValue(field.Elem(), values)
	}
	
	return nil
}

// setSliceValue handles setting slice values
func (p *Parser) setSliceValue(field reflect.Value, values []string) {
	sliceType := field.Type()
	elemType := sliceType.Elem()
	
	slice := reflect.MakeSlice(sliceType, len(values), len(values))
	
	for i, value := range values {
		elem := slice.Index(i)
		
		switch elemType.Kind() {
		case reflect.String:
			elem.SetString(value)
			
		case reflect.Int, reflect.Int64:
			if val, err := strconv.ParseInt(value, 10, 64); err == nil {
				elem.SetInt(val)
			}
			
		case reflect.Float64:
			if val, err := strconv.ParseFloat(value, 64); err == nil {
				elem.SetFloat(val)
			}
		}
	}
	
	field.Set(slice)
}

// BindFormData binds form data to a struct and validates it
func BindFormData(r *http.Request, dest interface{}, validator *Validator) error {
	parser := NewParser()
	
	// Parse form data
	if err := parser.Parse(r, dest); err != nil {
		return err
	}
	
	// Validate if validator provided
	if validator != nil && !validator.ValidateRequest(r) {
		return ErrValidationFailed
	}
	
	return nil
}

// FillForm fills form fields from a struct
func (b *Builder) FillFrom(data interface{}) *Builder {
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	
	if v.Kind() != reflect.Struct {
		return b
	}
	
	t := v.Type()
	
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)
		
		// Get form field name
		formFieldName := strings.ToLower(field.Name)
		tag := field.Tag.Get("form")
		if tag != "" && tag != "-" {
			parts := strings.Split(tag, ",")
			formFieldName = parts[0]
		}
		
		// Find matching form field
		formField := b.GetField(formFieldName)
		if formField != nil {
			// Convert value to string
			parser := NewParser()
			stringValue := parser.fieldValueToString(fieldValue)
			formField.SetValue(stringValue)
		}
	}
	
	return b
}

// fieldValueToString converts a reflect.Value to string
func (p *Parser) fieldValueToString(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		return v.String()
		
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
		
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10)
		
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'f', -1, 64)
		
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
		
	case reflect.Struct:
		// Handle time.Time
		if t, ok := v.Interface().(time.Time); ok {
			return t.Format("2006-01-02")
		}
		
	case reflect.Ptr:
		if !v.IsNil() {
			return p.fieldValueToString(v.Elem())
		}
	}
	
	return ""
}