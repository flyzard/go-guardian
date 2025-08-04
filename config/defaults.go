package config

import (
	"reflect"
	"strconv"
)

// DefaultApplier applies default values to configuration structs
type DefaultApplier struct {
	// tagName is the struct tag to look for defaults (default: "default")
	tagName string
}

// NewDefaultApplier creates a new default applier
func NewDefaultApplier() *DefaultApplier {
	return &DefaultApplier{tagName: "default"}
}

// Apply applies defaults from struct tags to the given configuration
func (d *DefaultApplier) Apply(cfg interface{}) error {
	v := reflect.ValueOf(cfg)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	
	if v.Kind() != reflect.Struct {
		return nil
	}
	
	return d.applyDefaults(v)
}

// applyDefaults recursively applies defaults to struct fields
func (d *DefaultApplier) applyDefaults(v reflect.Value) error {
	t := v.Type()
	
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		
		// Skip unexported fields
		if !field.CanSet() {
			continue
		}
		
		// Handle nested structs
		if field.Kind() == reflect.Struct {
			if err := d.applyDefaults(field); err != nil {
				return err
			}
			continue
		}
		
		// Skip if field already has a value
		if !field.IsZero() {
			continue
		}
		
		// Get default value from tag
		defaultValue := fieldType.Tag.Get(d.tagName)
		if defaultValue == "" {
			continue
		}
		
		// Set the default value based on field type
		if err := d.setFieldValue(field, defaultValue); err != nil {
			return err
		}
	}
	
	return nil
}

// setFieldValue sets the field value based on its type
func (d *DefaultApplier) setFieldValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
		
	case reflect.Bool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		field.SetBool(b)
		
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		field.SetInt(i)
		
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return err
		}
		field.SetUint(u)
		
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		field.SetFloat(f)
		
	case reflect.Slice:
		// For byte slices, interpret as string
		if field.Type().Elem().Kind() == reflect.Uint8 {
			field.SetBytes([]byte(value))
		}
	}
	
	return nil
}

// ApplyDefaultsWithTags applies defaults from struct tags
func ApplyDefaultsWithTags(cfg interface{}) error {
	return NewDefaultApplier().Apply(cfg)
}

// MergeConfigs merges multiple configurations, with later configs taking precedence
func MergeConfigs[T any](configs ...T) T {
	var result T
	
	for _, cfg := range configs {
		mergeStructs(&result, cfg)
	}
	
	return result
}

// DeepCopy creates a deep copy of a configuration struct
func DeepCopy[T any](src T) T {
	var dst T
	
	// Use reflection to copy all fields
	srcVal := reflect.ValueOf(src)
	dstVal := reflect.ValueOf(&dst).Elem()
	
	if srcVal.Kind() == reflect.Struct {
		copyStruct(dstVal, srcVal)
	}
	
	return dst
}

// copyStruct recursively copies struct fields
func copyStruct(dst, src reflect.Value) {
	for i := 0; i < src.NumField(); i++ {
		srcField := src.Field(i)
		dstField := dst.Field(i)
		
		if !dstField.CanSet() {
			continue
		}
		
		if srcField.Kind() == reflect.Struct {
			copyStruct(dstField, srcField)
		} else {
			dstField.Set(srcField)
		}
	}
}