package config

import (
	"errors"
	"reflect"
)

// Configurable provides a standard interface for all configurations
type Configurable[T any] interface {
	// Defaults returns the default configuration
	Defaults() T
	// Validate validates the configuration
	Validate() error
	// Merge merges with another configuration (for partial configs)
	Merge(other T) T
}

// BaseConfig provides common configuration functionality
type BaseConfig[T any] struct {
	defaults T
}

// NewBaseConfig creates a new BaseConfig with the given defaults
func NewBaseConfig[T any](defaults T) *BaseConfig[T] {
	return &BaseConfig[T]{defaults: defaults}
}

// Defaults returns the default configuration
func (b *BaseConfig[T]) Defaults() T {
	return b.defaults
}

// Validate provides basic validation (can be overridden)
func (b *BaseConfig[T]) Validate() error {
	return nil
}

// Merge provides basic merge functionality using reflection
func (b *BaseConfig[T]) Merge(other T) T {
	result := b.defaults
	mergeStructs(&result, other)
	return result
}

// ApplyDefaults uses reflection to apply default values to zero fields
func ApplyDefaults[T any](cfg *T, defaults T) {
	if cfg == nil {
		return
	}
	
	cfgVal := reflect.ValueOf(cfg).Elem()
	defaultVal := reflect.ValueOf(defaults)
	
	if cfgVal.Kind() != reflect.Struct || defaultVal.Kind() != reflect.Struct {
		return
	}
	
	applyDefaultsRecursive(cfgVal, defaultVal)
}

// applyDefaultsRecursive recursively applies defaults to struct fields
func applyDefaultsRecursive(cfgVal, defaultVal reflect.Value) {
	for i := 0; i < cfgVal.NumField(); i++ {
		field := cfgVal.Field(i)
		defaultField := defaultVal.Field(i)
		
		// Skip unexported fields
		if !field.CanSet() {
			continue
		}
		
		// Handle nested structs
		if field.Kind() == reflect.Struct && defaultField.Kind() == reflect.Struct {
			applyDefaultsRecursive(field, defaultField)
			continue
		}
		
		// Apply default if field is zero value
		if field.IsZero() && !defaultField.IsZero() {
			field.Set(defaultField)
		}
	}
}

// mergeStructs merges src into dst using reflection
func mergeStructs(dst, src interface{}) {
	dstVal := reflect.ValueOf(dst).Elem()
	srcVal := reflect.ValueOf(src)
	
	if dstVal.Kind() != reflect.Struct || srcVal.Kind() != reflect.Struct {
		return
	}
	
	for i := 0; i < srcVal.NumField(); i++ {
		srcField := srcVal.Field(i)
		dstField := dstVal.Field(i)
		
		// Skip unexported fields
		if !dstField.CanSet() {
			continue
		}
		
		// Skip zero values in source
		if srcField.IsZero() {
			continue
		}
		
		// Handle nested structs
		if srcField.Kind() == reflect.Struct && dstField.Kind() == reflect.Struct {
			mergeStructs(dstField.Addr().Interface(), srcField.Interface())
			continue
		}
		
		// Set the value
		dstField.Set(srcField)
	}
}

// ValidateRequired checks that required fields are not zero values
func ValidateRequired(cfg interface{}, requiredFields ...string) error {
	val := reflect.ValueOf(cfg)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	
	if val.Kind() != reflect.Struct {
		return errors.New("configuration must be a struct")
	}
	
	typ := val.Type()
	for _, fieldName := range requiredFields {
		field, found := typ.FieldByName(fieldName)
		if !found {
			return errors.New("required field not found: " + fieldName)
		}
		
		fieldVal := val.FieldByName(fieldName)
		if fieldVal.IsZero() {
			return errors.New("required field is empty: " + field.Name)
		}
	}
	
	return nil
}