// Package diff provides data comparison and visualization functionality
package diff

import (
	"fmt"
	"reflect"
	"sort"
)

// DiffType represents the type of difference found
type DiffType string

const (
	DiffTypeAdded   DiffType = "added"
	DiffTypeRemoved DiffType = "removed"
	DiffTypeChanged DiffType = "changed"
	DiffTypeEqual   DiffType = "equal"
)

// Difference represents a single difference between two values
type Difference struct {
	Type     DiffType
	Path     string
	OldValue interface{}
	NewValue interface{}
	Key      interface{} // For map/slice differences
}

// ComparisonResult holds the results of a comparison
type ComparisonResult struct {
	Differences []Difference
	Added       []interface{}
	Removed     []interface{}
	Changed     []interface{}
	Statistics  Statistics
}

// Statistics holds comparison statistics
type Statistics struct {
	TotalItems    int
	AddedCount    int
	RemovedCount  int
	ChangedCount  int
	UnchangedCount int
}

// Comparator provides data comparison functionality
type Comparator struct {
	ignoreFields map[string]bool
	keyFields    map[string]string
	customComps  map[reflect.Type]CompareFunc
}

// CompareFunc is a custom comparison function
type CompareFunc func(a, b interface{}) ([]Difference, error)

// NewComparator creates a new comparator
func NewComparator() *Comparator {
	return &Comparator{
		ignoreFields: make(map[string]bool),
		keyFields:    make(map[string]string),
		customComps:  make(map[reflect.Type]CompareFunc),
	}
}

// IgnoreField marks a field to be ignored during comparison
func (c *Comparator) IgnoreField(fieldName string) *Comparator {
	c.ignoreFields[fieldName] = true
	return c
}

// SetKeyField sets the field to use as key for a type
func (c *Comparator) SetKeyField(typeName, fieldName string) *Comparator {
	c.keyFields[typeName] = fieldName
	return c
}

// RegisterCustomCompare registers a custom comparison function for a type
func (c *Comparator) RegisterCustomCompare(t reflect.Type, fn CompareFunc) *Comparator {
	c.customComps[t] = fn
	return c
}

// Compare compares two values and returns the differences
func (c *Comparator) Compare(old, new interface{}) (*ComparisonResult, error) {
	result := &ComparisonResult{
		Differences: []Difference{},
		Added:       []interface{}{},
		Removed:     []interface{}{},
		Changed:     []interface{}{},
	}
	
	diffs, err := c.compareValues("", old, new)
	if err != nil {
		return nil, err
	}
	
	result.Differences = diffs
	
	// Calculate statistics
	for _, diff := range diffs {
		switch diff.Type {
		case DiffTypeAdded:
			result.Statistics.AddedCount++
			result.Added = append(result.Added, diff.NewValue)
		case DiffTypeRemoved:
			result.Statistics.RemovedCount++
			result.Removed = append(result.Removed, diff.OldValue)
		case DiffTypeChanged:
			result.Statistics.ChangedCount++
			result.Changed = append(result.Changed, diff.NewValue)
		}
	}
	
	return result, nil
}

// CompareSlices compares two slices using a key extractor
func (c *Comparator) CompareSlices(old, new interface{}, keyExtractor func(interface{}) interface{}) (*ComparisonResult, error) {
	oldVal := reflect.ValueOf(old)
	newVal := reflect.ValueOf(new)
	
	if oldVal.Kind() != reflect.Slice || newVal.Kind() != reflect.Slice {
		return nil, fmt.Errorf("both values must be slices")
	}
	
	// Create maps for efficient lookup
	oldMap := make(map[interface{}]interface{})
	newMap := make(map[interface{}]interface{})
	
	for i := 0; i < oldVal.Len(); i++ {
		item := oldVal.Index(i).Interface()
		key := keyExtractor(item)
		oldMap[key] = item
	}
	
	for i := 0; i < newVal.Len(); i++ {
		item := newVal.Index(i).Interface()
		key := keyExtractor(item)
		newMap[key] = item
	}
	
	result := &ComparisonResult{
		Differences: []Difference{},
	}
	
	// Find removed and changed items
	for key, oldItem := range oldMap {
		if newItem, exists := newMap[key]; exists {
			// Item exists in both - check for changes
			diffs, err := c.compareValues(fmt.Sprintf("[%v]", key), oldItem, newItem)
			if err != nil {
				return nil, err
			}
			if len(diffs) > 0 {
				result.Differences = append(result.Differences, diffs...)
				result.Changed = append(result.Changed, newItem)
				result.Statistics.ChangedCount++
			} else {
				result.Statistics.UnchangedCount++
			}
		} else {
			// Item removed
			result.Differences = append(result.Differences, Difference{
				Type:     DiffTypeRemoved,
				Path:     fmt.Sprintf("[%v]", key),
				OldValue: oldItem,
				Key:      key,
			})
			result.Removed = append(result.Removed, oldItem)
			result.Statistics.RemovedCount++
		}
	}
	
	// Find added items
	for key, newItem := range newMap {
		if _, exists := oldMap[key]; !exists {
			// Item added
			result.Differences = append(result.Differences, Difference{
				Type:     DiffTypeAdded,
				Path:     fmt.Sprintf("[%v]", key),
				NewValue: newItem,
				Key:      key,
			})
			result.Added = append(result.Added, newItem)
			result.Statistics.AddedCount++
		}
	}
	
	result.Statistics.TotalItems = len(newMap)
	
	return result, nil
}

// compareValues recursively compares two values
func (c *Comparator) compareValues(path string, old, new interface{}) ([]Difference, error) {
	if old == nil && new == nil {
		return nil, nil
	}
	
	if old == nil {
		return []Difference{{
			Type:     DiffTypeAdded,
			Path:     path,
			NewValue: new,
		}}, nil
	}
	
	if new == nil {
		return []Difference{{
			Type:     DiffTypeRemoved,
			Path:     path,
			OldValue: old,
		}}, nil
	}
	
	oldVal := reflect.ValueOf(old)
	newVal := reflect.ValueOf(new)
	
	// Check if types match
	if oldVal.Type() != newVal.Type() {
		return []Difference{{
			Type:     DiffTypeChanged,
			Path:     path,
			OldValue: old,
			NewValue: new,
		}}, nil
	}
	
	// Check for custom compare function
	if fn, ok := c.customComps[oldVal.Type()]; ok {
		return fn(old, new)
	}
	
	switch oldVal.Kind() {
	case reflect.Struct:
		return c.compareStructs(path, oldVal, newVal)
	case reflect.Slice:
		return c.compareSlicesReflect(path, oldVal, newVal)
	case reflect.Map:
		return c.compareMaps(path, oldVal, newVal)
	case reflect.Ptr:
		if oldVal.IsNil() && newVal.IsNil() {
			return nil, nil
		}
		if oldVal.IsNil() || newVal.IsNil() {
			return []Difference{{
				Type:     DiffTypeChanged,
				Path:     path,
				OldValue: old,
				NewValue: new,
			}}, nil
		}
		return c.compareValues(path, oldVal.Elem().Interface(), newVal.Elem().Interface())
	default:
		// Compare primitive values
		if !reflect.DeepEqual(old, new) {
			return []Difference{{
				Type:     DiffTypeChanged,
				Path:     path,
				OldValue: old,
				NewValue: new,
			}}, nil
		}
		return nil, nil
	}
}

// compareStructs compares two struct values
func (c *Comparator) compareStructs(path string, oldVal, newVal reflect.Value) ([]Difference, error) {
	var diffs []Difference
	
	t := oldVal.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		
		// Skip ignored fields
		if c.ignoreFields[field.Name] {
			continue
		}
		
		// Skip unexported fields
		if !field.IsExported() {
			continue
		}
		
		fieldPath := path
		if fieldPath == "" {
			fieldPath = field.Name
		} else {
			fieldPath = path + "." + field.Name
		}
		
		oldField := oldVal.Field(i).Interface()
		newField := newVal.Field(i).Interface()
		
		fieldDiffs, err := c.compareValues(fieldPath, oldField, newField)
		if err != nil {
			return nil, err
		}
		
		diffs = append(diffs, fieldDiffs...)
	}
	
	return diffs, nil
}

// compareSlicesReflect compares two slice values using reflection
func (c *Comparator) compareSlicesReflect(path string, oldVal, newVal reflect.Value) ([]Difference, error) {
	var diffs []Difference
	
	oldLen := oldVal.Len()
	newLen := newVal.Len()
	
	// Simple index-based comparison for non-keyed slices
	minLen := oldLen
	if newLen < minLen {
		minLen = newLen
	}
	
	// Compare common elements
	for i := 0; i < minLen; i++ {
		elemPath := fmt.Sprintf("%s[%d]", path, i)
		elemDiffs, err := c.compareValues(elemPath, oldVal.Index(i).Interface(), newVal.Index(i).Interface())
		if err != nil {
			return nil, err
		}
		diffs = append(diffs, elemDiffs...)
	}
	
	// Handle removed elements
	for i := minLen; i < oldLen; i++ {
		diffs = append(diffs, Difference{
			Type:     DiffTypeRemoved,
			Path:     fmt.Sprintf("%s[%d]", path, i),
			OldValue: oldVal.Index(i).Interface(),
		})
	}
	
	// Handle added elements
	for i := minLen; i < newLen; i++ {
		diffs = append(diffs, Difference{
			Type:     DiffTypeAdded,
			Path:     fmt.Sprintf("%s[%d]", path, i),
			NewValue: newVal.Index(i).Interface(),
		})
	}
	
	return diffs, nil
}

// compareMaps compares two map values
func (c *Comparator) compareMaps(path string, oldVal, newVal reflect.Value) ([]Difference, error) {
	var diffs []Difference
	
	// Get all keys
	allKeys := make(map[interface{}]bool)
	for _, key := range oldVal.MapKeys() {
		allKeys[key.Interface()] = true
	}
	for _, key := range newVal.MapKeys() {
		allKeys[key.Interface()] = true
	}
	
	// Sort keys for consistent output
	var sortedKeys []interface{}
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		return fmt.Sprintf("%v", sortedKeys[i]) < fmt.Sprintf("%v", sortedKeys[j])
	})
	
	// Compare each key
	for _, key := range sortedKeys {
		keyPath := fmt.Sprintf("%s[%v]", path, key)
		keyVal := reflect.ValueOf(key)
		
		oldElem := oldVal.MapIndex(keyVal)
		newElem := newVal.MapIndex(keyVal)
		
		if !oldElem.IsValid() {
			// Key added
			diffs = append(diffs, Difference{
				Type:     DiffTypeAdded,
				Path:     keyPath,
				NewValue: newElem.Interface(),
				Key:      key,
			})
		} else if !newElem.IsValid() {
			// Key removed
			diffs = append(diffs, Difference{
				Type:     DiffTypeRemoved,
				Path:     keyPath,
				OldValue: oldElem.Interface(),
				Key:      key,
			})
		} else {
			// Key exists in both - compare values
			elemDiffs, err := c.compareValues(keyPath, oldElem.Interface(), newElem.Interface())
			if err != nil {
				return nil, err
			}
			diffs = append(diffs, elemDiffs...)
		}
	}
	
	return diffs, nil
}

// IsEqual checks if the comparison result indicates equality
func (r *ComparisonResult) IsEqual() bool {
	return len(r.Differences) == 0
}

// HasChanges checks if there are any changes
func (r *ComparisonResult) HasChanges() bool {
	return r.Statistics.AddedCount > 0 || r.Statistics.RemovedCount > 0 || r.Statistics.ChangedCount > 0
}

// Summary returns a summary of the comparison
func (r *ComparisonResult) Summary() string {
	if r.IsEqual() {
		return "No differences found"
	}
	
	return fmt.Sprintf("Found %d differences: %d added, %d removed, %d changed",
		len(r.Differences), r.Statistics.AddedCount, r.Statistics.RemovedCount, r.Statistics.ChangedCount)
}