package form

import "errors"

var (
	// ErrInvalidDestination is returned when the destination is not a pointer to a struct
	ErrInvalidDestination = errors.New("destination must be a pointer to a struct")
	
	// ErrValidationFailed is returned when form validation fails
	ErrValidationFailed = errors.New("form validation failed")
	
	// ErrFieldNotFound is returned when a field is not found in the form
	ErrFieldNotFound = errors.New("field not found in form")
	
	// ErrInvalidFieldType is returned when trying to perform an operation on an incompatible field type
	ErrInvalidFieldType = errors.New("invalid field type for this operation")
)