package security

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
)

var (
	validate   = validator.New()
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// Input validation structs
type RegisterInput struct {
	Email    string `validate:"required,email,max=255"`
	Password string `validate:"required,min=8,max=72"` // bcrypt limit is 72
}

type LoginInput struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

type PasswordResetInput struct {
	Email string `validate:"required,email"`
}

type NewPasswordInput struct {
	Token    string `validate:"required,len=64"` // hex encoded 32 bytes
	Password string `validate:"required,min=8,max=72"`
}

// ValidateInput validates any struct with validation tags
func ValidateInput(input any) error {
	return validate.Struct(input)
}

// ValidateEmail validates email format
func ValidateEmail(email string) bool {
	email = strings.TrimSpace(strings.ToLower(email))
	return emailRegex.MatchString(email)
}

// SanitizeEmail normalizes email format
func SanitizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

// ValidatePassword checks password requirements
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len(password) > 72 {
		return errors.New("password must not exceed 72 characters")
	}
	return nil
}

// Pattern validators

// ValidatePattern validates a value against a regex pattern
func ValidatePattern(value, pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return errors.New("invalid validation pattern")
	}
	
	if !regex.MatchString(value) {
		return errors.New("value does not match required pattern")
	}
	
	return nil
}

// ValidateAlphanumeric checks if value contains only alphanumeric characters
func ValidateAlphanumeric(value string) error {
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			return errors.New("value must contain only alphanumeric characters")
		}
	}
	return nil
}

// ValidateNoSpecialChars validates that value contains no special characters except those allowed
func ValidateNoSpecialChars(value string, allowedChars string) error {
	for _, char := range value {
		isAlphaNum := (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')
		isAllowed := strings.ContainsRune(allowedChars, char)
		
		if !isAlphaNum && !isAllowed {
			return errors.New("value contains invalid special characters")
		}
	}
	return nil
}

// Range validators

// ValidateIntRange validates that a string value is an integer within a range
func ValidateIntRange(value string, min, max int64) error {
	if value == "" {
		return errors.New("value is required")
	}
	
	intVal, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return errors.New("value must be a valid integer")
	}
	
	if intVal < min || intVal > max {
		return fmt.Errorf("value must be between %d and %d", min, max)
	}
	
	return nil
}

// ValidateFloatRange validates that a string value is a float within a range
func ValidateFloatRange(value string, min, max float64) error {
	if value == "" {
		return errors.New("value is required")
	}
	
	floatVal, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return errors.New("value must be a valid number")
	}
	
	if floatVal < min || floatVal > max {
		return fmt.Errorf("value must be between %f and %f", min, max)
	}
	
	return nil
}

// Collection validators

// ValidateInList checks if value is in the list of valid values
func ValidateInList(value string, validValues []string) error {
	for _, valid := range validValues {
		if value == valid {
			return nil
		}
	}
	return fmt.Errorf("value must be one of: %s", strings.Join(validValues, ", "))
}

// ValidateNotEmpty checks that a value is not empty after trimming whitespace
func ValidateNotEmpty(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value cannot be empty")
	}
	return nil
}

// Composite validators

// ValidateAll runs all validators and returns error if any fail
func ValidateAll(value string, validators ...func(string) error) error {
	for _, validator := range validators {
		if err := validator(value); err != nil {
			return err
		}
	}
	return nil
}

// ValidateAny runs all validators and returns nil if any succeed
func ValidateAny(value string, validators ...func(string) error) error {
	var errs []string
	for _, validator := range validators {
		if err := validator(value); err == nil {
			return nil
		} else {
			errs = append(errs, err.Error())
		}
	}
	return fmt.Errorf("value failed all validations: %s", strings.Join(errs, "; "))
}
