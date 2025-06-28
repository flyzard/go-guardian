package security

import (
	"errors"
	"regexp"
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
func ValidateInput(input interface{}) error {
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
