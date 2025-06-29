package security

import (
	"strings"
	"testing"
)

func TestEmailValidation(t *testing.T) {
	validEmails := []string{
		"test@example.com",
		"user.name@example.com",
		"user+tag@example.co.uk",
		"test123@sub.example.com",
	}

	for _, email := range validEmails {
		if !ValidateEmail(email) {
			t.Errorf("Valid email rejected: %s", email)
		}
	}

	invalidEmails := []string{
		"",
		"notanemail",
		"@example.com",
		"user@",
		"user space@example.com",
		"user@example",
		"user@@example.com",
	}

	for _, email := range invalidEmails {
		if ValidateEmail(email) {
			t.Errorf("Invalid email accepted: %s", email)
		}
	}
}

func TestInputValidation(t *testing.T) {
	// Test registration validation
	tests := []struct {
		input RegisterInput
		valid bool
		desc  string
	}{
		{
			RegisterInput{Email: "test@example.com", Password: "password123"},
			true,
			"valid registration",
		},
		{
			RegisterInput{Email: "", Password: "password123"},
			false,
			"empty email",
		},
		{
			RegisterInput{Email: "invalid-email", Password: "password123"},
			false,
			"invalid email format",
		},
		{
			RegisterInput{Email: "test@example.com", Password: "short"},
			false,
			"password too short",
		},
		{
			RegisterInput{Email: "test@example.com", Password: strings.Repeat("a", 73)},
			false,
			"password too long",
		},
	}

	for _, tt := range tests {
		err := ValidateInput(tt.input)
		if (err == nil) != tt.valid {
			t.Errorf("%s: expected valid=%v, got error=%v", tt.desc, tt.valid, err)
		}
	}
}
