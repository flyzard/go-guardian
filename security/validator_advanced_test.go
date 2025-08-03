package security

import (
	"errors"
	"strconv"
	"testing"
)

func TestValidatePattern(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		pattern string
		wantErr bool
	}{
		{
			name:    "valid email pattern",
			value:   "test@example.com",
			pattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			wantErr: false,
		},
		{
			name:    "invalid email pattern",
			value:   "not-an-email",
			pattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			wantErr: true,
		},
		{
			name:    "valid phone pattern",
			value:   "123-456-7890",
			pattern: `^\d{3}-\d{3}-\d{4}$`,
			wantErr: false,
		},
		{
			name:    "invalid phone pattern",
			value:   "123456789",
			pattern: `^\d{3}-\d{3}-\d{4}$`,
			wantErr: true,
		},
		{
			name:    "invalid regex pattern",
			value:   "test",
			pattern: `[`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePattern(tt.value, tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePattern() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAlphanumeric(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:    "valid alphanumeric",
			value:   "Test123",
			wantErr: false,
		},
		{
			name:    "only letters",
			value:   "TestOnly",
			wantErr: false,
		},
		{
			name:    "only numbers",
			value:   "123456",
			wantErr: false,
		},
		{
			name:    "contains space",
			value:   "Test 123",
			wantErr: true,
		},
		{
			name:    "contains special char",
			value:   "Test@123",
			wantErr: true,
		},
		{
			name:    "contains hyphen",
			value:   "Test-123",
			wantErr: true,
		},
		{
			name:    "empty string",
			value:   "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAlphanumeric(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAlphanumeric() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateNoSpecialChars(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		allowedChars string
		wantErr      bool
	}{
		{
			name:         "alphanumeric with allowed chars",
			value:        "Test-123_value",
			allowedChars: "-_",
			wantErr:      false,
		},
		{
			name:         "contains disallowed special char",
			value:        "Test@123",
			allowedChars: "-_",
			wantErr:      true,
		},
		{
			name:         "all allowed chars",
			value:        "Test-123_value.com",
			allowedChars: "-_.",
			wantErr:      false,
		},
		{
			name:         "no special chars allowed",
			value:        "Test123",
			allowedChars: "",
			wantErr:      false,
		},
		{
			name:         "spaces allowed",
			value:        "Test 123 value",
			allowedChars: " ",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNoSpecialChars(tt.value, tt.allowedChars)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNoSpecialChars() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIntRange(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		min     int64
		max     int64
		wantErr bool
	}{
		{
			name:    "valid int in range",
			value:   "50",
			min:     1,
			max:     100,
			wantErr: false,
		},
		{
			name:    "int at minimum",
			value:   "1",
			min:     1,
			max:     100,
			wantErr: false,
		},
		{
			name:    "int at maximum",
			value:   "100",
			min:     1,
			max:     100,
			wantErr: false,
		},
		{
			name:    "int below minimum",
			value:   "0",
			min:     1,
			max:     100,
			wantErr: true,
		},
		{
			name:    "int above maximum",
			value:   "101",
			min:     1,
			max:     100,
			wantErr: true,
		},
		{
			name:    "empty value",
			value:   "",
			min:     1,
			max:     100,
			wantErr: true,
		},
		{
			name:    "non-integer value",
			value:   "abc",
			min:     1,
			max:     100,
			wantErr: true,
		},
		{
			name:    "negative value in negative range",
			value:   "-50",
			min:     -100,
			max:     -1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIntRange(tt.value, tt.min, tt.max)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIntRange() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFloatRange(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		min     float64
		max     float64
		wantErr bool
	}{
		{
			name:    "valid float in range",
			value:   "50.5",
			min:     1.0,
			max:     100.0,
			wantErr: false,
		},
		{
			name:    "float at minimum",
			value:   "1.0",
			min:     1.0,
			max:     100.0,
			wantErr: false,
		},
		{
			name:    "float at maximum",
			value:   "100.0",
			min:     1.0,
			max:     100.0,
			wantErr: false,
		},
		{
			name:    "float below minimum",
			value:   "0.5",
			min:     1.0,
			max:     100.0,
			wantErr: true,
		},
		{
			name:    "float above maximum",
			value:   "100.5",
			min:     1.0,
			max:     100.0,
			wantErr: true,
		},
		{
			name:    "integer value",
			value:   "50",
			min:     1.0,
			max:     100.0,
			wantErr: false,
		},
		{
			name:    "empty value",
			value:   "",
			min:     1.0,
			max:     100.0,
			wantErr: true,
		},
		{
			name:    "non-numeric value",
			value:   "abc",
			min:     1.0,
			max:     100.0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFloatRange(tt.value, tt.min, tt.max)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFloatRange() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateInList(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		validValues []string
		wantErr     bool
	}{
		{
			name:        "value in list",
			value:       "active",
			validValues: []string{"active", "inactive", "pending"},
			wantErr:     false,
		},
		{
			name:        "value not in list",
			value:       "deleted",
			validValues: []string{"active", "inactive", "pending"},
			wantErr:     true,
		},
		{
			name:        "empty value in list",
			value:       "",
			validValues: []string{"", "active", "inactive"},
			wantErr:     false,
		},
		{
			name:        "empty value not in list",
			value:       "",
			validValues: []string{"active", "inactive"},
			wantErr:     true,
		},
		{
			name:        "case sensitive",
			value:       "Active",
			validValues: []string{"active", "inactive"},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInList(tt.value, tt.validValues)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateInList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateNotEmpty(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:    "non-empty value",
			value:   "test",
			wantErr: false,
		},
		{
			name:    "empty string",
			value:   "",
			wantErr: true,
		},
		{
			name:    "only spaces",
			value:   "   ",
			wantErr: true,
		},
		{
			name:    "spaces with content",
			value:   "  test  ",
			wantErr: false,
		},
		{
			name:    "tabs and newlines",
			value:   "\t\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNotEmpty(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNotEmpty() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAll(t *testing.T) {
	// Test validators
	isNotEmpty := func(v string) error {
		if v == "" {
			return errors.New("value is empty")
		}
		return nil
	}

	isNumeric := func(v string) error {
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return errors.New("value is not numeric")
		}
		return nil
	}

	isPositive := func(v string) error {
		n, _ := strconv.ParseInt(v, 10, 64)
		if n <= 0 {
			return errors.New("value is not positive")
		}
		return nil
	}

	tests := []struct {
		name       string
		value      string
		validators []func(string) error
		wantErr    bool
	}{
		{
			name:       "all validators pass",
			value:      "42",
			validators: []func(string) error{isNotEmpty, isNumeric, isPositive},
			wantErr:    false,
		},
		{
			name:       "first validator fails",
			value:      "",
			validators: []func(string) error{isNotEmpty, isNumeric, isPositive},
			wantErr:    true,
		},
		{
			name:       "middle validator fails",
			value:      "abc",
			validators: []func(string) error{isNotEmpty, isNumeric, isPositive},
			wantErr:    true,
		},
		{
			name:       "last validator fails",
			value:      "-5",
			validators: []func(string) error{isNotEmpty, isNumeric, isPositive},
			wantErr:    true,
		},
		{
			name:       "no validators",
			value:      "test",
			validators: []func(string) error{},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAll(tt.value, tt.validators...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAll() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAny(t *testing.T) {
	// Test validators
	isEmail := func(v string) error {
		if !contains(v, "@") {
			return errors.New("not an email")
		}
		return nil
	}

	isPhone := func(v string) error {
		if len(v) != 10 || !isNumeric(v) {
			return errors.New("not a phone")
		}
		return nil
	}

	isUsername := func(v string) error {
		if len(v) < 3 {
			return errors.New("not a username")
		}
		return nil
	}

	tests := []struct {
		name       string
		value      string
		validators []func(string) error
		wantErr    bool
	}{
		{
			name:       "first validator passes",
			value:      "test@example.com",
			validators: []func(string) error{isEmail, isPhone, isUsername},
			wantErr:    false,
		},
		{
			name:       "middle validator passes",
			value:      "1234567890",
			validators: []func(string) error{isEmail, isPhone, isUsername},
			wantErr:    false,
		},
		{
			name:       "last validator passes",
			value:      "username",
			validators: []func(string) error{isEmail, isPhone, isUsername},
			wantErr:    false,
		},
		{
			name:       "all validators fail",
			value:      "ab",
			validators: []func(string) error{isEmail, isPhone, isUsername},
			wantErr:    true,
		},
		{
			name:       "no validators",
			value:      "test",
			validators: []func(string) error{},
			wantErr:    true, // Should fail with no validators
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAny(tt.value, tt.validators...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAny() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s != "" && substr != "" && (s == substr || contains(s[1:], substr) || contains(s[:len(s)-1], substr))
}

func isNumeric(s string) bool {
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}