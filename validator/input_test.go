package validator

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/flyzard/go-guardian"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
		errType error
	}{
		// Valid emails
		{
			name:    "valid simple email",
			email:   "user@example.com",
			wantErr: false,
		},
		{
			name:    "valid email with subdomain",
			email:   "user@sub.example.com",
			wantErr: false,
		},
		{
			name:    "valid email with plus",
			email:   "user+tag@example.com",
			wantErr: false,
		},
		{
			name:    "valid email with dots",
			email:   "first.last@example.com",
			wantErr: false,
		},
		{
			name:    "valid email with numbers",
			email:   "user123@example123.com",
			wantErr: false,
		},
		{
			name:    "valid email with hyphens",
			email:   "user@ex-ample.com",
			wantErr: false,
		},
		{
			name:    "valid email with underscores",
			email:   "user_name@example.com",
			wantErr: false,
		},

		// Invalid emails - empty/whitespace
		{
			name:    "empty email",
			email:   "",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "whitespace only",
			email:   "   ",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "email with leading whitespace",
			email:   " user@example.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "email with trailing whitespace",
			email:   "user@example.com ",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},

		// Invalid emails - format issues
		{
			name:    "missing @ symbol",
			email:   "userexample.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "multiple @ symbols",
			email:   "user@@example.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "missing local part",
			email:   "@example.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "missing domain",
			email:   "user@",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "dots in wrong places",
			email:   ".user@example.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "consecutive dots",
			email:   "user..name@example.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "domain starts with dot",
			email:   "user@.example.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "domain ends with dot",
			email:   "user@example.com.",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},

		// Invalid emails - length issues
		{
			name:    "too long overall",
			email:   strings.Repeat("a", 250) + "@example.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "local part too long",
			email:   strings.Repeat("a", 65) + "@example.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "domain too long",
			email:   "user@" + strings.Repeat("a", 254) + ".com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},

		// Invalid emails - special characters
		{
			name:    "invalid characters in local",
			email:   "user@#$@example.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "invalid characters in domain",
			email:   "user@exam$ple.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "unicode in domain",
			email:   "user@examplé.com",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},

		// Edge cases
		{
			name:    "IP address in brackets",
			email:   "user@[192.168.1.1]",
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
		{
			name:    "quoted local part",
			email:   `"user name"@example.com`,
			wantErr: true,
			errType: guardian.ErrEmailInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateEmail() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if tt.errType != nil && err != tt.errType {
					t.Errorf("ValidateEmail() error = %v, want %v", err, tt.errType)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateEmail() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
		errType  error
	}{
		// Valid usernames
		{
			name:     "valid alphanumeric",
			username: "user123",
			wantErr:  false,
		},
		{
			name:     "valid with underscore",
			username: "user_name",
			wantErr:  false,
		},
		{
			name:     "valid with hyphen",
			username: "user-name",
			wantErr:  false,
		},
		{
			name:     "valid with dot",
			username: "user.name",
			wantErr:  false,
		},
		{
			name:     "valid minimum length",
			username: "abc",
			wantErr:  false,
		},
		{
			name:     "valid maximum length",
			username: strings.Repeat("a", 50),
			wantErr:  false,
		},

		// Invalid usernames - length
		{
			name:     "too short",
			username: "ab",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "too long",
			username: strings.Repeat("a", 51),
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "empty username",
			username: "",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},

		// Invalid usernames - format
		{
			name:     "starts with number",
			username: "123user",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "starts with underscore",
			username: "_user",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "starts with hyphen",
			username: "-user",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "starts with dot",
			username: ".user",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "ends with dot",
			username: "user.",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "consecutive dots",
			username: "user..name",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "consecutive underscores",
			username: "user__name",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "consecutive hyphens",
			username: "user--name",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},

		// Invalid usernames - special characters
		{
			name:     "space in username",
			username: "user name",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "special characters",
			username: "user@name",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "unicode characters",
			username: "usér",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},

		// Reserved usernames
		{
			name:     "admin reserved",
			username: "admin",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "root reserved",
			username: "root",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "system reserved",
			username: "system",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "null reserved",
			username: "null",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "undefined reserved",
			username: "undefined",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "www reserved",
			username: "www",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "api reserved",
			username: "api",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},

		// Case insensitive reserved names
		{
			name:     "ADMIN reserved",
			username: "ADMIN",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
		{
			name:     "Admin reserved",
			username: "Admin",
			wantErr:  true,
			errType:  guardian.ErrInvalidUsername,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.username)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateUsername() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if tt.errType != nil && err != tt.errType {
					t.Errorf("ValidateUsername() error = %v, want %v", err, tt.errType)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateUsername() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "normal string unchanged",
			input:    "hello world",
			maxLen:   50,
			expected: "hello world",
		},
		{
			name:     "trim leading and trailing spaces",
			input:    "  hello world  ",
			maxLen:   50,
			expected: "hello world",
		},
		{
			name:     "normalize internal whitespace",
			input:    "hello    world",
			maxLen:   50,
			expected: "hello world",
		},
		{
			name:     "remove control characters",
			input:    "hello\x00\x01world",
			maxLen:   50,
			expected: "helloworld",
		},
		{
			name:     "remove tabs and newlines",
			input:    "hello\t\nworld",
			maxLen:   50,
			expected: "hello world",
		},
		{
			name:     "truncate long strings",
			input:    strings.Repeat("a", 100),
			maxLen:   10,
			expected: strings.Repeat("a", 10),
		},
		{
			name:     "handle unicode properly",
			input:    "héllo wörld",
			maxLen:   50,
			expected: "héllo wörld",
		},
		{
			name:     "unicode truncation at boundary",
			input:    "hello wörld",
			maxLen:   9,
			expected: "hello wör",
		},
		{
			name:     "empty string",
			input:    "",
			maxLen:   50,
			expected: "",
		},
		{
			name:     "whitespace only",
			input:    "   \t\n   ",
			maxLen:   50,
			expected: "",
		},
		{
			name:     "mixed control and printable",
			input:    "hello\x00 \x01world\x02",
			maxLen:   50,
			expected: "hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeString() = %q, want %q", result, tt.expected)
			}

			// Verify length constraint if maxLen is specified in test
			if tt.maxLen > 0 && utf8.RuneCountInString(result) > tt.maxLen {
				t.Errorf("SanitizeString() result length %d exceeds expected max %d", utf8.RuneCountInString(result), tt.maxLen)
			}

			// Verify no control characters remain
			for _, r := range result {
				if r < ' ' && r != ' ' {
					t.Errorf("SanitizeString() contains control character: %q", r)
				}
			}
		})
	}
}

func TestValidateRequestSize(t *testing.T) {
	tests := []struct {
		name    string
		size    int64
		maxSize int64
		wantErr bool
		errType error
	}{
		{
			name:    "size within limit",
			size:    1000,
			maxSize: 2000,
			wantErr: false,
		},
		{
			name:    "size at limit",
			size:    2000,
			maxSize: 2000,
			wantErr: false,
		},
		{
			name:    "size exceeds limit",
			size:    3000,
			maxSize: 2000,
			wantErr: true,
			errType: guardian.ErrRequestTooLarge,
		},
		{
			name:    "zero size allowed",
			size:    0,
			maxSize: 1000,
			wantErr: false,
		},
		{
			name:    "negative size invalid",
			size:    -1,
			maxSize: 1000,
			wantErr: true,
			errType: guardian.ErrRequestTooLarge,
		},
		{
			name:    "zero max size blocks all",
			size:    1,
			maxSize: 0,
			wantErr: true,
			errType: guardian.ErrRequestTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequestSize(tt.size, tt.maxSize)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateRequestSize() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if tt.errType != nil && err != tt.errType {
					t.Errorf("ValidateRequestSize() error = %v, want %v", err, tt.errType)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateRequestSize() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestIsValidUUID(t *testing.T) {
	tests := []struct {
		name     string
		uuid     string
		expected bool
	}{
		{
			name:     "valid UUID v4",
			uuid:     "123e4567-e89b-12d3-a456-426614174000",
			expected: true,
		},
		{
			name:     "valid UUID v1",
			uuid:     "01234567-89ab-1def-8123-456789abcdef",
			expected: true,
		},
		{
			name:     "uppercase UUID",
			uuid:     "123E4567-E89B-12D3-A456-426614174000",
			expected: true,
		},
		{
			name:     "invalid length",
			uuid:     "123e4567-e89b-12d3-a456-42661417400",
			expected: false,
		},
		{
			name:     "missing hyphens",
			uuid:     "123e4567e89b12d3a456426614174000",
			expected: false,
		},
		{
			name:     "invalid characters",
			uuid:     "123e4567-e89g-12d3-a456-426614174000",
			expected: false,
		},
		{
			name:     "empty string",
			uuid:     "",
			expected: false,
		},
		{
			name:     "nil UUID",
			uuid:     "00000000-0000-0000-0000-000000000000",
			expected: true,
		},
		{
			name:     "wrong hyphen positions",
			uuid:     "123e4567e-89b-12d3-a456-426614174000",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidUUID(tt.uuid)
			if result != tt.expected {
				t.Errorf("IsValidUUID() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkValidateEmail(b *testing.B) {
	email := "user@example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateEmail(email)
	}
}

func BenchmarkValidateUsername(b *testing.B) {
	username := "validuser123"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateUsername(username)
	}
}

func BenchmarkSanitizeString(b *testing.B) {
	input := "hello   world   with   spaces"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SanitizeString(input)
	}
}

func BenchmarkSanitizeStringLong(b *testing.B) {
	input := strings.Repeat("hello world ", 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SanitizeString(input)
	}
}

// Fuzz testing for edge cases
func FuzzValidateEmail(f *testing.F) {
	// Add seed corpus
	f.Add("user@example.com")
	f.Add("invalid.email")
	f.Add("@example.com")
	f.Add("user@")

	f.Fuzz(func(_ *testing.T, email string) {
		// Should not panic on any input
		ValidateEmail(email)
	})
}

func FuzzValidateUsername(f *testing.F) {
	// Add seed corpus
	f.Add("validuser")
	f.Add("admin")
	f.Add("123invalid")

	f.Fuzz(func(_ *testing.T, username string) {
		// Should not panic on any input
		ValidateUsername(username)
	})
}

func FuzzSanitizeString(f *testing.F) {
	// Add seed corpus
	f.Add("normal string", 100)
	f.Add("string\x00with\x01control", 50)
	f.Add("   spaced   string   ", 25)

	f.Fuzz(func(t *testing.T, input string, maxLen int) {
		// Ensure maxLen is reasonable for testing
		if maxLen < 0 {
			maxLen = 0
		}
		if maxLen > 10000 {
			maxLen = 10000
		}

		result := SanitizeString(input)

		// Should not panic and result should be within length limit
		if utf8.RuneCountInString(result) > maxLen {
			t.Errorf("Result exceeds max length: got %d, max %d", utf8.RuneCountInString(result), maxLen)
		}
	})
}
