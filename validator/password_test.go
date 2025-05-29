package validator

import (
	"strings"
	"testing"

	"github.com/flyzard/go-guardian/types"
)

func TestValidatePassword(t *testing.T) {
	defaultPolicy := types.DefaultPasswordPolicy()

	tests := []struct {
		name     string
		password string
		policy   types.PasswordPolicy
		wantErr  bool
		errMsg   string
	}{
		// Length validation tests
		{
			name:     "valid password meets all requirements",
			password: "MySecure123!",
			policy:   defaultPolicy,
			wantErr:  false,
		},
		{
			name:     "password too short",
			password: "Abc1!",
			policy:   defaultPolicy,
			wantErr:  true,
			errMsg:   "password must be at least 8 characters long",
		},
		{
			name:     "minimum length exactly met",
			password: "Abcd123!",
			policy:   defaultPolicy,
			wantErr:  false,
		},

		// Uppercase requirement tests
		{
			name:     "missing uppercase letter",
			password: "mypassword123!",
			policy:   defaultPolicy,
			wantErr:  true,
			errMsg:   "password must contain at least one uppercase letter",
		},
		{
			name:     "uppercase requirement disabled",
			password: "mypassword123!",
			policy: types.PasswordPolicy{
				MinLength:        8,
				RequireUppercase: false,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				PreventCommon:    true,
				PreventUserInfo:  true,
			},
			wantErr: false,
		},

		// Lowercase requirement tests
		{
			name:     "missing lowercase letter",
			password: "MYPASSWORD123!",
			policy:   defaultPolicy,
			wantErr:  true,
			errMsg:   "password must contain at least one lowercase letter",
		},
		{
			name:     "lowercase requirement disabled",
			password: "MYPASSWORD123!",
			policy: types.PasswordPolicy{
				MinLength:        8,
				RequireUppercase: true,
				RequireLowercase: false,
				RequireNumbers:   true,
				RequireSpecial:   true,
				PreventCommon:    true,
				PreventUserInfo:  true,
			},
			wantErr: false,
		},

		// Numbers requirement tests
		{
			name:     "missing numbers",
			password: "MyPassword!",
			policy:   defaultPolicy,
			wantErr:  true,
			errMsg:   "password must contain at least one number",
		},
		{
			name:     "numbers requirement disabled",
			password: "MyPassword!",
			policy: types.PasswordPolicy{
				MinLength:        8,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   false,
				RequireSpecial:   true,
				PreventCommon:    true,
				PreventUserInfo:  true,
			},
			wantErr: false,
		},

		// Special characters requirement tests
		{
			name:     "missing special characters when required",
			password: "MyPassword123",
			policy: types.PasswordPolicy{
				MinLength:        8,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				PreventCommon:    true,
				PreventUserInfo:  true,
			},
			wantErr: true,
			errMsg:  "password must contain at least one special character",
		},
		{
			name:     "special characters not required",
			password: "MyPassword123",
			policy:   defaultPolicy, // default has RequireSpecial: false
			wantErr:  false,
		},

		// Common password tests
		{
			name:     "common password rejected",
			password: "Password123",
			policy:   defaultPolicy,
			wantErr:  true,
			errMsg:   "password is too common and easily guessable",
		},
		{
			name:     "123456 rejected",
			password: "123456",
			policy:   defaultPolicy,
			wantErr:  true,
			errMsg:   "password is too common and easily guessable",
		},
		{
			name:     "qwerty rejected",
			password: "qwerty",
			policy:   defaultPolicy,
			wantErr:  true,
			errMsg:   "password is too common and easily guessable",
		},
		{
			name:     "common password check disabled",
			password: "password",
			policy: types.PasswordPolicy{
				MinLength:        8,
				RequireUppercase: false,
				RequireLowercase: false,
				RequireNumbers:   false,
				RequireSpecial:   false,
				PreventCommon:    false,
				PreventUserInfo:  true,
			},
			wantErr: false,
		},

		// Unicode and international characters
		{
			name:     "unicode characters supported",
			password: "Пароль123!",
			policy:   defaultPolicy,
			wantErr:  false,
		},
		{
			name:     "emoji in password",
			password: "MyPass🔒123",
			policy:   defaultPolicy,
			wantErr:  false,
		},

		// Edge cases
		{
			name:     "empty password",
			password: "",
			policy:   defaultPolicy,
			wantErr:  true,
			errMsg:   "password must be at least 8 characters long",
		},
		{
			name:     "whitespace only password",
			password: "        ",
			policy:   defaultPolicy,
			wantErr:  true,
			errMsg:   "password must contain at least one uppercase letter",
		},
		{
			name:     "very long password",
			password: strings.Repeat("A", 100) + "a1!",
			policy:   defaultPolicy,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password, tt.policy)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidatePassword() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidatePassword() error = %v, want error containing %v", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidatePassword() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestValidatePasswordWithUserInfo(t *testing.T) {
	policy := types.DefaultPasswordPolicy()

	tests := []struct {
		name     string
		password string
		email    string
		userName string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "password without user info is valid",
			password: "SecurePass123!",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  false,
		},
		{
			name:     "password contains full email",
			password: "user@example.com123",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "password must not contain your email address",
		},
		{
			name:     "password contains email username",
			password: "myuser123!",
			email:    "myuser@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "password must not contain your email username",
		},
		{
			name:     "password contains email domain",
			password: "example123!",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "password must not contain your email domain",
		},
		{
			name:     "password contains full name",
			password: "john doe123!",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "password must not contain your name",
		},
		{
			name:     "password contains first name",
			password: "johnPassword123!",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "password must not contain parts of your name",
		},
		{
			name:     "password contains last name",
			password: "doeSecure123!",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "password must not contain parts of your name",
		},
		{
			name:     "case insensitive email check",
			password: "USER123!",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "password must not contain your email username",
		},
		{
			name:     "case insensitive name check",
			password: "JOHN123!",
			email:    "user@example.com",
			userName: "john doe",
			wantErr:  true,
			errMsg:   "password must not contain parts of your name",
		},
		{
			name:     "short email parts ignored",
			password: "ab123!Test",
			email:    "ab@cd.com",
			userName: "cd ef",
			wantErr:  false, // 'ab' and 'cd' are too short (< 3 chars)
		},
		{
			name:     "empty email and name",
			password: "SecurePass123!",
			email:    "",
			userName: "",
			wantErr:  false,
		},
		{
			name:     "user info prevention disabled",
			password: "john123!",
			email:    "john@example.com",
			userName: "John Doe",
			wantErr:  false, // Should pass standard validation but fail with user info
		},
		{
			name:     "complex name with multiple words",
			password: "elizabeth123!",
			email:    "user@example.com",
			userName: "Mary Elizabeth Johnson Smith",
			wantErr:  true,
			errMsg:   "password must not contain parts of your name",
		},
		{
			name:     "subdomain in email",
			password: "subdomain123!",
			email:    "user@subdomain.example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "password must not contain your email domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordWithUserInfo(tt.password, policy, tt.email, tt.userName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidatePasswordWithUserInfo() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidatePasswordWithUserInfo() error = %v, want error containing %v", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidatePasswordWithUserInfo() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestCharacterClassValidation(t *testing.T) {
	tests := []struct {
		name     string
		function func(string) bool
		input    string
		expected bool
	}{
		// Uppercase tests
		{"hasUppercase with uppercase", hasUppercase, "Hello", true},
		{"hasUppercase without uppercase", hasUppercase, "hello123!", false},
		{"hasUppercase empty string", hasUppercase, "", false},
		{"hasUppercase unicode uppercase", hasUppercase, "Ñoño", true},

		// Lowercase tests
		{"hasLowercase with lowercase", hasLowercase, "Hello", true},
		{"hasLowercase without lowercase", hasLowercase, "HELLO123!", false},
		{"hasLowercase empty string", hasLowercase, "", false},
		{"hasLowercase unicode lowercase", hasLowercase, "ñOÑO", true},

		// Numbers tests
		{"hasNumbers with numbers", hasNumbers, "hello123", true},
		{"hasNumbers without numbers", hasNumbers, "hello!", false},
		{"hasNumbers empty string", hasNumbers, "", false},
		{"hasNumbers unicode numbers", hasNumbers, "test٧", true},

		// Special characters tests
		{"hasSpecialChars with special", hasSpecialChars, "hello!", true},
		{"hasSpecialChars without special", hasSpecialChars, "hello123", false},
		{"hasSpecialChars empty string", hasSpecialChars, "", false},
		{"hasSpecialChars with space", hasSpecialChars, "hello world", false}, // spaces don't count
		{"hasSpecialChars with unicode special", hasSpecialChars, "hello©", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.function(tt.input)
			if result != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestCommonPasswords(t *testing.T) {
	// Test a selection of known common passwords
	commonPwds := []string{
		"123456", "password", "123456789", "qwerty", "abc123",
		"Password", "PASSWORD", "123456", "admin", "guest",
	}

	for _, pwd := range commonPwds {
		t.Run("common_password_"+pwd, func(t *testing.T) {
			if !isCommonPassword(pwd) {
				t.Errorf("isCommonPassword(%s) = false, want true", pwd)
			}
		})
	}

	// Test some passwords that should NOT be common
	uniquePwds := []string{
		"MyVeryUniquePassword123!", "Th1s1sN0tC0mm0n!", "RandomSecure789#",
		"ComplexP@ssw0rd!", "UnusualCombination567$",
	}

	for _, pwd := range uniquePwds {
		t.Run("unique_password_"+pwd, func(t *testing.T) {
			if isCommonPassword(pwd) {
				t.Errorf("isCommonPassword(%s) = true, want false", pwd)
			}
		})
	}
}

func TestUserInfoLeakage(t *testing.T) {
	tests := []struct {
		name     string
		password string
		email    string
		userName string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "no leakage",
			password: "SecurePassword123!",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  false,
		},
		{
			name:     "email in password",
			password: "user@example.com",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "email address",
		},
		{
			name:     "username part in password",
			password: "userPassword",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "email username",
		},
		{
			name:     "domain in password",
			password: "examplePassword",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "email domain",
		},
		{
			name:     "name in password",
			password: "john doe",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "your name",
		},
		{
			name:     "name part in password",
			password: "johnSecure",
			email:    "user@example.com",
			userName: "John Doe",
			wantErr:  true,
			errMsg:   "parts of your name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkUserInfoLeakage(tt.password, tt.email, tt.userName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("checkUserInfoLeakage() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("checkUserInfoLeakage() error = %v, want error containing %v", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("checkUserInfoLeakage() unexpected error = %v", err)
				}
			}
		})
	}
}

// Benchmark tests for performance
func BenchmarkValidatePassword(b *testing.B) {
	policy := types.DefaultPasswordPolicy()
	password := "MySecurePassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidatePassword(password, policy)
	}
}

func BenchmarkValidatePasswordWithUserInfo(b *testing.B) {
	policy := types.DefaultPasswordPolicy()
	password := "MySecurePassword123!"
	email := "user@example.com"
	name := "John Doe"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidatePasswordWithUserInfo(password, policy, email, name)
	}
}

func BenchmarkCommonPasswordCheck(b *testing.B) {
	password := "MySecurePassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isCommonPassword(password)
	}
}

// Test edge cases with international characters
func TestInternationalCharacters(t *testing.T) {
	policy := types.DefaultPasswordPolicy()

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "russian characters",
			password: "Пароль123!",
			wantErr:  false,
		},
		{
			name:     "chinese characters",
			password: "密码123ABC!",
			wantErr:  false,
		},
		{
			name:     "arabic characters",
			password: "كلمةسر123ABC!",
			wantErr:  false,
		},
		{
			name:     "mixed scripts",
			password: "МойPаss密码123!",
			wantErr:  false,
		},
		{
			name:     "emoji characters",
			password: "MyPass🔒🛡️123!",
			wantErr:  false,
		},
		{
			name:     "accented characters",
			password: "Contraseña123!",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password, policy)

			if tt.wantErr && err == nil {
				t.Errorf("ValidatePassword() expected error but got none")
			} else if !tt.wantErr && err != nil {
				t.Errorf("ValidatePassword() unexpected error = %v", err)
			}
		})
	}
}
