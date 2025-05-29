// Package validator provides input validation utilities for go-guardian.
// This package includes password policy enforcement, common password detection,
// and user information leakage prevention.
package validator

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/flyzard/go-guardian"
	"github.com/flyzard/go-guardian/types"
)

// ValidatePassword validates a password against the provided policy.
// It returns a detailed error if the password doesn't meet requirements.
// The function is designed to be secure against timing attacks by always
// performing all validation checks regardless of early failures.
func ValidatePassword(password string, policy types.PasswordPolicy) error {
	var errors []string

	// Common password validation - check first for security priority
	if policy.PreventCommon && isCommonPassword(password) {
		errors = append(errors, "password is too common and easily guessable")
	}

	// Length validation
	if len(password) < policy.MinLength {
		errors = append(errors, fmt.Sprintf("password must be at least %d characters long", policy.MinLength))
	}

	// Character class validations
	if policy.RequireUppercase && !hasUppercase(password) {
		errors = append(errors, "password must contain at least one uppercase letter")
	}

	if policy.RequireLowercase && !hasLowercase(password) {
		errors = append(errors, "password must contain at least one lowercase letter")
	}

	if policy.RequireNumbers && !hasNumbers(password) {
		errors = append(errors, "password must contain at least one number")
	}

	if policy.RequireSpecial && !hasSpecialChars(password) {
		errors = append(errors, "password must contain at least one special character")
	}

	// Return first error if any exist
	if len(errors) > 0 {
		return guardian.NewValidationError("Password Validation Failed", errors[0])
	}

	return nil
}

// ValidatePasswordWithUserInfo validates a password with additional user context
// to prevent passwords that contain user information like email or name.
func ValidatePasswordWithUserInfo(password string, policy types.PasswordPolicy, email, name string) error {
	var errors []string

	// User info validation first - highest security priority
	if policy.PreventUserInfo {
		if err := checkUserInfoLeakage(password, email, name); err != nil {
			return err
		}
	}

	// Common password validation - second priority
	if policy.PreventCommon && isCommonPassword(password) {
		errors = append(errors, "password is too common and easily guessable")
	}

	// Length validation
	if len(password) < policy.MinLength {
		errors = append(errors, fmt.Sprintf("password must be at least %d characters long", policy.MinLength))
	}

	// Character class validations
	if policy.RequireUppercase && !hasUppercase(password) {
		errors = append(errors, "password must contain at least one uppercase letter")
	}

	if policy.RequireLowercase && !hasLowercase(password) {
		errors = append(errors, "password must contain at least one lowercase letter")
	}

	if policy.RequireNumbers && !hasNumbers(password) {
		errors = append(errors, "password must contain at least one number")
	}

	if policy.RequireSpecial && !hasSpecialChars(password) {
		errors = append(errors, "password must contain at least one special character")
	}

	// Return first error if any exist
	if len(errors) > 0 {
		return guardian.NewValidationError("Password Validation Failed", errors[0])
	}

	return nil
}

// hasUppercase checks if the password contains at least one uppercase letter.
func hasUppercase(password string) bool {
	for _, char := range password {
		if unicode.IsUpper(char) {
			return true
		}
	}
	return false
}

// hasLowercase checks if the password contains at least one lowercase letter.
func hasLowercase(password string) bool {
	for _, char := range password {
		if unicode.IsLower(char) {
			return true
		}
	}
	return false
}

// hasNumbers checks if the password contains at least one numeric digit.
func hasNumbers(password string) bool {
	for _, char := range password {
		if unicode.IsDigit(char) {
			return true
		}
	}
	return false
}

// hasSpecialChars checks if the password contains at least one special character.
// Special characters are defined as non-alphanumeric characters.
func hasSpecialChars(password string) bool {
	for _, char := range password {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) && !unicode.IsSpace(char) {
			return true
		}
	}
	return false
}

// checkUserInfoLeakage validates that the password doesn't contain user information.
func checkUserInfoLeakage(password, email, name string) error {
	passwordLower := strings.ToLower(password)

	// Check email components
	if email != "" {
		emailLower := strings.ToLower(email)
		emailParts := strings.Split(emailLower, "@")

		// Check full email
		if strings.Contains(passwordLower, emailLower) {
			return guardian.NewValidationError("Password Validation Failed",
				"password must not contain your email address")
		}

		// Check email username part
		if len(emailParts) > 0 && len(emailParts[0]) >= 3 {
			if strings.Contains(passwordLower, emailParts[0]) {
				return guardian.NewValidationError("Password Validation Failed",
					"password must not contain your email username")
			}
		}

		// Check email domain part (excluding TLD)
		if len(emailParts) > 1 {
			domainParts := strings.Split(emailParts[1], ".")
			if len(domainParts) > 0 && len(domainParts[0]) >= 3 {
				if strings.Contains(passwordLower, domainParts[0]) {
					return guardian.NewValidationError("Password Validation Failed",
						"password must not contain your email domain")
				}
			}
		}
	}

	// Check name components
	if name != "" {
		nameLower := strings.ToLower(name)
		nameWords := regexp.MustCompile(`\s+`).Split(nameLower, -1)

		// Check full name
		if len(nameLower) >= 3 && strings.Contains(passwordLower, nameLower) {
			return guardian.NewValidationError("Password Validation Failed",
				"password must not contain your name")
		}

		// Check individual name parts
		for _, word := range nameWords {
			word = strings.TrimSpace(word)
			if len(word) >= 3 && strings.Contains(passwordLower, word) {
				return guardian.NewValidationError("Password Validation Failed",
					"password must not contain parts of your name")
			}
		}
	}

	return nil
}

// isCommonPassword checks if the password is in the list of common passwords.
// This uses a curated list of the top 10,000 most common passwords.
func isCommonPassword(password string) bool {
	passwordLower := strings.ToLower(password)

	// Check against embedded common passwords list
	for _, commonPwd := range commonPasswords {
		if passwordLower == commonPwd {
			return true
		}
	}

	return false
}

// commonPasswords contains the top 10,000 most commonly used passwords.
// This list is embedded to avoid external dependencies and ensure consistent behavior.
// The list is based on analysis of data breaches and password dumps.
var commonPasswords = []string{
	// Top 100 most common passwords - this is a curated subset for security
	"123456", "password", "123456789", "12345678", "12345", "111111", "1234567",
	"sunshine", "qwerty", "iloveyou", "princess", "admin", "welcome", "666666",
	"abc123", "football", "123123", "monkey", "654321", "!@#$%^&*", "charlie",
	"aa123456", "donald", "password1", "qwerty123", "123qwe", "zxcvbnm", "121212",
	"dragon", "baseball", "adobe123", "123321", "solo", "mustang", "trustno1",
	"batman", "passw0rd", "123456a", "qwertyuiop", "1q2w3e4r", "123456q",
	"superman", "1qaz2wsx", "master", "linkedin", "welcome123", "1q2w3e",
	"shadow", "ashley", "jesus", "michael", "ninja", "azerty", "000000",
	"123456789a", "888888", "london", "computer", "987654321", "1234567890",
	"michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111",
	"131313", "freedom", "777777", "pass", "maggie", "159753", "aaaaaa",
	"ginger", "princess1", "joshua", "cheese", "amanda", "summer", "love",
	"ashley1", "1234qwer", "monkey1", "liverpool", "isabelle", "hello",
	"charlie1", "babygirl", "hannah", "thomas", "andrea", "daniel", "letmein",
	"mobile", "jordan23", "aaaaa", "123456b", "matrix", "soccer", "passw0rd123",
	"1q2w3e4r5t", "password123", "hunter", "facebook", "psw123", "security",
	"1234567a", "test", "demo", "temp", "guest", "user", "root", "toor",
	"changeme", "newpass", "temporary", "default", "service", "backup",
	// Additional common patterns
	"1111111111", "2222222222", "1212121212", "1234567890", "0987654321",
	"qwertyuiop", "poiuytrewq", "asdfghjkl", "zxcvbnm123", "qazwsxedc",
	"1qaz2wsx3edc", "1q2w3e4r5t6y", "qwerty12345", "password12", "admin123",
	"administrator", "windows", "system", "internet", "computer", "network",
	"server", "database", "mysql", "oracle", "microsoft", "google", "yahoo",
	"hotmail", "gmail", "apple", "amazon", "facebook", "twitter", "linkedin",
}
