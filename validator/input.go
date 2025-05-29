// Package validator provides input validation utilities for go-guardian.
// This module includes email validation, username validation, and string sanitization
// to prevent common security vulnerabilities.
package validator

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/flyzard/go-guardian"
)

// Input validation constants
const (
	// MaxEmailLength is the maximum allowed length for email addresses
	MaxEmailLength = 254

	// MaxUsernameLength is the maximum allowed length for usernames
	MaxUsernameLength = 32

	// MinUsernameLength is the minimum allowed length for usernames
	MinUsernameLength = 3

	// MaxStringLength is the maximum allowed length for general string inputs
	MaxStringLength = 1024
)

// Regular expressions for validation
var (
	// RFC 5322 compliant email regex (simplified but secure)
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

	// Username validation: alphanumeric, underscore, dash, dot (no spaces)
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

	// Reserved usernames that should not be allowed
	reservedUsernames = map[string]bool{
		"admin":     true,
		"root":      true,
		"system":    true,
		"user":      true,
		"guest":     true,
		"test":      true,
		"api":       true,
		"www":       true,
		"mail":      true,
		"ftp":       true,
		"support":   true,
		"service":   true,
		"daemon":    true,
		"operator":  true,
		"manager":   true,
		"moderator": true,
		"anonymous": true,
		"null":      true,
		"undefined": true,
	}
)

// ValidateEmail validates an email address according to RFC 5322 standards.
// It performs comprehensive validation including length, format, and domain checks.
func ValidateEmail(email string) error {
	if email == "" {
		return guardian.NewValidationError("Email Validation Failed", "email address cannot be empty")
	}

	// Length validation
	if len(email) > MaxEmailLength {
		return guardian.NewValidationError("Email Validation Failed",
			fmt.Sprintf("email address must be no more than %d characters", MaxEmailLength))
	}

	// Basic format validation
	if !emailRegex.MatchString(email) {
		return guardian.NewValidationError("Email Validation Failed", "email address format is invalid")
	}

	// Additional validation checks
	if strings.HasPrefix(email, ".") || strings.HasSuffix(email, ".") {
		return guardian.NewValidationError("Email Validation Failed", "email address cannot start or end with a dot")
	}

	if strings.Contains(email, "..") {
		return guardian.NewValidationError("Email Validation Failed", "email address cannot contain consecutive dots")
	}

	// Split and validate parts
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return guardian.NewValidationError("Email Validation Failed", "email address must contain exactly one @ symbol")
	}

	localPart := parts[0]
	domainPart := parts[1]

	// Local part validation
	if len(localPart) == 0 || len(localPart) > 64 {
		return guardian.NewValidationError("Email Validation Failed", "email local part must be between 1 and 64 characters")
	}

	// Domain part validation
	if len(domainPart) == 0 || len(domainPart) > 253 {
		return guardian.NewValidationError("Email Validation Failed", "email domain part must be between 1 and 253 characters")
	}

	// Domain must contain at least one dot
	if !strings.Contains(domainPart, ".") {
		return guardian.NewValidationError("Email Validation Failed", "email domain must contain at least one dot")
	}

	// Validate domain labels
	domainLabels := strings.Split(domainPart, ".")
	for _, label := range domainLabels {
		if len(label) == 0 || len(label) > 63 {
			return guardian.NewValidationError("Email Validation Failed", "email domain labels must be between 1 and 63 characters")
		}

		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return guardian.NewValidationError("Email Validation Failed", "email domain labels cannot start or end with hyphens")
		}
	}

	return nil
}

// ValidateUsername validates a username according to security best practices.
// It checks length, format, and prevents reserved usernames.
func ValidateUsername(username string) error {
	if username == "" {
		return guardian.NewValidationError("Username Validation Failed", "username cannot be empty")
	}

	// Length validation
	if len(username) < MinUsernameLength {
		return guardian.NewValidationError("Username Validation Failed",
			fmt.Sprintf("username must be at least %d characters long", MinUsernameLength))
	}

	if len(username) > MaxUsernameLength {
		return guardian.NewValidationError("Username Validation Failed",
			fmt.Sprintf("username must be no more than %d characters long", MaxUsernameLength))
	}

	// Format validation
	if !usernameRegex.MatchString(username) {
		return guardian.NewValidationError("Username Validation Failed",
			"username can only contain letters, numbers, dots, underscores, and hyphens")
	}

	// Cannot start or end with special characters
	if strings.HasPrefix(username, ".") || strings.HasPrefix(username, "_") || strings.HasPrefix(username, "-") {
		return guardian.NewValidationError("Username Validation Failed",
			"username cannot start with a dot, underscore, or hyphen")
	}

	if strings.HasSuffix(username, ".") || strings.HasSuffix(username, "_") || strings.HasSuffix(username, "-") {
		return guardian.NewValidationError("Username Validation Failed",
			"username cannot end with a dot, underscore, or hyphen")
	}

	// Cannot contain consecutive special characters
	if strings.Contains(username, "..") || strings.Contains(username, "__") || strings.Contains(username, "--") {
		return guardian.NewValidationError("Username Validation Failed",
			"username cannot contain consecutive special characters")
	}

	// Check for reserved usernames
	usernameLower := strings.ToLower(username)
	if reservedUsernames[usernameLower] {
		return guardian.NewValidationError("Username Validation Failed",
			"this username is reserved and cannot be used")
	}

	return nil
}

// SanitizeString sanitizes input strings to prevent common security vulnerabilities.
// It removes or escapes potentially dangerous characters while preserving readability.
func SanitizeString(input string) string {
	if input == "" {
		return ""
	}

	// Limit string length
	if len(input) > MaxStringLength {
		input = input[:MaxStringLength]
	}

	// Remove null bytes and other control characters (except tab and newline)
	var sanitized strings.Builder
	for _, r := range input {
		if r == 0 {
			// Skip null bytes completely
			continue
		}

		if unicode.IsControl(r) {
			// Allow tab (9) and newline (10, 13) but remove other control characters
			if r == '\t' || r == '\n' || r == '\r' {
				sanitized.WriteRune(r)
			}
			// Skip other control characters
			continue
		}

		sanitized.WriteRune(r)
	}

	result := sanitized.String()

	// Normalize whitespace - replace multiple consecutive spaces with single space
	normalizeSpace := regexp.MustCompile(`\s+`)
	result = normalizeSpace.ReplaceAllString(result, " ")

	// Trim leading and trailing whitespace
	result = strings.TrimSpace(result)

	return result
}

// ValidateRequestSize validates that the request size is within acceptable limits.
// This helps prevent DoS attacks through oversized requests.
func ValidateRequestSize(size int64, maxSize int64) error {
	if size < 0 {
		return guardian.NewValidationError("Request Validation Failed", "request size cannot be negative")
	}

	if size > maxSize {
		return guardian.NewValidationError("Request Validation Failed",
			fmt.Sprintf("request size %d exceeds maximum allowed size %d", size, maxSize))
	}

	return nil
}

// IsValidUUID validates that a string is a valid UUID format.
func IsValidUUID(uuid string) bool {
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return uuidRegex.MatchString(uuid)
}

// ValidateUUID validates a UUID and returns a proper error if invalid.
func ValidateUUID(uuid string) error {
	if uuid == "" {
		return guardian.NewValidationError("UUID Validation Failed", "UUID cannot be empty")
	}

	if !IsValidUUID(uuid) {
		return guardian.NewValidationError("UUID Validation Failed", "invalid UUID format")
	}

	return nil
}
