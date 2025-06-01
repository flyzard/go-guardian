package security

import (
	"html"
	"regexp"
	"strings"
)

// Sanitizer provides input sanitization functions
type Sanitizer struct{}

// NewSanitizer creates a new sanitizer instance
func NewSanitizer() *Sanitizer {
	return &Sanitizer{}
}

// SanitizeHTML removes potentially dangerous HTML tags and attributes
func (s *Sanitizer) SanitizeHTML(input string) string {
	// Remove script tags
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	input = scriptRegex.ReplaceAllString(input, "")

	// Remove style tags
	styleRegex := regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	input = styleRegex.ReplaceAllString(input, "")

	// Remove dangerous attributes
	onEventRegex := regexp.MustCompile(`(?i)\s+on\w+\s*=\s*["\'][^"\']*["\']`)
	input = onEventRegex.ReplaceAllString(input, "")

	// Remove javascript: protocol
	jsProtocolRegex := regexp.MustCompile(`(?i)javascript:`)
	input = jsProtocolRegex.ReplaceAllString(input, "")

	// Escape remaining HTML
	return html.EscapeString(input)
}

// SanitizeSQL removes SQL injection attempts
func (s *Sanitizer) SanitizeSQL(input string) string {
	// Remove common SQL injection patterns
	patterns := []string{
		`(?i)\s*(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+`,
		`(?i)\s*;\s*`,
		`(?i)\s*--\s*`,
		`(?i)\s*/\*.*?\*/\s*`,
		`(?i)\s*'\s*(or|and)\s*'.*?'\s*`,
		`(?i)\s*1\s*=\s*1\s*`,
		`(?i)\s*1\s*=\s*0\s*`,
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		input = regex.ReplaceAllString(input, "")
	}

	return strings.TrimSpace(input)
}

// SanitizeEmail validates and sanitizes email addresses
func (s *Sanitizer) SanitizeEmail(email string) string {
	email = strings.TrimSpace(strings.ToLower(email))
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	if !emailRegex.MatchString(email) {
		return ""
	}

	return email
}

// SanitizeFilename sanitizes filenames for safe storage
func (s *Sanitizer) SanitizeFilename(filename string) string {
	// Remove dangerous characters
	dangerousChars := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	filename = dangerousChars.ReplaceAllString(filename, "_")

	// Remove leading/trailing dots and spaces
	filename = strings.Trim(filename, ". ")

	// Limit length
	if len(filename) > 255 {
		filename = filename[:255]
	}

	return filename
}

// StripTags removes all HTML tags from input
func (s *Sanitizer) StripTags(input string) string {
	tagRegex := regexp.MustCompile(`<[^>]*>`)
	return tagRegex.ReplaceAllString(input, "")
}

// ValidatePassword checks password strength
func (s *Sanitizer) ValidatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	// Check for at least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)

	// Check for at least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)

	// Check for at least one digit
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)

	// Check for at least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)

	return hasUpper && hasLower && hasDigit && hasSpecial
}
