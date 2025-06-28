package security

import (
	"html"
	"regexp"
)

var (
	// Patterns that might indicate XSS attempts
	scriptPattern = regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	eventPattern  = regexp.MustCompile(`(?i)\bon\w+\s*=`)
	jsPattern     = regexp.MustCompile(`(?i)javascript:`)
)

// SanitizeHTML escapes HTML special characters
func SanitizeHTML(input string) string {
	return html.EscapeString(input)
}

// SanitizeOutput prepares user content for safe display
func SanitizeOutput(input string) string {
	// Remove potential script tags
	input = scriptPattern.ReplaceAllString(input, "")

	// Remove event handlers
	input = eventPattern.ReplaceAllString(input, "")

	// Remove javascript: URLs
	input = jsPattern.ReplaceAllString(input, "")

	// Escape HTML
	return html.EscapeString(input)
}

// StripTags removes all HTML tags
func StripTags(input string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(input, "")
}

// TruncateString safely truncates strings to prevent buffer overflows
func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	return s[:maxLength]
}
