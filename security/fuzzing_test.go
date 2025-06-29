package security

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestInputSanitizationFuzzing(t *testing.T) {
	// Test with various malformed inputs
	fuzzInputs := []string{
		// Unicode edge cases
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08",
		"\u200B\u200C\u200D\uFEFF", // Zero-width characters
		"\U0001F4A9",               // Emoji
		strings.Repeat("A", 10000), // Long string

		// HTML/JS injection variants
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<iframe src=javascript:alert(1)>",
		"<object data=javascript:alert(1)>",
		"<embed src=javascript:alert(1)>",
		"<form action=javascript:alert(1)>",
		"<input onfocus=alert(1) autofocus>",
		"<select onfocus=alert(1) autofocus>",
		"<textarea onfocus=alert(1) autofocus>",
		"<button onclick=alert(1)>",

		// Protocol handlers
		"javascript:void(0)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",

		// SQL-like patterns (should be safely handled)
		"'; DROP TABLE users; --",
		"1' OR '1'='1",
		"admin'--",
		"1 UNION SELECT * FROM users",
	}

	for _, input := range fuzzInputs {
		output := SanitizeHTML(input)

		// Ensure output is valid UTF-8
		if !utf8.ValidString(output) {
			t.Errorf("Invalid UTF-8 output for input: %q", input)
		}

		// For SanitizeHTML, we only escape HTML - we don't remove content
		// So we should check that angle brackets are escaped
		if strings.Contains(output, "<") || strings.Contains(output, ">") {
			t.Errorf("Unescaped HTML in output: %q", output)
		}

		// Test SanitizeOutput which should remove dangerous patterns
		sanitized := SanitizeOutput(input)

		// Check that script tags and event handlers are removed
		dangerousPatterns := []string{
			"<script", "</script>", "onerror=", "onclick=",
			"onload=", "onfocus=", "javascript:",
		}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(sanitized, pattern) {
				t.Errorf("SanitizeOutput failed to remove %q from input: %q", pattern, input)
			}
		}
	}
}

func TestTruncateStringBoundaries(t *testing.T) {
	tests := []struct {
		input     string
		maxLength int
		expected  string
	}{
		{"", 10, ""},
		{"short", 10, "short"},
		{"exactlength", 11, "exactlength"},
		{"toolongstring", 10, "toolongstr"},
		{"Hello\x00World", 20, "Hello\x00World"}, // Null bytes
	}

	for _, tt := range tests {
		result := TruncateString(tt.input, tt.maxLength)
		if result != tt.expected {
			t.Errorf("TruncateString(%q, %d) = %q, want %q",
				tt.input, tt.maxLength, result, tt.expected)
		}
	}

	// Test multi-byte character truncation separately
	// This is tricky because we need to ensure we don't break UTF-8 sequences
	multiByteTest := strings.Repeat("あ", 10) // 30 bytes total (3 bytes per character)

	// Truncate to 15 bytes should give us 5 complete characters (15 bytes)
	result := TruncateString(multiByteTest, 15)
	if !utf8.ValidString(result) {
		t.Error("TruncateString produced invalid UTF-8")
	}

	// The result should be 5 characters or less
	if utf8.RuneCountInString(result) > 5 {
		t.Errorf("TruncateString with multi-byte chars: got %d runes, want <= 5",
			utf8.RuneCountInString(result))
	}
}
