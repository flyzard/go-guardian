package security

import (
	"strings"
	"testing"
)

func TestXSSPrevention(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		desc     string
	}{
		{
			`<script>alert('xss')</script>`,
			`&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;`,
			"script tag",
		},
		{
			`<img src=x onerror="alert('xss')">`,
			`&lt;img src=x onerror=&#34;alert(&#39;xss&#39;)&#34;&gt;`,
			"event handler",
		},
		{
			`<a href="javascript:alert('xss')">click</a>`,
			`&lt;a href=&#34;javascript:alert(&#39;xss&#39;)&#34;&gt;click&lt;/a&gt;`,
			"javascript URL",
		},
		{
			`Hello <b>World</b>`,
			`Hello &lt;b&gt;World&lt;/b&gt;`,
			"HTML tags",
		},
		{
			`Plain text with special chars: <>&"'`,
			`Plain text with special chars: &lt;&gt;&amp;&#34;&#39;`,
			"special characters",
		},
	}

	for _, tt := range tests {
		result := SanitizeHTML(tt.input)
		if result != tt.expected {
			t.Errorf("%s: expected %q, got %q", tt.desc, tt.expected, result)
		}
	}
}

func TestSanitizeOutput(t *testing.T) {
	// Test that malicious patterns are removed before escaping
	input := `<script>alert('xss')</script>Hello<img onerror="bad()">World`
	output := SanitizeOutput(input)

	if strings.Contains(output, "<script>") || strings.Contains(output, "onerror") {
		t.Errorf("Malicious content not properly sanitized: %s", output)
	}
}
