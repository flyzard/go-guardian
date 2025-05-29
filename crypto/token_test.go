package crypto

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/flyzard/go-guardian"
)

func TestGenerateToken(t *testing.T) {
	tests := []struct {
		name         string
		bytes        int
		wantErr      bool
		checkURLSafe bool
	}{
		{
			name:         "valid default length",
			bytes:        DefaultTokenLength,
			wantErr:      false,
			checkURLSafe: true,
		},
		{
			name:         "valid minimum length",
			bytes:        MinTokenLength,
			wantErr:      false,
			checkURLSafe: true,
		},
		{
			name:         "valid maximum length",
			bytes:        MaxTokenLength,
			wantErr:      false,
			checkURLSafe: true,
		},
		{
			name:    "length too small",
			bytes:   MinTokenLength - 1,
			wantErr: true,
		},
		{
			name:    "length too large",
			bytes:   MaxTokenLength + 1,
			wantErr: true,
		},
		{
			name:    "zero length",
			bytes:   0,
			wantErr: true,
		},
		{
			name:    "negative length",
			bytes:   -1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(tt.bytes)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateToken() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateToken() unexpected error: %v", err)
				return
			}

			if token == "" {
				t.Error("GenerateToken() returned empty token")
			}

			// Verify URL-safe encoding
			if tt.checkURLSafe && !IsURLSafe(token) {
				t.Error("GenerateToken() produced non-URL-safe token")
			}

			// Verify the token can be decoded
			decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(token)
			if err != nil {
				t.Errorf("GenerateToken() produced invalid base64: %v", err)
			}

			if len(decoded) != tt.bytes {
				t.Errorf("GenerateToken() decoded length = %d, want %d", len(decoded), tt.bytes)
			}
		})
	}
}

func TestGenerateSecureToken(t *testing.T) {
	token, err := GenerateSecureToken()
	if err != nil {
		t.Errorf("GenerateSecureToken() error: %v", err)
	}

	if token == "" {
		t.Error("GenerateSecureToken() returned empty token")
	}

	// Verify URL-safe encoding
	if !IsURLSafe(token) {
		t.Error("GenerateSecureToken() produced non-URL-safe token")
	}

	// Verify it's 32 bytes when decoded
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(token)
	if err != nil {
		t.Errorf("GenerateSecureToken() produced invalid base64: %v", err)
	}

	if len(decoded) != DefaultTokenLength {
		t.Errorf("GenerateSecureToken() decoded length = %d, want %d", len(decoded), DefaultTokenLength)
	}
}

func TestTokenUniqueness(t *testing.T) {
	const numTokens = 1000
	tokens := make(map[string]bool)

	for i := 0; i < numTokens; i++ {
		token, err := GenerateSecureToken()
		if err != nil {
			t.Fatalf("GenerateSecureToken() error: %v", err)
		}

		if tokens[token] {
			t.Errorf("Duplicate token generated: %s", token)
		}
		tokens[token] = true
	}

	if len(tokens) != numTokens {
		t.Errorf("Expected %d unique tokens, got %d", numTokens, len(tokens))
	}
}

func TestSecureTokenGenerator(t *testing.T) {
	generator := NewSecureTokenGenerator()
	ctx := context.Background()

	t.Run("GenerateToken with different formats", func(t *testing.T) {
		formats := []guardian.TokenFormat{
			guardian.TokenFormatBase64,
			guardian.TokenFormatHex,
			guardian.TokenFormatBase32,
			guardian.TokenFormatAlphanumeric,
			guardian.TokenFormatNumeric,
			guardian.TokenFormatAlpha,
		}

		for _, format := range formats {
			token, err := generator.GenerateToken(ctx, 16, format)
			if err != nil {
				t.Errorf("GenerateToken(%s) error: %v", format, err)
				continue
			}

			if token == "" {
				t.Errorf("GenerateToken(%s) returned empty token", format)
				continue
			}

			// Validate the format
			if err := generator.ValidateTokenFormat(token, format); err != nil {
				t.Errorf("ValidateTokenFormat(%s) error: %v", format, err)
			}
		}
	})

	t.Run("GenerateSecureRandom", func(t *testing.T) {
		bytes, err := generator.GenerateSecureRandom(ctx, 32)
		if err != nil {
			t.Errorf("GenerateSecureRandom() error: %v", err)
		}

		if len(bytes) != 32 {
			t.Errorf("GenerateSecureRandom() length = %d, want 32", len(bytes))
		}
	})

	t.Run("Specific token generation methods", func(t *testing.T) {
		tokens := []struct {
			name   string
			method func(context.Context) (string, error)
		}{
			{"SessionToken", generator.GenerateSessionToken},
			{"ResetToken", generator.GenerateResetToken},
			{"EmailVerificationToken", generator.GenerateEmailVerificationToken},
			{"APIKey", generator.GenerateAPIKey},
		}

		for _, tc := range tokens {
			token, err := tc.method(ctx)
			if err != nil {
				t.Errorf("%s() error: %v", tc.name, err)
				continue
			}

			if token == "" {
				t.Errorf("%s() returned empty token", tc.name)
			}
		}
	})

	t.Run("TwoFactorSecret", func(t *testing.T) {
		secret, err := generator.GenerateTwoFactorSecret(ctx)
		if err != nil {
			t.Errorf("GenerateTwoFactorSecret() error: %v", err)
		}

		// Should be base32 format
		if err := generator.ValidateTokenFormat(secret, guardian.TokenFormatBase32); err != nil {
			t.Errorf("TwoFactorSecret should be base32 format: %v", err)
		}
	})
}

func TestJWTGeneration(t *testing.T) {
	secret := []byte("test-secret-key-12345678901234567890")
	generator := NewSecureTokenGeneratorWithJWTSecret(secret)
	ctx := context.Background()

	t.Run("Generate and validate JWT", func(t *testing.T) {
		claims := map[string]interface{}{
			"user_id": "12345",
			"role":    "admin",
		}

		token, err := generator.GenerateJWT(ctx, claims, time.Hour)
		if err != nil {
			t.Errorf("GenerateJWT() error: %v", err)
		}

		if token == "" {
			t.Error("GenerateJWT() returned empty token")
		}

		// Validate the token
		parsedClaims, err := generator.ValidateJWT(ctx, token)
		if err != nil {
			t.Errorf("ValidateJWT() error: %v", err)
		}

		if parsedClaims["user_id"] != "12345" {
			t.Errorf("JWT user_id = %v, want 12345", parsedClaims["user_id"])
		}

		if parsedClaims["role"] != "admin" {
			t.Errorf("JWT role = %v, want admin", parsedClaims["role"])
		}
	})

	t.Run("JWT without secret", func(t *testing.T) {
		generatorNoSecret := NewSecureTokenGenerator()
		_, err := generatorNoSecret.GenerateJWT(ctx, nil, time.Hour)
		if err == nil {
			t.Error("GenerateJWT() should fail without secret")
		}
	})

	t.Run("Validate invalid JWT", func(t *testing.T) {
		_, err := generator.ValidateJWT(ctx, "invalid.jwt.token")
		if err == nil {
			t.Error("ValidateJWT() should fail for invalid token")
		}
	})
}

func TestTokenFormats(t *testing.T) {
	generator := NewSecureTokenGenerator()
	ctx := context.Background()
	length := 16

	tests := []struct {
		format    guardian.TokenFormat
		validator func(string) bool
	}{
		{
			format: guardian.TokenFormatHex,
			validator: func(token string) bool {
				matched, _ := regexp.MatchString("^[0-9a-f]+$", token)
				return matched
			},
		},
		{
			format: guardian.TokenFormatAlphanumeric,
			validator: func(token string) bool {
				matched, _ := regexp.MatchString("^[A-Za-z0-9]+$", token)
				return matched
			},
		},
		{
			format: guardian.TokenFormatNumeric,
			validator: func(token string) bool {
				matched, _ := regexp.MatchString("^[0-9]+$", token)
				return matched
			},
		},
		{
			format: guardian.TokenFormatAlpha,
			validator: func(token string) bool {
				matched, _ := regexp.MatchString("^[A-Za-z]+$", token)
				return matched
			},
		},
		{
			format: guardian.TokenFormatBase32,
			validator: func(token string) bool {
				matched, _ := regexp.MatchString("^[A-Z2-7]+$", strings.ToUpper(token))
				return matched
			},
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			token, err := generator.GenerateToken(ctx, length, tt.format)
			if err != nil {
				t.Errorf("GenerateToken(%s) error: %v", tt.format, err)
				return
			}

			if !tt.validator(token) {
				t.Errorf("Token %s doesn't match format %s", token, tt.format)
			}
		})
	}
}

func TestValidateTokenFormat(t *testing.T) {
	generator := NewSecureTokenGenerator()

	tests := []struct {
		name    string
		token   string
		format  guardian.TokenFormat
		wantErr bool
	}{
		{
			name:    "valid base64",
			token:   "SGVsbG9Xb3JsZA",
			format:  guardian.TokenFormatBase64,
			wantErr: false,
		},
		{
			name:    "valid hex",
			token:   "48656c6c6f576f726c64",
			format:  guardian.TokenFormatHex,
			wantErr: false,
		},
		{
			name:    "valid alphanumeric",
			token:   "HelloWorld123",
			format:  guardian.TokenFormatAlphanumeric,
			wantErr: false,
		},
		{
			name:    "valid numeric",
			token:   "1234567890",
			format:  guardian.TokenFormatNumeric,
			wantErr: false,
		},
		{
			name:    "valid alpha",
			token:   "HelloWorld",
			format:  guardian.TokenFormatAlpha,
			wantErr: false,
		},
		{
			name:    "invalid hex with non-hex chars",
			token:   "HelloWorld",
			format:  guardian.TokenFormatHex,
			wantErr: true,
		},
		{
			name:    "invalid numeric with letters",
			token:   "123abc",
			format:  guardian.TokenFormatNumeric,
			wantErr: true,
		},
		{
			name:    "empty token",
			token:   "",
			format:  guardian.TokenFormatBase64,
			wantErr: true,
		},
		{
			name:    "invalid format",
			token:   "token",
			format:  guardian.TokenFormat("invalid"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := generator.ValidateTokenFormat(tt.token, tt.format)

			if tt.wantErr && err == nil {
				t.Error("ValidateTokenFormat() expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("ValidateTokenFormat() unexpected error: %v", err)
			}
		})
	}
}

func TestGetTokenEntropy(t *testing.T) {
	generator := NewSecureTokenGenerator()

	tests := []struct {
		format     guardian.TokenFormat
		length     int
		minEntropy float64
	}{
		{guardian.TokenFormatBase64, 32, 192.0},       // 32 * log2(64) = 192
		{guardian.TokenFormatHex, 32, 128.0},          // 32 * log2(16) = 128
		{guardian.TokenFormatAlphanumeric, 32, 186.5}, // 32 * log2(62) ≈ 186.5
		{guardian.TokenFormatNumeric, 16, 53.1},       // 16 * log2(10) ≈ 53.1
		{guardian.TokenFormatAlpha, 16, 90.0},         // 16 * log2(52) ≈ 90.0
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			entropy := generator.GetTokenEntropy(tt.length, tt.format)

			if entropy < tt.minEntropy {
				t.Errorf("GetTokenEntropy() = %f, want >= %f", entropy, tt.minEntropy)
			}
		})
	}
}

func TestIsURLSafe(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		urlSafe bool
	}{
		{
			name:    "URL-safe base64",
			token:   "SGVsbG9Xb3JsZA",
			urlSafe: true,
		},
		{
			name:    "URL-safe with dash and underscore",
			token:   "Hello-World_123",
			urlSafe: true,
		},
		{
			name:    "not URL-safe with plus",
			token:   "Hello+World",
			urlSafe: false,
		},
		{
			name:    "not URL-safe with slash",
			token:   "Hello/World",
			urlSafe: false,
		},
		{
			name:    "not URL-safe with padding",
			token:   "HelloWorld==",
			urlSafe: false,
		},
		{
			name:    "not URL-safe with spaces",
			token:   "Hello World",
			urlSafe: false,
		},
		{
			name:    "empty token",
			token:   "",
			urlSafe: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsURLSafe(tt.token)
			if result != tt.urlSafe {
				t.Errorf("IsURLSafe() = %v, want %v", result, tt.urlSafe)
			}
		})
	}
}

func TestContextCancellationToken(t *testing.T) {
	generator := NewSecureTokenGenerator()

	t.Run("GenerateToken with cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := generator.GenerateToken(ctx, 32, guardian.TokenFormatBase64)
		if err == nil {
			t.Error("GenerateToken() should fail with cancelled context")
		}

		if err != context.Canceled {
			t.Errorf("GenerateToken() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("GenerateSecureRandom with cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := generator.GenerateSecureRandom(ctx, 32)
		if err == nil {
			t.Error("GenerateSecureRandom() should fail with cancelled context")
		}

		if err != context.Canceled {
			t.Errorf("GenerateSecureRandom() error = %v, want %v", err, context.Canceled)
		}
	})
}

func TestRandomnessQuality(t *testing.T) {
	const numSamples = 1000
	const tokenLength = 16

	// Generate many tokens and check for patterns
	tokens := make([]string, numSamples)
	for i := 0; i < numSamples; i++ {
		token, err := GenerateToken(tokenLength)
		if err != nil {
			t.Fatalf("GenerateToken() error: %v", err)
		}
		tokens[i] = token
	}

	// Check for duplicate tokens (extremely unlikely with crypto/rand)
	uniqueTokens := make(map[string]bool)
	for _, token := range tokens {
		if uniqueTokens[token] {
			t.Error("Duplicate token found - poor randomness quality")
		}
		uniqueTokens[token] = true
	}

	// Basic entropy check - convert to hex and check byte distribution
	byteFreq := make(map[byte]int)
	for _, token := range tokens {
		decoded, _ := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(token)
		for _, b := range decoded {
			byteFreq[b]++
		}
	}

	// With good randomness, we should see most byte values
	if len(byteFreq) < 200 { // Should see most of 256 possible byte values
		t.Logf("Warning: Only %d unique byte values seen in %d samples", len(byteFreq), numSamples*tokenLength)
	}
}

// Benchmark tests for performance
func BenchmarkGenerateToken(b *testing.B) {
	b.Run("GenerateToken32", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := GenerateToken(32)
			if err != nil {
				b.Fatalf("GenerateToken() error: %v", err)
			}
		}
	})

	b.Run("GenerateSecureToken", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := GenerateSecureToken()
			if err != nil {
				b.Fatalf("GenerateSecureToken() error: %v", err)
			}
		}
	})
}

func BenchmarkSecureTokenGenerator(b *testing.B) {
	generator := NewSecureTokenGenerator()
	ctx := context.Background()

	formats := []guardian.TokenFormat{
		guardian.TokenFormatBase64,
		guardian.TokenFormatHex,
		guardian.TokenFormatAlphanumeric,
	}

	for _, format := range formats {
		b.Run(string(format), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := generator.GenerateToken(ctx, 32, format)
				if err != nil {
					b.Fatalf("GenerateToken() error: %v", err)
				}
			}
		})
	}
}
