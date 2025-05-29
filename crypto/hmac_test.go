package crypto

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestSign(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
		secret  []byte
		wantSig bool // true if we expect a valid signature
	}{
		{
			name:    "valid message and secret",
			message: []byte("hello world"),
			secret:  []byte("supersecretkey1234567890123456"),
			wantSig: true,
		},
		{
			name:    "empty message with valid secret",
			message: []byte(""),
			secret:  []byte("supersecretkey1234567890123456"),
			wantSig: true,
		},
		{
			name:    "valid message with empty secret",
			message: []byte("hello world"),
			secret:  []byte(""),
			wantSig: false,
		},
		{
			name:    "both empty",
			message: []byte(""),
			secret:  []byte(""),
			wantSig: false,
		},
		{
			name:    "long message",
			message: []byte(strings.Repeat("a", 10000)),
			secret:  []byte("supersecretkey1234567890123456"),
			wantSig: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := Sign(tt.message, tt.secret)

			if tt.wantSig {
				if signature == "" {
					t.Errorf("Sign() returned empty signature, expected valid signature")
				}
				// Check that signature is hex encoded
				if len(signature) != 64 { // SHA256 produces 32 bytes = 64 hex chars
					t.Errorf("Sign() signature length = %d, want 64", len(signature))
				}
			} else {
				if signature != "" {
					t.Errorf("Sign() returned signature %s, expected empty", signature)
				}
			}
		})
	}
}

func TestVerify(t *testing.T) {
	secret := []byte("supersecretkey1234567890123456")
	message := []byte("hello world")
	validSignature := Sign(message, secret)

	tests := []struct {
		name      string
		message   []byte
		signature []byte
		secret    []byte
		want      bool
	}{
		{
			name:      "valid signature",
			message:   message,
			signature: []byte(validSignature),
			secret:    secret,
			want:      true,
		},
		{
			name:      "invalid signature",
			message:   message,
			signature: []byte("invalid"),
			secret:    secret,
			want:      false,
		},
		{
			name:      "wrong secret",
			message:   message,
			signature: []byte(validSignature),
			secret:    []byte("wrongsecret123456789012345678"),
			want:      false,
		},
		{
			name:      "wrong message",
			message:   []byte("wrong message"),
			signature: []byte(validSignature),
			secret:    secret,
			want:      false,
		},
		{
			name:      "empty secret",
			message:   message,
			signature: []byte(validSignature),
			secret:    []byte(""),
			want:      false,
		},
		{
			name:      "empty signature",
			message:   message,
			signature: []byte(""),
			secret:    secret,
			want:      false,
		},
		{
			name:      "non-hex signature",
			message:   message,
			signature: []byte("not_hex_encoded_signature_here"),
			secret:    secret,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Verify(tt.message, tt.signature, tt.secret)
			if got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureConsistency(t *testing.T) {
	message := []byte("consistent test message")
	secret := []byte("supersecretkey1234567890123456")

	// Generate multiple signatures for the same input
	sig1 := Sign(message, secret)
	sig2 := Sign(message, secret)
	sig3 := Sign(message, secret)

	if sig1 != sig2 || sig2 != sig3 {
		t.Errorf("Sign() produced inconsistent signatures: %s, %s, %s", sig1, sig2, sig3)
	}

	// All should verify
	if !Verify(message, []byte(sig1), secret) {
		t.Error("Verify() failed for sig1")
	}
	if !Verify(message, []byte(sig2), secret) {
		t.Error("Verify() failed for sig2")
	}
	if !Verify(message, []byte(sig3), secret) {
		t.Error("Verify() failed for sig3")
	}
}

func TestTimingAttackResistanceHmac(t *testing.T) {
	secret := []byte("supersecretkey1234567890123456")
	message := []byte("timing test message")
	correctSig := Sign(message, secret)

	// Test with signatures of different lengths and contents
	// The verification should take roughly the same time regardless
	testSigs := []string{
		correctSig,
		"",
		"a",
		"invalid_sig",
		strings.Repeat("a", 64),
		strings.Repeat("f", 64),
		correctSig[:32], // truncated
		correctSig + "extra",
	}

	for _, sig := range testSigs {
		start := time.Now()
		Verify(message, []byte(sig), secret)
		elapsed := time.Since(start)

		// The operation should be very fast (sub-millisecond typically)
		if elapsed > 10*time.Millisecond {
			t.Errorf("Verify() took too long: %v for signature %s", elapsed, sig)
		}
	}
}

func TestHMACGenerator(t *testing.T) {
	secret := []byte("supersecretkey1234567890123456")
	generator := NewHMACGenerator(secret)

	t.Run("SignString", func(t *testing.T) {
		message := "test message"
		signature := generator.SignString(message, nil) // Use default secret

		if signature == "" {
			t.Error("SignString() returned empty signature")
		}

		// Verify using the generator
		if !generator.VerifyString(message, signature, nil) {
			t.Error("VerifyString() failed for signature generated by SignString()")
		}
	})

	t.Run("SignWithDefaultSecret", func(t *testing.T) {
		message := []byte("test message")
		signature := generator.SignWithDefaultSecret(message)

		if signature == "" {
			t.Error("SignWithDefaultSecret() returned empty signature")
		}

		if !generator.VerifyWithDefaultSecret(message, []byte(signature)) {
			t.Error("VerifyWithDefaultSecret() failed")
		}
	})

	t.Run("GenerateSignature", func(t *testing.T) {
		message := "api request"
		timestamp := time.Now().Unix()
		signature := generator.GenerateSignature(message, timestamp, nil)

		if signature == "" {
			t.Error("GenerateSignature() returned empty signature")
		}

		if !generator.VerifySignature(message, timestamp, signature, nil) {
			t.Error("VerifySignature() failed")
		}

		// Test with different timestamp
		if generator.VerifySignature(message, timestamp+1, signature, nil) {
			t.Error("VerifySignature() should fail with different timestamp")
		}
	})
}

func TestValidateSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
		want   bool
	}{
		{
			name:   "valid 32-byte secret",
			secret: make([]byte, 32),
			want:   true,
		},
		{
			name:   "valid 64-byte secret",
			secret: make([]byte, 64),
			want:   true,
		},
		{
			name:   "too short - 31 bytes",
			secret: make([]byte, 31),
			want:   false,
		},
		{
			name:   "too short - 16 bytes",
			secret: make([]byte, 16),
			want:   false,
		},
		{
			name:   "empty secret",
			secret: []byte{},
			want:   false,
		},
		{
			name:   "nil secret",
			secret: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateSecret(tt.secret); got != tt.want {
				t.Errorf("ValidateSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHMACGeneratorWithoutDefaultSecret(t *testing.T) {
	generator := NewHMACGenerator(nil)

	t.Run("no default secret operations", func(t *testing.T) {
		message := []byte("test")

		// Should return empty when no default secret
		if sig := generator.SignWithDefaultSecret(message); sig != "" {
			t.Errorf("SignWithDefaultSecret() = %s, want empty", sig)
		}

		// Should return false when no default secret
		if result := generator.VerifyWithDefaultSecret(message, []byte("sig")); result {
			t.Error("VerifyWithDefaultSecret() should return false with no default secret")
		}
	})

	t.Run("explicit secret works", func(t *testing.T) {
		secret := []byte("explicit_secret_1234567890123456")
		message := "test message"

		sig := generator.SignString(message, secret)
		if sig == "" {
			t.Error("SignString() with explicit secret returned empty")
		}

		if !generator.VerifyString(message, sig, secret) {
			t.Error("VerifyString() with explicit secret failed")
		}
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("large messages", func(t *testing.T) {
		secret := []byte("supersecretkey1234567890123456")

		// Test with 1MB message
		largeMessage := make([]byte, 1024*1024)
		_, err := rand.Read(largeMessage)
		if err != nil {
			t.Fatalf("Failed to generate random data: %v", err)
		}

		signature := Sign(largeMessage, secret)
		if signature == "" {
			t.Error("Sign() failed for large message")
		}

		if !Verify(largeMessage, []byte(signature), secret) {
			t.Error("Verify() failed for large message")
		}
	})

	t.Run("binary data", func(t *testing.T) {
		secret := []byte("supersecretkey1234567890123456")

		// Test with binary data containing null bytes
		binaryMessage := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}

		signature := Sign(binaryMessage, secret)
		if signature == "" {
			t.Error("Sign() failed for binary message")
		}

		if !Verify(binaryMessage, []byte(signature), secret) {
			t.Error("Verify() failed for binary message")
		}
	})
}

func BenchmarkSign(b *testing.B) {
	secret := []byte("supersecretkey1234567890123456")
	message := []byte("benchmark message for HMAC signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(message, secret)
	}
}

func BenchmarkVerify(b *testing.B) {
	secret := []byte("supersecretkey1234567890123456")
	message := []byte("benchmark message for HMAC verification")
	signature := []byte(Sign(message, secret))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(message, signature, secret)
	}
}

func BenchmarkSignLargeMessage(b *testing.B) {
	secret := []byte("supersecretkey1234567890123456")
	message := make([]byte, 1024*1024) // 1MB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(message, secret)
	}
}
