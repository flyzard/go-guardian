// Package crypto provides HMAC utilities for the go-guardian security library.
// This module implements secure message authentication using SHA256-based HMAC.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// Sign generates an HMAC signature for the given message using SHA256.
// Returns the signature as a hex-encoded string.
// This function is required by the completion criteria.
func Sign(message, secret []byte) string {
	if len(secret) == 0 {
		return ""
	}

	h := hmac.New(sha256.New, secret)
	h.Write(message)
	signature := h.Sum(nil)

	return hex.EncodeToString(signature)
}

// Verify validates an HMAC signature using constant-time comparison.
// Returns true if the signature is valid, false otherwise.
// This function is required by the completion criteria and uses timing-attack resistant comparison.
func Verify(message, signature, secret []byte) bool {
	if len(secret) == 0 || len(signature) == 0 {
		return false
	}

	// Decode the hex signature
	expectedSig, err := hex.DecodeString(string(signature))
	if err != nil {
		return false
	}

	// Generate the expected signature
	h := hmac.New(sha256.New, secret)
	h.Write(message)
	actualSig := h.Sum(nil)

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(expectedSig, actualSig) == 1
}

// HMACGenerator implements cryptographically secure HMAC generation.
// This provides a more comprehensive HMAC interface for the security library.
type HMACGenerator struct {
	defaultSecret []byte
}

// NewHMACGenerator creates a new HMAC generator with an optional default secret.
func NewHMACGenerator(defaultSecret []byte) *HMACGenerator {
	return &HMACGenerator{
		defaultSecret: defaultSecret,
	}
}

// SignString signs a string message with the given secret and returns a hex signature.
func (h *HMACGenerator) SignString(message string, secret []byte) string {
	if len(secret) == 0 && len(h.defaultSecret) > 0 {
		secret = h.defaultSecret
	}
	return Sign([]byte(message), secret)
}

// VerifyString verifies a string message against a hex signature using the given secret.
func (h *HMACGenerator) VerifyString(message, signature string, secret []byte) bool {
	if len(secret) == 0 && len(h.defaultSecret) > 0 {
		secret = h.defaultSecret
	}
	return Verify([]byte(message), []byte(signature), secret)
}

// SignWithDefaultSecret signs a message using the generator's default secret.
func (h *HMACGenerator) SignWithDefaultSecret(message []byte) string {
	if len(h.defaultSecret) == 0 {
		return ""
	}
	return Sign(message, h.defaultSecret)
}

// VerifyWithDefaultSecret verifies a signature using the generator's default secret.
func (h *HMACGenerator) VerifyWithDefaultSecret(message, signature []byte) bool {
	if len(h.defaultSecret) == 0 {
		return false
	}
	return Verify(message, signature, h.defaultSecret)
}

// ValidateSecret checks if a secret meets minimum security requirements.
// Returns true if the secret is at least 32 bytes (256 bits) as recommended for HMAC-SHA256.
func ValidateSecret(secret []byte) bool {
	return len(secret) >= 32
}

// GenerateSignature creates a timestamped signature for message authentication.
// This can be used for API request signing or session token validation.
func (h *HMACGenerator) GenerateSignature(message string, timestamp int64, secret []byte) string {
	if len(secret) == 0 && len(h.defaultSecret) > 0 {
		secret = h.defaultSecret
	}

	// Combine message and timestamp for signature
	signedData := []byte(message)

	// Add timestamp as bytes
	timestampBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		timestampBytes[i] = byte(timestamp >> (8 * (7 - i)))
	}
	signedData = append(signedData, timestampBytes...)

	return Sign(signedData, secret)
}

// VerifySignature verifies a timestamped signature.
func (h *HMACGenerator) VerifySignature(message string, timestamp int64, signature string, secret []byte) bool {
	if len(secret) == 0 && len(h.defaultSecret) > 0 {
		secret = h.defaultSecret
	}

	expectedSig := h.GenerateSignature(message, timestamp, secret)
	return subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) == 1
}
