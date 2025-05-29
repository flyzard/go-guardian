// Package crypto provides token generation utilities for the go-guardian security library.
// This module implements secure random token generation with various formats and purposes.
package crypto

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/flyzard/go-guardian"
	"github.com/golang-jwt/jwt/v5"
)

// Token generation constants
const (
	// DefaultTokenLength is the default length for secure tokens (32 bytes = 256 bits)
	DefaultTokenLength = 32

	// MinTokenLength is the minimum allowed token length
	MinTokenLength = 8

	// MaxTokenLength is the maximum allowed token length
	MaxTokenLength = 256

	// SessionTokenLength is the standard length for session tokens
	SessionTokenLength = 32

	// ResetTokenLength is the standard length for password reset tokens
	ResetTokenLength = 32

	// EmailVerificationTokenLength is the standard length for email verification tokens
	EmailVerificationTokenLength = 32

	// APIKeyLength is the standard length for API keys
	APIKeyLength = 32

	// TwoFactorSecretLength is the standard length for 2FA secrets
	TwoFactorSecretLength = 32
)

// Character sets for different token formats
const (
	alphanumericChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	numericChars      = "0123456789"
	alphaChars        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	hexChars          = "0123456789abcdef"
)

// Token generation errors
var (
	ErrInvalidTokenLength  = errors.New("token length must be between 8 and 256 bytes")
	ErrInvalidTokenFormat  = errors.New("invalid token format")
	ErrTokenGeneration     = errors.New("failed to generate secure token")
	ErrInsufficientEntropy = errors.New("insufficient entropy for secure token generation")
	ErrInvalidJWTClaims    = errors.New("invalid JWT claims")
	ErrJWTGeneration       = errors.New("failed to generate JWT token")
	ErrJWTValidation       = errors.New("failed to validate JWT token")
)

// SecureTokenGenerator implements cryptographically secure token generation.
type SecureTokenGenerator struct {
	jwtSecret []byte
}

// NewSecureTokenGenerator creates a new secure token generator.
func NewSecureTokenGenerator() *SecureTokenGenerator {
	return &SecureTokenGenerator{}
}

// NewSecureTokenGeneratorWithJWTSecret creates a new secure token generator with JWT support.
func NewSecureTokenGeneratorWithJWTSecret(secret []byte) *SecureTokenGenerator {
	return &SecureTokenGenerator{
		jwtSecret: secret,
	}
}

// GenerateToken generates a secure random token with specified length (in bytes) - required by completion criteria.
func GenerateToken(bytes int) (string, error) {
	if bytes < MinTokenLength || bytes > MaxTokenLength {
		return "", fmt.Errorf("%w: got %d", ErrInvalidTokenLength, bytes)
	}

	randomBytes := make([]byte, bytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}

	// Use URL-safe base64 encoding without padding for maximum compatibility
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(randomBytes), nil
}

// GenerateSecureToken generates a secure 32-byte token - required by completion criteria.
func GenerateSecureToken() (string, error) {
	return GenerateToken(DefaultTokenLength)
}

// GenerateToken implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) GenerateToken(ctx context.Context, length int, tokenType guardian.TokenFormat) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	if length < MinTokenLength || length > MaxTokenLength {
		return "", fmt.Errorf("%w: got %d", ErrInvalidTokenLength, length)
	}

	switch tokenType {
	case guardian.TokenFormatBase64:
		return GenerateToken(length)
	case guardian.TokenFormatHex:
		return tg.generateHexToken(length)
	case guardian.TokenFormatBase32:
		return tg.generateBase32Token(length)
	case guardian.TokenFormatAlphanumeric:
		return tg.generateAlphanumericToken(length)
	case guardian.TokenFormatNumeric:
		return tg.generateNumericToken(length)
	case guardian.TokenFormatAlpha:
		return tg.generateAlphaToken(length)
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidTokenFormat, tokenType)
	}
}

// generateHexToken generates a hex-encoded token.
func (tg *SecureTokenGenerator) generateHexToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}
	return hex.EncodeToString(bytes), nil
}

// generateBase32Token generates a base32-encoded token.
func (tg *SecureTokenGenerator) generateBase32Token(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}
	encoded := base32.StdEncoding.EncodeToString(bytes)
	// Remove padding for cleaner tokens
	return strings.TrimRight(encoded, "="), nil
}

// generateAlphanumericToken generates an alphanumeric token.
func (tg *SecureTokenGenerator) generateAlphanumericToken(length int) (string, error) {
	return tg.generateFromCharset(length, alphanumericChars)
}

// generateNumericToken generates a numeric-only token.
func (tg *SecureTokenGenerator) generateNumericToken(length int) (string, error) {
	return tg.generateFromCharset(length, numericChars)
}

// generateAlphaToken generates an alphabetic-only token.
func (tg *SecureTokenGenerator) generateAlphaToken(length int) (string, error) {
	return tg.generateFromCharset(length, alphaChars)
}

// generateFromCharset generates a token from a given character set.
func (tg *SecureTokenGenerator) generateFromCharset(length int, charset string) (string, error) {
	if length <= 0 {
		return "", ErrInvalidTokenLength
	}

	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrTokenGeneration, err)
		}
		result[i] = charset[randomIndex.Int64()]
	}

	return string(result), nil
}

// GenerateJWT implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) GenerateJWT(ctx context.Context, claims map[string]interface{}, expiresIn time.Duration) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	if tg.jwtSecret == nil {
		return "", fmt.Errorf("%w: JWT secret not configured", ErrJWTGeneration)
	}

	if claims == nil {
		claims = make(map[string]interface{})
	}

	// Add standard claims
	now := time.Now()
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(expiresIn).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	tokenString, err := token.SignedString(tg.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrJWTGeneration, err)
	}

	return tokenString, nil
}

// ValidateJWT implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) ValidateJWT(ctx context.Context, tokenString string) (map[string]interface{}, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if tg.jwtSecret == nil {
		return nil, fmt.Errorf("%w: JWT secret not configured", ErrJWTValidation)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tg.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWTValidation, err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("%w: invalid token", ErrJWTValidation)
}

// GenerateSecureRandom implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) GenerateSecureRandom(ctx context.Context, length int) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if length < MinTokenLength || length > MaxTokenLength {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidTokenLength, length)
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}

	return bytes, nil
}

// GenerateSessionToken implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) GenerateSessionToken(ctx context.Context) (string, error) {
	return tg.GenerateToken(ctx, SessionTokenLength, guardian.TokenFormatBase64)
}

// GenerateResetToken implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) GenerateResetToken(ctx context.Context) (string, error) {
	return tg.GenerateToken(ctx, ResetTokenLength, guardian.TokenFormatBase64)
}

// GenerateEmailVerificationToken implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) GenerateEmailVerificationToken(ctx context.Context) (string, error) {
	return tg.GenerateToken(ctx, EmailVerificationTokenLength, guardian.TokenFormatBase64)
}

// GenerateAPIKey implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) GenerateAPIKey(ctx context.Context) (string, error) {
	return tg.GenerateToken(ctx, APIKeyLength, guardian.TokenFormatBase64)
}

// GenerateTwoFactorSecret implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) GenerateTwoFactorSecret(ctx context.Context) (string, error) {
	return tg.GenerateToken(ctx, TwoFactorSecretLength, guardian.TokenFormatBase32)
}

// ValidateTokenFormat implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) ValidateTokenFormat(token string, format guardian.TokenFormat) error {
	if token == "" {
		return ErrInvalidTokenFormat
	}

	switch format {
	case guardian.TokenFormatBase64:
		return tg.validateBase64Token(token)
	case guardian.TokenFormatHex:
		return tg.validateHexToken(token)
	case guardian.TokenFormatBase32:
		return tg.validateBase32Token(token)
	case guardian.TokenFormatAlphanumeric:
		return tg.validateAlphanumericToken(token)
	case guardian.TokenFormatNumeric:
		return tg.validateNumericToken(token)
	case guardian.TokenFormatAlpha:
		return tg.validateAlphaToken(token)
	default:
		return fmt.Errorf("%w: %s", ErrInvalidTokenFormat, format)
	}
}

// validateBase64Token validates a base64 URL-safe token.
func (tg *SecureTokenGenerator) validateBase64Token(token string) error {
	_, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(token)
	if err != nil {
		return fmt.Errorf("%w: invalid base64 format", ErrInvalidTokenFormat)
	}
	return nil
}

// validateHexToken validates a hex token.
func (tg *SecureTokenGenerator) validateHexToken(token string) error {
	matched, err := regexp.MatchString("^[0-9a-fA-F]+$", token)
	if err != nil || !matched {
		return fmt.Errorf("%w: invalid hex format", ErrInvalidTokenFormat)
	}
	return nil
}

// validateBase32Token validates a base32 token.
func (tg *SecureTokenGenerator) validateBase32Token(token string) error {
	// Add padding if needed for validation
	padded := token
	for len(padded)%8 != 0 {
		padded += "="
	}
	_, err := base32.StdEncoding.DecodeString(padded)
	if err != nil {
		return fmt.Errorf("%w: invalid base32 format", ErrInvalidTokenFormat)
	}
	return nil
}

// validateAlphanumericToken validates an alphanumeric token.
func (tg *SecureTokenGenerator) validateAlphanumericToken(token string) error {
	matched, err := regexp.MatchString("^[A-Za-z0-9]+$", token)
	if err != nil || !matched {
		return fmt.Errorf("%w: invalid alphanumeric format", ErrInvalidTokenFormat)
	}
	return nil
}

// validateNumericToken validates a numeric token.
func (tg *SecureTokenGenerator) validateNumericToken(token string) error {
	matched, err := regexp.MatchString("^[0-9]+$", token)
	if err != nil || !matched {
		return fmt.Errorf("%w: invalid numeric format", ErrInvalidTokenFormat)
	}
	return nil
}

// validateAlphaToken validates an alphabetic token.
func (tg *SecureTokenGenerator) validateAlphaToken(token string) error {
	matched, err := regexp.MatchString("^[A-Za-z]+$", token)
	if err != nil || !matched {
		return fmt.Errorf("%w: invalid alphabetic format", ErrInvalidTokenFormat)
	}
	return nil
}

// GetTokenEntropy implements the TokenGenerator interface.
func (tg *SecureTokenGenerator) GetTokenEntropy(length int, format guardian.TokenFormat) float64 {
	var charsetSize float64

	switch format {
	case guardian.TokenFormatBase64:
		charsetSize = 64 // Base64 character set
	case guardian.TokenFormatHex:
		charsetSize = 16 // Hex character set
	case guardian.TokenFormatBase32:
		charsetSize = 32 // Base32 character set
	case guardian.TokenFormatAlphanumeric:
		charsetSize = 62 // A-Z, a-z, 0-9
	case guardian.TokenFormatNumeric:
		charsetSize = 10 // 0-9
	case guardian.TokenFormatAlpha:
		charsetSize = 52 // A-Z, a-z
	default:
		return 0
	}

	// Entropy = length * log2(charset_size)
	return float64(length) * math.Log2(charsetSize)
}

// IsURLSafe checks if a token is URL-safe (required by completion criteria).
func IsURLSafe(token string) bool {
	// URL-safe characters: A-Z, a-z, 0-9, -, _, and no padding
	matched, err := regexp.MatchString("^[A-Za-z0-9_-]+$", token)
	return err == nil && matched
}

// ValidateTokenLength validates that token length is within acceptable bounds.
func ValidateTokenLength(length int) error {
	if length < MinTokenLength || length > MaxTokenLength {
		return fmt.Errorf("%w: got %d", ErrInvalidTokenLength, length)
	}
	return nil
}
