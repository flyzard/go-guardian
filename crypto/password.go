// Package crypto provides cryptographic utilities for the go-guardian security library.
// This package implements secure password hashing, token generation, and other
// cryptographic operations required for authentication and authorization.
package crypto

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Password hashing constants
const (
	// DefaultCost is the default bcrypt cost factor (12 = ~300ms on modern hardware)
	DefaultCost = 12

	// MinCost is the minimum allowed bcrypt cost factor
	MinCost = 10

	// MaxCost is the maximum allowed bcrypt cost factor
	MaxCost = 31
)

// Password hashing errors
var (
	ErrInvalidCost      = errors.New("bcrypt cost must be between 10 and 31")
	ErrHashGeneration   = errors.New("failed to generate password hash")
	ErrHashComparison   = errors.New("failed to compare password hash")
	ErrInvalidHash      = errors.New("invalid bcrypt hash format")
	ErrPasswordMismatch = errors.New("password does not match hash")
)

// PasswordHasher implements secure password hashing using bcrypt.
// It provides constant-time comparison and configurable cost factors for
// defending against rainbow table and brute force attacks.
type PasswordHasher struct {
	defaultCost int
}

// NewPasswordHasher creates a new password hasher with the default cost factor.
func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{
		defaultCost: DefaultCost,
	}
}

// NewPasswordHasherWithCost creates a new password hasher with a custom default cost factor.
func NewPasswordHasherWithCost(cost int) (*PasswordHasher, error) {
	if cost < MinCost || cost > MaxCost {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidCost, cost)
	}

	return &PasswordHasher{
		defaultCost: cost,
	}, nil
}

// HashPassword hashes a password using the default cost factor.
// This is the main function required by the completion criteria.
func HashPassword(password string, cost int) (string, error) {
	if cost < MinCost || cost > MaxCost {
		return "", fmt.Errorf("%w: got %d", ErrInvalidCost, cost)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrHashGeneration, err)
	}

	return string(hash), nil
}

// ComparePassword compares a password against a hash using constant-time comparison.
// This is the main function required by the completion criteria.
func ComparePassword(hash, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrPasswordMismatch
		}
		return fmt.Errorf("%w: %v", ErrHashComparison, err)
	}

	return nil
}

// Hash implements the Hasher interface - hashes a password with default cost.
func (ph *PasswordHasher) Hash(ctx context.Context, password string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	return HashPassword(password, ph.defaultCost)
}

// HashWithCost implements the Hasher interface - hashes a password with custom cost.
func (ph *PasswordHasher) HashWithCost(ctx context.Context, password string, cost int) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	return HashPassword(password, cost)
}

// Verify implements the Hasher interface - verifies a password against a hash.
func (ph *PasswordHasher) Verify(ctx context.Context, password, hash string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return ComparePassword(hash, password)
}

// NeedsRehash implements the Hasher interface - checks if hash needs rehashing.
func (ph *PasswordHasher) NeedsRehash(hash string, cost int) bool {
	currentCost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true // If we can't get cost, assume it needs rehashing
	}

	return currentCost < cost
}

// GetCost implements the Hasher interface - extracts cost factor from hash.
func (ph *PasswordHasher) GetCost(hash string) (int, error) {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}

	return cost, nil
}

// GenerateSalt implements the Hasher interface - generates a random salt.
// Note: bcrypt handles salt generation internally, but this provides compatibility.
func (ph *PasswordHasher) GenerateSalt(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Generate a temporary hash to extract the salt portion
	// bcrypt handles salt generation internally, so we create a dummy hash
	hash, err := bcrypt.GenerateFromPassword([]byte("dummy"), ph.defaultCost)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHashGeneration, err)
	}

	// Extract salt from bcrypt hash (first 29 characters include salt)
	if len(hash) < 29 {
		return nil, ErrInvalidHash
	}

	return hash[:29], nil
}

// ValidateCost validates that a bcrypt cost factor is within acceptable bounds.
func ValidateCost(cost int) error {
	if cost < MinCost || cost > MaxCost {
		return fmt.Errorf("%w: got %d", ErrInvalidCost, cost)
	}
	return nil
}

// IsValidHash checks if a string is a valid bcrypt hash format.
func IsValidHash(hash string) bool {
	_, err := bcrypt.Cost([]byte(hash))
	return err == nil
}
