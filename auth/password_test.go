package auth

import (
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	password := "SecurePass123!"

	// Test hashing
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Ensure hash is not empty and not equal to password
	if hash == "" || hash == password {
		t.Fatal("Invalid hash generated")
	}

	// Test verification with correct password
	if !CheckPasswordHash(password, hash) {
		t.Fatal("Failed to verify correct password")
	}

	// Test verification with incorrect password
	if CheckPasswordHash("WrongPassword", hash) {
		t.Fatal("Incorrectly verified wrong password")
	}

	// Test that same password generates different hashes
	hash2, _ := HashPassword(password)
	if hash == hash2 {
		t.Fatal("Same password generated identical hashes")
	}
}

func TestSecureCompare(t *testing.T) {
	// Test timing-safe comparison
	if !SecureCompare("token123", "token123") {
		t.Fatal("Failed to match identical strings")
	}

	if SecureCompare("token123", "token456") {
		t.Fatal("Incorrectly matched different strings")
	}
}

func TestPasswordHashTiming(t *testing.T) {
	// Ensure password checking takes similar time for existing and non-existing users
	hash, _ := HashPassword("testpass")

	start := time.Now()
	CheckPasswordHash("wrongpass", hash)
	wrongDuration := time.Since(start)

	start = time.Now()
	CheckPasswordHash("testpass", hash)
	correctDuration := time.Since(start)

	// The timing difference should be minimal (within 10x)
	ratio := float64(wrongDuration) / float64(correctDuration)
	if ratio > 10 || ratio < 0.1 {
		t.Fatalf("Timing attack possible: wrong=%v correct=%v ratio=%v",
			wrongDuration, correctDuration, ratio)
	}
}
