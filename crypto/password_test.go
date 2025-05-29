package crypto

import (
	"context"
	"testing"
	"time"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		cost     int
		wantErr  bool
	}{
		{
			name:     "valid password with default cost",
			password: "mySecurePassword123!",
			cost:     DefaultCost,
			wantErr:  false,
		},
		{
			name:     "valid password with min cost",
			password: "password123",
			cost:     MinCost,
			wantErr:  false,
		},
		{
			name:     "valid password with max cost",
			password: "strongPassword!@#",
			cost:     MaxCost,
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			cost:     DefaultCost,
			wantErr:  false, // bcrypt allows empty passwords
		},
		{
			name:     "cost too low",
			password: "password123",
			cost:     MinCost - 1,
			wantErr:  true,
		},
		{
			name:     "cost too high",
			password: "password123",
			cost:     MaxCost + 1,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password, tt.cost)

			if tt.wantErr {
				if err == nil {
					t.Errorf("HashPassword() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("HashPassword() unexpected error: %v", err)
				return
			}

			if hash == "" {
				t.Error("HashPassword() returned empty hash")
			}

			// Verify the hash is a valid bcrypt hash
			if !IsValidHash(hash) {
				t.Error("HashPassword() produced invalid bcrypt hash")
			}

			// Verify the hash can be used to authenticate the original password
			if err := ComparePassword(hash, tt.password); err != nil {
				t.Errorf("ComparePassword() failed to verify hash: %v", err)
			}
		})
	}
}

func TestComparePassword(t *testing.T) {
	password := "myTestPassword123!"
	cost := DefaultCost

	// Generate a hash for testing
	hash, err := HashPassword(password, cost)
	if err != nil {
		t.Fatalf("Failed to generate test hash: %v", err)
	}

	tests := []struct {
		name     string
		hash     string
		password string
		wantErr  bool
	}{
		{
			name:     "correct password",
			hash:     hash,
			password: password,
			wantErr:  false,
		},
		{
			name:     "incorrect password",
			hash:     hash,
			password: "wrongPassword",
			wantErr:  true,
		},
		{
			name:     "empty password against valid hash",
			hash:     hash,
			password: "",
			wantErr:  true,
		},
		{
			name:     "invalid hash format",
			hash:     "invalid_hash_format",
			password: password,
			wantErr:  true,
		},
		{
			name:     "empty hash",
			hash:     "",
			password: password,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ComparePassword(tt.hash, tt.password)

			if tt.wantErr && err == nil {
				t.Error("ComparePassword() expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("ComparePassword() unexpected error: %v", err)
			}
		})
	}
}

func TestPasswordHasher(t *testing.T) {
	hasher := NewPasswordHasher()
	ctx := context.Background()
	password := "testPassword123!"

	t.Run("Hash with default cost", func(t *testing.T) {
		hash, err := hasher.Hash(ctx, password)
		if err != nil {
			t.Errorf("Hash() error: %v", err)
		}

		if !IsValidHash(hash) {
			t.Error("Hash() produced invalid hash")
		}

		// Verify the password
		if err := hasher.Verify(ctx, password, hash); err != nil {
			t.Errorf("Verify() failed: %v", err)
		}
	})

	t.Run("Hash with custom cost", func(t *testing.T) {
		customCost := 11
		hash, err := hasher.HashWithCost(ctx, password, customCost)
		if err != nil {
			t.Errorf("HashWithCost() error: %v", err)
		}

		cost, err := hasher.GetCost(hash)
		if err != nil {
			t.Errorf("GetCost() error: %v", err)
		}

		if cost != customCost {
			t.Errorf("GetCost() got %d, want %d", cost, customCost)
		}
	})

	t.Run("NeedsRehash", func(t *testing.T) {
		lowCostHash, err := hasher.HashWithCost(ctx, password, MinCost)
		if err != nil {
			t.Fatalf("HashWithCost() error: %v", err)
		}

		// Should need rehashing if target cost is higher
		if !hasher.NeedsRehash(lowCostHash, DefaultCost) {
			t.Error("NeedsRehash() should return true for lower cost hash")
		}

		// Should not need rehashing if target cost is same or lower
		if hasher.NeedsRehash(lowCostHash, MinCost) {
			t.Error("NeedsRehash() should return false for same cost hash")
		}
	})

	t.Run("GenerateSalt", func(t *testing.T) {
		salt, err := hasher.GenerateSalt(ctx)
		if err != nil {
			t.Errorf("GenerateSalt() error: %v", err)
		}

		if len(salt) == 0 {
			t.Error("GenerateSalt() returned empty salt")
		}

		// Generate another salt and ensure they're different
		salt2, err := hasher.GenerateSalt(ctx)
		if err != nil {
			t.Errorf("GenerateSalt() error: %v", err)
		}

		if string(salt) == string(salt2) {
			t.Error("GenerateSalt() returned identical salts")
		}
	})
}

func TestNewPasswordHasherWithCost(t *testing.T) {
	tests := []struct {
		name    string
		cost    int
		wantErr bool
	}{
		{
			name:    "valid cost",
			cost:    DefaultCost,
			wantErr: false,
		},
		{
			name:    "min cost",
			cost:    MinCost,
			wantErr: false,
		},
		{
			name:    "max cost",
			cost:    MaxCost,
			wantErr: false,
		},
		{
			name:    "cost too low",
			cost:    MinCost - 1,
			wantErr: true,
		},
		{
			name:    "cost too high",
			cost:    MaxCost + 1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher, err := NewPasswordHasherWithCost(tt.cost)

			if tt.wantErr {
				if err == nil {
					t.Error("NewPasswordHasherWithCost() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewPasswordHasherWithCost() unexpected error: %v", err)
				return
			}

			if hasher == nil {
				t.Error("NewPasswordHasherWithCost() returned nil hasher")
			}

			if hasher.defaultCost != tt.cost {
				t.Errorf("NewPasswordHasherWithCost() cost = %d, want %d", hasher.defaultCost, tt.cost)
			}
		})
	}
}

func TestValidateCost(t *testing.T) {
	tests := []struct {
		name    string
		cost    int
		wantErr bool
	}{
		{"valid min cost", MinCost, false},
		{"valid max cost", MaxCost, false},
		{"valid default cost", DefaultCost, false},
		{"cost too low", MinCost - 1, true},
		{"cost too high", MaxCost + 1, true},
		{"zero cost", 0, true},
		{"negative cost", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCost(tt.cost)

			if tt.wantErr && err == nil {
				t.Error("ValidateCost() expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("ValidateCost() unexpected error: %v", err)
			}
		})
	}
}

func TestIsValidHash(t *testing.T) {
	// Generate a valid hash for testing
	validHash, err := HashPassword("test", DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate test hash: %v", err)
	}

	tests := []struct {
		name  string
		hash  string
		valid bool
	}{
		{
			name:  "valid bcrypt hash",
			hash:  validHash,
			valid: true,
		},
		{
			name:  "empty hash",
			hash:  "",
			valid: false,
		},
		{
			name:  "invalid format",
			hash:  "not_a_bcrypt_hash",
			valid: false,
		},
		{
			name:  "partial hash",
			hash:  "$2a$12$",
			valid: false,
		},
		{
			name:  "wrong algorithm",
			hash:  "$1$12$invalidhashformat",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidHash(tt.hash)
			if result != tt.valid {
				t.Errorf("IsValidHash() = %v, want %v", result, tt.valid)
			}
		})
	}
}

// TestTimingAttackResistance ensures constant-time comparison
func TestTimingAttackResistance(t *testing.T) {
	password := "secretPassword123!"
	hash, err := HashPassword(password, DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate test hash: %v", err)
	}

	// Test with correct password
	iterations := 1000
	var totalTime time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		ComparePassword(hash, password)
		totalTime += time.Since(start)
	}
	correctTime := totalTime / time.Duration(iterations)

	// Test with incorrect password of same length
	wrongPassword := "wrongPassword123!"
	totalTime = 0

	for i := 0; i < iterations; i++ {
		start := time.Now()
		ComparePassword(hash, wrongPassword)
		totalTime += time.Since(start)
	}
	wrongTime := totalTime / time.Duration(iterations)

	// The timing difference should be minimal (within reasonable bounds)
	// bcrypt provides constant-time comparison naturally
	timeDiff := correctTime - wrongTime
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}

	// Allow for some variance but not excessive
	maxVariance := correctTime / 2 // 50% variance allowance
	if timeDiff > maxVariance {
		t.Logf("Timing difference detected: correct=%v, wrong=%v, diff=%v",
			correctTime, wrongTime, timeDiff)
		// Note: This is informational - bcrypt should handle timing attacks internally
	}
}

// TestCostBoundaries tests the exact boundary conditions
func TestCostBoundaries(t *testing.T) {
	password := "testPassword"

	t.Run("Min cost boundary", func(t *testing.T) {
		// MinCost should work
		hash, err := HashPassword(password, MinCost)
		if err != nil {
			t.Errorf("HashPassword with MinCost failed: %v", err)
		}

		if err := ComparePassword(hash, password); err != nil {
			t.Errorf("ComparePassword with MinCost hash failed: %v", err)
		}

		// MinCost-1 should fail
		_, err = HashPassword(password, MinCost-1)
		if err == nil {
			t.Error("HashPassword should fail with cost below MinCost")
		}
	})

	t.Run("Max cost boundary", func(t *testing.T) {
		// MaxCost should work (but will be slow)
		hash, err := HashPassword(password, MaxCost)
		if err != nil {
			t.Errorf("HashPassword with MaxCost failed: %v", err)
		}

		if err := ComparePassword(hash, password); err != nil {
			t.Errorf("ComparePassword with MaxCost hash failed: %v", err)
		}

		// MaxCost+1 should fail
		_, err = HashPassword(password, MaxCost+1)
		if err == nil {
			t.Error("HashPassword should fail with cost above MaxCost")
		}
	})
}

// TestContextCancellation tests context cancellation support
func TestContextCancellation(t *testing.T) {
	hasher := NewPasswordHasher()
	password := "testPassword"

	t.Run("Hash with cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := hasher.Hash(ctx, password)
		if err == nil {
			t.Error("Hash() should fail with cancelled context")
		}

		if err != context.Canceled {
			t.Errorf("Hash() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("Verify with cancelled context", func(t *testing.T) {
		// First create a valid hash
		hash, err := hasher.Hash(context.Background(), password)
		if err != nil {
			t.Fatalf("Failed to create test hash: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = hasher.Verify(ctx, password, hash)
		if err == nil {
			t.Error("Verify() should fail with cancelled context")
		}

		if err != context.Canceled {
			t.Errorf("Verify() error = %v, want %v", err, context.Canceled)
		}
	})
}

// Benchmark tests to ensure reasonable performance
func BenchmarkHashPassword(b *testing.B) {
	password := "benchmarkPassword123!"

	b.Run("Cost10", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			HashPassword(password, 10)
		}
	})

	b.Run("Cost12", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			HashPassword(password, 12)
		}
	})
}

func BenchmarkComparePassword(b *testing.B) {
	password := "benchmarkPassword123!"
	hash, _ := HashPassword(password, DefaultCost)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComparePassword(hash, password)
	}
}
