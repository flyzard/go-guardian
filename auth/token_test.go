package auth

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func setupAuthDB(t *testing.T) (*Service, *sql.DB) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			email TEXT UNIQUE,
			password_hash TEXT,
			verified BOOLEAN DEFAULT 0,
			created_at DATETIME
		);
		CREATE TABLE tokens (
			id INTEGER PRIMARY KEY,
			token TEXT UNIQUE,
			user_id INTEGER,
			purpose TEXT,
			expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

	// Insert test user
	_, err = db.Exec(
		"INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
		"test@example.com", "hash123", time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}

	store := NewSessionStore([]byte("test-secret-key-32-bytes-long!!!"))
	service := NewService(store, db)

	return service, db
}

func TestTokenGeneration(t *testing.T) {
	// Test token uniqueness
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token := GenerateToken()
		if len(token) != 64 { // 32 bytes hex encoded
			t.Errorf("Invalid token length: %d", len(token))
		}
		if tokens[token] {
			t.Fatal("Duplicate token generated")
		}
		tokens[token] = true
	}
}

func TestVerificationToken(t *testing.T) {
	service, db := setupAuthDB(t)
	defer db.Close()

	// Create verification token
	token, err := service.CreateVerificationToken(1)
	if err != nil {
		t.Fatal(err)
	}

	// Validate token
	validated, err := service.ValidateToken(token.Value, "email_verification")
	if err != nil {
		t.Fatal(err)
	}

	if validated.UserID != 1 {
		t.Errorf("Wrong user ID: %d", validated.UserID)
	}

	// Token should be deleted after use
	_, err = service.ValidateToken(token.Value, "email_verification")
	if err == nil {
		t.Fatal("Token not deleted after use")
	}
}

func TestTokenExpiration(t *testing.T) {
	service, db := setupAuthDB(t)
	defer db.Close()

	// Insert expired token
	expiredToken := GenerateToken()
	_, err := db.Exec(`
		INSERT INTO tokens (token, user_id, purpose, expires_at)
		VALUES (?, ?, ?, ?)
	`, expiredToken, 1, "password_reset", time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// Try to validate expired token
	_, err = service.ValidateToken(expiredToken, "password_reset")
	if err == nil {
		t.Fatal("Expired token was accepted")
	}
}
