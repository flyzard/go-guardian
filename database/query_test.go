package database

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) *DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	// Create test table
	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			email TEXT UNIQUE,
			password_hash TEXT,
			verified BOOLEAN DEFAULT 0
		)
	`)
	if err != nil {
		t.Fatal(err)
	}

	return &DB{DB: db, dbType: "sqlite"}
}

func TestSQLInjectionPrevention(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert test user
	_, err := db.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)",
		"admin@test.com", "hash123")
	if err != nil {
		t.Fatal(err)
	}

	qb := db.Query()

	// Test various SQL injection attempts
	maliciousInputs := []string{
		"admin' OR '1'='1",
		"admin'; DROP TABLE users;--",
		"admin' UNION SELECT * FROM users--",
		"admin' OR 1=1--",
		"admin\" OR \"1\"=\"1",
		"'; DELETE FROM users WHERE '1'='1",
	}

	for _, input := range maliciousInputs {
		var count int
		err := qb.Select("users", "COUNT(*)").
			Where("email", "=", input).
			QueryRow().
			Scan(&count)

		if err != sql.ErrNoRows && count > 0 {
			t.Errorf("SQL injection successful with input: %s", input)
		}
	}
}

func TestQueryBuilder(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Insert test data
	testUsers := []struct {
		email    string
		verified bool
	}{
		{"user1@test.com", true},
		{"user2@test.com", false},
		{"user3@test.com", true},
	}

	for _, u := range testUsers {
		_, err := db.Exec("INSERT INTO users (email, verified) VALUES (?, ?)",
			u.email, u.verified)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Test SELECT query
	qb := db.Query()

	var email string
	err := qb.Select("users", "email").
		Where("verified", "=", true).
		OrderBy("email", false).
		Limit(1).
		QueryRow().
		Scan(&email)

	if err != nil {
		t.Fatal(err)
	}

	if email != "user1@test.com" {
		t.Errorf("Expected user1@test.com, got %s", email)
	}
}
