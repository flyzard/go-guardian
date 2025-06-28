package database

import (
	"fmt"
	"log"
)

// Migration represents a single database migration
type Migration struct {
	Version string
	Name    string
	Up      string
	Down    string
}

var migrations = []Migration{
	{
		Version: "001",
		Name:    "create_users_table",
		Up: `
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                verified BOOLEAN DEFAULT FALSE,
                created_at DATETIME NOT NULL,
                updated_at DATETIME
            );
            CREATE INDEX idx_users_email ON users(email);
        `,
		Down: `DROP TABLE IF EXISTS users;`,
	},
	{
		Version: "002",
		Name:    "create_tokens_table",
		Up: `
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX idx_tokens_token ON tokens(token);
            CREATE INDEX idx_tokens_expires ON tokens(expires_at);
        `,
		Down: `DROP TABLE IF EXISTS tokens;`,
	},
	{
		Version: "003",
		Name:    "create_sessions_table",
		Up: `
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                data TEXT,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX idx_sessions_expires ON sessions(expires_at);
        `,
		Down: `DROP TABLE IF EXISTS sessions;`,
	},
}

// Migrate runs the database migrations
func (db *DB) Migrate() error {
	// Create migrations table
	if _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS migrations (
            version TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `); err != nil {
		return err
	}

	// Run migrations
	for _, m := range migrations {
		if err := db.runMigration(m); err != nil {
			return fmt.Errorf("migration %s failed: %w", m.Version, err)
		}
	}

	return nil
}

func (db *DB) runMigration(m Migration) error {
	// Check if already applied
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM migrations WHERE version = ?", m.Version).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil // Already applied
	}

	// Run migration in transaction
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(m.Up); err != nil {
		return err
	}

	if _, err := tx.Exec(
		"INSERT INTO migrations (version, name) VALUES (?, ?)",
		m.Version, m.Name,
	); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	log.Printf("Applied migration %s: %s", m.Version, m.Name)
	return nil
}
