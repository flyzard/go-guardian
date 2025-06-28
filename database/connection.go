// Package database provides a wrapper around the database/sql package
package database

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

// DB represents a database connection
type DB struct {
	*sql.DB
	path string
}

// New creates a new database connection
func New(path string) (*DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Configure for better performance and security
	if _, err := db.Exec(`
        PRAGMA foreign_keys = ON;
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
    `); err != nil {
		return nil, err
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	wrapped := &DB{
		DB:   db,
		path: path,
	}

	// Run initial migrations
	if err := wrapped.Migrate(); err != nil {
		return nil, err
	}

	return wrapped, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.DB.Close()
}
