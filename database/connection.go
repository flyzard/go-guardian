package database

import (
	"database/sql"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	*sql.DB
	dbType string // "sqlite" or "mysql"
}

type MySQLConfig struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// NewSQLite creates a new SQLite database connection
func NewSQLite(path string) (*DB, error) {
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
		DB:     db,
		dbType: "sqlite",
	}

	// Run initial migrations
	if err := wrapped.Migrate(); err != nil {
		return nil, err
	}

	return wrapped, nil
}

// NewMySQL creates a new MySQL database connection
func NewMySQL(cfg MySQLConfig) (*DB, error) {
	// DSN format: "user:password@tcp(localhost:3306)/dbname?parseTime=true&loc=Local"
	// parseTime=true is REQUIRED for proper time.Time scanning
	db, err := sql.Open("mysql", cfg.DSN)
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	} else {
		db.SetMaxOpenConns(25) // Default
	}

	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	} else {
		db.SetMaxIdleConns(5) // Default
	}

	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	} else {
		db.SetConnMaxLifetime(5 * time.Minute) // Default
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	wrapped := &DB{
		DB:     db,
		dbType: "mysql",
	}

	// Run initial migrations
	if err := wrapped.Migrate(); err != nil {
		return nil, err
	}

	return wrapped, nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}

func (db *DB) Type() string {
	return db.dbType
}
