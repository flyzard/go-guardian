package database

import (
	"database/sql"
	"time"

	"github.com/flyzard/go-guardian/config"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
)

// TableMapping is an alias to config.TableNames for backward compatibility
type TableMapping = config.TableNames


type DB struct {
	*sql.DB
	dbType         string // "sqlite" or "mysql"
	migrationTable string // Name of migrations table
	tableNames     TableMapping
}

type SQLiteConfig struct {
	Path           string
	AutoMigrate    bool
	MigrationTable string
	TableNames     TableMapping
}

type MySQLConfig struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	AutoMigrate     bool
	MigrationTable  string
	TableNames      TableMapping
}

// NewSQLite creates a new SQLite database connection with default config (backward compatible)
func NewSQLite(path string) (*DB, error) {
	return NewSQLiteWithConfig(SQLiteConfig{
		Path:           path,
		AutoMigrate:    true,
		MigrationTable: "migrations",
		TableNames:     config.DefaultTableNames(),
	})
}

// NewSQLiteWithConfig creates a new SQLite database connection with custom config
func NewSQLiteWithConfig(cfg SQLiteConfig) (*DB, error) {
	db, err := sql.Open("sqlite3", cfg.Path)
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

	// Set defaults
	if cfg.TableNames == (TableMapping{}) {
		cfg.TableNames = config.DefaultTableNames()
	} else {
		// Apply defaults to missing fields
		config.ApplyDefaults(&cfg.TableNames, config.DefaultTableNames())
	}
	if cfg.MigrationTable == "" {
		cfg.MigrationTable = "migrations"
	}

	wrapped := &DB{
		DB:             db,
		dbType:         "sqlite",
		migrationTable: cfg.MigrationTable,
		tableNames:     cfg.TableNames,
	}

	// Run migrations only if AutoMigrate is true
	if cfg.AutoMigrate {
		if err := wrapped.Migrate(); err != nil {
			return nil, err
		}
	}

	return wrapped, nil
}

// NewMySQL creates a new MySQL database connection with default config (backward compatible)
func NewMySQL(cfg MySQLConfig) (*DB, error) {
	// Set defaults for backward compatibility
	if cfg.MigrationTable == "" {
		cfg.MigrationTable = "migrations"
	}
	if !cfg.AutoMigrate {
		cfg.AutoMigrate = true
	}
	if cfg.TableNames == (TableMapping{}) {
		cfg.TableNames = config.DefaultTableNames()
	} else {
		// Apply defaults to missing fields
		config.ApplyDefaults(&cfg.TableNames, config.DefaultTableNames())
	}
	return NewMySQLWithConfig(cfg)
}

// NewMySQLWithConfig creates a new MySQL database connection with custom config
func NewMySQLWithConfig(cfg MySQLConfig) (*DB, error) {
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

	// Set defaults
	if cfg.TableNames == (TableMapping{}) {
		cfg.TableNames = config.DefaultTableNames()
	} else {
		// Apply defaults to missing fields
		config.ApplyDefaults(&cfg.TableNames, config.DefaultTableNames())
	}
	if cfg.MigrationTable == "" {
		cfg.MigrationTable = "migrations"
	}

	wrapped := &DB{
		DB:             db,
		dbType:         "mysql",
		migrationTable: cfg.MigrationTable,
		tableNames:     cfg.TableNames,
	}

	// Run migrations only if AutoMigrate is true
	if cfg.AutoMigrate {
		if err := wrapped.Migrate(); err != nil {
			return nil, err
		}
	}

	return wrapped, nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}

func (db *DB) Type() string {
	return db.dbType
}

func (db *DB) MigrationTable() string {
	if db.migrationTable == "" {
		return "migrations"
	}
	return db.migrationTable
}

func (db *DB) TableNames() TableMapping {
	if db.tableNames == (TableMapping{}) {
		return config.DefaultTableNames()
	}
	return db.tableNames
}

// Table name getters for easy access
func (db *DB) UsersTable() string {
	return db.tableNames.Users
}

func (db *DB) TokensTable() string {
	return db.tableNames.Tokens
}

func (db *DB) SessionsTable() string {
	return db.tableNames.Sessions
}

func (db *DB) RolesTable() string {
	return db.tableNames.Roles
}

func (db *DB) PermissionsTable() string {
	return db.tableNames.Permissions
}

func (db *DB) RolePermissionsTable() string {
	return db.tableNames.RolePermissions
}

func (db *DB) RememberTokensTable() string {
	return db.tableNames.RememberTokens
}
