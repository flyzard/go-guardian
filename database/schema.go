package database

import (
	"database/sql"
	"fmt"
	"slices"
	"strings"
)

// RequiredColumns defines the columns required for each logical table
var RequiredColumns = map[string][]string{
	"users": {
		"id",
		"email",
		"password_hash",
		"verified",
		"created_at",
		"role_id", // Optional, for RBAC
	},
	"tokens": {
		"id",
		"token",
		"user_id",
		"purpose",
		"expires_at",
		"created_at",
	},
	"sessions": {
		"id",
		"user_id",
		"data",
		"expires_at",
		"created_at",
	},
}

// OptionalColumns for RBAC functionality
var OptionalColumns = map[string][]string{
	"roles": {
		"id",
		"name",
	},
	"permissions": {
		"id",
		"name",
	},
	"role_permissions": {
		"role_id",
		"permission_id",
	},
	"remember_tokens": {
		"id",
		"user_id",
		"token",
		"expires_at",
		"created_at",
	},
}

type SchemaValidator struct {
	db *DB
}

func NewSchemaValidator(db *DB) *SchemaValidator {
	return &SchemaValidator{db: db}
}

// Validate uses the default table names from the DB connection
func (v *SchemaValidator) Validate() error {
	return v.ValidateWithMapping(v.db.TableNames())
}

// ValidateWithMapping validates schema with custom table mapping
func (v *SchemaValidator) ValidateWithMapping(mapping TableMapping) error {
	// Map logical tables to actual table names
	tableMap := map[string]string{
		"users":    mapping.Users,
		"tokens":   mapping.Tokens,
		"sessions": mapping.Sessions,
	}

	// Check required tables
	for logicalTable, columns := range RequiredColumns {
		actualTable := tableMap[logicalTable]
		if actualTable == "" {
			return fmt.Errorf("no table mapping for logical table '%s'", logicalTable)
		}

		exists, err := v.tableExists(actualTable)
		if err != nil {
			return fmt.Errorf("error checking table %s (mapped from %s): %w", actualTable, logicalTable, err)
		}
		if !exists {
			return fmt.Errorf("required table '%s' (for %s) does not exist", actualTable, logicalTable)
		}

		// Check required columns
		for _, column := range columns {
			exists, err := v.columnExists(actualTable, column)
			if err != nil {
				// Column might be optional (like role_id)
				continue
			}
			if !exists && column != "role_id" { // role_id is optional
				return fmt.Errorf("required column '%s.%s' does not exist", actualTable, column)
			}
		}
	}

	return nil
}

// ValidateRBAC validates optional RBAC tables
func (v *SchemaValidator) ValidateRBAC() error {
	return v.ValidateRBACWithMapping(v.db.TableNames())
}

// ValidateRBACWithMapping validates RBAC tables with custom mapping
func (v *SchemaValidator) ValidateRBACWithMapping(mapping TableMapping) error {
	// Map logical tables to actual table names
	tableMap := map[string]string{
		"roles":            mapping.Roles,
		"permissions":      mapping.Permissions,
		"role_permissions": mapping.RolePermissions,
		"remember_tokens":  mapping.RememberTokens,
	}

	// Check optional RBAC tables
	for logicalTable, columns := range OptionalColumns {
		actualTable := tableMap[logicalTable]
		if actualTable == "" {
			return fmt.Errorf("no table mapping for logical table '%s'", logicalTable)
		}

		exists, err := v.tableExists(actualTable)
		if err != nil {
			return fmt.Errorf("error checking table %s (mapped from %s): %w", actualTable, logicalTable, err)
		}
		if !exists {
			return fmt.Errorf("RBAC table '%s' (for %s) does not exist", actualTable, logicalTable)
		}

		for _, column := range columns {
			exists, err := v.columnExists(actualTable, column)
			if err != nil {
				return fmt.Errorf("error checking column %s.%s: %w", actualTable, column, err)
			}
			if !exists {
				return fmt.Errorf("RBAC column '%s.%s' does not exist", actualTable, column)
			}
		}
	}

	return nil
}

func (v *SchemaValidator) tableExists(name string) (bool, error) {
	var query string
	switch v.db.Type() {
	case "sqlite":
		query = "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
	case "mysql":
		query = "SELECT table_name FROM information_schema.tables WHERE table_name=? AND table_schema=DATABASE()"
	default:
		return false, fmt.Errorf("unsupported database type: %s", v.db.Type())
	}

	var tableName string
	err := v.db.QueryRow(query, name).Scan(&tableName)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (v *SchemaValidator) columnExists(table, column string) (bool, error) {
	switch v.db.Type() {
	case "sqlite":
		// PRAGMA doesn't support parameters, but table name comes from our mapping
		// which is user-provided, so we need to be careful here
		// We'll validate the table name doesn't contain SQL injection
		if err := validateTableName(table); err != nil {
			return false, err
		}

		query := fmt.Sprintf("PRAGMA table_info(%s)", table)
		rows, err := v.db.DB.Query(query)
		if err != nil {
			return false, err
		}
		defer rows.Close()

		for rows.Next() {
			var cid int
			var name, dtype string
			var notnull, pk int
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &dtype, &notnull, &dflt, &pk); err != nil {
				continue
			}
			if name == column {
				return true, nil
			}
		}
		return false, nil

	case "mysql":
		query := `SELECT column_name FROM information_schema.columns 
		         WHERE table_name = ? AND column_name = ? AND table_schema = DATABASE()`
		var colName string
		err := v.db.QueryRow(query, table, column).Scan(&colName)
		if err == sql.ErrNoRows {
			return false, nil
		}
		return err == nil, err

	default:
		return false, fmt.Errorf("unsupported database type: %s", v.db.Type())
	}
}

// validateTableName ensures table name is safe for direct SQL usage
func validateTableName(name string) error {
	// Allow alphanumeric, underscore, and dash
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-') {
			return fmt.Errorf("invalid table name: %s (contains invalid character: %c)", name, r)
		}
	}

	// Prevent SQL keywords
	keywords := []string{"SELECT", "DROP", "DELETE", "INSERT", "UPDATE", "WHERE", "FROM"}
	nameUpper := strings.ToUpper(name)
	if slices.Contains(keywords, nameUpper) {
		return fmt.Errorf("invalid table name: %s (SQL keyword)", name)
	}

	return nil
}
