package database

import (
	"database/sql"
	"fmt"
	"strings"
)

// RequiredColumns defines the columns that are always required
var RequiredColumns = map[string][]string{
	"users": {
		"id",
		"email",
		"password_hash",
		"verified",
		"created_at",
		"role_id", // Optional column within the users table
	},
}

// ConditionalColumns for tables that are only required based on features
var ConditionalColumns = map[string][]string{
	"tokens": { // Required for email verification or password reset
		"id",
		"token",
		"user_id",
		"purpose",
		"expires_at",
		"created_at",
	},
	"sessions": { // Required for database session backend
		"id",
		"user_id",
		"data",
		"expires_at",
		"created_at",
	},
	"remember_tokens": { // Required for remember me feature
		"id",
		"user_id",
		"token",
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
	// REMOVED remember_tokens from here - it was duplicated
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
	// Always validate users table
	if mapping.Users == "" {
		return fmt.Errorf("users table mapping is required")
	}

	exists, err := v.tableExists(mapping.Users)
	if err != nil {
		return fmt.Errorf("error checking users table %s: %w", mapping.Users, err)
	}
	if !exists {
		return fmt.Errorf("required table '%s' (users) does not exist", mapping.Users)
	}

	// Check users table columns
	for _, column := range RequiredColumns["users"] {
		exists, err := v.columnExists(mapping.Users, column)
		if err != nil {
			// Column might be optional (like role_id)
			continue
		}
		if !exists && column != "role_id" { // role_id is optional
			return fmt.Errorf("required column '%s.%s' does not exist", mapping.Users, column)
		}
	}

	// Check tokens table if provided in mapping
	if mapping.Tokens != "" {
		exists, err := v.tableExists(mapping.Tokens)
		if err != nil {
			return fmt.Errorf("error checking tokens table %s: %w", mapping.Tokens, err)
		}
		if !exists {
			return fmt.Errorf("tokens table '%s' does not exist (required for email verification/password reset)", mapping.Tokens)
		}

		// Check tokens columns
		for _, column := range ConditionalColumns["tokens"] {
			exists, err := v.columnExists(mapping.Tokens, column)
			if err != nil {
				return fmt.Errorf("error checking column %s.%s: %w", mapping.Tokens, column, err)
			}
			if !exists {
				return fmt.Errorf("required column '%s.%s' does not exist", mapping.Tokens, column)
			}
		}
	}

	// Check remember_tokens table if provided in mapping
	if mapping.RememberTokens != "" {
		exists, err := v.tableExists(mapping.RememberTokens)
		if err != nil {
			return fmt.Errorf("error checking remember_tokens table %s: %w", mapping.RememberTokens, err)
		}
		if !exists {
			return fmt.Errorf("remember_tokens table '%s' does not exist (required for remember me feature)", mapping.RememberTokens)
		}

		// Check columns
		for _, column := range ConditionalColumns["remember_tokens"] {
			exists, err := v.columnExists(mapping.RememberTokens, column)
			if err != nil {
				return fmt.Errorf("error checking column %s.%s: %w", mapping.RememberTokens, column, err)
			}
			if !exists {
				return fmt.Errorf("required column '%s.%s' does not exist", mapping.RememberTokens, column)
			}
		}
	}

	// Check RBAC tables if provided in mapping
	if mapping.Roles != "" || mapping.Permissions != "" || mapping.RolePermissions != "" {
		// Validate RBAC tables
		err := v.validateRBACTables(mapping)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateRBACTables validates RBAC-related tables
func (v *SchemaValidator) validateRBACTables(mapping TableMapping) error {
	// Check roles table
	if mapping.Roles != "" {
		exists, err := v.tableExists(mapping.Roles)
		if err != nil {
			return fmt.Errorf("error checking roles table %s: %w", mapping.Roles, err)
		}
		if !exists {
			return fmt.Errorf("RBAC table '%s' (roles) does not exist", mapping.Roles)
		}

		for _, column := range OptionalColumns["roles"] {
			exists, err := v.columnExists(mapping.Roles, column)
			if err != nil {
				return fmt.Errorf("error checking column %s.%s: %w", mapping.Roles, column, err)
			}
			if !exists {
				return fmt.Errorf("RBAC column '%s.%s' does not exist", mapping.Roles, column)
			}
		}
	}

	// Check permissions table
	if mapping.Permissions != "" {
		exists, err := v.tableExists(mapping.Permissions)
		if err != nil {
			return fmt.Errorf("error checking permissions table %s: %w", mapping.Permissions, err)
		}
		if !exists {
			return fmt.Errorf("RBAC table '%s' (permissions) does not exist", mapping.Permissions)
		}

		for _, column := range OptionalColumns["permissions"] {
			exists, err := v.columnExists(mapping.Permissions, column)
			if err != nil {
				return fmt.Errorf("error checking column %s.%s: %w", mapping.Permissions, column, err)
			}
			if !exists {
				return fmt.Errorf("RBAC column '%s.%s' does not exist", mapping.Permissions, column)
			}
		}
	}

	// Check role_permissions table
	if mapping.RolePermissions != "" {
		exists, err := v.tableExists(mapping.RolePermissions)
		if err != nil {
			return fmt.Errorf("error checking role_permissions table %s: %w", mapping.RolePermissions, err)
		}
		if !exists {
			return fmt.Errorf("RBAC table '%s' (role_permissions) does not exist", mapping.RolePermissions)
		}

		for _, column := range OptionalColumns["role_permissions"] {
			exists, err := v.columnExists(mapping.RolePermissions, column)
			if err != nil {
				return fmt.Errorf("error checking column %s.%s: %w", mapping.RolePermissions, column, err)
			}
			if !exists {
				return fmt.Errorf("RBAC column '%s.%s' does not exist", mapping.RolePermissions, column)
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
	return v.validateRBACTables(mapping)
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
	for _, keyword := range keywords {
		if nameUpper == keyword {
			return fmt.Errorf("invalid table name: %s (SQL keyword)", name)
		}
	}

	return nil
}
