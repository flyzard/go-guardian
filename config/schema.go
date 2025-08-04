package config

// SchemaConfig centralizes all table and column name mappings
type SchemaConfig struct {
	Tables  TableNames
	Columns FlatColumnNames // Using flat structure directly
}

// TableNames defines all table names (single source of truth)
type TableNames struct {
	Users           string
	Tokens          string // Only required if using email verification or password reset
	Roles           string
	Permissions     string
	RolePermissions string
	RememberTokens  string
}

// FlatColumnNames defines all column names with prefix-based naming

// This is the primary structure used throughout the codebase
type FlatColumnNames struct {
	// Users table columns
	UserID       string
	UserEmail    string
	UserPassword string
	UserVerified string
	UserCreated  string
	UserRoleID   string

	// Tokens table columns
	TokenID      string
	TokenValue   string
	TokenUserID  string
	TokenPurpose string
	TokenExpires string
	TokenCreated string

	// Roles table columns
	RoleID          string
	RoleName        string
	RoleSlug        string
	RoleDescription string
	RoleCreated     string

	// Permissions table columns
	PermID          string
	PermName        string
	PermSlug        string
	PermDescription string
	PermCategory    string
	PermCreated     string
}

// Features defines which optional features are enabled
type Features struct {
	EmailVerification bool // Requires tokens table
	PasswordReset     bool // Requires tokens table
	RememberMe        bool // Requires remember_tokens table
	RBAC              bool // Requires roles, permissions tables
	ExternalAuth      bool // Enable external authentication (SSO, LDAP, etc.)
}

// DefaultSchema returns the default schema configuration
func DefaultSchema() SchemaConfig {
	return SchemaConfig{
		Tables:  DefaultTableNames(),
		Columns: DefaultColumnNames(),
	}
}

// DefaultTableNames returns the default table names
func DefaultTableNames() TableNames {
	return TableNames{
		Users:           "users",
		Tokens:          "tokens",
		Roles:           "roles",
		Permissions:     "permissions",
		RolePermissions: "role_permissions",
		RememberTokens:  "remember_tokens",
	}
}

// DefaultColumnNames returns the default column names
func DefaultColumnNames() FlatColumnNames {
	return FlatColumnNames{
		// Users table columns
		UserID:       "id",
		UserEmail:    "email",
		UserPassword: "password_hash",
		UserVerified: "verified",
		UserCreated:  "created_at",
		UserRoleID:   "role_id",

		// Tokens table columns
		TokenID:      "id",
		TokenValue:   "token",
		TokenUserID:  "user_id",
		TokenPurpose: "purpose",
		TokenExpires: "expires_at",
		TokenCreated: "created_at",

		// Roles table columns
		RoleID:          "id",
		RoleName:        "name",
		RoleSlug:        "slug",
		RoleDescription: "description",
		RoleCreated:     "created_at",

		// Permissions table columns
		PermID:          "id",
		PermName:        "name",
		PermSlug:        "slug",
		PermDescription: "description",
		PermCategory:    "category",
		PermCreated:     "created_at",
	}
}

// DefaultFlatColumnNames is an alias for DefaultColumnNames for backward compatibility
func DefaultFlatColumnNames() FlatColumnNames {
	return DefaultColumnNames()
}

// DefaultFeatures returns all features enabled
// This maintains backward compatibility - existing apps get all features
func DefaultFeatures() Features {
	return Features{
		EmailVerification: true,
		PasswordReset:     true,
		RememberMe:        true,
		RBAC:              true,
		ExternalAuth:      false,
	}
}

