package config

// SchemaConfig centralizes all table and column name mappings
type SchemaConfig struct {
	Tables  TableNames
	Columns ColumnNames
}

// TableNames defines all table names (single source of truth)
type TableNames struct {
	Users           string
	Tokens          string // Only required if using email verification or password reset
	Sessions        string // Only required if using database sessions
	Roles           string
	Permissions     string
	RolePermissions string
	RememberTokens  string
}

// ColumnNames defines all column names (nested structure)
type ColumnNames struct {
	User   UserColumns
	Token  TokenColumns
	Role   RoleColumns
	Perm   PermissionColumns
}

// UserColumns defines columns for the users table
type UserColumns struct {
	ID       string
	Email    string
	Password string
	Verified string
	Created  string
	RoleID   string
}

// TokenColumns defines columns for the tokens table
type TokenColumns struct {
	ID      string
	Value   string
	UserID  string
	Purpose string
	Expires string
	Created string
}

// RoleColumns defines columns for the roles table
type RoleColumns struct {
	ID          string
	Name        string
	Slug        string
	Description string
	Created     string
}

// PermissionColumns defines columns for the permissions table
type PermissionColumns struct {
	ID          string
	Name        string
	Slug        string
	Description string
	Category    string
	Created     string
}

// FlatColumnNames provides backward compatibility with flat structure
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
		Sessions:        "sessions",
		Roles:           "roles",
		Permissions:     "permissions",
		RolePermissions: "role_permissions",
		RememberTokens:  "remember_tokens",
	}
}

// DefaultColumnNames returns the default column names (nested structure)
func DefaultColumnNames() ColumnNames {
	return ColumnNames{
		User: UserColumns{
			ID:       "id",
			Email:    "email",
			Password: "password_hash",
			Verified: "verified",
			Created:  "created_at",
			RoleID:   "role_id",
		},
		Token: TokenColumns{
			ID:      "id",
			Value:   "token",
			UserID:  "user_id",
			Purpose: "purpose",
			Expires: "expires_at",
			Created: "created_at",
		},
		Role: RoleColumns{
			ID:          "id",
			Name:        "name",
			Slug:        "slug",
			Description: "description",
			Created:     "created_at",
		},
		Perm: PermissionColumns{
			ID:          "id",
			Name:        "name",
			Slug:        "slug",
			Description: "description",
			Category:    "category",
			Created:     "created_at",
		},
	}
}

// DefaultFlatColumnNames returns the default column names (flat structure for backward compatibility)
func DefaultFlatColumnNames() FlatColumnNames {
	nested := DefaultColumnNames()
	return FlatColumnNames{
		// Users table columns
		UserID:       nested.User.ID,
		UserEmail:    nested.User.Email,
		UserPassword: nested.User.Password,
		UserVerified: nested.User.Verified,
		UserCreated:  nested.User.Created,
		UserRoleID:   nested.User.RoleID,

		// Tokens table columns
		TokenID:      nested.Token.ID,
		TokenValue:   nested.Token.Value,
		TokenUserID:  nested.Token.UserID,
		TokenPurpose: nested.Token.Purpose,
		TokenExpires: nested.Token.Expires,
		TokenCreated: nested.Token.Created,

		// Roles table columns
		RoleID:          nested.Role.ID,
		RoleName:        nested.Role.Name,
		RoleSlug:        nested.Role.Slug,
		RoleDescription: nested.Role.Description,
		RoleCreated:     nested.Role.Created,

		// Permissions table columns
		PermID:          nested.Perm.ID,
		PermName:        nested.Perm.Name,
		PermSlug:        nested.Perm.Slug,
		PermDescription: nested.Perm.Description,
		PermCategory:    nested.Perm.Category,
		PermCreated:     nested.Perm.Created,
	}
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

// ToFlat converts nested ColumnNames to flat structure
func (c ColumnNames) ToFlat() FlatColumnNames {
	return FlatColumnNames{
		// Users table columns
		UserID:       c.User.ID,
		UserEmail:    c.User.Email,
		UserPassword: c.User.Password,
		UserVerified: c.User.Verified,
		UserCreated:  c.User.Created,
		UserRoleID:   c.User.RoleID,

		// Tokens table columns
		TokenID:      c.Token.ID,
		TokenValue:   c.Token.Value,
		TokenUserID:  c.Token.UserID,
		TokenPurpose: c.Token.Purpose,
		TokenExpires: c.Token.Expires,
		TokenCreated: c.Token.Created,

		// Roles table columns
		RoleID:          c.Role.ID,
		RoleName:        c.Role.Name,
		RoleSlug:        c.Role.Slug,
		RoleDescription: c.Role.Description,
		RoleCreated:     c.Role.Created,

		// Permissions table columns
		PermID:          c.Perm.ID,
		PermName:        c.Perm.Name,
		PermSlug:        c.Perm.Slug,
		PermDescription: c.Perm.Description,
		PermCategory:    c.Perm.Category,
		PermCreated:     c.Perm.Created,
	}
}

// ToNested converts flat FlatColumnNames to nested structure
func (f FlatColumnNames) ToNested() ColumnNames {
	return ColumnNames{
		User: UserColumns{
			ID:       f.UserID,
			Email:    f.UserEmail,
			Password: f.UserPassword,
			Verified: f.UserVerified,
			Created:  f.UserCreated,
			RoleID:   f.UserRoleID,
		},
		Token: TokenColumns{
			ID:      f.TokenID,
			Value:   f.TokenValue,
			UserID:  f.TokenUserID,
			Purpose: f.TokenPurpose,
			Expires: f.TokenExpires,
			Created: f.TokenCreated,
		},
		Role: RoleColumns{
			ID:          f.RoleID,
			Name:        f.RoleName,
			Slug:        f.RoleSlug,
			Description: f.RoleDescription,
			Created:     f.RoleCreated,
		},
		Perm: PermissionColumns{
			ID:          f.PermID,
			Name:        f.PermName,
			Slug:        f.PermSlug,
			Description: f.PermDescription,
			Category:    f.PermCategory,
			Created:     f.PermCreated,
		},
	}
}