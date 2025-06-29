package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserNotVerified    = errors.New("email not verified")
	ErrFeatureDisabled    = errors.New("feature is disabled")
)

// TableConfig defines table names for auth operations
type TableConfig struct {
	Users           string
	Tokens          string
	Sessions        string
	Roles           string
	Permissions     string
	RolePermissions string
	RememberTokens  string
}

// DefaultTableConfig returns the default table names
func DefaultTableConfig() TableConfig {
	return TableConfig{
		Users:           "users",
		Tokens:          "tokens",
		Sessions:        "sessions",
		Roles:           "roles",
		Permissions:     "permissions",
		RolePermissions: "role_permissions",
		RememberTokens:  "remember_tokens",
	}
}

// ColumnConfig maps Guardian's expected columns to actual database columns
type ColumnConfig struct {
	// Users table columns
	UserID       string // Default: "id"
	UserEmail    string // Default: "email"
	UserPassword string // Default: "password_hash"
	UserVerified string // Default: "verified"
	UserCreated  string // Default: "created_at"
	UserRoleID   string // Default: "role_id"

	// Tokens table columns (if using email verification or password reset)
	TokenID      string // Default: "id"
	TokenValue   string // Default: "token"
	TokenUserID  string // Default: "user_id"
	TokenPurpose string // Default: "purpose"
	TokenExpires string // Default: "expires_at"
	TokenCreated string // Default: "created_at"
}

// DefaultColumnConfig returns the default column names
func DefaultColumnConfig() ColumnConfig {
	return ColumnConfig{
		UserID:       "id",
		UserEmail:    "email",
		UserPassword: "password_hash",
		UserVerified: "verified",
		UserCreated:  "created_at",
		UserRoleID:   "role_id",

		TokenID:      "id",
		TokenValue:   "token",
		TokenUserID:  "user_id",
		TokenPurpose: "purpose",
		TokenExpires: "expires_at",
		TokenCreated: "created_at",
	}
}

// FeatureConfig defines which features are enabled
type FeatureConfig struct {
	EmailVerification bool
	PasswordReset     bool
	RememberMe        bool
	RBAC              bool
	ExternalAuth      bool // New: Allow external authentication (SSO, LDAP, etc.)
}

// DefaultFeatureConfig returns all features enabled
func DefaultFeatureConfig() FeatureConfig {
	return FeatureConfig{
		EmailVerification: true,
		PasswordReset:     true,
		RememberMe:        true,
		RBAC:              true,
		ExternalAuth:      false,
	}
}

type ServiceConfig struct {
	Store       sessions.Store
	DB          *sql.DB
	TableNames  TableConfig
	ColumnNames ColumnConfig
	Features    FeatureConfig
}

type Service struct {
	store    sessions.Store
	db       *sql.DB
	tables   TableConfig
	columns  ColumnConfig
	features FeatureConfig
}

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Verified     bool
	CreatedAt    time.Time
}

// NewService creates a new auth service with default table names (backward compatible)
func NewService(store sessions.Store, db *sql.DB) *Service {
	return NewServiceWithConfig(ServiceConfig{
		Store:       store,
		DB:          db,
		TableNames:  DefaultTableConfig(),
		ColumnNames: DefaultColumnConfig(),
		Features:    DefaultFeatureConfig(),
	})
}

// NewServiceWithConfig creates a new auth service with custom table names
func NewServiceWithConfig(cfg ServiceConfig) *Service {
	// Set defaults if not provided
	if cfg.TableNames == (TableConfig{}) {
		cfg.TableNames = DefaultTableConfig()
	}

	if cfg.ColumnNames == (ColumnConfig{}) {
		cfg.ColumnNames = DefaultColumnConfig()
	}

	if cfg.Features == (FeatureConfig{}) {
		cfg.Features = DefaultFeatureConfig()
	}

	return &Service{
		store:    cfg.Store,
		db:       cfg.DB,
		tables:   cfg.TableNames,
		columns:  cfg.ColumnNames,
		features: cfg.Features,
	}
}

func (s *Service) Login(w http.ResponseWriter, r *http.Request, email, password string) error {
	// Find user
	user, err := s.findUserByEmail(email)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidCredentials
		}
		return err
	}

	// Skip password check if external auth is enabled
	if !s.features.ExternalAuth {
		// Check password
		if !CheckPasswordHash(password, user.PasswordHash) {
			return ErrInvalidCredentials
		}
	}

	// Check if verified only if email verification is enabled
	if s.features.EmailVerification && !user.Verified {
		return ErrUserNotVerified
	}

	// Create session
	return s.CreateSessionForUser(w, r, user.ID, user.Email)
}

// LoginWithoutPassword allows login without password verification
// Useful for SSO or when password is checked externally
func (s *Service) LoginWithoutPassword(w http.ResponseWriter, r *http.Request, email string) error {
	if !s.features.ExternalAuth {
		return errors.New("external authentication is not enabled")
	}

	user, err := s.findUserByEmail(email)
	if err != nil {
		return err
	}

	// Check if verified only if email verification is enabled
	if s.features.EmailVerification && !user.Verified {
		return ErrUserNotVerified
	}

	return s.CreateSessionForUser(w, r, user.ID, user.Email)
}

// CreateSessionForUser creates a session for an already-authenticated user
// This allows SSO/external auth systems to create Guardian sessions
func (s *Service) CreateSessionForUser(w http.ResponseWriter, r *http.Request, userID int64, email string) error {
	// Create new session
	session, _ := s.store.New(r, "auth-session")
	session.Values["user_id"] = userID
	session.Values["email"] = email

	// Regenerate session ID for security
	session.Options.MaxAge = 1800 // 30 minutes

	return session.Save(r, w)
}

// LoginWithRememberMe logs in the user with an option to remember the session
func (s *Service) LoginWithRememberMe(w http.ResponseWriter, r *http.Request, email, password string, rememberMe bool) error {
	if rememberMe && !s.features.RememberMe {
		return ErrFeatureDisabled
	}

	user, err := s.findUserByEmail(email)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidCredentials
		}
		return err
	}

	// Skip password check if external auth is enabled
	if !s.features.ExternalAuth {
		// Check password
		if !CheckPasswordHash(password, user.PasswordHash) {
			return ErrInvalidCredentials
		}
	}

	// Check if verified only if email verification is enabled
	if s.features.EmailVerification && !user.Verified {
		return ErrUserNotVerified
	}

	// After successful login
	session, _ := s.store.New(r, "auth-session")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email

	// Set longer expiration if remember me is checked
	if rememberMe && s.features.RememberMe {
		session.Options.MaxAge = 86400 * 30 // 30 days

		// Create a remember token
		token := GenerateToken()
		query := fmt.Sprintf(`
			INSERT INTO %s (user_id, token, expires_at)
			VALUES (?, ?, ?)
		`, s.tables.RememberTokens)

		_, err := s.db.Exec(query, user.ID, token, time.Now().Add(30*24*time.Hour))

		if err == nil {
			// Set remember me cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "remember_token",
				Value:    token,
				MaxAge:   86400 * 30,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})
		}
	} else {
		session.Options.MaxAge = 1800 // 30 minutes
	}

	return session.Save(r, w)
}

func (s *Service) Logout(w http.ResponseWriter, r *http.Request) error {
	session, err := s.store.Get(r, "auth-session")
	if err != nil {
		return err
	}

	// Delete session
	session.Options.MaxAge = -1
	return session.Save(r, w)
}

func (s *Service) Register(email, password string) (*User, error) {
	// Check if user exists
	existing, _ := s.findUserByEmail(email)
	if existing != nil {
		return nil, errors.New("email already registered")
	}

	// Hash password if not using external auth
	var hash string
	if !s.features.ExternalAuth {
		var err error
		hash, err = HashPassword(password)
		if err != nil {
			return nil, err
		}
	}

	// If email verification is disabled, mark user as verified immediately
	verified := !s.features.EmailVerification

	// Insert user
	query := fmt.Sprintf(`
        INSERT INTO %s (%s, %s, %s, %s)
        VALUES (?, ?, ?, ?)
    `, s.tables.Users, s.columns.UserEmail, s.columns.UserPassword,
		s.columns.UserVerified, s.columns.UserCreated)

	result, err := s.db.Exec(query, email, hash, verified, time.Now())

	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()

	return &User{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		Verified:     verified,
		CreatedAt:    time.Now(),
	}, nil
}

// RegisterExternalUser registers a user without a password (for SSO/external auth)
func (s *Service) RegisterExternalUser(email string) (*User, error) {
	if !s.features.ExternalAuth {
		return nil, errors.New("external authentication is not enabled")
	}

	return s.Register(email, "")
}

func (s *Service) GetUser(r *http.Request) (*User, error) {
	session, err := s.store.Get(r, "auth-session")
	if err != nil {
		return nil, err
	}

	userID, ok := session.Values["user_id"].(int64)
	if !ok {
		return nil, ErrUserNotFound
	}

	return s.findUserByID(userID)
}

func (s *Service) findUserByEmail(email string) (*User, error) {
	var user User
	query := fmt.Sprintf(`
        SELECT %s, %s, %s, %s, %s
        FROM %s
        WHERE %s = ?
        LIMIT 1
    `, s.columns.UserID, s.columns.UserEmail, s.columns.UserPassword,
		s.columns.UserVerified, s.columns.UserCreated,
		s.tables.Users,
		s.columns.UserEmail)

	err := s.db.QueryRow(query, email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Verified, &user.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *Service) findUserByID(id int64) (*User, error) {
	var user User
	query := fmt.Sprintf(`
        SELECT %s, %s, %s, %s, %s
        FROM %s
        WHERE %s = ?
        LIMIT 1
    `, s.columns.UserID, s.columns.UserEmail, s.columns.UserPassword,
		s.columns.UserVerified, s.columns.UserCreated,
		s.tables.Users,
		s.columns.UserID)

	err := s.db.QueryRow(query, id).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Verified, &user.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetTableConfig returns the current table configuration
func (s *Service) GetTableConfig() TableConfig {
	return s.tables
}

// GetColumnConfig returns the current column configuration
func (s *Service) GetColumnConfig() ColumnConfig {
	return s.columns
}

// GetFeatures returns the enabled features
func (s *Service) GetFeatures() FeatureConfig {
	return s.features
}

// IsFeatureEnabled checks if a specific feature is enabled
func (s *Service) IsFeatureEnabled(feature string) bool {
	switch feature {
	case "email_verification":
		return s.features.EmailVerification
	case "password_reset":
		return s.features.PasswordReset
	case "remember_me":
		return s.features.RememberMe
	case "rbac":
		return s.features.RBAC
	case "external_auth":
		return s.features.ExternalAuth
	default:
		return false
	}
}

// SessionsTable returns the sessions table name, if configured
func (s *Service) SessionsTable() string {
	return s.tables.Sessions
}
