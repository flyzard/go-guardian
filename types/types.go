// Package types defines the core data structures used throughout go-guardian.
// All types are designed to be immutable after creation for security and thread safety.
package types

import (
	"time"
)

// User represents a user account in the system.
// Users are immutable after creation to prevent accidental modification.
type User struct {
	ID             string     `json:"id" db:"id"`
	Email          string     `json:"email" db:"email"`
	PasswordHash   string     `json:"-" db:"password_hash"` // Never include in JSON
	EmailVerified  bool       `json:"email_verified" db:"email_verified"`
	AccountLocked  bool       `json:"account_locked" db:"account_locked"`
	FailedAttempts int        `json:"-" db:"failed_attempts"` // Sensitive info
	LastLoginAt    *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`

	// Optional fields for enhanced security
	TwoFAEnabled bool   `json:"two_fa_enabled" db:"two_fa_enabled"`
	TwoFASecret  string `json:"-" db:"two_fa_secret"` // Never include in JSON
}

// IsValid checks if the user has the minimum required fields.
func (u *User) IsValid() bool {
	return u.ID != "" && u.Email != "" && u.PasswordHash != ""
}

// IsLocked returns true if the account is locked due to security policies.
func (u *User) IsLocked() bool {
	return u.AccountLocked
}

// Session represents an authenticated user session.
// Sessions are immutable after creation and use secure random tokens.
type Session struct {
	Token      string    `json:"token" db:"token"`
	UserID     string    `json:"user_id" db:"user_id"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at" db:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at" db:"expires_at"`
	IPAddress  string    `json:"ip_address" db:"ip_address"`
	UserAgent  string    `json:"user_agent" db:"user_agent"`
	IsActive   bool      `json:"is_active" db:"is_active"`

	// Optional device fingerprinting
	DeviceFingerprint string `json:"-" db:"device_fingerprint"` // Sensitive
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsValid checks if the session has the minimum required fields.
func (s *Session) IsValid() bool {
	return s.Token != "" && s.UserID != "" && s.IsActive && !s.IsExpired()
}

// RemainingTime returns the time until session expiration.
func (s *Session) RemainingTime() time.Duration {
	if s.IsExpired() {
		return 0
	}
	return time.Until(s.ExpiresAt)
}

// WithUpdatedLastSeen returns a new session with updated LastSeenAt.
// This maintains immutability while allowing session refresh.
func (s *Session) WithUpdatedLastSeen() *Session {
	updated := *s
	updated.LastSeenAt = time.Now()
	return &updated
}

// TokenType defines the type of token (for different purposes).
type TokenType string

const (
	TokenTypePasswordReset     TokenType = "password_reset"
	TokenTypeEmailVerification TokenType = "email_verification"
	TokenTypeAPIAccess         TokenType = "api_access"
)

// Token represents a security token for various operations.
// Tokens are single-use and have expiration times.
type Token struct {
	Value     string     `json:"-" db:"value"` // Never include in JSON responses
	Type      TokenType  `json:"type" db:"type"`
	UserID    string     `json:"user_id" db:"user_id"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty" db:"used_at"`
	IsUsed    bool       `json:"is_used" db:"is_used"`

	// Optional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// IsExpired checks if the token has expired.
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsValid checks if the token is usable (not expired and not used).
func (t *Token) IsValid() bool {
	return !t.IsExpired() && !t.IsUsed && t.Value != ""
}

// MarkAsUsed marks the token as used and records the usage time.
// Returns a new token instance to maintain immutability.
func (t *Token) MarkAsUsed() *Token {
	used := *t
	now := time.Now()
	used.IsUsed = true
	used.UsedAt = &now
	return &used
}

// SecurityEventType defines the type of security event.
type SecurityEventType string

const (
	EventTypeLogin               SecurityEventType = "login"
	EventTypeLoginFailed         SecurityEventType = "login_failed"
	EventTypeLogout              SecurityEventType = "logout"
	EventTypePasswordReset       SecurityEventType = "password_reset"
	EventTypePasswordResetFailed SecurityEventType = "password_reset_failed"
	EventTypePasswordChanged     SecurityEventType = "password_changed"
	EventTypeEmailVerified       SecurityEventType = "email_verified"
	EventTypeAccountLocked       SecurityEventType = "account_locked"
	EventTypeSessionExpired      SecurityEventType = "session_expired"
	EventTypeRateLimitExceeded   SecurityEventType = "rate_limit_exceeded"
	EventTypeTwoFAEnabled        SecurityEventType = "two_fa_enabled"
	EventTypeTwoFADisabled       SecurityEventType = "two_fa_disabled"
)

// SecurityEvent represents an audit log entry for security-related events.
// All security events should be logged for compliance and monitoring.
type SecurityEvent struct {
	ID        string            `json:"id" db:"id"`
	Type      SecurityEventType `json:"type" db:"type"`
	UserID    string            `json:"user_id,omitempty" db:"user_id"`
	Email     string            `json:"email,omitempty" db:"email"`
	IPAddress string            `json:"ip_address" db:"ip_address"`
	UserAgent string            `json:"user_agent" db:"user_agent"`
	Success   bool              `json:"success" db:"success"`
	Reason    string            `json:"reason,omitempty" db:"reason"`
	Timestamp time.Time         `json:"timestamp" db:"timestamp"`

	// Additional context
	Metadata map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// IsValid checks if the security event has the minimum required fields.
func (se *SecurityEvent) IsValid() bool {
	return se.Type != "" && se.IPAddress != "" && !se.Timestamp.IsZero()
}

// Permission represents a specific action that can be performed.
type Permission string

const (
	PermissionReadUsers    Permission = "users:read"
	PermissionWriteUsers   Permission = "users:write"
	PermissionDeleteUsers  Permission = "users:delete"
	PermissionReadSessions Permission = "sessions:read"
	PermissionManageRoles  Permission = "roles:manage"
	PermissionViewAudit    Permission = "audit:view"
	PermissionSystemAdmin  Permission = "system:admin"
)

// Role represents a collection of permissions.
// Roles are immutable after creation.
type Role struct {
	Name        string       `json:"name" db:"name"`
	Description string       `json:"description" db:"description"`
	Permissions []Permission `json:"permissions" db:"permissions"`
	CreatedAt   time.Time    `json:"created_at" db:"created_at"`
	IsActive    bool         `json:"is_active" db:"is_active"`
}

// HasPermission checks if the role has a specific permission.
func (r *Role) HasPermission(permission Permission) bool {
	for _, p := range r.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// IsValid checks if the role has the minimum required fields.
func (r *Role) IsValid() bool {
	return r.Name != "" && len(r.Permissions) > 0 && r.IsActive
}

// UserRole represents the association between a user and a role.
type UserRole struct {
	UserID    string    `json:"user_id" db:"user_id"`
	RoleName  string    `json:"role_name" db:"role_name"`
	GrantedAt time.Time `json:"granted_at" db:"granted_at"`
	GrantedBy string    `json:"granted_by" db:"granted_by"`
	IsActive  bool      `json:"is_active" db:"is_active"`
}

// PasswordPolicy defines password requirements for user accounts.
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSpecial   bool `json:"require_special"`
	PreventCommon    bool `json:"prevent_common"`
	PreventUserInfo  bool `json:"prevent_user_info"`
}

// DefaultPasswordPolicy returns the default password policy with secure settings.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSpecial:   false,
		PreventCommon:    true,
		PreventUserInfo:  true,
	}
}

// IsValid checks if the password policy has valid settings.
func (pp *PasswordPolicy) IsValid() bool {
	return pp.MinLength >= 4 && pp.MinLength <= 128
}

// LoginDetails contains information about a login attempt for security notifications.
type LoginDetails struct {
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Location  string    `json:"location,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
}

// RateLimitConfig defines rate limiting rules for different operations.
type RateLimitConfig struct {
	LoginAttempts         int           `json:"login_attempts"`          // Per IP
	LoginWindow           time.Duration `json:"login_window"`            // Time window for login attempts
	RegisterAttempts      int           `json:"register_attempts"`       // Per IP
	RegisterWindow        time.Duration `json:"register_window"`         // Time window for register attempts
	PasswordResetAttempts int           `json:"password_reset_attempts"` // Per IP
	PasswordResetWindow   time.Duration `json:"password_reset_window"`   // Time window for password reset
	EmailVerifyAttempts   int           `json:"email_verify_attempts"`   // Per IP
	EmailVerifyWindow     time.Duration `json:"email_verify_window"`     // Time window for email verify
	APIRequestsPerHour    int           `json:"api_requests_per_hour"`   // Per authenticated user
}

// DefaultRateLimitConfig returns secure default rate limiting settings.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		LoginAttempts:         5,
		LoginWindow:           15 * time.Minute,
		RegisterAttempts:      3,
		RegisterWindow:        time.Hour,
		PasswordResetAttempts: 3,
		PasswordResetWindow:   time.Hour,
		EmailVerifyAttempts:   5,
		EmailVerifyWindow:     time.Hour,
		APIRequestsPerHour:    1000,
	}
}
