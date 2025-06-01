package auth

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID              uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	Email           string         `gorm:"uniqueIndex;not null" json:"email"`
	Password        string         `gorm:"not null" json:"-"`
	FirstName       string         `gorm:"not null" json:"first_name"`
	LastName        string         `gorm:"not null" json:"last_name"`
	IsActive        bool           `gorm:"default:true" json:"is_active"`
	IsEmailVerified bool           `gorm:"default:false" json:"is_email_verified"`
	MFAEnabled      bool           `gorm:"default:false" json:"mfa_enabled"`
	FailedAttempts  int            `gorm:"default:0" json:"-"`
	LockedUntil     *time.Time     `json:"-"`
	LastLoginAt     *time.Time     `json:"last_login_at"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

// PasswordReset represents a password reset token
type PasswordReset struct {
	ID        uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
	User      User       `gorm:"foreignKey:UserID" json:"-"`
	Token     string     `gorm:"uniqueIndex;not null" json:"-"`
	ExpiresAt time.Time  `gorm:"not null" json:"-"`
	UsedAt    *time.Time `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
}

// EmailVerification represents an email verification token
type EmailVerification struct {
	ID         uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
	User       User       `gorm:"foreignKey:UserID" json:"-"`
	Token      string     `gorm:"uniqueIndex;not null" json:"-"`
	ExpiresAt  time.Time  `gorm:"not null" json:"-"`
	VerifiedAt *time.Time `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
}

// MFASecret represents an MFA secret for a user
type MFASecret struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex" json:"user_id"`
	User      User      `gorm:"foreignKey:UserID" json:"-"`
	Secret    string    `gorm:"not null" json:"-"`
	IsActive  bool      `gorm:"default:false" json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BackupCode represents a backup code for MFA
type BackupCode struct {
	ID        uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
	User      User       `gorm:"foreignKey:UserID" json:"-"`
	Code      string     `gorm:"not null" json:"-"`
	IsUsed    bool       `gorm:"default:false" json:"is_used"`
	UsedAt    *time.Time `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
}

// BeforeCreate sets the ID for new records
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

func (pr *PasswordReset) BeforeCreate(tx *gorm.DB) error {
	if pr.ID == uuid.Nil {
		pr.ID = uuid.New()
	}
	return nil
}

func (ev *EmailVerification) BeforeCreate(tx *gorm.DB) error {
	if ev.ID == uuid.Nil {
		ev.ID = uuid.New()
	}
	return nil
}

func (ms *MFASecret) BeforeCreate(tx *gorm.DB) error {
	if ms.ID == uuid.Nil {
		ms.ID = uuid.New()
	}
	return nil
}

func (bc *BackupCode) BeforeCreate(tx *gorm.DB) error {
	if bc.ID == uuid.Nil {
		bc.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for User
func (User) TableName() string {
	return "users"
}

// TableName returns the table name for PasswordReset
func (PasswordReset) TableName() string {
	return "password_resets"
}

// TableName returns the table name for EmailVerification
func (EmailVerification) TableName() string {
	return "email_verifications"
}

// TableName returns the table name for MFASecret
func (MFASecret) TableName() string {
	return "mfa_secrets"
}

// TableName returns the table name for BackupCode
func (BackupCode) TableName() string {
	return "backup_codes"
}
