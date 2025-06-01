package tokens

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// APIKey represents an API key for authentication
type APIKey struct {
	ID         uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
	Name       string     `gorm:"not null" json:"name"`
	Key        string     `gorm:"uniqueIndex;not null" json:"key"`
	IsActive   bool       `gorm:"default:true" json:"is_active"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// RefreshToken represents a refresh token
type RefreshToken struct {
	ID        uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
	Token     string     `gorm:"uniqueIndex;not null" json:"token"`
	IsUsed    bool       `gorm:"default:false" json:"is_used"`
	UsedAt    *time.Time `json:"used_at"`
	ExpiresAt time.Time  `gorm:"not null" json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// BeforeCreate sets the ID for new records
func (ak *APIKey) BeforeCreate(tx *gorm.DB) error {
	if ak.ID == uuid.Nil {
		ak.ID = uuid.New()
	}
	return nil
}

func (rt *RefreshToken) BeforeCreate(tx *gorm.DB) error {
	if rt.ID == uuid.Nil {
		rt.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for APIKey
func (APIKey) TableName() string {
	return "api_keys"
}

// TableName returns the table name for RefreshToken
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}
