// Package sessions provides session management functionality
package sessions

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"gorm.io/gorm"
)

// Manager handles session management
type Manager struct {
	db           *gorm.DB
	secureCookie *securecookie.SecureCookie
	config       *Config
}

// Config holds session configuration
type Config struct {
	CookieName string
	MaxAge     time.Duration
	Secure     bool
	HTTPOnly   bool
	SameSite   string
	Domain     string
	Path       string
}

// Session represents a user session
type Session struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null" json:"user_id"`
	Data      string    `gorm:"type:text" json:"-"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewManager creates a new session manager
func NewManager(db *gorm.DB, secret []byte) *Manager {
	config := &Config{
		CookieName: "guardian_session",
		MaxAge:     24 * time.Hour,
		Secure:     false, // Set to true in production with HTTPS
		HTTPOnly:   true,
		SameSite:   "Lax",
		Path:       "/",
	}

	return &Manager{
		db:           db,
		secureCookie: securecookie.New(secret, nil),
		config:       config,
	}
}

// SessionData represents session data
type SessionData map[string]interface{}

// CreateSession creates a new session
func (m *Manager) CreateSession(userID uuid.UUID, data SessionData) (*Session, error) {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:        uuid.New(),
		UserID:    userID,
		Data:      string(dataJSON),
		ExpiresAt: time.Now().Add(m.config.MaxAge),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := m.db.Create(session).Error; err != nil {
		return nil, err
	}

	return session, nil
}

// GetSession retrieves a session by ID
func (m *Manager) GetSession(sessionID uuid.UUID) (*Session, error) {
	var session Session
	if err := m.db.Where("id = ? AND expires_at > ?", sessionID, time.Now()).First(&session).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

// UpdateSession updates session data
func (m *Manager) UpdateSession(sessionID uuid.UUID, data SessionData) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return m.db.Model(&Session{}).
		Where("id = ?", sessionID).
		Updates(map[string]interface{}{
			"data":       string(dataJSON),
			"updated_at": time.Now(),
		}).Error
}

// DeleteSession deletes a session
func (m *Manager) DeleteSession(sessionID uuid.UUID) error {
	return m.db.Delete(&Session{}, "id = ?", sessionID).Error
}

// CleanupExpiredSessions removes expired sessions
func (m *Manager) CleanupExpiredSessions() error {
	return m.db.Delete(&Session{}, "expires_at < ?", time.Now()).Error
}

// SessionMiddleware provides session middleware for Gin
func (m *Manager) SessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session cookie
		cookie, err := c.Cookie(m.config.CookieName)
		if err != nil {
			c.Next()
			return
		}

		// Decode session ID
		var sessionID string
		if err := m.secureCookie.Decode(m.config.CookieName, cookie, &sessionID); err != nil {
			c.Next()
			return
		}

		// Parse session ID
		id, err := uuid.Parse(sessionID)
		if err != nil {
			c.Next()
			return
		}

		// Get session
		session, err := m.GetSession(id)
		if err != nil {
			c.Next()
			return
		}

		// Parse session data
		var data SessionData
		if err := json.Unmarshal([]byte(session.Data), &data); err != nil {
			c.Next()
			return
		}

		// Set session in context
		c.Set("session", session)
		c.Set("session_data", data)
		c.Next()
	}
}

// BeforeCreate sets the ID for new sessions
func (s *Session) BeforeCreate(_ *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for Session
func (Session) TableName() string {
	return "sessions"
}
