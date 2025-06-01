package tokens

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Manager handles token operations
type Manager struct {
	db        *gorm.DB
	jwtSecret []byte
}

// NewManager creates a new token manager
func NewManager(db *gorm.DB, jwtSecret []byte) *Manager {
	return &Manager{
		db:        db,
		jwtSecret: jwtSecret,
	}
}

// GenerateAPIKey generates a new API key for a user
func (m *Manager) GenerateAPIKey(userID uuid.UUID, name string, expiresAt *time.Time) (*APIKey, error) {
	// Generate random key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}

	key := base64.URLEncoding.EncodeToString(keyBytes)

	apiKey := &APIKey{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      name,
		Key:       key,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := m.db.Create(apiKey).Error; err != nil {
		return nil, err
	}

	return apiKey, nil
}

// ValidateAPIKey validates an API key
func (m *Manager) ValidateAPIKey(key string) (*APIKey, error) {
	var apiKey APIKey
	query := m.db.Where("key = ? AND is_active = ?", key, true)

	// Check expiration if set
	query = query.Where("expires_at IS NULL OR expires_at > ?", time.Now())

	if err := query.First(&apiKey).Error; err != nil {
		return nil, err
	}

	// Update last used
	apiKey.LastUsedAt = &time.Time{}
	*apiKey.LastUsedAt = time.Now()
	m.db.Save(&apiKey)

	return &apiKey, nil
}

// RevokeAPIKey revokes an API key
func (m *Manager) RevokeAPIKey(keyID uuid.UUID) error {
	return m.db.Model(&APIKey{}).
		Where("id = ?", keyID).
		Update("is_active", false).Error
}

// GenerateRefreshToken generates a refresh token
func (m *Manager) GenerateRefreshToken(userID uuid.UUID) (*RefreshToken, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}

	token := base64.URLEncoding.EncodeToString(tokenBytes)

	refreshToken := &RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := m.db.Create(refreshToken).Error; err != nil {
		return nil, err
	}

	return refreshToken, nil
}

// ValidateRefreshToken validates a refresh token
func (m *Manager) ValidateRefreshToken(token string) (*RefreshToken, error) {
	var refreshToken RefreshToken
	if err := m.db.Where("token = ? AND expires_at > ? AND is_used = ?",
		token, time.Now(), false).First(&refreshToken).Error; err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

// UseRefreshToken marks a refresh token as used
func (m *Manager) UseRefreshToken(tokenID uuid.UUID) error {
	return m.db.Model(&RefreshToken{}).
		Where("id = ?", tokenID).
		Updates(map[string]interface{}{
			"is_used": true,
			"used_at": time.Now(),
		}).Error
}

// GenerateJWT generates a JWT token
func (m *Manager) GenerateJWT(userID uuid.UUID, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID.String(),
		"exp":     time.Now().Add(duration).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// ValidateJWT validates a JWT token
func (m *Manager) ValidateJWT(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.jwtSecret, nil
	})
}

// APIKeyMiddleware provides API key authentication middleware
func (m *Manager) APIKeyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(401, gin.H{"error": "API key required"})
			c.Abort()
			return
		}

		key, err := m.ValidateAPIKey(apiKey)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}

		c.Set("api_key", key)
		c.Set("user_id", key.UserID)
		c.Next()
	}
}

// GetUserAPIKeys returns all API keys for a user
func (m *Manager) GetUserAPIKeys(userID uuid.UUID) ([]APIKey, error) {
	var keys []APIKey
	err := m.db.Where("user_id = ?", userID).Find(&keys).Error
	return keys, err
}

// CleanupExpiredTokens removes expired tokens
func (m *Manager) CleanupExpiredTokens() error {
	// Clean up expired API keys
	if err := m.db.Delete(&APIKey{}, "expires_at IS NOT NULL AND expires_at < ?", time.Now()).Error; err != nil {
		return err
	}

	// Clean up expired refresh tokens
	return m.db.Delete(&RefreshToken{}, "expires_at < ?", time.Now()).Error
}
