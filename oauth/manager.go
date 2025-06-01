// Package oauth provides OAuth management functionality
package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Manager handles OAuth operations
type Manager struct {
	db        *gorm.DB
	providers map[string]*ProviderConfig
}

// ProviderConfig holds OAuth provider configuration
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}

// OAuthState represents OAuth state for CSRF protection
type OAuthState struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	State     string    `gorm:"uniqueIndex;not null" json:"state"`
	Provider  string    `gorm:"not null" json:"provider"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// OAuthToken represents stored OAuth tokens
type OAuthToken struct {
	ID           uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	UserID       uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
	Provider     string     `gorm:"not null" json:"provider"`
	AccessToken  string     `gorm:"type:text;not null" json:"-"`
	RefreshToken string     `gorm:"type:text" json:"-"`
	ExpiresAt    *time.Time `json:"expires_at"`
	Scope        string     `json:"scope"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// NewManager creates a new OAuth manager
func NewManager(db *gorm.DB, providers map[string]*ProviderConfig) *Manager {
	if providers == nil {
		providers = make(map[string]*ProviderConfig)
	}

	return &Manager{
		db:        db,
		providers: providers,
	}
}

// AddProvider adds an OAuth provider
func (m *Manager) AddProvider(name string, config *ProviderConfig) {
	if m.providers == nil {
		m.providers = make(map[string]*ProviderConfig)
	}
	m.providers[name] = config
}

// GenerateState generates a secure state parameter for OAuth
func (m *Manager) GenerateState(provider string) (string, error) {
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", err
	}

	state := base64.URLEncoding.EncodeToString(stateBytes)

	// Store state in database
	oauthState := OAuthState{
		ID:        uuid.New(),
		State:     state,
		Provider:  provider,
		ExpiresAt: time.Now().Add(10 * time.Minute), // 10 minutes
		CreatedAt: time.Now(),
	}

	if err := m.db.Create(&oauthState).Error; err != nil {
		return "", err
	}

	return state, nil
}

// ValidateState validates an OAuth state parameter
func (m *Manager) ValidateState(state, provider string) bool {
	var oauthState OAuthState
	err := m.db.Where("state = ? AND provider = ? AND expires_at > ?",
		state, provider, time.Now()).First(&oauthState).Error

	if err != nil {
		return false
	}

	// Delete used state
	m.db.Delete(&oauthState)
	return true
}

// StoreToken stores an OAuth token
func (m *Manager) StoreToken(userID uuid.UUID, provider, accessToken, refreshToken string, expiresAt *time.Time, scope string) error {
	// Delete existing token for this user/provider
	m.db.Delete(&OAuthToken{}, "user_id = ? AND provider = ?", userID, provider)

	token := OAuthToken{
		ID:           uuid.New(),
		UserID:       userID,
		Provider:     provider,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		Scope:        scope,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return m.db.Create(&token).Error
}

// GetToken retrieves an OAuth token
func (m *Manager) GetToken(userID uuid.UUID, provider string) (*OAuthToken, error) {
	var token OAuthToken
	err := m.db.Where("user_id = ? AND provider = ?", userID, provider).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// RefreshToken refreshes an OAuth token
func (m *Manager) RefreshToken(userID uuid.UUID, provider string) (*OAuthToken, error) {
	token, err := m.GetToken(userID, provider)
	if err != nil {
		return nil, err
	}

	if token.RefreshToken == "" {
		return nil, gorm.ErrRecordNotFound
	}

	// Implement token refresh logic here
	// This would involve making an HTTP request to the provider's token endpoint
	// For now, this is a placeholder

	return token, nil
}

// DeleteToken deletes an OAuth token
func (m *Manager) DeleteToken(userID uuid.UUID, provider string) error {
	return m.db.Delete(&OAuthToken{}, "user_id = ? AND provider = ?", userID, provider).Error
}

// GetAuthURL returns the authorization URL for a provider
func (m *Manager) GetAuthURL(provider string) (string, error) {
	config, exists := m.providers[provider]
	if !exists {
		return "", gorm.ErrRecordNotFound
	}

	state, err := m.GenerateState(provider)
	if err != nil {
		return "", err
	}

	// Build auth URL
	authURL := config.AuthURL + "?client_id=" + config.ClientID +
		"&redirect_uri=" + config.RedirectURL +
		"&response_type=code" +
		"&state=" + state

	if len(config.Scopes) > 0 {
		authURL += "&scope=" + config.Scopes[0] // Simplified
	}

	return authURL, nil
}

// AuthHandler returns a handler for OAuth authorization
func (m *Manager) AuthHandler(provider string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authURL, err := m.GetAuthURL(provider)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to generate auth URL"})
			return
		}

		c.Redirect(302, authURL)
	}
}

// CallbackHandler returns a handler for OAuth callbacks
func (m *Manager) CallbackHandler(provider string) gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")

		if code == "" || state == "" {
			c.JSON(400, gin.H{"error": "Missing code or state parameter"})
			return
		}

		if !m.ValidateState(state, provider) {
			c.JSON(400, gin.H{"error": "Invalid state parameter"})
			return
		}

		// Exchange code for token
		// This would involve making an HTTP request to the provider's token endpoint
		// For now, this is a placeholder

		c.JSON(200, gin.H{"message": "OAuth callback successful"})
	}
}

// CleanupExpiredStates removes expired OAuth states
func (m *Manager) CleanupExpiredStates() error {
	return m.db.Delete(&OAuthState{}, "expires_at < ?", time.Now()).Error
}

// GetUserTokens returns all OAuth tokens for a user
func (m *Manager) GetUserTokens(userID uuid.UUID) ([]OAuthToken, error) {
	var tokens []OAuthToken
	err := m.db.Where("user_id = ?", userID).Find(&tokens).Error
	return tokens, err
}

// BeforeCreate sets the ID for new records
func (os *OAuthState) BeforeCreate(tx *gorm.DB) error {
	if os.ID == uuid.Nil {
		os.ID = uuid.New()
	}
	return nil
}

func (ot *OAuthToken) BeforeCreate(tx *gorm.DB) error {
	if ot.ID == uuid.Nil {
		ot.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for OAuthState
func (OAuthState) TableName() string {
	return "oauth_states"
}

// TableName returns the table name for OAuthToken
func (OAuthToken) TableName() string {
	return "oauth_tokens"
}
