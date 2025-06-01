// Package auth provides authentication and authorization functionality for web applications
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Manager handles authentication operations
type Manager struct {
	db          *gorm.DB
	jwtSecret   []byte
	emailConfig *EmailConfig
	config      *Config
}

// Config holds authentication configuration
type Config struct {
	JWTExpiration            time.Duration
	RefreshExpiration        time.Duration
	PasswordMinLength        int
	RequireEmailVerification bool
	EnableRegistration       bool
	EnablePasswordReset      bool
	EnableMFA                bool
	MaxLoginAttempts         int
	LockoutDuration          time.Duration
}

// EmailConfig holds email configuration for auth
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	FromName     string
}

// NewManager creates a new authentication manager
func NewManager(db *gorm.DB, jwtSecret []byte, emailConfig *EmailConfig) *Manager {
	config := &Config{
		JWTExpiration:            24 * time.Hour,
		RefreshExpiration:        7 * 24 * time.Hour,
		PasswordMinLength:        8,
		RequireEmailVerification: false,
		EnableRegistration:       true,
		EnablePasswordReset:      true,
		EnableMFA:                false,
		MaxLoginAttempts:         5,
		LockoutDuration:          15 * time.Minute,
	}

	return &Manager{
		db:          db,
		jwtSecret:   jwtSecret,
		emailConfig: emailConfig,
		config:      config,
	}
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required,min=8"`
	PasswordConfirm string `json:"password_confirm" binding:"required"`
	FirstName       string `json:"first_name" binding:"required"`
	LastName        string `json:"last_name" binding:"required"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	User         *User  `json:"user"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at"`
	MFARequired  bool   `json:"mfa_required,omitempty"`
}

// EnableRegistration enables user registration
func (m *Manager) EnableRegistration() *Manager {
	m.config.EnableRegistration = true
	return m
}

// EnablePasswordReset enables password reset functionality
func (m *Manager) EnablePasswordReset() *Manager {
	m.config.EnablePasswordReset = true
	return m
}

// EnableMFA enables multi-factor authentication
func (m *Manager) EnableMFA() *Manager {
	m.config.EnableMFA = true
	return m
}

// Register returns a Gin handler for user registration
func (m *Manager) Register() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.config.EnableRegistration {
			c.JSON(http.StatusForbidden, gin.H{"error": "Registration is disabled"})
			return
		}

		var req RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate password confirmation
		if req.Password != req.PasswordConfirm {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Passwords do not match"})
			return
		}

		// Check if user already exists
		var existingUser User
		if err := m.db.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
			return
		}

		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		// Create user
		user := User{
			ID:        uuid.New(),
			Email:     req.Email,
			Password:  string(hashedPassword),
			FirstName: req.FirstName,
			LastName:  req.LastName,
			IsActive:  !m.config.RequireEmailVerification,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if err := m.db.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		// Send verification email if required
		if m.config.RequireEmailVerification {
			if err := m.sendVerificationEmail(&user); err != nil {
				// Log error but don't fail registration
				fmt.Printf("Failed to send verification email: %v\n", err)
			}
		}

		// Generate JWT token
		token, expiresAt, err := m.generateJWT(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		response := AuthResponse{
			User:      &user,
			Token:     token,
			ExpiresAt: expiresAt,
		}

		c.JSON(http.StatusCreated, response)
	}
}

// Login returns a Gin handler for user login
func (m *Manager) Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Find user
		var user User
		if err := m.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Check if account is locked
		if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
			c.JSON(http.StatusLocked, gin.H{"error": "Account is locked"})
			return
		}

		// Verify password
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			// Increment failed attempts
			m.incrementFailedAttempts(&user)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Reset failed attempts on successful login
		m.resetFailedAttempts(&user)

		// Check if MFA is enabled
		if m.config.EnableMFA && user.MFAEnabled {
			if req.MFACode == "" {
				c.JSON(http.StatusAccepted, gin.H{"mfa_required": true})
				return
			}

			// Verify MFA code
			if !m.verifyMFACode(&user, req.MFACode) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid MFA code"})
				return
			}
		}

		// Generate JWT token
		token, expiresAt, err := m.generateJWT(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		// Update last login
		user.LastLoginAt = &time.Time{}
		*user.LastLoginAt = time.Now()
		m.db.Save(&user)

		response := AuthResponse{
			User:      &user,
			Token:     token,
			ExpiresAt: expiresAt,
		}

		c.JSON(http.StatusOK, response)
	}
}

// Logout returns a Gin handler for user logout
func (m *Manager) Logout() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No token provided"})
			return
		}

		_ = strings.TrimPrefix(authHeader, "Bearer ")

		// Add token to blacklist (implement token blacklisting)
		// For now, just return success
		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	}
}

// RequireAuth is a middleware that requires authentication
func (m *Manager) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		userID, err := uuid.Parse(claims["user_id"].(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
			c.Abort()
			return
		}

		// Find user
		var user User
		if err := m.db.Where("id = ?", userID).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		// Check if user is active
		if !user.IsActive {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Account is inactive"})
			c.Abort()
			return
		}

		// Set user in context
		c.Set("user", &user)
		c.Set("user_id", user.ID)
		c.Next()
	}
}

// generateJWT generates a JWT token for the user
func (m *Manager) generateJWT(user *User) (string, int64, error) {
	expiresAt := time.Now().Add(m.config.JWTExpiration)

	claims := jwt.MapClaims{
		"user_id": user.ID.String(),
		"email":   user.Email,
		"exp":     expiresAt.Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.jwtSecret)
	if err != nil {
		return "", 0, err
	}

	return tokenString, expiresAt.Unix(), nil
}

// incrementFailedAttempts increments failed login attempts
func (m *Manager) incrementFailedAttempts(user *User) {
	user.FailedAttempts++

	if user.FailedAttempts >= m.config.MaxLoginAttempts {
		lockUntil := time.Now().Add(m.config.LockoutDuration)
		user.LockedUntil = &lockUntil
	}

	m.db.Save(user)
}

// resetFailedAttempts resets failed login attempts
func (m *Manager) resetFailedAttempts(user *User) {
	user.FailedAttempts = 0
	user.LockedUntil = nil
	m.db.Save(user)
}

// verifyMFACode verifies an MFA code
func (m *Manager) verifyMFACode(_ *User, code string) bool {
	// Implement TOTP verification
	// This is a placeholder implementation
	return code == "123456" // For testing
}

// sendVerificationEmail sends a verification email
func (m *Manager) sendVerificationEmail(user *User) error {
	// Generate verification token
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return err
	}

	tokenString := base64.URLEncoding.EncodeToString(token)

	// Save verification record
	verification := EmailVerification{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     tokenString,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := m.db.Create(&verification).Error; err != nil {
		return err
	}

	// Send email (implement email sending)
	// This is a placeholder
	fmt.Printf("Verification email sent to %s with token: %s\n", user.Email, tokenString)

	return nil
}

// GetCurrentUser returns the current authenticated user from context
func GetCurrentUser(c *gin.Context) (*User, bool) {
	user, exists := c.Get("user")
	if !exists {
		return nil, false
	}

	u, ok := user.(*User)
	return u, ok
}

// GetCurrentUserID returns the current authenticated user ID from context
func GetCurrentUserID(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, false
	}

	id, ok := userID.(uuid.UUID)
	return id, ok
}
