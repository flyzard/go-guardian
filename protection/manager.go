// Package protection provides security protection features such as rate limiting, IP blocking, and account lockout.
package protection

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Manager handles security protection features
type Manager struct {
	db           *gorm.DB
	rateLimiters map[string]*RateLimiter
	blockedIPs   map[string]time.Time
	allowedIPs   map[string]bool
	mutex        sync.RWMutex
	config       *Config
}

// Config holds protection configuration
type Config struct {
	MaxLoginAttempts     int
	LockoutDuration      time.Duration
	RateLimitWindow      time.Duration
	RateLimitRequests    int
	EnableIPBlocking     bool
	EnableRateLimit      bool
	EnableAccountLockout bool
}

// RateLimiter tracks request rates
type RateLimiter struct {
	requests []time.Time
	mutex    sync.Mutex
}

// LoginAttempt represents a login attempt
type LoginAttempt struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	IP        string    `gorm:"not null" json:"ip"`
	UserAgent string    `gorm:"type:text" json:"user_agent"`
	Email     string    `json:"email"`
	Success   bool      `gorm:"default:false" json:"success"`
	CreatedAt time.Time `json:"created_at"`
}

// BlockedIP represents a blocked IP address
type BlockedIP struct {
	ID        uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	IP        string     `gorm:"uniqueIndex;not null" json:"ip"`
	Reason    string     `gorm:"type:text" json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
}

// NewManager creates a new protection manager
func NewManager(db *gorm.DB) *Manager {
	config := &Config{
		MaxLoginAttempts:     5,
		LockoutDuration:      15 * time.Minute,
		RateLimitWindow:      time.Minute,
		RateLimitRequests:    60,
		EnableIPBlocking:     true,
		EnableRateLimit:      true,
		EnableAccountLockout: true,
	}

	return &Manager{
		db:           db,
		rateLimiters: make(map[string]*RateLimiter),
		blockedIPs:   make(map[string]time.Time),
		allowedIPs:   make(map[string]bool),
		config:       config,
	}
}

// RecordLoginAttempt records a login attempt
func (m *Manager) RecordLoginAttempt(c *gin.Context, email string, success bool) {
	attempt := LoginAttempt{
		ID:        uuid.New(),
		IP:        c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		Email:     email,
		Success:   success,
		CreatedAt: time.Now(),
	}

	m.db.Create(&attempt)

	// Check for brute force attempts
	if !success {
		m.checkBruteForce(c.ClientIP(), email)
	}
}

// checkBruteForce checks for brute force attempts
func (m *Manager) checkBruteForce(ip, _ string) {
	if !m.config.EnableAccountLockout {
		return
	}

	// Count failed attempts in the last lockout duration
	var count int64
	m.db.Model(&LoginAttempt{}).
		Where("ip = ? AND success = ? AND created_at > ?",
			ip, false, time.Now().Add(-m.config.LockoutDuration)).
		Count(&count)

	if count >= int64(m.config.MaxLoginAttempts) {
		m.blockIP(ip, "Brute force detection", m.config.LockoutDuration)
	}
}

// blockIP blocks an IP address
func (m *Manager) blockIP(ip, reason string, duration time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	expiresAt := time.Now().Add(duration)
	m.blockedIPs[ip] = expiresAt

	// Store in database
	blockedIP := BlockedIP{
		ID:        uuid.New(),
		IP:        ip,
		Reason:    reason,
		ExpiresAt: &expiresAt,
		CreatedAt: time.Now(),
	}

	m.db.Create(&blockedIP)
}

// IsIPBlocked checks if an IP is blocked
func (m *Manager) IsIPBlocked(ip string) bool {
	if !m.config.EnableIPBlocking {
		return false
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if expiresAt, exists := m.blockedIPs[ip]; exists {
		if time.Now().Before(expiresAt) {
			return true
		}
		// Remove expired block
		delete(m.blockedIPs, ip)
	}

	return false
}

// AllowIP adds an IP to the allowlist
func (m *Manager) AllowIP(ip string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.allowedIPs[ip] = true
}

// IsIPAllowed checks if an IP is in the allowlist
func (m *Manager) IsIPAllowed(ip string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.allowedIPs[ip]
}

// RateLimitMiddleware provides rate limiting middleware
func (m *Manager) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.config.EnableRateLimit {
			c.Next()
			return
		}

		ip := c.ClientIP()

		// Skip rate limiting for allowed IPs
		if m.IsIPAllowed(ip) {
			c.Next()
			return
		}

		if m.isRateLimited(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// IPBlockingMiddleware provides IP blocking middleware
func (m *Manager) IPBlockingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		// Skip blocking for allowed IPs
		if m.IsIPAllowed(ip) {
			c.Next()
			return
		}

		if m.IsIPBlocked(ip) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "IP address is blocked",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// isRateLimited checks if an IP is rate limited
func (m *Manager) isRateLimited(ip string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	limiter, exists := m.rateLimiters[ip]
	if !exists {
		limiter = &RateLimiter{
			requests: make([]time.Time, 0),
		}
		m.rateLimiters[ip] = limiter
	}

	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()

	now := time.Now()
	windowStart := now.Add(-m.config.RateLimitWindow)

	// Remove old requests
	validRequests := make([]time.Time, 0)
	for _, req := range limiter.requests {
		if req.After(windowStart) {
			validRequests = append(validRequests, req)
		}
	}
	limiter.requests = validRequests

	// Check if limit exceeded
	if len(limiter.requests) >= m.config.RateLimitRequests {
		return true
	}

	// Add current request
	limiter.requests = append(limiter.requests, now)
	return false
}

// UnblockIP removes an IP from the blocklist
func (m *Manager) UnblockIP(ip string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.blockedIPs, ip)

	// Remove from database
	m.db.Delete(&BlockedIP{}, "ip = ?", ip)
}

// GetFailedAttempts returns failed login attempts for an IP or email
func (m *Manager) GetFailedAttempts(ip, email string, since time.Time) ([]LoginAttempt, error) {
	var attempts []LoginAttempt
	query := m.db.Where("success = ? AND created_at > ?", false, since)

	if ip != "" {
		query = query.Where("ip = ?", ip)
	}
	if email != "" {
		query = query.Where("email = ?", email)
	}

	err := query.Order("created_at DESC").Find(&attempts).Error
	return attempts, err
}

// CleanupOldAttempts removes old login attempts
func (m *Manager) CleanupOldAttempts() error {
	cutoff := time.Now().Add(-24 * time.Hour * 30) // Keep for 30 days
	return m.db.Delete(&LoginAttempt{}, "created_at < ?", cutoff).Error
}

// CleanupExpiredBlocks removes expired IP blocks
func (m *Manager) CleanupExpiredBlocks() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Clean up in-memory blocks
	now := time.Now()
	for ip, expiresAt := range m.blockedIPs {
		if now.After(expiresAt) {
			delete(m.blockedIPs, ip)
		}
	}

	// Clean up database blocks
	return m.db.Delete(&BlockedIP{}, "expires_at IS NOT NULL AND expires_at < ?", now).Error
}

// BeforeCreate sets the ID for new records
func (la *LoginAttempt) BeforeCreate(_ *gorm.DB) error {
	if la.ID == uuid.Nil {
		la.ID = uuid.New()
	}
	return nil
}

// BeforeCreate sets the ID for new records
func (bi *BlockedIP) BeforeCreate(_ *gorm.DB) error {
	if bi.ID == uuid.Nil {
		bi.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for LoginAttempt
func (LoginAttempt) TableName() string {
	return "login_attempts"
}

// TableName returns the table name for BlockedIP
func (BlockedIP) TableName() string {
	return "blocked_ips"
}
