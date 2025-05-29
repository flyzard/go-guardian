// Package guardian provides interface definitions for the go-guardian security library.
// These interfaces define contracts for external dependencies and enable dependency injection,
// testing, and pluggable implementations.
package guardian

import (
	"context"
	"time"

	"github.com/flyzard/go-guardian/types"
)

// Store defines the interface for persistent storage operations.
// All methods are context-aware for timeout and cancellation support.
// Implementations should be thread-safe and handle concurrent access properly.
type Store interface {
	// User management operations
	CreateUser(ctx context.Context, user *types.User) error
	GetUser(ctx context.Context, id string) (*types.User, error)
	GetUserByEmail(ctx context.Context, email string) (*types.User, error)
	UpdateUser(ctx context.Context, user *types.User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, limit, offset int) ([]*types.User, error)

	// Session management operations
	CreateSession(ctx context.Context, session *types.Session) error
	GetSession(ctx context.Context, token string) (*types.Session, error)
	GetSessionsByUser(ctx context.Context, userID string) ([]*types.Session, error)
	UpdateSession(ctx context.Context, session *types.Session) error
	DeleteSession(ctx context.Context, token string) error
	DeleteSessionsByUser(ctx context.Context, userID string) error
	DeleteExpiredSessions(ctx context.Context) (int64, error)

	// Token management operations
	CreateToken(ctx context.Context, token *types.Token) error
	GetToken(ctx context.Context, value string) (*types.Token, error)
	GetTokensByUser(ctx context.Context, userID string, tokenType types.TokenType) ([]*types.Token, error)
	UpdateToken(ctx context.Context, token *types.Token) error
	DeleteToken(ctx context.Context, value string) error
	DeleteTokensByUser(ctx context.Context, userID string) error
	DeleteExpiredTokens(ctx context.Context) (int64, error)

	// Role and permission management
	CreateRole(ctx context.Context, role *types.Role) error
	GetRole(ctx context.Context, name string) (*types.Role, error)
	UpdateRole(ctx context.Context, role *types.Role) error
	DeleteRole(ctx context.Context, name string) error
	ListRoles(ctx context.Context) ([]*types.Role, error)

	AssignRoleToUser(ctx context.Context, userID, roleName string) error
	RemoveRoleFromUser(ctx context.Context, userID, roleName string) error
	GetUserRoles(ctx context.Context, userID string) ([]*types.Role, error)

	// Security event logging
	LogSecurityEvent(ctx context.Context, event *types.SecurityEvent) error
	GetSecurityEvents(ctx context.Context, userID string, eventType types.SecurityEventType, limit int) ([]*types.SecurityEvent, error)
	CleanupOldEvents(ctx context.Context, olderThan time.Time) (int64, error)

	// Rate limiting operations
	GetRateLimit(ctx context.Context, key string) (*RateLimitInfo, error)
	IncrementRateLimit(ctx context.Context, key string, window time.Duration) (*RateLimitInfo, error)
	ResetRateLimit(ctx context.Context, key string) error

	// Utility operations
	Ping(ctx context.Context) error
	Close() error
	Stats() StoreStats
}

// RateLimitInfo contains rate limiting information for a specific key.
type RateLimitInfo struct {
	Key       string        `json:"key"`
	Count     int64         `json:"count"`
	Limit     int64         `json:"limit"`
	Window    time.Duration `json:"window"`
	ResetTime time.Time     `json:"reset_time"`
	Remaining int64         `json:"remaining"`
}

// IsLimitExceeded returns true if the rate limit has been exceeded.
func (r *RateLimitInfo) IsLimitExceeded() bool {
	return r.Count >= r.Limit
}

// StoreStats provides statistics about the store performance and usage.
type StoreStats struct {
	TotalUsers     int64         `json:"total_users"`
	ActiveSessions int64         `json:"active_sessions"`
	TotalTokens    int64         `json:"total_tokens"`
	TotalEvents    int64         `json:"total_events"`
	Uptime         time.Duration `json:"uptime"`
	LastBackup     *time.Time    `json:"last_backup,omitempty"`
}

// Mailer defines the interface for sending emails.
// All methods are context-aware and should support templates and localization.
type Mailer interface {
	// Send a simple email with text content
	SendText(ctx context.Context, to, subject, body string) error

	// Send an HTML email
	SendHTML(ctx context.Context, to, subject, htmlBody string) error

	// Send using a template with data
	SendTemplate(ctx context.Context, template string, to string, data interface{}) error

	// Send to multiple recipients
	SendBulk(ctx context.Context, template string, recipients []EmailRecipient) error

	// Send with attachments
	SendWithAttachments(ctx context.Context, email *Email) error

	// Utility methods
	ValidateEmail(email string) error
	GetTemplates() []string
	TestConnection(ctx context.Context) error
}

// EmailRecipient represents an email recipient with personalized data.
type EmailRecipient struct {
	Email string                 `json:"email"`
	Name  string                 `json:"name,omitempty"`
	Data  map[string]interface{} `json:"data,omitempty"`
}

// Email represents a complete email message with all options.
type Email struct {
	From        string                 `json:"from,omitempty"`
	To          []string               `json:"to"`
	CC          []string               `json:"cc,omitempty"`
	BCC         []string               `json:"bcc,omitempty"`
	Subject     string                 `json:"subject"`
	TextBody    string                 `json:"text_body,omitempty"`
	HTMLBody    string                 `json:"html_body,omitempty"`
	Template    string                 `json:"template,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Attachments []EmailAttachment      `json:"attachments,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Priority    EmailPriority          `json:"priority,omitempty"`
}

// EmailAttachment represents a file attachment for emails.
type EmailAttachment struct {
	Filename    string `json:"filename"`
	Content     []byte `json:"content"`
	ContentType string `json:"content_type"`
	Inline      bool   `json:"inline,omitempty"`
}

// EmailPriority defines the priority level for emails.
type EmailPriority string

// EmailPriority constants represent different email priority levels.
const (
	EmailPriorityLow    EmailPriority = "low"
	EmailPriorityNormal EmailPriority = "normal"
	EmailPriorityHigh   EmailPriority = "high"
)

// TokenGenerator defines the interface for generating secure tokens.
// Implementations should use cryptographically secure random generators.
type TokenGenerator interface {
	// Generate a random token of specified length and type
	GenerateToken(ctx context.Context, length int, tokenType TokenFormat) (string, error)

	// Generate a JWT token with claims
	GenerateJWT(ctx context.Context, claims map[string]interface{}, expiresIn time.Duration) (string, error)

	// Validate and parse a JWT token
	ValidateJWT(ctx context.Context, token string) (map[string]interface{}, error)

	// Generate a cryptographically secure random string
	GenerateSecureRandom(ctx context.Context, length int) ([]byte, error)

	// Generate tokens for specific purposes
	GenerateSessionToken(ctx context.Context) (string, error)
	GenerateResetToken(ctx context.Context) (string, error)
	GenerateEmailVerificationToken(ctx context.Context) (string, error)
	GenerateAPIKey(ctx context.Context) (string, error)
	GenerateTwoFactorSecret(ctx context.Context) (string, error)

	// Utility methods
	ValidateTokenFormat(token string, format TokenFormat) error
	GetTokenEntropy(length int, format TokenFormat) float64
}

// TokenFormat defines the format for generated tokens.
type TokenFormat string

// TokenFormat constants represent different token formats.
const (
	TokenFormatAlphanumeric TokenFormat = "alphanumeric" // A-Z, a-z, 0-9
	TokenFormatHex          TokenFormat = "hex"          // 0-9, a-f
	TokenFormatBase64       TokenFormat = "base64"       // Base64 URL safe
	TokenFormatBase32       TokenFormat = "base32"       // Base32 encoding
	TokenFormatNumeric      TokenFormat = "numeric"      // 0-9 only
	TokenFormatAlpha        TokenFormat = "alpha"        // A-Z, a-z only
)

// Hasher defines the interface for password hashing operations.
// Implementations should use secure, slow hashing algorithms like bcrypt, scrypt, or Argon2.
type Hasher interface {
	// Hash a password with default cost
	Hash(ctx context.Context, password string) (string, error)

	// Hash a password with custom cost
	HashWithCost(ctx context.Context, password string, cost int) (string, error)

	// Verify a password against a hash
	Verify(ctx context.Context, password, hash string) error

	// Check if a hash needs rehashing (due to cost changes)
	NeedsRehash(hash string, cost int) bool

	// Get the cost factor from a hash
	GetCost(hash string) (int, error)

	// Generate a random salt
	GenerateSalt(ctx context.Context) ([]byte, error)
}

// Validator defines the interface for data validation operations.
// Implementations should provide comprehensive validation for security-sensitive data.
type Validator interface {
	// Validate user input
	ValidateUser(ctx context.Context, user *types.User) error
	ValidateEmail(ctx context.Context, email string) error
	ValidatePassword(ctx context.Context, password string, policy *types.PasswordPolicy) error
	ValidateRole(ctx context.Context, role *types.Role) error
	ValidatePermission(ctx context.Context, permission *types.Permission) error

	// Validate tokens and sessions
	ValidateSession(ctx context.Context, session *types.Session) error
	ValidateToken(ctx context.Context, token *types.Token) error

	// Security validations
	ValidateIPAddress(ctx context.Context, ip string) error
	ValidateUserAgent(ctx context.Context, userAgent string) error
	ValidateDeviceFingerprint(ctx context.Context, fingerprint string) error

	// Custom validation rules
	AddRule(name string, rule ValidationRule) error
	RemoveRule(name string) error
	GetRules() map[string]ValidationRule
}

// ValidationRule defines a custom validation rule.
type ValidationRule interface {
	Validate(ctx context.Context, value interface{}) error
	Name() string
	Description() string
}

// RateLimiter defines the interface for rate limiting operations.
// Implementations should be distributed-system aware for horizontal scaling.
type RateLimiter interface {
	// Check if an action is allowed under rate limiting rules
	IsAllowed(ctx context.Context, key string, limit int64, window time.Duration) (bool, *RateLimitInfo, error)

	// Allow an action and increment the counter
	Allow(ctx context.Context, key string, limit int64, window time.Duration) (*RateLimitInfo, error)

	// Reset rate limit for a specific key
	Reset(ctx context.Context, key string) error

	// Get current rate limit status
	Status(ctx context.Context, key string) (*RateLimitInfo, error)

	// Clean up expired rate limit entries
	Cleanup(ctx context.Context) error

	// Batch operations for efficiency
	BatchAllow(ctx context.Context, keys []string, limit int64, window time.Duration) (map[string]*RateLimitInfo, error)
	BatchReset(ctx context.Context, keys []string) error
}

// Logger defines the interface for structured logging operations.
// Implementations should support different log levels and structured data.
type Logger interface {
	// Standard log levels
	Debug(ctx context.Context, msg string, fields ...LogField)
	Info(ctx context.Context, msg string, fields ...LogField)
	Warn(ctx context.Context, msg string, fields ...LogField)
	Error(ctx context.Context, msg string, fields ...LogField)
	Fatal(ctx context.Context, msg string, fields ...LogField)

	// Security-specific logging
	LogSecurityEvent(ctx context.Context, event *types.SecurityEvent, fields ...LogField)
	LogAuthAttempt(ctx context.Context, userID, email, ip string, success bool, fields ...LogField)
	LogPermissionCheck(ctx context.Context, userID, resource, action string, allowed bool, fields ...LogField)

	// Structured logging with context
	WithFields(fields ...LogField) Logger
	WithUser(userID string) Logger
	WithRequest(requestID string) Logger

	// Log level management
	SetLevel(level LogLevel)
	GetLevel() LogLevel
}

// LogField represents a structured log field.
type LogField struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

// LogLevel defines the logging level.
type LogLevel string

// LogLevel constants represent different logging levels.
const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

// Encryptor defines the interface for encryption and decryption operations.
// Implementations should use strong encryption algorithms and proper key management.
type Encryptor interface {
	// Symmetric encryption
	Encrypt(ctx context.Context, plaintext []byte, key []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte, key []byte) ([]byte, error)

	// String encryption (base64 encoded)
	EncryptString(ctx context.Context, plaintext string, key []byte) (string, error)
	DecryptString(ctx context.Context, ciphertext string, key []byte) (string, error)

	// Key derivation
	DeriveKey(ctx context.Context, password, salt []byte, keyLength int) ([]byte, error)
	GenerateKey(ctx context.Context, length int) ([]byte, error)
	GenerateSalt(ctx context.Context) ([]byte, error)

	// Digital signatures
	Sign(ctx context.Context, data []byte, privateKey []byte) ([]byte, error)
	Verify(ctx context.Context, data, signature, publicKey []byte) error

	// Key pair generation
	GenerateKeyPair(ctx context.Context) (privateKey, publicKey []byte, err error)
}

// MetricsCollector defines the interface for collecting performance and security metrics.
// Implementations should support various metric types and export formats.
type MetricsCollector interface {
	// Counter metrics
	IncrementCounter(name string, labels map[string]string)
	IncrementCounterBy(name string, value float64, labels map[string]string)

	// Gauge metrics
	SetGauge(name string, value float64, labels map[string]string)
	IncrementGauge(name string, labels map[string]string)
	DecrementGauge(name string, labels map[string]string)

	// Histogram metrics
	RecordHistogram(name string, value float64, labels map[string]string)
	RecordDuration(name string, duration time.Duration, labels map[string]string)

	// Security metrics
	RecordAuthAttempt(success bool, method string, labels map[string]string)
	RecordPermissionCheck(allowed bool, resource string, labels map[string]string)
	RecordRateLimitHit(key string, labels map[string]string)
	RecordSecurityEvent(eventType types.SecurityEventType, labels map[string]string)

	// System metrics
	RecordActiveUsers(count int64)
	RecordActiveSessions(count int64)
	RecordDatabaseConnections(count int64)
	RecordResponseTime(endpoint string, duration time.Duration)

	// Export and collection
	GetMetrics() map[string]interface{}
	Reset()
	Export(format string) ([]byte, error)
}

// CacheProvider defines the interface for caching operations.
// Implementations should support TTL, eviction policies, and be thread-safe.
type CacheProvider interface {
	// Basic cache operations
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)

	// Batch operations
	GetMulti(ctx context.Context, keys []string) (map[string][]byte, error)
	SetMulti(ctx context.Context, items map[string][]byte, ttl time.Duration) error
	DeleteMulti(ctx context.Context, keys []string) error

	// Pattern operations
	DeletePattern(ctx context.Context, pattern string) (int64, error)
	Keys(ctx context.Context, pattern string) ([]string, error)

	// TTL operations
	SetTTL(ctx context.Context, key string, ttl time.Duration) error
	GetTTL(ctx context.Context, key string) (time.Duration, error)

	// Atomic operations
	Increment(ctx context.Context, key string, delta int64) (int64, error)
	Decrement(ctx context.Context, key string, delta int64) (int64, error)

	// Utility operations
	Clear(ctx context.Context) error
	Size(ctx context.Context) (int64, error)
	Stats() CacheStats
	Close() error
}

// CacheStats provides statistics about cache performance and usage.
type CacheStats struct {
	Hits         int64     `json:"hits"`
	Misses       int64     `json:"misses"`
	Sets         int64     `json:"sets"`
	Deletes      int64     `json:"deletes"`
	Evictions    int64     `json:"evictions"`
	Keys         int64     `json:"keys"`
	HitRate      float64   `json:"hit_rate"`
	MemoryUsage  int64     `json:"memory_usage"`
	LastAccessed time.Time `json:"last_accessed"`
}
