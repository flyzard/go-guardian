package guardian

import (
	"context"
	"testing"
	"time"

	"github.com/flyzard/go-guardian/types"
)

// Test interface implementations using mock implementations
// This ensures that interfaces are properly defined and can be implemented

// MockStore is a minimal implementation for testing interface compliance
type MockStore struct{}

func (m *MockStore) CreateUser(ctx context.Context, user *types.User) error      { return nil }
func (m *MockStore) GetUser(ctx context.Context, id string) (*types.User, error) { return nil, nil }
func (m *MockStore) GetUserByEmail(ctx context.Context, email string) (*types.User, error) {
	return nil, nil
}
func (m *MockStore) UpdateUser(ctx context.Context, user *types.User) error { return nil }
func (m *MockStore) DeleteUser(ctx context.Context, id string) error        { return nil }
func (m *MockStore) ListUsers(ctx context.Context, limit, offset int) ([]*types.User, error) {
	return nil, nil
}

func (m *MockStore) CreateSession(ctx context.Context, session *types.Session) error { return nil }
func (m *MockStore) GetSession(ctx context.Context, token string) (*types.Session, error) {
	return nil, nil
}
func (m *MockStore) GetSessionsByUser(ctx context.Context, userID string) ([]*types.Session, error) {
	return nil, nil
}
func (m *MockStore) UpdateSession(ctx context.Context, session *types.Session) error { return nil }
func (m *MockStore) DeleteSession(ctx context.Context, token string) error           { return nil }
func (m *MockStore) DeleteSessionsByUser(ctx context.Context, userID string) error   { return nil }
func (m *MockStore) DeleteExpiredSessions(ctx context.Context) (int64, error)        { return 0, nil }

func (m *MockStore) CreateToken(ctx context.Context, token *types.Token) error { return nil }
func (m *MockStore) GetToken(ctx context.Context, value string) (*types.Token, error) {
	return nil, nil
}
func (m *MockStore) GetTokensByUser(ctx context.Context, userID string, tokenType types.TokenType) ([]*types.Token, error) {
	return nil, nil
}
func (m *MockStore) UpdateToken(ctx context.Context, token *types.Token) error   { return nil }
func (m *MockStore) DeleteToken(ctx context.Context, value string) error         { return nil }
func (m *MockStore) DeleteTokensByUser(ctx context.Context, userID string) error { return nil }
func (m *MockStore) DeleteExpiredTokens(ctx context.Context) (int64, error)      { return 0, nil }

func (m *MockStore) CreateRole(ctx context.Context, role *types.Role) error        { return nil }
func (m *MockStore) GetRole(ctx context.Context, name string) (*types.Role, error) { return nil, nil }
func (m *MockStore) UpdateRole(ctx context.Context, role *types.Role) error        { return nil }
func (m *MockStore) DeleteRole(ctx context.Context, name string) error             { return nil }
func (m *MockStore) ListRoles(ctx context.Context) ([]*types.Role, error)          { return nil, nil }

func (m *MockStore) AssignRoleToUser(ctx context.Context, userID, roleName string) error { return nil }
func (m *MockStore) RemoveRoleFromUser(ctx context.Context, userID, roleName string) error {
	return nil
}
func (m *MockStore) GetUserRoles(ctx context.Context, userID string) ([]*types.Role, error) {
	return nil, nil
}

func (m *MockStore) LogSecurityEvent(ctx context.Context, event *types.SecurityEvent) error {
	return nil
}
func (m *MockStore) GetSecurityEvents(ctx context.Context, userID string, eventType types.SecurityEventType, limit int) ([]*types.SecurityEvent, error) {
	return nil, nil
}
func (m *MockStore) CleanupOldEvents(ctx context.Context, olderThan time.Time) (int64, error) {
	return 0, nil
}

func (m *MockStore) GetRateLimit(ctx context.Context, key string) (*RateLimitInfo, error) {
	return nil, nil
}
func (m *MockStore) IncrementRateLimit(ctx context.Context, key string, window time.Duration) (*RateLimitInfo, error) {
	return nil, nil
}
func (m *MockStore) ResetRateLimit(ctx context.Context, key string) error { return nil }

func (m *MockStore) Ping(ctx context.Context) error { return nil }
func (m *MockStore) Close() error                   { return nil }
func (m *MockStore) Stats() StoreStats              { return StoreStats{} }

// MockMailer implementation
type MockMailer struct{}

func (m *MockMailer) SendText(ctx context.Context, to, subject, body string) error     { return nil }
func (m *MockMailer) SendHTML(ctx context.Context, to, subject, htmlBody string) error { return nil }
func (m *MockMailer) SendTemplate(ctx context.Context, template string, to string, data interface{}) error {
	return nil
}
func (m *MockMailer) SendBulk(ctx context.Context, template string, recipients []EmailRecipient) error {
	return nil
}
func (m *MockMailer) SendWithAttachments(ctx context.Context, email *Email) error { return nil }
func (m *MockMailer) ValidateEmail(email string) error                            { return nil }
func (m *MockMailer) GetTemplates() []string                                      { return nil }
func (m *MockMailer) TestConnection(ctx context.Context) error                    { return nil }

// MockTokenGenerator implementation
type MockTokenGenerator struct{}

func (m *MockTokenGenerator) GenerateToken(ctx context.Context, length int, tokenType TokenFormat) (string, error) {
	return "", nil
}
func (m *MockTokenGenerator) GenerateJWT(ctx context.Context, claims map[string]interface{}, expiresIn time.Duration) (string, error) {
	return "", nil
}
func (m *MockTokenGenerator) ValidateJWT(ctx context.Context, token string) (map[string]interface{}, error) {
	return nil, nil
}
func (m *MockTokenGenerator) GenerateSecureRandom(ctx context.Context, length int) ([]byte, error) {
	return nil, nil
}
func (m *MockTokenGenerator) GenerateSessionToken(ctx context.Context) (string, error) {
	return "", nil
}
func (m *MockTokenGenerator) GenerateResetToken(ctx context.Context) (string, error) { return "", nil }
func (m *MockTokenGenerator) GenerateEmailVerificationToken(ctx context.Context) (string, error) {
	return "", nil
}
func (m *MockTokenGenerator) GenerateAPIKey(ctx context.Context) (string, error) { return "", nil }
func (m *MockTokenGenerator) GenerateTwoFactorSecret(ctx context.Context) (string, error) {
	return "", nil
}
func (m *MockTokenGenerator) ValidateTokenFormat(token string, format TokenFormat) error { return nil }
func (m *MockTokenGenerator) GetTokenEntropy(length int, format TokenFormat) float64     { return 0 }

// MockHasher implementation
type MockHasher struct{}

func (m *MockHasher) Hash(ctx context.Context, password string) (string, error) { return "", nil }
func (m *MockHasher) HashWithCost(ctx context.Context, password string, cost int) (string, error) {
	return "", nil
}
func (m *MockHasher) Verify(ctx context.Context, password, hash string) error { return nil }
func (m *MockHasher) NeedsRehash(hash string, cost int) bool                  { return false }
func (m *MockHasher) GetCost(hash string) (int, error)                        { return 0, nil }
func (m *MockHasher) GenerateSalt(ctx context.Context) ([]byte, error)        { return nil, nil }

// MockValidator implementation
type MockValidator struct{}

func (m *MockValidator) ValidateUser(ctx context.Context, user *types.User) error { return nil }
func (m *MockValidator) ValidateEmail(ctx context.Context, email string) error    { return nil }
func (m *MockValidator) ValidatePassword(ctx context.Context, password string, policy *types.PasswordPolicy) error {
	return nil
}
func (m *MockValidator) ValidateRole(ctx context.Context, role *types.Role) error { return nil }
func (m *MockValidator) ValidatePermission(ctx context.Context, permission *types.Permission) error {
	return nil
}
func (m *MockValidator) ValidateSession(ctx context.Context, session *types.Session) error {
	return nil
}
func (m *MockValidator) ValidateToken(ctx context.Context, token *types.Token) error   { return nil }
func (m *MockValidator) ValidateIPAddress(ctx context.Context, ip string) error        { return nil }
func (m *MockValidator) ValidateUserAgent(ctx context.Context, userAgent string) error { return nil }
func (m *MockValidator) ValidateDeviceFingerprint(ctx context.Context, fingerprint string) error {
	return nil
}
func (m *MockValidator) AddRule(name string, rule ValidationRule) error { return nil }
func (m *MockValidator) RemoveRule(name string) error                   { return nil }
func (m *MockValidator) GetRules() map[string]ValidationRule            { return nil }

// MockRateLimiter implementation
type MockRateLimiter struct{}

func (m *MockRateLimiter) IsAllowed(ctx context.Context, key string, limit int64, window time.Duration) (bool, *RateLimitInfo, error) {
	return true, nil, nil
}
func (m *MockRateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (*RateLimitInfo, error) {
	return nil, nil
}
func (m *MockRateLimiter) Reset(ctx context.Context, key string) error { return nil }
func (m *MockRateLimiter) Status(ctx context.Context, key string) (*RateLimitInfo, error) {
	return nil, nil
}
func (m *MockRateLimiter) Cleanup(ctx context.Context) error { return nil }
func (m *MockRateLimiter) BatchAllow(ctx context.Context, keys []string, limit int64, window time.Duration) (map[string]*RateLimitInfo, error) {
	return nil, nil
}
func (m *MockRateLimiter) BatchReset(ctx context.Context, keys []string) error { return nil }

// MockLogger implementation
type MockLogger struct{}

func (m *MockLogger) Debug(ctx context.Context, msg string, fields ...LogField) {}
func (m *MockLogger) Info(ctx context.Context, msg string, fields ...LogField)  {}
func (m *MockLogger) Warn(ctx context.Context, msg string, fields ...LogField)  {}
func (m *MockLogger) Error(ctx context.Context, msg string, fields ...LogField) {}
func (m *MockLogger) Fatal(ctx context.Context, msg string, fields ...LogField) {}
func (m *MockLogger) LogSecurityEvent(ctx context.Context, event *types.SecurityEvent, fields ...LogField) {
}
func (m *MockLogger) LogAuthAttempt(ctx context.Context, userID, email, ip string, success bool, fields ...LogField) {
}
func (m *MockLogger) LogPermissionCheck(ctx context.Context, userID, resource, action string, allowed bool, fields ...LogField) {
}
func (m *MockLogger) WithFields(fields ...LogField) Logger { return m }
func (m *MockLogger) WithUser(userID string) Logger        { return m }
func (m *MockLogger) WithRequest(requestID string) Logger  { return m }
func (m *MockLogger) SetLevel(level LogLevel)              {}
func (m *MockLogger) GetLevel() LogLevel                   { return LogLevelInfo }

// MockEncryptor implementation
type MockEncryptor struct{}

func (m *MockEncryptor) Encrypt(ctx context.Context, plaintext []byte, key []byte) ([]byte, error) {
	return nil, nil
}
func (m *MockEncryptor) Decrypt(ctx context.Context, ciphertext []byte, key []byte) ([]byte, error) {
	return nil, nil
}
func (m *MockEncryptor) EncryptString(ctx context.Context, plaintext string, key []byte) (string, error) {
	return "", nil
}
func (m *MockEncryptor) DecryptString(ctx context.Context, ciphertext string, key []byte) (string, error) {
	return "", nil
}
func (m *MockEncryptor) DeriveKey(ctx context.Context, password, salt []byte, keyLength int) ([]byte, error) {
	return nil, nil
}
func (m *MockEncryptor) GenerateKey(ctx context.Context, length int) ([]byte, error) { return nil, nil }
func (m *MockEncryptor) GenerateSalt(ctx context.Context) ([]byte, error)            { return nil, nil }
func (m *MockEncryptor) Sign(ctx context.Context, data []byte, privateKey []byte) ([]byte, error) {
	return nil, nil
}
func (m *MockEncryptor) Verify(ctx context.Context, data, signature, publicKey []byte) error {
	return nil
}
func (m *MockEncryptor) GenerateKeyPair(ctx context.Context) (privateKey, publicKey []byte, err error) {
	return nil, nil, nil
}

// MockMetricsCollector implementation
type MockMetricsCollector struct{}

func (m *MockMetricsCollector) IncrementCounter(name string, labels map[string]string) {}
func (m *MockMetricsCollector) IncrementCounterBy(name string, value float64, labels map[string]string) {
}
func (m *MockMetricsCollector) SetGauge(name string, value float64, labels map[string]string) {}
func (m *MockMetricsCollector) IncrementGauge(name string, labels map[string]string)          {}
func (m *MockMetricsCollector) DecrementGauge(name string, labels map[string]string)          {}
func (m *MockMetricsCollector) RecordHistogram(name string, value float64, labels map[string]string) {
}
func (m *MockMetricsCollector) RecordDuration(name string, duration time.Duration, labels map[string]string) {
}
func (m *MockMetricsCollector) RecordAuthAttempt(success bool, method string, labels map[string]string) {
}
func (m *MockMetricsCollector) RecordPermissionCheck(allowed bool, resource string, labels map[string]string) {
}
func (m *MockMetricsCollector) RecordRateLimitHit(key string, labels map[string]string) {}
func (m *MockMetricsCollector) RecordSecurityEvent(eventType types.SecurityEventType, labels map[string]string) {
}
func (m *MockMetricsCollector) RecordActiveUsers(count int64)                              {}
func (m *MockMetricsCollector) RecordActiveSessions(count int64)                           {}
func (m *MockMetricsCollector) RecordDatabaseConnections(count int64)                      {}
func (m *MockMetricsCollector) RecordResponseTime(endpoint string, duration time.Duration) {}
func (m *MockMetricsCollector) GetMetrics() map[string]interface{}                         { return nil }
func (m *MockMetricsCollector) Reset()                                                     {}
func (m *MockMetricsCollector) Export(format string) ([]byte, error)                       { return nil, nil }

// MockCacheProvider implementation
type MockCacheProvider struct{}

func (m *MockCacheProvider) Get(ctx context.Context, key string) ([]byte, error) { return nil, nil }
func (m *MockCacheProvider) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return nil
}
func (m *MockCacheProvider) Delete(ctx context.Context, key string) error         { return nil }
func (m *MockCacheProvider) Exists(ctx context.Context, key string) (bool, error) { return false, nil }
func (m *MockCacheProvider) GetMulti(ctx context.Context, keys []string) (map[string][]byte, error) {
	return nil, nil
}
func (m *MockCacheProvider) SetMulti(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	return nil
}
func (m *MockCacheProvider) DeleteMulti(ctx context.Context, keys []string) error { return nil }
func (m *MockCacheProvider) DeletePattern(ctx context.Context, pattern string) (int64, error) {
	return 0, nil
}
func (m *MockCacheProvider) Keys(ctx context.Context, pattern string) ([]string, error) {
	return nil, nil
}
func (m *MockCacheProvider) SetTTL(ctx context.Context, key string, ttl time.Duration) error {
	return nil
}
func (m *MockCacheProvider) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	return 0, nil
}
func (m *MockCacheProvider) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	return 0, nil
}
func (m *MockCacheProvider) Decrement(ctx context.Context, key string, delta int64) (int64, error) {
	return 0, nil
}
func (m *MockCacheProvider) Clear(ctx context.Context) error         { return nil }
func (m *MockCacheProvider) Size(ctx context.Context) (int64, error) { return 0, nil }
func (m *MockCacheProvider) Stats() CacheStats                       { return CacheStats{} }
func (m *MockCacheProvider) Close() error                            { return nil }

// Test interface compliance
func TestInterfaceCompliance(t *testing.T) {
	t.Run("Store interface", func(t *testing.T) {
		var store Store = &MockStore{}
		if store == nil {
			t.Error("MockStore does not implement Store interface")
		}
	})

	t.Run("Mailer interface", func(t *testing.T) {
		var mailer Mailer = &MockMailer{}
		if mailer == nil {
			t.Error("MockMailer does not implement Mailer interface")
		}
	})

	t.Run("TokenGenerator interface", func(t *testing.T) {
		var generator TokenGenerator = &MockTokenGenerator{}
		if generator == nil {
			t.Error("MockTokenGenerator does not implement TokenGenerator interface")
		}
	})

	t.Run("Hasher interface", func(t *testing.T) {
		var hasher Hasher = &MockHasher{}
		if hasher == nil {
			t.Error("MockHasher does not implement Hasher interface")
		}
	})

	t.Run("Validator interface", func(t *testing.T) {
		var validator Validator = &MockValidator{}
		if validator == nil {
			t.Error("MockValidator does not implement Validator interface")
		}
	})

	t.Run("RateLimiter interface", func(t *testing.T) {
		var limiter RateLimiter = &MockRateLimiter{}
		if limiter == nil {
			t.Error("MockRateLimiter does not implement RateLimiter interface")
		}
	})

	t.Run("Logger interface", func(t *testing.T) {
		var logger Logger = &MockLogger{}
		if logger == nil {
			t.Error("MockLogger does not implement Logger interface")
		}
	})

	t.Run("Encryptor interface", func(t *testing.T) {
		var encryptor Encryptor = &MockEncryptor{}
		if encryptor == nil {
			t.Error("MockEncryptor does not implement Encryptor interface")
		}
	})

	t.Run("MetricsCollector interface", func(t *testing.T) {
		var collector MetricsCollector = &MockMetricsCollector{}
		if collector == nil {
			t.Error("MockMetricsCollector does not implement MetricsCollector interface")
		}
	})

	t.Run("CacheProvider interface", func(t *testing.T) {
		var cache CacheProvider = &MockCacheProvider{}
		if cache == nil {
			t.Error("MockCacheProvider does not implement CacheProvider interface")
		}
	})
}

// Test helper types and their methods
func TestHelperTypes(t *testing.T) {
	t.Run("RateLimitInfo", func(t *testing.T) {
		info := &RateLimitInfo{
			Count: 5,
			Limit: 10,
		}

		if info.IsLimitExceeded() {
			t.Error("Expected rate limit not to be exceeded")
		}

		info.Count = 10
		if !info.IsLimitExceeded() {
			t.Error("Expected rate limit to be exceeded")
		}

		info.Count = 15
		if !info.IsLimitExceeded() {
			t.Error("Expected rate limit to be exceeded when count > limit")
		}
	})

	t.Run("EmailRecipient", func(t *testing.T) {
		recipient := EmailRecipient{
			Email: "test@example.com",
			Name:  "Test User",
			Data:  map[string]interface{}{"key": "value"},
		}

		if recipient.Email != "test@example.com" {
			t.Error("Expected email to be set correctly")
		}
		if recipient.Name != "Test User" {
			t.Error("Expected name to be set correctly")
		}
		if recipient.Data["key"] != "value" {
			t.Error("Expected data to be set correctly")
		}
	})

	t.Run("Email", func(t *testing.T) {
		email := &Email{
			To:       []string{"test@example.com"},
			Subject:  "Test Subject",
			TextBody: "Test Body",
			Priority: EmailPriorityHigh,
		}

		if len(email.To) != 1 || email.To[0] != "test@example.com" {
			t.Error("Expected To field to be set correctly")
		}
		if email.Subject != "Test Subject" {
			t.Error("Expected Subject to be set correctly")
		}
		if email.Priority != EmailPriorityHigh {
			t.Error("Expected Priority to be set correctly")
		}
	})

	t.Run("LogField", func(t *testing.T) {
		field := LogField{
			Key:   "user_id",
			Value: "12345",
		}

		if field.Key != "user_id" {
			t.Error("Expected Key to be set correctly")
		}
		if field.Value != "12345" {
			t.Error("Expected Value to be set correctly")
		}
	})

	t.Run("StoreStats", func(t *testing.T) {
		stats := StoreStats{
			TotalUsers:     100,
			ActiveSessions: 25,
			TotalTokens:    50,
			TotalEvents:    1000,
			Uptime:         time.Hour * 24,
		}

		if stats.TotalUsers != 100 {
			t.Error("Expected TotalUsers to be set correctly")
		}
		if stats.ActiveSessions != 25 {
			t.Error("Expected ActiveSessions to be set correctly")
		}
		if stats.Uptime != time.Hour*24 {
			t.Error("Expected Uptime to be set correctly")
		}
	})

	t.Run("CacheStats", func(t *testing.T) {
		stats := CacheStats{
			Hits:        100,
			Misses:      20,
			HitRate:     0.83,
			Keys:        50,
			MemoryUsage: 1024,
		}

		if stats.Hits != 100 {
			t.Error("Expected Hits to be set correctly")
		}
		if stats.Misses != 20 {
			t.Error("Expected Misses to be set correctly")
		}
		if stats.HitRate != 0.83 {
			t.Error("Expected HitRate to be set correctly")
		}
	})
}

// Test constants and enums
func TestConstants(t *testing.T) {
	t.Run("TokenFormat constants", func(t *testing.T) {
		formats := []TokenFormat{
			TokenFormatAlphanumeric,
			TokenFormatHex,
			TokenFormatBase64,
			TokenFormatBase32,
			TokenFormatNumeric,
			TokenFormatAlpha,
		}

		expectedValues := []string{
			"alphanumeric",
			"hex",
			"base64",
			"base32",
			"numeric",
			"alpha",
		}

		for i, format := range formats {
			if string(format) != expectedValues[i] {
				t.Errorf("Expected format %d to be %s, got %s", i, expectedValues[i], string(format))
			}
		}
	})

	t.Run("EmailPriority constants", func(t *testing.T) {
		priorities := []EmailPriority{
			EmailPriorityLow,
			EmailPriorityNormal,
			EmailPriorityHigh,
		}

		expectedValues := []string{"low", "normal", "high"}

		for i, priority := range priorities {
			if string(priority) != expectedValues[i] {
				t.Errorf("Expected priority %d to be %s, got %s", i, expectedValues[i], string(priority))
			}
		}
	})

	t.Run("LogLevel constants", func(t *testing.T) {
		levels := []LogLevel{
			LogLevelDebug,
			LogLevelInfo,
			LogLevelWarn,
			LogLevelError,
			LogLevelFatal,
		}

		expectedValues := []string{"debug", "info", "warn", "error", "fatal"}

		for i, level := range levels {
			if string(level) != expectedValues[i] {
				t.Errorf("Expected level %d to be %s, got %s", i, expectedValues[i], string(level))
			}
		}
	})
}

// Test context awareness
func TestContextAwareness(t *testing.T) {
	ctx := context.Background()

	t.Run("Store methods with context", func(t *testing.T) {
		store := &MockStore{}

		// Test that methods accept context
		err := store.CreateUser(ctx, nil)
		if err != nil {
			t.Error("Expected CreateUser to accept context")
		}

		_, err = store.GetUser(ctx, "test")
		if err != nil {
			t.Error("Expected GetUser to accept context")
		}

		err = store.Ping(ctx)
		if err != nil {
			t.Error("Expected Ping to accept context")
		}
	})

	t.Run("Mailer methods with context", func(t *testing.T) {
		mailer := &MockMailer{}

		err := mailer.SendText(ctx, "to@example.com", "subject", "body")
		if err != nil {
			t.Error("Expected SendText to accept context")
		}

		err = mailer.TestConnection(ctx)
		if err != nil {
			t.Error("Expected TestConnection to accept context")
		}
	})

	t.Run("TokenGenerator methods with context", func(t *testing.T) {
		generator := &MockTokenGenerator{}

		_, err := generator.GenerateToken(ctx, 32, TokenFormatAlphanumeric)
		if err != nil {
			t.Error("Expected GenerateToken to accept context")
		}

		_, err = generator.GenerateSessionToken(ctx)
		if err != nil {
			t.Error("Expected GenerateSessionToken to accept context")
		}
	})
}

// Benchmark tests for interface method calls
func BenchmarkInterfaceMethodCalls(b *testing.B) {
	ctx := context.Background()
	store := &MockStore{}
	mailer := &MockMailer{}
	generator := &MockTokenGenerator{}

	b.Run("Store.GetUser", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = store.GetUser(ctx, "test-user")
		}
	})

	b.Run("Mailer.SendText", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = mailer.SendText(ctx, "test@example.com", "subject", "body")
		}
	})

	b.Run("TokenGenerator.GenerateToken", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = generator.GenerateToken(ctx, 32, TokenFormatAlphanumeric)
		}
	})
}
