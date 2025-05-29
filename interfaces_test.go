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

func (m *MockStore) CreateUser(_, _ *types.User) error        { return nil }
func (m *MockStore) GetUser(_, _ string) (*types.User, error) { return nil, nil }
func (m *MockStore) GetUserByEmail(_, _ string) (*types.User, error) {
	return nil, nil
}
func (m *MockStore) UpdateUser(_, _ *types.User) error { return nil }
func (m *MockStore) DeleteUser(_, _ string) error      { return nil }
func (m *MockStore) ListUsers(_, _, _ int) ([]*types.User, error) {
	return nil, nil
}

func (m *MockStore) CreateSession(_, _ *types.Session) error { return nil }
func (m *MockStore) GetSession(_, _ string) (*types.Session, error) {
	return nil, nil
}
func (m *MockStore) GetSessionsByUser(_, _ string) ([]*types.Session, error) {
	return nil, nil
}
func (m *MockStore) UpdateSession(_, _ *types.Session) error { return nil }
func (m *MockStore) DeleteSession(_, _ string) error         { return nil }
func (m *MockStore) DeleteSessionsByUser(_, _ string) error  { return nil }
func (m *MockStore) DeleteExpiredSessions(_) (int64, error)  { return 0, nil }

func (m *MockStore) CreateToken(_, _ *types.Token) error { return nil }
func (m *MockStore) GetToken(_, _ string) (*types.Token, error) {
	return nil, nil
}
func (m *MockStore) GetTokensByUser(_, _ string, _ types.TokenType) ([]*types.Token, error) {
	return nil, nil
}
func (m *MockStore) UpdateToken(_, _ *types.Token) error  { return nil }
func (m *MockStore) DeleteToken(_, _ string) error        { return nil }
func (m *MockStore) DeleteTokensByUser(_, _ string) error { return nil }
func (m *MockStore) DeleteExpiredTokens(_) (int64, error) { return 0, nil }

func (m *MockStore) CreateRole(_, _ *types.Role) error        { return nil }
func (m *MockStore) GetRole(_, _ string) (*types.Role, error) { return nil, nil }
func (m *MockStore) UpdateRole(_, _ *types.Role) error        { return nil }
func (m *MockStore) DeleteRole(_, _ string) error             { return nil }
func (m *MockStore) ListRoles(_) ([]*types.Role, error)       { return nil, nil }

func (m *MockStore) AssignRoleToUser(_, _, _ string) error { return nil }
func (m *MockStore) RemoveRoleFromUser(_, _, _ string) error {
	return nil
}
func (m *MockStore) GetUserRoles(_, _ string) ([]*types.Role, error) {
	return nil, nil
}

func (m *MockStore) LogSecurityEvent(_, _ *types.SecurityEvent) error {
	return nil
}
func (m *MockStore) GetSecurityEvents(_, _ string, _ types.SecurityEventType, _ int) ([]*types.SecurityEvent, error) {
	return nil, nil
}
func (m *MockStore) CleanupOldEvents(_, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *MockStore) GetRateLimit(_, _ string) (*RateLimitInfo, error) {
	return nil, nil
}
func (m *MockStore) IncrementRateLimit(_, _ string, _ time.Duration) (*RateLimitInfo, error) {
	return nil, nil
}
func (m *MockStore) ResetRateLimit(_, _ string) error { return nil }

func (m *MockStore) Ping(_) error { return nil }
func (m *MockStore) Close() error                 { return nil }
func (m *MockStore) Stats() StoreStats            { return StoreStats{} }

// MockMailer implementation
type MockMailer struct{}

func (m *MockMailer) SendText(_, _, _, _ string) error { return nil }
func (m *MockMailer) SendHTML(_, _, _, _ string) error { return nil }
func (m *MockMailer) SendTemplate(_, _ string, _ string, _ interface{}) error {
	return nil
}
func (m *MockMailer) SendBulk(_, _ string, _ []EmailRecipient) error {
	return nil
}
func (m *MockMailer) SendWithAttachments(_, _ *Email) error { return nil }
func (m *MockMailer) ValidateEmail(_ string) error                          { return nil }
func (m *MockMailer) GetTemplates() []string                                { return nil }
func (m *MockMailer) TestConnection(_) error                { return nil }

// MockTokenGenerator implementation
type MockTokenGenerator struct{}

func (m *MockTokenGenerator) GenerateToken(_, _ int, _ TokenFormat) (string, error) {
	return "", nil
}
func (m *MockTokenGenerator) GenerateJWT(_, _ map[string]interface{}, _ time.Duration) (string, error) {
	return "", nil
}
func (m *MockTokenGenerator) ValidateJWT(_, _ string) (map[string]interface{}, error) {
	return nil, nil
}
func (m *MockTokenGenerator) GenerateSecureRandom(_, _ int) ([]byte, error) {
	return nil, nil
}
func (m *MockTokenGenerator) GenerateSessionToken(_) (string, error) {
	return "", nil
}
func (m *MockTokenGenerator) GenerateResetToken(_) (string, error) { return "", nil }
func (m *MockTokenGenerator) GenerateEmailVerificationToken(_) (string, error) {
	return "", nil
}
func (m *MockTokenGenerator) GenerateAPIKey(_) (string, error) { return "", nil }
func (m *MockTokenGenerator) GenerateTwoFactorSecret(_) (string, error) {
	return "", nil
}
func (m *MockTokenGenerator) ValidateTokenFormat(_ string, _ TokenFormat) error { return nil }
func (m *MockTokenGenerator) GetTokenEntropy(_ int, _ TokenFormat) float64      { return 0 }

// MockHasher implementation
type MockHasher struct{}

func (m *MockHasher) Hash(_, _ string) (string, error) { return "", nil }
func (m *MockHasher) HashWithCost(_, _ string, _ int) (string, error) {
	return "", nil
}
func (m *MockHasher) Verify(_, _, _ string) error    { return nil }
func (m *MockHasher) NeedsRehash(_ string, _ int) bool               { return false }
func (m *MockHasher) GetCost(_ string) (int, error)                  { return 0, nil }
func (m *MockHasher) GenerateSalt(_) ([]byte, error) { return nil, nil }

// MockValidator implementation
type MockValidator struct{}

func (m *MockValidator) ValidateUser(_, _ *types.User) error { return nil }
func (m *MockValidator) ValidateEmail(_, _ string) error     { return nil }
func (m *MockValidator) ValidatePassword(_, _ string, _ *types.PasswordPolicy) error {
	return nil
}
func (m *MockValidator) ValidateRole(_, _ *types.Role) error { return nil }
func (m *MockValidator) ValidatePermission(_, _ *types.Permission) error {
	return nil
}
func (m *MockValidator) ValidateSession(_, _ *types.Session) error {
	return nil
}
func (m *MockValidator) ValidateToken(_, _ *types.Token) error { return nil }
func (m *MockValidator) ValidateIPAddress(_, _ string) error   { return nil }
func (m *MockValidator) ValidateUserAgent(_, _ string) error   { return nil }
func (m *MockValidator) ValidateDeviceFingerprint(_, _ string) error {
	return nil
}
func (m *MockValidator) AddRule(_ string, _ ValidationRule) error { return nil }
func (m *MockValidator) RemoveRule(_ string) error                { return nil }
func (m *MockValidator) GetRules() map[string]ValidationRule      { return nil }

// MockRateLimiter implementation
type MockRateLimiter struct{}

func (m *MockRateLimiter) IsAllowed(_, _ string, _ int64, _ time.Duration) (bool, *RateLimitInfo, error) {
	return true, nil, nil
}
func (m *MockRateLimiter) Allow(_, _ string, _ int64, _ time.Duration) (*RateLimitInfo, error) {
	return nil, nil
}
func (m *MockRateLimiter) Reset(_, _ string) error { return nil }
func (m *MockRateLimiter) Status(_, _ string) (*RateLimitInfo, error) {
	return nil, nil
}
func (m *MockRateLimiter) Cleanup(_) error { return nil }
func (m *MockRateLimiter) BatchAllow(_, _ []string, _ int64, _ time.Duration) (map[string]*RateLimitInfo, error) {
	return nil, nil
}
func (m *MockRateLimiter) BatchReset(_, _ []string) error { return nil }

// MockLogger implementation
type MockLogger struct{}

func (m *MockLogger) Debug(_, _ string, _ ...LogField) {}
func (m *MockLogger) Info(_, _ string, _ ...LogField)  {}
func (m *MockLogger) Warn(_, _ string, _ ...LogField)  {}
func (m *MockLogger) Error(_, _ string, _ ...LogField) {}
func (m *MockLogger) Fatal(_, _ string, _ ...LogField) {}
func (m *MockLogger) LogSecurityEvent(_, _ *types.SecurityEvent, _ ...LogField) {
}
func (m *MockLogger) LogAuthAttempt(_, _, _, _ string, _ bool, _ ...LogField) {
}
func (m *MockLogger) LogPermissionCheck(_, _, _, _ string, _ bool, _ ...LogField) {
}
func (m *MockLogger) WithFields(_ ...LogField) Logger { return m }
func (m *MockLogger) WithUser(_ string) Logger        { return m }
func (m *MockLogger) WithRequest(_ string) Logger     { return m }
func (m *MockLogger) SetLevel(_ LogLevel)             {}
func (m *MockLogger) GetLevel() LogLevel              { return LogLevelInfo }

// MockEncryptor implementation
type MockEncryptor struct{}

func (m *MockEncryptor) Encrypt(_, _ []byte, _ []byte) ([]byte, error) {
	return nil, nil
}
func (m *MockEncryptor) Decrypt(_, _ []byte, _ []byte) ([]byte, error) {
	return nil, nil
}
func (m *MockEncryptor) EncryptString(_, _ string, _ []byte) (string, error) {
	return "", nil
}
func (m *MockEncryptor) DecryptString(_, _ string, _ []byte) (string, error) {
	return "", nil
}
func (m *MockEncryptor) DeriveKey(_, _, _ []byte, _ int) ([]byte, error) {
	return nil, nil
}
func (m *MockEncryptor) GenerateKey(_, _ int) ([]byte, error) { return nil, nil }
func (m *MockEncryptor) GenerateSalt(_) ([]byte, error)       { return nil, nil }
func (m *MockEncryptor) Sign(_, _, _ []byte) ([]byte, error) {
	return nil, nil
}
func (m *MockEncryptor) Verify(_, _, _, _ []byte) error {
	return nil
}
func (m *MockEncryptor) GenerateKeyPair(_) (privateKey, publicKey []byte, err error) {
	return nil, nil, nil
}

// MockMetricsCollector implementation
type MockMetricsCollector struct{}

func (m *MockMetricsCollector) IncrementCounter(_ string, _ map[string]string) {}
func (m *MockMetricsCollector) IncrementCounterBy(_ string, _ float64, _ map[string]string) {
}
func (m *MockMetricsCollector) SetGauge(_ string, _ float64, _ map[string]string) {}
func (m *MockMetricsCollector) IncrementGauge(_ string, _ map[string]string)      {}
func (m *MockMetricsCollector) DecrementGauge(_ string, _ map[string]string)      {}
func (m *MockMetricsCollector) RecordHistogram(_ string, _ float64, _ map[string]string) {
}
func (m *MockMetricsCollector) RecordDuration(_ string, _ time.Duration, _ map[string]string) {
}
func (m *MockMetricsCollector) RecordAuthAttempt(_ bool, _ string, _ map[string]string) {
}
func (m *MockMetricsCollector) RecordPermissionCheck(_ bool, _ string, _ map[string]string) {
}
func (m *MockMetricsCollector) RecordRateLimitHit(_ string, _ map[string]string) {}
func (m *MockMetricsCollector) RecordSecurityEvent(_ types.SecurityEventType, _ map[string]string) {
}
func (m *MockMetricsCollector) RecordActiveUsers(_ int64)                    {}
func (m *MockMetricsCollector) RecordActiveSessions(_ int64)                 {}
func (m *MockMetricsCollector) RecordDatabaseConnections(_ int64)            {}
func (m *MockMetricsCollector) RecordResponseTime(_ string, _ time.Duration) {}
func (m *MockMetricsCollector) GetMetrics() map[string]interface{}           { return nil }
func (m *MockMetricsCollector) Reset()                                       {}
func (m *MockMetricsCollector) Export(_ string) ([]byte, error)              { return nil, nil }

// MockCacheProvider implementation
type MockCacheProvider struct{}

func (m *MockCacheProvider) Get(_, _ string) ([]byte, error) { return nil, nil }
func (m *MockCacheProvider) Set(_, _ string, _ []byte, _ time.Duration) error {
	return nil
}
func (m *MockCacheProvider) Delete(_, _ string) error         { return nil }
func (m *MockCacheProvider) Exists(_, _ string) (bool, error) { return false, nil }
func (m *MockCacheProvider) GetMulti(_, _ []string) (map[string][]byte, error) {
	return nil, nil
}
func (m *MockCacheProvider) SetMulti(_, _ map[string][]byte, _ time.Duration) error {
	return nil
}
func (m *MockCacheProvider) DeleteMulti(_, _ []string) error { return nil }
func (m *MockCacheProvider) DeletePattern(_, _ string) (int64, error) {
	return 0, nil
}
func (m *MockCacheProvider) Keys(_, _ string) ([]string, error) {
	return nil, nil
}
func (m *MockCacheProvider) SetTTL(_, _ string, _ time.Duration) error {
	return nil
}
func (m *MockCacheProvider) GetTTL(_, _ string) (time.Duration, error) {
	return 0, nil
}
func (m *MockCacheProvider) Increment(_, _ string, _ int64) (int64, error) {
	return 0, nil
}
func (m *MockCacheProvider) Decrement(_, _ string, _ int64) (int64, error) {
	return 0, nil
}
func (m *MockCacheProvider) Clear(_) error         { return nil }
func (m *MockCacheProvider) Size(_) (int64, error) { return 0, nil }
func (m *MockCacheProvider) Stats() CacheStats                     { return CacheStats{} }
func (m *MockCacheProvider) Close() error                          { return nil }

// Test interface compliance
func TestInterfaceCompliance(t *testing.T) {
	t.Run("Store interface", func(_ *testing.T) {
		var store Store = &MockStore{}
		_ = store // Interface assignment successful if this compiles
	})

	t.Run("Mailer interface", func(_ *testing.T) {
		var mailer Mailer = &MockMailer{}
		_ = mailer // Interface assignment successful if this compiles
	})

	t.Run("TokenGenerator interface", func(_ *testing.T) {
		var generator TokenGenerator = &MockTokenGenerator{}
		_ = generator // Interface assignment successful if this compiles
	})

	t.Run("Hasher interface", func(_ *testing.T) {
		var hasher Hasher = &MockHasher{}
		_ = hasher // Interface assignment successful if this compiles
	})

	t.Run("Validator interface", func(_ *testing.T) {
		var validator Validator = &MockValidator{}
		_ = validator // Interface assignment successful if this compiles
	})

	t.Run("RateLimiter interface", func(_ *testing.T) {
		var limiter RateLimiter = &MockRateLimiter{}
		_ = limiter // Interface assignment successful if this compiles
	})

	t.Run("Logger interface", func(_ *testing.T) {
		var logger Logger = &MockLogger{}
		_ = logger // Interface assignment successful if this compiles
	})

	t.Run("Encryptor interface", func(_ *testing.T) {
		var encryptor Encryptor = &MockEncryptor{}
		_ = encryptor // Interface assignment successful if this compiles
	})

	t.Run("MetricsCollector interface", func(_ *testing.T) {
		var collector MetricsCollector = &MockMetricsCollector{}
		_ = collector // Interface assignment successful if this compiles
	})

	t.Run("CacheProvider interface", func(_ *testing.T) {
		var cache CacheProvider = &MockCacheProvider{}
		_ = cache // Interface assignment successful if this compiles
	})
}

// Test helper types and their methods
func TestHelperTypes(t *testing.T) {
	t.Run("RateLimitInfo", func(_ *testing.T) {
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

	t.Run("EmailRecipient", func(_ *testing.T) {
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

	t.Run("Email", func(_ *testing.T) {
		email := &Email{
			To:       []string{"test@example.com"},
			Subject:  "Test Subject",
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

	t.Run("LogField", func(_ *testing.T) {
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

	t.Run("StoreStats", func(_ *testing.T) {
		stats := StoreStats{
			TotalUsers:     100,
			ActiveSessions: 25,
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

	t.Run("CacheStats", func(_ *testing.T) {
		stats := CacheStats{
			Hits:    100,
			Misses:  20,
			HitRate: 0.83,
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
	t.Run("TokenFormat constants", func(_ *testing.T) {
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

	t.Run("EmailPriority constants", func(_ *testing.T) {
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

	t.Run("LogLevel constants", func(_ *testing.T) {
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

	t.Run("Store methods with context", func(_ *testing.T) {
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

	t.Run("Mailer methods with context", func(_ *testing.T) {
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

	t.Run("TokenGenerator methods with context", func(_ *testing.T) {
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
