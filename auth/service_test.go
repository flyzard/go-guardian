package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/flyzard/go-guardian"

	"github.com/flyzard/go-guardian/types"
)

// Mock implementations for testing

type mockStore struct {
	users          map[string]*types.User
	usersByEmail   map[string]*types.User
	sessions       map[string]*types.Session
	sessionsByUser map[string][]*types.Session
	rateLimits     map[string]*guardian.RateLimitInfo
	events         []*types.SecurityEvent
}

func newMockStore() *mockStore {
	return &mockStore{
		users:          make(map[string]*types.User),
		usersByEmail:   make(map[string]*types.User),
		sessions:       make(map[string]*types.Session),
		sessionsByUser: make(map[string][]*types.Session),
		rateLimits:     make(map[string]*guardian.RateLimitInfo),
		events:         make([]*types.SecurityEvent, 0),
	}
}

func (m *mockStore) CreateUser(_, user *types.User) error {
	if _, exists := m.usersByEmail[user.Email]; exists {
		return guardian.ErrUserExists
	}
	m.users[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func (m *mockStore) GetUser(_, id string) (*types.User, error) {
	if user, exists := m.users[id]; exists {
		return user, nil
	}
	return nil, guardian.ErrUserNotFound
}

func (m *mockStore) GetUserByEmail(_, email string) (*types.User, error) {
	if user, exists := m.usersByEmail[email]; exists {
		return user, nil
	}
	return nil, guardian.ErrUserNotFound
}

func (m *mockStore) UpdateUser(_, user *types.User) error {
	if _, exists := m.users[user.ID]; !exists {
		return guardian.ErrUserNotFound
	}
	m.users[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func (m *mockStore) DeleteUser(_, id string) error {
	if user, exists := m.users[id]; exists {
		delete(m.users, id)
		delete(m.usersByEmail, user.Email)
		return nil
	}
	return guardian.ErrUserNotFound
}

func (m *mockStore) ListUsers(_, limit, offset int) ([]*types.User, error) {
	users := make([]*types.User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
}

func (m *mockStore) CreateSession(_, session *types.Session) error {
	m.sessions[session.Token] = session
	m.sessionsByUser[session.UserID] = append(m.sessionsByUser[session.UserID], session)
	return nil
}

func (m *mockStore) GetSession(_, token string) (*types.Session, error) {
	if session, exists := m.sessions[token]; exists {
		return session, nil
	}
	return nil, guardian.ErrSessionNotFound
}

func (m *mockStore) GetSessionsByUser(_, userID string) ([]*types.Session, error) {
	if sessions, exists := m.sessionsByUser[userID]; exists {
		return sessions, nil
	}
	return []*types.Session{}, nil
}

func (m *mockStore) UpdateSession(_, session *types.Session) error {
	if _, exists := m.sessions[session.Token]; !exists {
		return guardian.ErrSessionNotFound
	}
	m.sessions[session.Token] = session
	return nil
}

func (m *mockStore) DeleteSession(_, token string) error {
	if session, exists := m.sessions[token]; exists {
		delete(m.sessions, token)
		// Remove from user sessions
		userSessions := m.sessionsByUser[session.UserID]
		for i, s := range userSessions {
			if s.Token == token {
				m.sessionsByUser[session.UserID] = append(userSessions[:i], userSessions[i+1:]...)
				break
			}
		}
		return nil
	}
	return guardian.ErrSessionNotFound
}

func (m *mockStore) DeleteSessionsByUser(_, userID string) error {
	sessions := m.sessionsByUser[userID]
	for _, session := range sessions {
		delete(m.sessions, session.Token)
	}
	delete(m.sessionsByUser, userID)
	return nil
}

func (m *mockStore) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	count := int64(0)
	now := time.Now()
	for token, session := range m.sessions {
		if session.ExpiresAt.Before(now) {
			m.DeleteSession(ctx, token)
			count++
		}
	}
	return count, nil
}

// Stub implementations for other Store methods
func (m *mockStore) CreateToken(_, token *types.Token) error { return nil }
func (m *mockStore) GetToken(_, value string) (*types.Token, error) {
	return nil, guardian.ErrTokenNotFound
}
func (m *mockStore) GetTokensByUser(_, userID string, tokenType types.TokenType) ([]*types.Token, error) {
	return nil, nil
}
func (m *mockStore) UpdateToken(_, token *types.Token) error   { return nil }
func (m *mockStore) DeleteToken(_, value string) error         { return nil }
func (m *mockStore) DeleteTokensByUser(_, userID string) error { return nil }
func (m *mockStore) DeleteExpiredTokens(_) (int64, error)      { return 0, nil }
func (m *mockStore) CreateRole(_, role *types.Role) error      { return nil }
func (m *mockStore) GetRole(_, name string) (*types.Role, error) {
	return nil, guardian.ErrRoleNotFound
}
func (m *mockStore) UpdateRole(_, role *types.Role) error              { return nil }
func (m *mockStore) DeleteRole(_, name string) error                   { return nil }
func (m *mockStore) ListRoles(_) ([]*types.Role, error)                { return nil, nil }
func (m *mockStore) AssignRoleToUser(_, userID, roleName string) error { return nil }
func (m *mockStore) RemoveRoleFromUser(_, userID, roleName string) error {
	return nil
}
func (m *mockStore) GetUserRoles(_, userID string) ([]*types.Role, error) {
	return nil, nil
}

func (m *mockStore) LogSecurityEvent(_, event *types.SecurityEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *mockStore) GetSecurityEvents(_, userID string, eventType types.SecurityEventType, limit int) ([]*types.SecurityEvent, error) {
	return m.events, nil
}

func (m *mockStore) CleanupOldEvents(_, olderThan time.Time) (int64, error) {
	return 0, nil
}

func (m *mockStore) GetRateLimit(_, key string) (*guardian.RateLimitInfo, error) {
	if info, exists := m.rateLimits[key]; exists {
		return info, nil
	}
	return &guardian.RateLimitInfo{Count: 0}, nil
}

func (m *mockStore) IncrementRateLimit(_, key string, window time.Duration) (*guardian.RateLimitInfo, error) {
	info, exists := m.rateLimits[key]
	if !exists {
		info = &guardian.RateLimitInfo{Count: 0}
	}
	info.Count++
	m.rateLimits[key] = info
	return info, nil
}

func (m *mockStore) ResetRateLimit(_, key string) error {
	delete(m.rateLimits, key)
	return nil
}

func (m *mockStore) Ping(_) error               { return nil }
func (m *mockStore) Close() error               { return nil }
func (m *mockStore) Stats() guardian.StoreStats { return guardian.StoreStats{} }

// Mock hasher
type mockHasher struct{}

func (m *mockHasher) Hash(_, password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("empty password")
	}
	return fmt.Sprintf("hashed_%s", password), nil
}

func (m *mockHasher) HashWithCost(_, password string, cost int) (string, error) {
	return m.Hash(ctx, password)
}

func (m *mockHasher) Verify(_, password, hash string) error {
	expected := fmt.Sprintf("hashed_%s", password)
	if hash != expected {
		return guardian.ErrInvalidCredentials
	}
	return nil
}

func (m *mockHasher) NeedsRehash(hash string, cost int) bool { return false }
func (m *mockHasher) GetCost(hash string) (int, error)       { return 12, nil }
func (m *mockHasher) GenerateSalt(_) ([]byte, error)         { return []byte("salt"), nil }

// Mock rate limiter
type mockRateLimiter struct {
	allowedRequests map[string]bool
}

func newMockRateLimiter() *mockRateLimiter {
	return &mockRateLimiter{
		allowedRequests: make(map[string]bool),
	}
}

func (m *mockRateLimiter) IsAllowed(_, key string, limit int64, window time.Duration) (bool, *guardian.RateLimitInfo, error) {
	allowed, exists := m.allowedRequests[key]
	if !exists {
		allowed = true
	}
	return allowed, &guardian.RateLimitInfo{Count: 1, Limit: limit, Remaining: limit - 1}, nil
}

func (m *mockRateLimiter) Allow(_, key string, limit int64, window time.Duration) (*guardian.RateLimitInfo, error) {
	return &guardian.RateLimitInfo{Count: 1, Limit: limit, Remaining: limit - 1}, nil
}

func (m *mockRateLimiter) Reset(_, key string) error {
	delete(m.allowedRequests, key)
	return nil
}

func (m *mockRateLimiter) Status(_, key string) (*guardian.RateLimitInfo, error) {
	return &guardian.RateLimitInfo{Count: 0, Limit: 10, Remaining: 10}, nil
}

func (m *mockRateLimiter) Cleanup(_) error { return nil }
func (m *mockRateLimiter) BatchAllow(_, keys []string, limit int64, window time.Duration) (map[string]*guardian.RateLimitInfo, error) {
	return nil, nil
}
func (m *mockRateLimiter) BatchReset(_, keys []string) error { return nil }

func (m *mockRateLimiter) setAllowed(key string, allowed bool) {
	m.allowedRequests[key] = allowed
}

// Mock logger
type mockLogger struct {
	events []string
}

func newMockLogger() *mockLogger {
	return &mockLogger{events: make([]string, 0)}
}

func (m *mockLogger) Debug(_, msg string, fields ...guardian.LogField) {
	m.events = append(m.events, fmt.Sprintf("DEBUG: %s", msg))
}

func (m *mockLogger) Info(_, msg string, fields ...guardian.LogField) {
	m.events = append(m.events, fmt.Sprintf("INFO: %s", msg))
}

func (m *mockLogger) Warn(_, msg string, fields ...guardian.LogField) {
	m.events = append(m.events, fmt.Sprintf("WARN: %s", msg))
}

func (m *mockLogger) Error(_, msg string, fields ...guardian.LogField) {
	m.events = append(m.events, fmt.Sprintf("ERROR: %s", msg))
}

func (m *mockLogger) Fatal(_, msg string, fields ...guardian.LogField) {
	m.events = append(m.events, fmt.Sprintf("FATAL: %s", msg))
}

func (m *mockLogger) LogSecurityEvent(_, event *types.SecurityEvent, fields ...guardian.LogField) {
	m.events = append(m.events, fmt.Sprintf("SECURITY: %s", event.Type))
}

func (m *mockLogger) LogAuthAttempt(_, userID, email, ip string, success bool, fields ...guardian.LogField) {
	m.events = append(m.events, fmt.Sprintf("AUTH: %s success=%t", email, success))
}

func (m *mockLogger) LogPermissionCheck(_, userID, resource, action string, allowed bool, fields ...guardian.LogField) {
	m.events = append(m.events, fmt.Sprintf("PERM: %s allowed=%t", action, allowed))
}

func (m *mockLogger) WithFields(fields ...guardian.LogField) guardian.Logger { return m }
func (m *mockLogger) WithUser(userID string) guardian.Logger                 { return m }
func (m *mockLogger) WithRequest(requestID string) guardian.Logger           { return m }
func (m *mockLogger) SetLevel(level guardian.LogLevel)                       {}
func (m *mockLogger) GetLevel() guardian.LogLevel                            { return guardian.LogLevelInfo }

// Mock metrics collector
type mockMetrics struct{}

func (m *mockMetrics) IncrementCounter(name string, labels map[string]string)                       {}
func (m *mockMetrics) IncrementCounterBy(name string, value float64, labels map[string]string)      {}
func (m *mockMetrics) SetGauge(name string, value float64, labels map[string]string)                {}
func (m *mockMetrics) IncrementGauge(name string, labels map[string]string)                         {}
func (m *mockMetrics) DecrementGauge(name string, labels map[string]string)                         {}
func (m *mockMetrics) RecordHistogram(name string, value float64, labels map[string]string)         {}
func (m *mockMetrics) RecordDuration(name string, duration time.Duration, labels map[string]string) {}
func (m *mockMetrics) RecordAuthAttempt(success bool, method string, labels map[string]string)      {}
func (m *mockMetrics) RecordPermissionCheck(allowed bool, resource string, labels map[string]string) {
}
func (m *mockMetrics) RecordRateLimitHit(key string, labels map[string]string) {}
func (m *mockMetrics) RecordSecurityEvent(eventType types.SecurityEventType, labels map[string]string) {
}
func (m *mockMetrics) RecordActiveUsers(count int64)                              {}
func (m *mockMetrics) RecordActiveSessions(count int64)                           {}
func (m *mockMetrics) RecordDatabaseConnections(count int64)                      {}
func (m *mockMetrics) RecordResponseTime(endpoint string, duration time.Duration) {}
func (m *mockMetrics) GetMetrics() map[string]interface{}                         { return nil }
func (m *mockMetrics) Reset()                                                     {}
func (m *mockMetrics) Export(format string) ([]byte, error)                       { return nil, nil }

// Test setup helper
func setupTestService(t *testing.T) (*Service, *mockStore, *mockRateLimiter, *mockLogger) {
	store := newMockStore()
	hasher := &mockHasher{}
	rateLimiter := newMockRateLimiter()
	logger := newMockLogger()
	metrics := &mockMetrics{}

	config := DefaultConfig()
	service, err := NewService(config, hasher, rateLimiter, logger, metrics)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	return service, store, rateLimiter, logger
}

// Tests

func TestServiceCreation(t *testing.T) {
	t.Run("successful creation with default config", func(t *testing.T) {
		_, _, _, _ = setupTestService(t)
	})

	t.Run("creation with nil config uses defaults", func(t *testing.T) {
		hasher := &mockHasher{}
		logger := newMockLogger()

		service, err := NewService(nil, hasher, nil, logger, nil)
		if err != nil {
			t.Fatalf("Expected service creation to succeed with nil config, got: %v", err)
		}
		if service == nil {
			t.Fatal("Expected service to be created")
		}
	})

	t.Run("creation fails with nil hasher", func(t *testing.T) {
		config := DefaultConfig()
		logger := newMockLogger()

		_, err := NewService(config, nil, nil, logger, nil)
		if err == nil {
			t.Fatal("Expected error when hasher is nil")
		}
	})

	t.Run("creation fails with nil logger", func(t *testing.T) {
		config := DefaultConfig()
		hasher := &mockHasher{}

		_, err := NewService(config, hasher, nil, nil, nil)
		if err == nil {
			t.Fatal("Expected error when logger is nil")
		}
	})
}

func TestRegister(t *testing.T) {
	service, store, rateLimiter, _ := setupTestService(t)
	ctx := context.WithValue(context.Background(), "ip_address", "192.168.1.1")

	t.Run("successful registration", func(t *testing.T) {
		email := "test@example.com"
		password := "Password123!"

		user, err := service.Register(ctx, email, password, store)
		if err != nil {
			t.Fatalf("Expected successful registration, got: %v", err)
		}

		if user == nil {
			t.Fatal("Expected user to be returned")
		}
		if user.Email != email {
			t.Errorf("Expected email %s, got %s", email, user.Email)
		}
		if user.ID == "" {
			t.Error("Expected user ID to be set")
		}
		if user.EmailVerified {
			t.Error("Expected email to not be verified initially")
		}
	})

	t.Run("registration with invalid email", func(t *testing.T) {
		_, err := service.Register(ctx, "invalid-email", "Password123!", store)
		if err == nil {
			t.Fatal("Expected error for invalid email")
		}
	})

	t.Run("registration with weak password", func(t *testing.T) {
		_, err := service.Register(ctx, "test2@example.com", "weak", store)
		if err == nil {
			t.Fatal("Expected error for weak password")
		}
	})

	t.Run("registration with existing email", func(t *testing.T) {
		email := "existing@example.com"
		password := "Password123!"

		// First registration
		_, err := service.Register(ctx, email, password, store)
		if err != nil {
			t.Fatalf("First registration failed: %v", err)
		}

		// Second registration with same email
		_, err = service.Register(ctx, email, password, store)
		if err != guardian.ErrUserExists {
			t.Fatalf("Expected ErrUserExists, got: %v", err)
		}
	})

	t.Run("registration rate limiting", func(t *testing.T) {
		rateLimiter.setAllowed("register:192.168.1.1", false)

		_, err := service.Register(ctx, "ratelimited@example.com", "Password123!", store)
		if err != guardian.ErrRateLimitExceeded {
			t.Fatalf("Expected ErrRateLimitExceeded, got: %v", err)
		}
	})
}

func TestLogin(t *testing.T) {
	service, store, rateLimiter, _ := setupTestService(t)
	ctx := context.WithValue(context.Background(), "ip_address", "192.168.1.1")

	// Setup test user
	email := "login@example.com"
	password := "Password123!"
	_, err := service.Register(ctx, email, password, store)
	if err != nil {
		t.Fatalf("Failed to setup test user: %v", err)
	}

	t.Run("successful login", func(t *testing.T) {
		session, err := service.Login(ctx, email, password, store)
		if err != nil {
			t.Fatalf("Expected successful login, got: %v", err)
		}

		if session == nil {
			t.Fatal("Expected session to be returned")
		}
		if session.Token == "" {
			t.Error("Expected session token to be set")
		}
		if session.UserID == "" {
			t.Error("Expected user ID to be set in session")
		}
	})

	t.Run("login with invalid email", func(t *testing.T) {
		_, err := service.Login(ctx, "nonexistent@example.com", password, store)
		if err != guardian.ErrInvalidCredentials {
			t.Fatalf("Expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("login with invalid password", func(t *testing.T) {
		_, err := service.Login(ctx, email, "wrongpassword", store)
		if err != guardian.ErrInvalidCredentials {
			t.Fatalf("Expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("login with empty password", func(t *testing.T) {
		_, err := service.Login(ctx, email, "", store)
		if err != guardian.ErrInvalidCredentials {
			t.Fatalf("Expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("login rate limiting", func(t *testing.T) {
		rateLimiter.setAllowed("login:192.168.1.1", false)

		_, err := service.Login(ctx, email, password, store)
		if err != guardian.ErrRateLimitExceeded {
			t.Fatalf("Expected ErrRateLimitExceeded, got: %v", err)
		}
	})
}

func TestAccountLockout(t *testing.T) {
	service, store, _, _ := setupTestService(t)
	ctx := context.WithValue(context.Background(), "ip_address", "192.168.1.1")

	// Setup test user
	email := "lockout@example.com"
	password := "Password123!"
	_, err := service.Register(ctx, email, password, store)
	if err != nil {
		t.Fatalf("Failed to setup test user: %v", err)
	}

	t.Run("account lockout after max failed attempts", func(t *testing.T) {
		// Make 5 failed login attempts (default max)
		for i := 0; i < 5; i++ {
			_, err := service.Login(ctx, email, "wrongpassword", store)
			if err != guardian.ErrInvalidCredentials {
				t.Fatalf("Attempt %d: Expected ErrInvalidCredentials, got: %v", i+1, err)
			}
		}

		// Next attempt should return account locked
		_, err := service.Login(ctx, email, "wrongpassword", store)
		if err != guardian.ErrAccountLocked {
			t.Fatalf("Expected ErrAccountLocked after max attempts, got: %v", err)
		}

		// Even correct password should fail when locked
		_, err = service.Login(ctx, email, password, store)
		if err != guardian.ErrAccountLocked {
			t.Fatalf("Expected ErrAccountLocked with correct password, got: %v", err)
		}
	})
}

func TestLogout(t *testing.T) {
	service, store, _, _ := setupTestService(t)
	ctx := context.WithValue(context.Background(), "ip_address", "192.168.1.1")

	// Setup test user and session
	email := "logout@example.com"
	password := "Password123!"
	_, err := service.Register(ctx, email, password, store)
	if err != nil {
		t.Fatalf("Failed to setup test user: %v", err)
	}

	session, err := service.Login(ctx, email, password, store)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	t.Run("successful logout", func(t *testing.T) {
		err := service.Logout(ctx, session.Token, store)
		if err != nil {
			t.Fatalf("Expected successful logout, got: %v", err)
		}

		// Verify session is invalidated
		_, err = store.GetSession(ctx, session.Token)
		if err != guardian.ErrSessionNotFound {
			t.Fatalf("Expected session to be deleted, but found: %v", err)
		}
	})

	t.Run("logout with invalid token", func(t *testing.T) {
		err := service.Logout(ctx, "invalid-token", store)
		if err != guardian.ErrTokenInvalid {
			t.Fatalf("Expected ErrTokenInvalid, got: %v", err)
		}
	})

	t.Run("logout with empty token", func(t *testing.T) {
		err := service.Logout(ctx, "", store)
		if err != guardian.ErrTokenInvalid {
			t.Fatalf("Expected ErrTokenInvalid, got: %v", err)
		}
	})
}

func TestLogoutAll(t *testing.T) {
	service, store, _, _ := setupTestService(t)
	ctx := context.WithValue(context.Background(), "ip_address", "192.168.1.1")

	// Setup test user and multiple sessions
	email := "logoutall@example.com"
	password := "Password123!"
	user, err := service.Register(ctx, email, password, store)
	if err != nil {
		t.Fatalf("Failed to setup test user: %v", err)
	}

	// Create multiple sessions
	var sessions []*types.Session
	for i := 0; i < 3; i++ {
		session, err := service.Login(ctx, email, password, store)
		if err != nil {
			t.Fatalf("Failed to create session %d: %v", i, err)
		}
		sessions = append(sessions, session)
	}

	t.Run("successful logout all", func(t *testing.T) {
		err := service.LogoutAll(ctx, user.ID, store)
		if err != nil {
			t.Fatalf("Expected successful logout all, got: %v", err)
		}

		// Verify all sessions are invalidated
		for i, session := range sessions {
			_, err := store.GetSession(ctx, session.Token)
			if err != guardian.ErrSessionNotFound {
				t.Fatalf("Expected session %d to be deleted, but found: %v", i, err)
			}
		}
	})

	t.Run("logout all with invalid user ID", func(t *testing.T) {
		err := service.LogoutAll(ctx, "invalid-user-id", store)
		if err != guardian.ErrUserNotFound {
			t.Fatalf("Expected ErrUserNotFound, got: %v", err)
		}
	})

	t.Run("logout all with empty user ID", func(t *testing.T) {
		err := service.LogoutAll(ctx, "", store)
		if err != guardian.ErrInvalidInput {
			t.Fatalf("Expected ErrInvalidInput, got: %v", err)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.SessionTTL != 24*time.Hour {
		t.Errorf("Expected session TTL to be 24h, got %v", config.SessionTTL)
	}
	if config.MaxSessions != 5 {
		t.Errorf("Expected max sessions to be 5, got %d", config.MaxSessions)
	}
	if config.MaxFailedAttempts != 5 {
		t.Errorf("Expected max failed attempts to be 5, got %d", config.MaxFailedAttempts)
	}
	if config.LockoutDuration != 15*time.Minute {
		t.Errorf("Expected lockout duration to be 15m, got %v", config.LockoutDuration)
	}
	if config.PasswordPolicy == nil {
		t.Error("Expected password policy to be set")
	}
}
