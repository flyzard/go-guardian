package session

import (
	"context"
	"testing"
	"time"

	"github.com/flyzard/go-guardian"
	"github.com/flyzard/go-guardian/crypto"
	"github.com/flyzard/go-guardian/types"
)

// MockStore is a simple in-memory store for testing
type MockStore struct {
	users    map[string]*types.User
	sessions map[string]*types.Session
	events   []*types.SecurityEvent
}

// NewMockStore creates a new mock store
func NewMockStore() *MockStore {
	return &MockStore{
		users:    make(map[string]*types.User),
		sessions: make(map[string]*types.Session),
		events:   make([]*types.SecurityEvent, 0),
	}
}

// Store interface implementations for testing
func (m *MockStore) GetUser(_ context.Context, id string) (*types.User, error) {
	if user, exists := m.users[id]; exists {
		return user, nil
	}
	return nil, nil
}

func (m *MockStore) CreateSession(_ context.Context, session *types.Session) error {
	m.sessions[session.Token] = session
	return nil
}

func (m *MockStore) GetSession(_ context.Context, token string) (*types.Session, error) {
	if session, exists := m.sessions[token]; exists {
		return session, nil
	}
	return nil, nil
}

func (m *MockStore) GetSessionsByUser(_ context.Context, userID string) ([]*types.Session, error) {
	var sessions []*types.Session
	for _, session := range m.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

func (m *MockStore) UpdateSession(_ context.Context, session *types.Session) error {
	if _, exists := m.sessions[session.Token]; exists {
		m.sessions[session.Token] = session
		return nil
	}
	return guardian.ErrSessionNotFound
}

func (m *MockStore) DeleteSession(_ context.Context, token string) error {
	if _, exists := m.sessions[token]; exists {
		delete(m.sessions, token)
		return nil
	}
	return guardian.ErrSessionNotFound
}

func (m *MockStore) DeleteExpiredSessions(_ context.Context) (int64, error) {
	now := time.Now().UTC()
	var deleted int64
	for token, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, token)
			deleted++
		}
	}
	return deleted, nil
}

func (m *MockStore) LogSecurityEvent(_ context.Context, event *types.SecurityEvent) error {
	m.events = append(m.events, event)
	return nil
}

// Missing Store interface methods - implementing stubs for testing
func (m *MockStore) CreateUser(_ context.Context, user *types.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *MockStore) GetUserByEmail(_ context.Context, email string) (*types.User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, guardian.ErrUserNotFound
}

func (m *MockStore) UpdateUser(_ context.Context, user *types.User) error {
	if _, exists := m.users[user.ID]; exists {
		m.users[user.ID] = user
		return nil
	}
	return guardian.ErrUserNotFound
}

func (m *MockStore) DeleteUser(_ context.Context, id string) error {
	if _, exists := m.users[id]; exists {
		delete(m.users, id)
		return nil
	}
	return guardian.ErrUserNotFound
}

func (m *MockStore) ListUsers(_ context.Context, limit, offset int) ([]*types.User, error) {
	var users []*types.User
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
}

func (m *MockStore) DeleteSessionsByUser(_ context.Context, userID string) error {
	for token, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessions, token)
		}
	}
	return nil
}

func (m *MockStore) CreateToken(_ context.Context, token *types.Token) error {
	// Token management not needed for session tests
	return nil
}

func (m *MockStore) GetToken(_ context.Context, value string) (*types.Token, error) {
	return nil, guardian.ErrTokenNotFound
}

func (m *MockStore) GetTokensByUser(_ context.Context, userID string, tokenType types.TokenType) ([]*types.Token, error) {
	return []*types.Token{}, nil
}

func (m *MockStore) UpdateToken(_ context.Context, token *types.Token) error {
	return nil
}

func (m *MockStore) DeleteToken(_ context.Context, value string) error {
	return nil
}

func (m *MockStore) DeleteTokensByUser(_ context.Context, userID string) error {
	return nil
}

func (m *MockStore) DeleteExpiredTokens(_ context.Context) (int64, error) {
	return 0, nil
}

func (m *MockStore) CreateRole(_ context.Context, role *types.Role) error {
	return nil
}

func (m *MockStore) GetRole(_ context.Context, name string) (*types.Role, error) {
	return nil, guardian.ErrRoleNotFound
}

func (m *MockStore) UpdateRole(_ context.Context, role *types.Role) error {
	return nil
}

func (m *MockStore) DeleteRole(_ context.Context, name string) error {
	return nil
}

func (m *MockStore) ListRoles(_ context.Context) ([]*types.Role, error) {
	return []*types.Role{}, nil
}

func (m *MockStore) AssignRoleToUser(_ context.Context, userID, roleName string) error {
	return nil
}

func (m *MockStore) RemoveRoleFromUser(_ context.Context, userID, roleName string) error {
	return nil
}

func (m *MockStore) GetUserRoles(_ context.Context, userID string) ([]*types.Role, error) {
	return []*types.Role{}, nil
}

func (m *MockStore) GetSecurityEvents(_ context.Context, userID string, eventType types.SecurityEventType, limit int) ([]*types.SecurityEvent, error) {
	var filtered []*types.SecurityEvent
	for _, event := range m.events {
		if (userID == "" || event.UserID == userID) && (eventType == "" || event.Type == eventType) {
			filtered = append(filtered, event)
		}
	}
	return filtered, nil
}

func (m *MockStore) CleanupOldEvents(_ context.Context, olderThan time.Time) (int64, error) {
	return 0, nil
}

func (m *MockStore) GetRateLimit(_ context.Context, key string) (*guardian.RateLimitInfo, error) {
	return &guardian.RateLimitInfo{Count: 0}, nil
}

func (m *MockStore) IncrementRateLimit(_ context.Context, key string, window time.Duration) (*guardian.RateLimitInfo, error) {
	return &guardian.RateLimitInfo{Count: 1}, nil
}

func (m *MockStore) ResetRateLimit(_ context.Context, key string) error {
	return nil
}

func (m *MockStore) Ping(_ context.Context) error {
	return nil
}

func (m *MockStore) Close() error {
	return nil
}

func (m *MockStore) Stats() guardian.StoreStats {
	return guardian.StoreStats{
		TotalUsers:     int64(len(m.users)),
		ActiveSessions: int64(len(m.sessions)),
		TotalEvents:    int64(len(m.events)),
	}
}

// Helper methods for testing
func (m *MockStore) AddUser(user *types.User) {
	m.users[user.ID] = user
}

func (m *MockStore) GetEventCount() int {
	return len(m.events)
}

func (m *MockStore) GetLastEvent() *types.SecurityEvent {
	if len(m.events) == 0 {
		return nil
	}
	return m.events[len(m.events)-1]
}

func (m *MockStore) GetSessionCount() int {
	return len(m.sessions)
}

// Test helper functions
func createTestUser(id string) *types.User {
	return &types.User{
		ID:             id,
		Email:          id + "@example.com",
		PasswordHash:   "hashed_password",
		EmailVerified:  true,
		AccountLocked:  false,
		FailedAttempts: 0,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
}

func createTestContext() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, "ip_address", "192.168.1.1")
	ctx = context.WithValue(ctx, "user_agent", "Test-Agent/1.0")
	return ctx
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.SessionTTL != 24*time.Hour {
		t.Errorf("Expected SessionTTL to be 24 hours, got %v", config.SessionTTL)
	}

	if config.MaxSessions != 5 {
		t.Errorf("Expected MaxSessions to be 5, got %d", config.MaxSessions)
	}

	if config.TokenGenerator == nil {
		t.Error("Expected TokenGenerator to be non-nil")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "invalid session TTL",
			config: Config{
				SessionTTL:     0,
				MaxSessions:    5,
				TokenGenerator: crypto.NewSecureTokenGenerator(),
			},
			wantErr: true,
		},
		{
			name: "invalid max sessions",
			config: Config{
				SessionTTL:     time.Hour,
				MaxSessions:    0,
				TokenGenerator: crypto.NewSecureTokenGenerator(),
			},
			wantErr: true,
		},
		{
			name: "nil token generator",
			config: Config{
				SessionTTL:     time.Hour,
				MaxSessions:    5,
				TokenGenerator: nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr && err == nil {
				t.Error("Expected validation error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Expected no validation error but got: %v", err)
			}
		})
	}
}

func TestNewManager(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "invalid config",
			config: Config{
				SessionTTL:     0,
				MaxSessions:    5,
				TokenGenerator: crypto.NewSecureTokenGenerator(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if manager != nil {
					t.Error("Expected nil manager on error")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if manager == nil {
					t.Error("Expected non-nil manager")
				}
			}
		})
	}
}

func TestCreateSession(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	store := NewMockStore()
	ctx := createTestContext()

	t.Run("create session for existing user", func(t *testing.T) {
		user := createTestUser("user1")
		store.AddUser(user)

		session, err := manager.CreateSession(ctx, user.ID, store)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if session == nil {
			t.Fatal("Expected non-nil session")
		}

		if session.UserID != user.ID {
			t.Errorf("Expected UserID %s, got %s", user.ID, session.UserID)
		}

		if session.Token == "" {
			t.Error("Expected non-empty token")
		}

		if !session.IsActive {
			t.Error("Expected session to be active")
		}

		if session.IPAddress != "192.168.1.1" {
			t.Errorf("Expected IP address 192.168.1.1, got %s", session.IPAddress)
		}

		if session.UserAgent != "Test-Agent/1.0" {
			t.Errorf("Expected User-Agent Test-Agent/1.0, got %s", session.UserAgent)
		}

		// Check if session was stored
		if store.GetSessionCount() != 1 {
			t.Errorf("Expected 1 session in store, got %d", store.GetSessionCount())
		}

		// Check if security event was logged
		if store.GetEventCount() != 1 {
			t.Errorf("Expected 1 security event, got %d", store.GetEventCount())
		}

		event := store.GetLastEvent()
		if event.Type != "session_created" {
			t.Errorf("Expected event type session_created, got %s", event.Type)
		}
	})

	t.Run("create session for non-existent user", func(t *testing.T) {
		session, err := manager.CreateSession(ctx, "nonexistent", store)
		if err == nil {
			t.Error("Expected error for non-existent user")
		}
		if session != nil {
			t.Error("Expected nil session for non-existent user")
		}
	})

	t.Run("create session with empty user ID", func(t *testing.T) {
		session, err := manager.CreateSession(ctx, "", store)
		if err != guardian.ErrInvalidInput {
			t.Errorf("Expected ErrInvalidInput, got %v", err)
		}
		if session != nil {
			t.Error("Expected nil session for empty user ID")
		}
	})
}

func TestValidateSession(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	store := NewMockStore()
	ctx := createTestContext()

	// Create a user and session for testing
	user := createTestUser("user1")
	store.AddUser(user)

	session, err := manager.CreateSession(ctx, user.ID, store)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	t.Run("validate valid session", func(t *testing.T) {
		validatedSession, err := manager.ValidateSession(ctx, session.Token, store)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if validatedSession == nil {
			t.Fatal("Expected non-nil session")
		}

		if validatedSession.UserID != user.ID {
			t.Errorf("Expected UserID %s, got %s", user.ID, validatedSession.UserID)
		}
	})

	t.Run("validate with empty token", func(t *testing.T) {
		validatedSession, err := manager.ValidateSession(ctx, "", store)
		if err != guardian.ErrSessionInvalid {
			t.Errorf("Expected ErrSessionInvalid, got %v", err)
		}
		if validatedSession != nil {
			t.Error("Expected nil session for empty token")
		}
	})

	t.Run("validate with non-existent token", func(t *testing.T) {
		validatedSession, err := manager.ValidateSession(ctx, "nonexistent", store)
		if err == nil {
			t.Error("Expected error for non-existent token")
		}
		if validatedSession != nil {
			t.Error("Expected nil session for non-existent token")
		}
	})

	t.Run("validate expired session", func(t *testing.T) {
		// Create an expired session
		expiredSession := &types.Session{
			Token:      "expired_token",
			UserID:     user.ID,
			CreatedAt:  time.Now().UTC().Add(-2 * time.Hour),
			LastSeenAt: time.Now().UTC().Add(-2 * time.Hour),
			ExpiresAt:  time.Now().UTC().Add(-1 * time.Hour), // Expired 1 hour ago
			IPAddress:  "192.168.1.1",
			UserAgent:  "Test-Agent/1.0",
			IsActive:   true,
		}
		store.CreateSession(ctx, expiredSession)

		validatedSession, err := manager.ValidateSession(ctx, expiredSession.Token, store)
		if err != guardian.ErrSessionExpired {
			t.Errorf("Expected ErrSessionExpired, got %v", err)
		}
		if validatedSession != nil {
			t.Error("Expected nil session for expired session")
		}
	})
}

func TestRefreshSession(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	store := NewMockStore()
	ctx := createTestContext()

	// Create a user and session for testing
	user := createTestUser("user1")
	store.AddUser(user)

	session, err := manager.CreateSession(ctx, user.ID, store)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	originalExpiry := session.ExpiresAt

	t.Run("refresh session without token rotation", func(t *testing.T) {
		refreshedSession, err := manager.RefreshSession(ctx, session, store, false)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if refreshedSession == nil {
			t.Fatal("Expected non-nil refreshed session")
		}

		// Token should remain the same
		if refreshedSession.Token != session.Token {
			t.Error("Expected token to remain the same without rotation")
		}

		// Expiry should be extended
		if !refreshedSession.ExpiresAt.After(originalExpiry) {
			t.Error("Expected expiry to be extended")
		}
	})

	t.Run("refresh session with token rotation", func(t *testing.T) {
		refreshedSession, err := manager.RefreshSession(ctx, session, store, true)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if refreshedSession == nil {
			t.Fatal("Expected non-nil refreshed session")
		}

		// Token should be different
		if refreshedSession.Token == session.Token {
			t.Error("Expected token to be different with rotation")
		}

		// Expiry should be extended
		if !refreshedSession.ExpiresAt.After(originalExpiry) {
			t.Error("Expected expiry to be extended")
		}
	})

	t.Run("refresh nil session", func(t *testing.T) {
		refreshedSession, err := manager.RefreshSession(ctx, nil, store, false)
		if err != guardian.ErrSessionInvalid {
			t.Errorf("Expected ErrSessionInvalid, got %v", err)
		}
		if refreshedSession != nil {
			t.Error("Expected nil session for nil input")
		}
	})
}

func TestInvalidateSession(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	store := NewMockStore()
	ctx := createTestContext()

	// Create a user and session for testing
	user := createTestUser("user1")
	store.AddUser(user)

	session, err := manager.CreateSession(ctx, user.ID, store)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	t.Run("invalidate existing session", func(t *testing.T) {
		err := manager.InvalidateSession(ctx, session.Token, store)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		// Session should be removed from store
		retrievedSession, err := store.GetSession(ctx, session.Token)
		if err != nil {
			t.Fatalf("Error retrieving session: %v", err)
		}
		if retrievedSession != nil {
			t.Error("Expected session to be removed from store")
		}
	})

	t.Run("invalidate with empty token", func(t *testing.T) {
		err := manager.InvalidateSession(ctx, "", store)
		if err != guardian.ErrSessionInvalid {
			t.Errorf("Expected ErrSessionInvalid, got %v", err)
		}
	})

	t.Run("invalidate non-existent session", func(t *testing.T) {
		err := manager.InvalidateSession(ctx, "nonexistent", store)
		if err == nil {
			t.Error("Expected error for non-existent session")
		}
	})
}

func TestInvalidateAllUserSessions(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	store := NewMockStore()
	ctx := createTestContext()

	// Create a user and multiple sessions
	user := createTestUser("user1")
	store.AddUser(user)

	var sessions []*types.Session
	for i := 0; i < 3; i++ {
		session, err := manager.CreateSession(ctx, user.ID, store)
		if err != nil {
			t.Fatalf("Failed to create session %d: %v", i, err)
		}
		sessions = append(sessions, session)
	}

	t.Run("invalidate all user sessions", func(t *testing.T) {
		err := manager.InvalidateAllUserSessions(ctx, user.ID, store)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		// All sessions should be removed
		userSessions, err := store.GetSessionsByUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("Error getting user sessions: %v", err)
		}

		if len(userSessions) != 0 {
			t.Errorf("Expected 0 sessions, got %d", len(userSessions))
		}
	})

	t.Run("invalidate with empty user ID", func(t *testing.T) {
		err := manager.InvalidateAllUserSessions(ctx, "", store)
		if err != guardian.ErrInvalidInput {
			t.Errorf("Expected ErrInvalidInput, got %v", err)
		}
	})
}

func TestSessionLimits(t *testing.T) {
	// Create manager with low session limit
	config := DefaultConfig()
	config.MaxSessions = 2
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	store := NewMockStore()
	ctx := createTestContext()

	user := createTestUser("user1")
	store.AddUser(user)

	t.Run("session limit enforcement", func(t *testing.T) {
		// Create sessions up to the limit
		var sessions []*types.Session
		for i := 0; i < 2; i++ {
			session, err := manager.CreateSession(ctx, user.ID, store)
			if err != nil {
				t.Fatalf("Failed to create session %d: %v", i, err)
			}
			sessions = append(sessions, session)
			time.Sleep(1 * time.Millisecond) // Ensure different creation times
		}

		// Create one more session - should trigger limit enforcement
		newSession, err := manager.CreateSession(ctx, user.ID, store)
		if err != nil {
			t.Fatalf("Failed to create session beyond limit: %v", err)
		}

		// Should still have only 2 sessions (oldest one removed)
		userSessions, err := store.GetSessionsByUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("Error getting user sessions: %v", err)
		}

		if len(userSessions) != 2 {
			t.Errorf("Expected 2 sessions after limit enforcement, got %d", len(userSessions))
		}

		// The new session should exist
		found := false
		for _, session := range userSessions {
			if session.Token == newSession.Token {
				found = true
				break
			}
		}
		if !found {
			t.Error("New session not found in store")
		}
	})
}

func TestGetActiveSessions(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	store := NewMockStore()
	ctx := createTestContext()

	user := createTestUser("user1")
	store.AddUser(user)

	t.Run("get active sessions", func(t *testing.T) {
		// Create multiple sessions
		for i := 0; i < 3; i++ {
			_, err := manager.CreateSession(ctx, user.ID, store)
			if err != nil {
				t.Fatalf("Failed to create session %d: %v", i, err)
			}
		}

		activeSessions, err := manager.GetActiveSessions(ctx, user.ID, store)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if len(activeSessions) != 3 {
			t.Errorf("Expected 3 active sessions, got %d", len(activeSessions))
		}

		// All sessions should be active and not expired
		for _, session := range activeSessions {
			if !session.IsActive {
				t.Error("Expected all sessions to be active")
			}
			if session.IsExpired() {
				t.Error("Expected all sessions to be non-expired")
			}
		}
	})

	t.Run("get active sessions with empty user ID", func(t *testing.T) {
		activeSessions, err := manager.GetActiveSessions(ctx, "", store)
		if err != guardian.ErrInvalidInput {
			t.Errorf("Expected ErrInvalidInput, got %v", err)
		}
		if activeSessions != nil {
			t.Error("Expected nil sessions for empty user ID")
		}
	})
}

func TestCleanupExpiredSessions(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	store := NewMockStore()
	ctx := createTestContext()

	user := createTestUser("user1")
	store.AddUser(user)

	t.Run("cleanup expired sessions", func(t *testing.T) {
		// Create some active sessions
		for i := 0; i < 2; i++ {
			_, err := manager.CreateSession(ctx, user.ID, store)
			if err != nil {
				t.Fatalf("Failed to create session %d: %v", i, err)
			}
		}

		// Add an expired session manually
		expiredSession := &types.Session{
			Token:      "expired_token_cleanup",
			UserID:     user.ID,
			CreatedAt:  time.Now().UTC().Add(-2 * time.Hour),
			LastSeenAt: time.Now().UTC().Add(-2 * time.Hour),
			ExpiresAt:  time.Now().UTC().Add(-1 * time.Hour), // Expired
			IPAddress:  "192.168.1.1",
			UserAgent:  "Test-Agent/1.0",
			IsActive:   true,
		}
		store.CreateSession(ctx, expiredSession)

		initialCount := store.GetSessionCount()
		if initialCount != 3 {
			t.Errorf("Expected 3 initial sessions, got %d", initialCount)
		}

		// Run cleanup
		err := manager.CleanupExpiredSessions(ctx, store)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		// Should have removed 1 expired session
		finalCount := store.GetSessionCount()
		if finalCount != 2 {
			t.Errorf("Expected 2 sessions after cleanup, got %d", finalCount)
		}
	})
}

// Benchmark tests
func BenchmarkCreateSession(b *testing.B) {
	manager, err := NewManager(DefaultConfig())
	if err != nil {
		b.Fatalf("Failed to create manager: %v", err)
	}

	store := NewMockStore()
	ctx := createTestContext()

	user := createTestUser("benchmark_user")
	store.AddUser(user)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session, err := manager.CreateSession(ctx, user.ID, store)
		if err != nil {
			b.Fatalf("Failed to create session: %v", err)
		}
		// Clean up to avoid memory issues
		store.DeleteSession(ctx, session.Token)
	}
}

func BenchmarkValidateSession(b *testing.B) {
	manager, err := NewManager(DefaultConfig())
	if err != nil {
		b.Fatalf("Failed to create manager: %v", err)
	}

	store := NewMockStore()
	ctx := createTestContext()

	user := createTestUser("benchmark_user")
	store.AddUser(user)

	session, err := manager.CreateSession(ctx, user.ID, store)
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.ValidateSession(ctx, session.Token, store)
		if err != nil {
			b.Fatalf("Failed to validate session: %v", err)
		}
	}
}
