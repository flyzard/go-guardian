package session

import (
	"context"
	"fmt"
	"time"

	"github.com/flyzard/go-guardian"
	"github.com/flyzard/go-guardian/crypto"
	"github.com/flyzard/go-guardian/types"
)

// Manager provides session management functionality
type Manager struct {
	tokenGenerator guardian.TokenGenerator
	sessionTTL     time.Duration
	maxSessions    int
}

// Config holds session manager configuration
type Config struct {
	// SessionTTL is the time-to-live for sessions
	SessionTTL time.Duration
	// MaxSessions is the maximum number of concurrent sessions per user
	MaxSessions int
	// TokenGenerator generates secure tokens for sessions
	TokenGenerator guardian.TokenGenerator
}

// DefaultConfig returns a configuration with secure defaults
func DefaultConfig() Config {
	return Config{
		SessionTTL:     24 * time.Hour,                   // 24 hours
		MaxSessions:    5,                                // Maximum 5 concurrent sessions
		TokenGenerator: crypto.NewSecureTokenGenerator(), // Default secure token generator
	}
}

// Validate ensures the configuration is valid
func (c Config) Validate() error {
	if c.SessionTTL <= 0 {
		return guardian.ErrConfigInvalid
	}
	if c.MaxSessions <= 0 {
		return guardian.ErrConfigInvalid
	}
	if c.TokenGenerator == nil {
		return guardian.ErrConfigInvalid
	}
	return nil
}

// NewManager creates a new session manager with the given configuration
func NewManager(config Config) (*Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid session config: %w", err)
	}

	return &Manager{
		tokenGenerator: config.TokenGenerator,
		sessionTTL:     config.SessionTTL,
		maxSessions:    config.MaxSessions,
	}, nil
}

// CreateSession creates a new session for the given user
func (m *Manager) CreateSession(ctx context.Context, userID string, store guardian.Store) (*types.Session, error) {
	if userID == "" {
		return nil, guardian.ErrInvalidInput
	}

	// Check if user exists
	user, err := store.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, guardian.ErrUserNotFound
	}

	// Check session limits
	if err := m.enforceSessionLimits(ctx, userID, store); err != nil {
		return nil, fmt.Errorf("session limit enforcement failed: %w", err)
	}

	// Generate secure session token
	token, err := m.tokenGenerator.GenerateSessionToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Create session
	now := time.Now().UTC()
	session := &types.Session{
		Token:      token,
		UserID:     userID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(m.sessionTTL),
		IPAddress:  extractIPFromContext(ctx),
		UserAgent:  extractUserAgentFromContext(ctx),
		IsActive:   true,
	}

	// Store session
	if err := store.CreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// Log security event
	event := &types.SecurityEvent{
		Type:      types.SecurityEventType("session_created"),
		UserID:    userID,
		IPAddress: session.IPAddress,
		UserAgent: session.UserAgent,
		Success:   true,
		Timestamp: now,
		Metadata: map[string]interface{}{
			"session_token": session.Token,
		},
	}
	_ = store.LogSecurityEvent(ctx, event) // Log but don't fail on logging errors

	return session, nil
}

// ValidateSession validates a session token and returns the session if valid
func (m *Manager) ValidateSession(ctx context.Context, token string, store guardian.Store) (*types.Session, error) {
	if token == "" {
		return nil, guardian.ErrSessionInvalid
	}

	// Get session by token
	session, err := store.GetSession(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	if session == nil {
		return nil, guardian.ErrSessionNotFound
	}

	// Check if session is active
	if !session.IsActive {
		return nil, guardian.ErrSessionExpired
	}

	// Check if session is expired
	if time.Now().UTC().After(session.ExpiresAt) {
		// Mark session as inactive and remove it
		_ = m.InvalidateSession(ctx, token, store)
		return nil, guardian.ErrSessionExpired
	}

	// Update last accessed time
	updatedSession := session.WithUpdatedLastSeen()
	if err := store.UpdateSession(ctx, updatedSession); err != nil {
		// Log but don't fail - session is still valid
		_ = store.LogSecurityEvent(ctx, &types.SecurityEvent{
			Type:      types.SecurityEventType("session_update_failed"),
			UserID:    session.UserID,
			IPAddress: extractIPFromContext(ctx),
			Success:   false,
			Reason:    err.Error(),
			Timestamp: time.Now().UTC(),
			Metadata: map[string]interface{}{
				"session_token": session.Token,
			},
		})
	}

	return updatedSession, nil
}

// RefreshSession extends the session expiration time and optionally rotates the token
func (m *Manager) RefreshSession(ctx context.Context, session *types.Session, store guardian.Store, rotateToken bool) (*types.Session, error) {
	if session == nil {
		return nil, guardian.ErrSessionInvalid
	}

	// Verify session is still valid
	currentSession, err := m.ValidateSession(ctx, session.Token, store)
	if err != nil {
		return nil, err
	}

	// Create refreshed session
	refreshedSession := *currentSession
	refreshedSession.ExpiresAt = time.Now().UTC().Add(m.sessionTTL)
	refreshedSession.LastSeenAt = time.Now().UTC()

	// Rotate token if requested
	if rotateToken {
		newToken, err := m.tokenGenerator.GenerateSessionToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new token: %w", err)
		}

		// Invalidate old session
		if err := m.InvalidateSession(ctx, currentSession.Token, store); err != nil {
			return nil, fmt.Errorf("failed to invalidate old session: %w", err)
		}

		// Update with new token and creation time
		refreshedSession.Token = newToken
		refreshedSession.CreatedAt = time.Now().UTC()

		// Store new session
		if err := store.CreateSession(ctx, &refreshedSession); err != nil {
			return nil, fmt.Errorf("failed to store refreshed session: %w", err)
		}
	} else {
		// Update existing session
		if err := store.UpdateSession(ctx, &refreshedSession); err != nil {
			return nil, fmt.Errorf("failed to update session: %w", err)
		}
	}

	// Log security event
	event := &types.SecurityEvent{
		Type:      types.SecurityEventType("session_refreshed"),
		UserID:    refreshedSession.UserID,
		IPAddress: extractIPFromContext(ctx),
		UserAgent: extractUserAgentFromContext(ctx),
		Success:   true,
		Timestamp: time.Now().UTC(),
		Metadata: map[string]interface{}{
			"session_token": refreshedSession.Token,
			"token_rotated": rotateToken,
			"expires_at":    refreshedSession.ExpiresAt,
		},
	}
	_ = store.LogSecurityEvent(ctx, event)

	return &refreshedSession, nil
}

// InvalidateSession invalidates a session by token
func (m *Manager) InvalidateSession(ctx context.Context, token string, store guardian.Store) error {
	if token == "" {
		return guardian.ErrSessionInvalid
	}

	// Get session to log the invalidation
	session, err := store.GetSession(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}
	if session == nil {
		return guardian.ErrSessionNotFound
	}

	// Remove session from store
	if err := store.DeleteSession(ctx, token); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Log security event
	event := &types.SecurityEvent{
		Type:      types.SecurityEventType("session_invalidated"),
		UserID:    session.UserID,
		IPAddress: extractIPFromContext(ctx),
		UserAgent: extractUserAgentFromContext(ctx),
		Success:   true,
		Timestamp: time.Now().UTC(),
		Metadata: map[string]interface{}{
			"session_token": session.Token,
		},
	}
	_ = store.LogSecurityEvent(ctx, event)

	return nil
}

// InvalidateAllUserSessions invalidates all sessions for a specific user
func (m *Manager) InvalidateAllUserSessions(ctx context.Context, userID string, store guardian.Store) error {
	if userID == "" {
		return guardian.ErrInvalidInput
	}

	// Get all user sessions
	sessions, err := store.GetSessionsByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Delete all sessions
	var invalidationErrors []error
	for _, session := range sessions {
		if err := store.DeleteSession(ctx, session.Token); err != nil {
			invalidationErrors = append(invalidationErrors, err)
		}
	}

	// Log security event
	event := &types.SecurityEvent{
		Type:      types.SecurityEventType("all_sessions_invalidated"),
		UserID:    userID,
		IPAddress: extractIPFromContext(ctx),
		UserAgent: extractUserAgentFromContext(ctx),
		Success:   len(invalidationErrors) == 0,
		Timestamp: time.Now().UTC(),
		Metadata: map[string]interface{}{
			"sessions_count": len(sessions),
			"errors_count":   len(invalidationErrors),
		},
	}
	_ = store.LogSecurityEvent(ctx, event)

	// Return error if any invalidations failed
	if len(invalidationErrors) > 0 {
		return fmt.Errorf("failed to invalidate %d of %d sessions", len(invalidationErrors), len(sessions))
	}

	return nil
}

// GetActiveSessions returns all active sessions for a user
func (m *Manager) GetActiveSessions(ctx context.Context, userID string, store guardian.Store) ([]*types.Session, error) {
	if userID == "" {
		return nil, guardian.ErrInvalidInput
	}

	sessions, err := store.GetSessionsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Filter active and non-expired sessions
	var activeSessions []*types.Session
	now := time.Now().UTC()
	for _, session := range sessions {
		if session.IsActive && now.Before(session.ExpiresAt) {
			activeSessions = append(activeSessions, session)
		}
	}

	return activeSessions, nil
}

// CleanupExpiredSessions removes expired sessions from storage
func (m *Manager) CleanupExpiredSessions(ctx context.Context, store guardian.Store) error {
	deletedCount, err := store.DeleteExpiredSessions(ctx)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	// Log cleanup event if sessions were deleted
	if deletedCount > 0 {
		event := &types.SecurityEvent{
			Type:      types.SecurityEventType("expired_sessions_cleaned"),
			IPAddress: extractIPFromContext(ctx),
			Success:   true,
			Timestamp: time.Now().UTC(),
			Metadata: map[string]interface{}{
				"deleted_count": deletedCount,
			},
		}
		_ = store.LogSecurityEvent(ctx, event)
	}

	return nil
}

// enforceSessionLimits ensures the user doesn't exceed maximum concurrent sessions
func (m *Manager) enforceSessionLimits(ctx context.Context, userID string, store guardian.Store) error {
	activeSessions, err := m.GetActiveSessions(ctx, userID, store)
	if err != nil {
		return err
	}

	if len(activeSessions) >= m.maxSessions {
		// Remove oldest session to make room for new one
		var oldestSession *types.Session
		for _, session := range activeSessions {
			if oldestSession == nil || session.CreatedAt.Before(oldestSession.CreatedAt) {
				oldestSession = session
			}
		}

		if oldestSession != nil {
			if err := m.InvalidateSession(ctx, oldestSession.Token, store); err != nil {
				return fmt.Errorf("failed to invalidate oldest session: %w", err)
			}

			// Log session limit enforcement
			event := &types.SecurityEvent{
				Type:      types.SecurityEventType("session_limit_enforced"),
				UserID:    userID,
				IPAddress: extractIPFromContext(ctx),
				Success:   true,
				Timestamp: time.Now().UTC(),
				Metadata: map[string]interface{}{
					"max_sessions":          m.maxSessions,
					"removed_session_token": oldestSession.Token,
				},
			}
			_ = store.LogSecurityEvent(ctx, event)
		}
	}

	return nil
}

// generateSessionID generates a unique session ID (keeping for potential future use)
// func generateSessionID() string {
// 	bytes := make([]byte, 16)
// 	if _, err := rand.Read(bytes); err != nil {
// 		// Fallback to timestamp-based ID if random generation fails
// 		return fmt.Sprintf("session_%d", time.Now().UnixNano())
// 	}
// 	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
// }

// extractIPFromContext extracts IP address from context
func extractIPFromContext(ctx context.Context) string {
	if ip, ok := ctx.Value("ip_address").(string); ok {
		return ip
	}
	return "unknown"
}

// extractUserAgentFromContext extracts user agent from context
func extractUserAgentFromContext(ctx context.Context) string {
	if ua, ok := ctx.Value("user_agent").(string); ok {
		return ua
	}
	return "unknown"
}
