// Package auth provides authentication services for the go-guardian security library.
// This package handles user registration, login, logout, and account security features
// including rate limiting, account lockout, and comprehensive audit logging.
package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/flyzard/go-guardian"
	"github.com/flyzard/go-guardian/crypto"
	"github.com/flyzard/go-guardian/session"
	"github.com/flyzard/go-guardian/types"
	"github.com/flyzard/go-guardian/validator"
)

// Service provides authentication operations with comprehensive security features.
// It handles user registration, login, logout, and security policy enforcement.
type Service struct {
	sessionManager *session.Manager
	passwordHasher guardian.Hasher
	passwordPolicy *types.PasswordPolicy
	rateLimiter    guardian.RateLimiter
	logger         guardian.Logger
	metrics        guardian.MetricsCollector

	// Security configuration
	maxFailedAttempts int
	lockoutDuration   time.Duration
	rateLimitWindow   time.Duration
	rateLimitRequests int64
}

// Config holds configuration for the authentication service.
type Config struct {
	SessionTTL        time.Duration         `json:"session_ttl"`
	MaxSessions       int                   `json:"max_sessions"`
	MaxFailedAttempts int                   `json:"max_failed_attempts"`
	LockoutDuration   time.Duration         `json:"lockout_duration"`
	RateLimitWindow   time.Duration         `json:"rate_limit_window"`
	RateLimitRequests int64                 `json:"rate_limit_requests"`
	PasswordPolicy    *types.PasswordPolicy `json:"password_policy"`
}

// DefaultConfig returns a secure default configuration for the authentication service.
func DefaultConfig() *Config {
	defaultPolicy := types.DefaultPasswordPolicy()
	return &Config{
		SessionTTL:        24 * time.Hour,
		MaxSessions:       5,
		MaxFailedAttempts: 5,
		LockoutDuration:   15 * time.Minute,
		RateLimitWindow:   time.Hour,
		RateLimitRequests: 10,
		PasswordPolicy:    &defaultPolicy,
	}
}

// NewService creates a new authentication service with the provided dependencies.
func NewService(
	config *Config,
	hasher guardian.Hasher,
	rateLimiter guardian.RateLimiter,
	logger guardian.Logger,
	metrics guardian.MetricsCollector,
) (*Service, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if hasher == nil {
		return nil, fmt.Errorf("password hasher is required")
	}

	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Create session manager
	sessionConfig := session.Config{
		SessionTTL:  config.SessionTTL,
		MaxSessions: config.MaxSessions,
	}
	sessionManager, err := session.NewManager(sessionConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	return &Service{
		sessionManager:    sessionManager,
		passwordHasher:    hasher,
		passwordPolicy:    config.PasswordPolicy,
		rateLimiter:       rateLimiter,
		logger:            logger,
		metrics:           metrics,
		maxFailedAttempts: config.MaxFailedAttempts,
		lockoutDuration:   config.LockoutDuration,
		rateLimitWindow:   config.RateLimitWindow,
		rateLimitRequests: config.RateLimitRequests,
	}, nil
}

// Register creates a new user account with comprehensive validation and security checks.
// It validates input, checks for existing users, enforces password policies, and logs security events.
func (s *Service) Register(ctx context.Context, email, password string, store guardian.Store) (*types.User, error) {
	// Rate limiting check
	if s.rateLimiter != nil {
		rateLimitKey := fmt.Sprintf("register:%s", s.extractIPFromContext(ctx))
		allowed, _, err := s.rateLimiter.IsAllowed(ctx, rateLimitKey, s.rateLimitRequests, s.rateLimitWindow)
		if err != nil {
			s.logError(ctx, "Rate limit check failed during registration", err, "email", email)
			return nil, fmt.Errorf("rate limit check failed: %w", err)
		}
		if !allowed {
			s.logSecurityEvent(ctx, "", email, types.EventTypeRegistrationRateLimited, "Rate limit exceeded for registration")
			s.recordMetric("registration_rate_limited", map[string]string{"ip": s.extractIPFromContext(ctx)})
			return nil, guardian.ErrRateLimitExceeded
		}
	}

	// Input validation
	email = strings.TrimSpace(strings.ToLower(email))
	if err := validator.ValidateEmail(email); err != nil {
		s.logSecurityEvent(ctx, "", email, types.EventTypeRegistrationFailed, "Invalid email format")
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	if err := validator.ValidatePassword(password, *s.passwordPolicy); err != nil {
		s.logSecurityEvent(ctx, "", email, types.EventTypeRegistrationFailed, "Password policy violation")
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Check if user already exists
	existingUser, err := store.GetUserByEmail(ctx, email)
	if err != nil && err != guardian.ErrUserNotFound {
		s.logError(ctx, "Database error during user existence check", err, "email", email)
		return nil, fmt.Errorf("failed to check user existence: %w", err)
	}
	if existingUser != nil {
		s.logSecurityEvent(ctx, "", email, types.EventTypeRegistrationFailed, "Email already exists")
		return nil, guardian.ErrUserExists
	}

	// Hash password
	passwordHash, err := s.passwordHasher.Hash(ctx, password)
	if err != nil {
		s.logError(ctx, "Failed to hash password during registration", err, "email", email)
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &types.User{
		ID:             generateUserID(),
		Email:          email,
		PasswordHash:   passwordHash,
		EmailVerified:  false,
		AccountLocked:  false,
		FailedAttempts: 0,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
		TwoFAEnabled:   false,
	}

	// Store user
	if err := store.CreateUser(ctx, user); err != nil {
		s.logError(ctx, "Failed to create user in database", err, "email", email, "userID", user.ID)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Log successful registration
	s.logSecurityEvent(ctx, user.ID, email, types.EventTypeUserRegistered, "User successfully registered")
	s.recordMetric("registration_success", map[string]string{"method": "email"})

	// Clear password from memory
	user.PasswordHash = ""

	s.logger.Info(ctx, "User registered successfully",
		guardian.LogField{Key: "userID", Value: user.ID},
		guardian.LogField{Key: "email", Value: email},
	)

	return user, nil
}

// Login authenticates a user and creates a new session with comprehensive security checks.
// It validates credentials, enforces account lockout policies, and logs authentication attempts.
func (s *Service) Login(ctx context.Context, email, password string, store guardian.Store) (*types.Session, error) {
	// Rate limiting check
	if s.rateLimiter != nil {
		rateLimitKey := fmt.Sprintf("login:%s", s.extractIPFromContext(ctx))
		allowed, _, err := s.rateLimiter.IsAllowed(ctx, rateLimitKey, s.rateLimitRequests, s.rateLimitWindow)
		if err != nil {
			s.logError(ctx, "Rate limit check failed during login", err, "email", email)
			return nil, fmt.Errorf("rate limit check failed: %w", err)
		}
		if !allowed {
			s.logSecurityEvent(ctx, "", email, types.EventTypeLoginRateLimited, "Rate limit exceeded for login")
			s.recordMetric("login_rate_limited", map[string]string{"ip": s.extractIPFromContext(ctx)})
			return nil, guardian.ErrRateLimitExceeded
		}
	}

	// Input validation
	email = strings.TrimSpace(strings.ToLower(email))
	if err := validator.ValidateEmail(email); err != nil {
		s.logSecurityEvent(ctx, "", email, types.EventTypeLoginFailed, "Invalid email format")
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	if len(password) == 0 {
		s.logSecurityEvent(ctx, "", email, types.EventTypeLoginFailed, "Empty password")
		return nil, guardian.ErrInvalidCredentials
	}

	// Get user
	user, err := store.GetUserByEmail(ctx, email)
	if err != nil {
		if err == guardian.ErrUserNotFound {
			s.logSecurityEvent(ctx, "", email, types.EventTypeLoginFailed, "User not found")
			s.recordMetric("login_failed", map[string]string{"reason": "user_not_found"})
			return nil, guardian.ErrInvalidCredentials
		}
		s.logError(ctx, "Database error during user lookup", err, "email", email)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if account is locked
	if user.IsLocked() {
		s.logSecurityEvent(ctx, user.ID, email, types.EventTypeLoginFailed, "Account is locked")
		s.recordMetric("login_failed", map[string]string{"reason": "account_locked"})
		return nil, guardian.ErrAccountLocked
	}

	// Verify password
	if err := s.passwordHasher.Verify(ctx, password, user.PasswordHash); err != nil {
		// Increment failed attempts
		user.FailedAttempts++
		user.UpdatedAt = time.Now().UTC()

		// Lock account if max attempts exceeded
		if user.FailedAttempts >= s.maxFailedAttempts {
			user.AccountLocked = true
			s.logSecurityEvent(ctx, user.ID, email, types.EventTypeAccountLocked,
				fmt.Sprintf("Account locked after %d failed attempts", s.maxFailedAttempts))
		}

		// Update user in store
		if updateErr := store.UpdateUser(ctx, user); updateErr != nil {
			s.logError(ctx, "Failed to update user after failed login", updateErr, "userID", user.ID)
		}

		s.logSecurityEvent(ctx, user.ID, email, types.EventTypeLoginFailed, "Invalid password")
		s.recordMetric("login_failed", map[string]string{"reason": "invalid_password"})
		return nil, guardian.ErrInvalidCredentials
	}

	// Reset failed attempts on successful login
	if user.FailedAttempts > 0 {
		user.FailedAttempts = 0
		user.UpdatedAt = time.Now().UTC()
	}

	// Update last login time
	now := time.Now().UTC()
	user.LastLoginAt = &now
	user.UpdatedAt = now

	if err := store.UpdateUser(ctx, user); err != nil {
		s.logError(ctx, "Failed to update user after successful login", err, "userID", user.ID)
		// Don't fail the login for this error, just log it
	}

	// Create session
	sessionObj, err := s.sessionManager.CreateSession(ctx, user.ID, store)
	if err != nil {
		s.logError(ctx, "Failed to create session", err, "userID", user.ID)
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Log successful login
	s.logSecurityEvent(ctx, user.ID, email, types.EventTypeLogin, "User successfully logged in")
	s.recordMetric("login_success", map[string]string{"method": "email"})

	s.logger.Info(ctx, "User logged in successfully",
		guardian.LogField{Key: "userID", Value: user.ID},
		guardian.LogField{Key: "email", Value: email},
		guardian.LogField{Key: "sessionToken", Value: sessionObj.Token[:8] + "..."},
	)

	return sessionObj, nil
}

// Logout invalidates a single session and logs the security event.
func (s *Service) Logout(ctx context.Context, token string, store guardian.Store) error {
	// Validate token format
	if len(token) == 0 {
		return guardian.ErrTokenInvalid
	}

	// Get session to log user information
	session, err := store.GetSession(ctx, token)
	if err != nil {
		if err == guardian.ErrSessionNotFound {
			return guardian.ErrTokenInvalid
		}
		s.logError(ctx, "Database error during session lookup for logout", err, "token", token[:8]+"...")
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Invalidate session
	if err := s.sessionManager.InvalidateSession(ctx, token, store); err != nil {
		s.logError(ctx, "Failed to invalidate session", err, "userID", session.UserID, "token", token[:8]+"...")
		return fmt.Errorf("failed to invalidate session: %w", err)
	}

	// Log logout event
	s.logSecurityEvent(ctx, session.UserID, "", types.SecurityEventUserLoggedOut, "User logged out")
	s.recordMetric("logout_success", map[string]string{"method": "single"})

	s.logger.Info(ctx, "User logged out successfully",
		guardian.LogField{Key: "userID", Value: session.UserID},
		guardian.LogField{Key: "sessionToken", Value: token[:8] + "..."},
	)

	return nil
}

// LogoutAll invalidates all sessions for a user and logs the security event.
func (s *Service) LogoutAll(ctx context.Context, userID string, store guardian.Store) error {
	// Validate userID
	if len(userID) == 0 {
		return guardian.ErrInvalidInput
	}

	// Check if user exists
	_, err := store.GetUser(ctx, userID)
	if err != nil {
		if err == guardian.ErrUserNotFound {
			return guardian.ErrUserNotFound
		}
		s.logError(ctx, "Database error during user lookup for logout all", err, "userID", userID)
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Get user sessions to count them
	sessions, err := store.GetSessionsByUser(ctx, userID)
	if err != nil {
		s.logError(ctx, "Failed to get user sessions for logout all", err, "userID", userID)
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Invalidate all user sessions
	if err := s.sessionManager.InvalidateAllUserSessions(ctx, userID, store); err != nil {
		s.logError(ctx, "Failed to invalidate all user sessions", err, "userID", userID)
		return fmt.Errorf("failed to invalidate user sessions: %w", err)
	}

	// Log logout all event
	s.logSecurityEvent(ctx, userID, "", types.SecurityEventUserLoggedOutAll,
		fmt.Sprintf("All user sessions invalidated (%d sessions)", len(sessions)))
	s.recordMetric("logout_success", map[string]string{"method": "all", "session_count": fmt.Sprintf("%d", len(sessions))})

	s.logger.Info(ctx, "All user sessions logged out successfully",
		guardian.LogField{Key: "userID", Value: userID},
		guardian.LogField{Key: "sessionCount", Value: len(sessions)},
	)

	return nil
}

// Helper methods

// generateUserID creates a unique user ID.
func generateUserID() string {
	// Use crypto package to generate secure random ID
	tokenGen := crypto.NewSecureTokenGenerator()
	token, err := tokenGen.GenerateSecureRandom(context.Background(), 16)
	if err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("user_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("user_%x", token)
}

// extractIPFromContext extracts IP address from context.
func (s *Service) extractIPFromContext(ctx context.Context) string {
	if ip, ok := ctx.Value("ip_address").(string); ok {
		return ip
	}
	return "unknown"
}

// extractUserAgentFromContext extracts User-Agent from context.
func (s *Service) extractUserAgentFromContext(ctx context.Context) string {
	if ua, ok := ctx.Value("user_agent").(string); ok {
		return ua
	}
	return "unknown"
}

// logSecurityEvent logs a security event if logger is available.
func (s *Service) logSecurityEvent(ctx context.Context, userID, email string, eventType types.SecurityEventType, details string) {
	if s.logger == nil {
		return
	}

	event := &types.SecurityEvent{
		ID:        generateEventID(),
		UserID:    userID,
		Type:      eventType,
		Reason:    details,
		IPAddress: s.extractIPFromContext(ctx),
		UserAgent: s.extractUserAgentFromContext(ctx),
		Timestamp: time.Now().UTC(),
		Metadata: map[string]interface{}{
			"email":     email,
			"component": "auth.Service",
		},
	}

	s.logger.LogSecurityEvent(ctx, event)
}

// logError logs an error with context information.
func (s *Service) logError(ctx context.Context, message string, err error, fields ...interface{}) {
	if s.logger == nil {
		return
	}

	logFields := []guardian.LogField{
		{Key: "error", Value: err.Error()},
		{Key: "component", Value: "auth.Service"},
	}

	// Add additional fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			logFields = append(logFields, guardian.LogField{Key: key, Value: fields[i+1]})
		}
	}

	s.logger.Error(ctx, message, logFields...)
}

// recordMetric records a metric if metrics collector is available.
func (s *Service) recordMetric(name string, labels map[string]string) {
	if s.metrics == nil {
		return
	}
	s.metrics.IncrementCounter(name, labels)
}

// generateEventID creates a unique event ID.
func generateEventID() string {
	tokenGen := crypto.NewSecureTokenGenerator()
	token, err := tokenGen.GenerateSecureRandom(context.Background(), 8)
	if err != nil {
		return fmt.Sprintf("event_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("event_%x", token)
}
