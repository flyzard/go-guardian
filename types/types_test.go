package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUser_IsValid(t *testing.T) {
	tests := []struct {
		name string
		user User
		want bool
	}{
		{
			name: "valid user",
			user: User{
				ID:           "user123",
				Email:        "test@example.com",
				PasswordHash: "hashedpassword",
			},
			want: true,
		},
		{
			name: "missing ID",
			user: User{
				Email:        "test@example.com",
				PasswordHash: "hashedpassword",
			},
			want: false,
		},
		{
			name: "missing email",
			user: User{
				ID:           "user123",
				PasswordHash: "hashedpassword",
			},
			want: false,
		},
		{
			name: "missing password hash",
			user: User{
				ID:    "user123",
				Email: "test@example.com",
			},
			want: false,
		},
		{
			name: "empty user",
			user: User{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.user.IsValid(); got != tt.want {
				t.Errorf("User.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_IsLocked(t *testing.T) {
	tests := []struct {
		name string
		user User
		want bool
	}{
		{
			name: "account locked",
			user: User{AccountLocked: true},
			want: true,
		},
		{
			name: "account not locked",
			user: User{AccountLocked: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.user.IsLocked(); got != tt.want {
				t.Errorf("User.IsLocked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_JSONMarshaling(t *testing.T) {
	user := User{
		ID:             "user123",
		Email:          "test@example.com",
		PasswordHash:   "secret",    // Should not appear in JSON
		FailedAttempts: 3,           // Should not appear in JSON
		TwoFASecret:    "secret2fa", // Should not appear in JSON
		EmailVerified:  true,
		AccountLocked:  false,
		CreatedAt:      time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:      time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
	}

	jsonData, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Failed to marshal user: %v", err)
	}

	jsonStr := string(jsonData)

	// Check that sensitive fields are not in JSON
	if contains(jsonStr, "secret") || contains(jsonStr, "secret2fa") || contains(jsonStr, "failed_attempts") {
		t.Errorf("Sensitive fields found in JSON: %s", jsonStr)
	}

	// Check that public fields are in JSON
	if !contains(jsonStr, "user123") || !contains(jsonStr, "test@example.com") {
		t.Errorf("Expected public fields not found in JSON: %s", jsonStr)
	}

	// Test unmarshaling
	var unmarshaled User
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal user: %v", err)
	}

	if unmarshaled.ID != user.ID || unmarshaled.Email != user.Email {
		t.Errorf("Unmarshaled user doesn't match original public fields")
	}
}

func TestSession_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		session Session
		want    bool
	}{
		{
			name: "not expired",
			session: Session{
				ExpiresAt: now.Add(time.Hour),
			},
			want: false,
		},
		{
			name: "expired",
			session: Session{
				ExpiresAt: now.Add(-time.Hour),
			},
			want: true,
		},
		{
			name: "expires exactly now",
			session: Session{
				ExpiresAt: now,
			},
			want: true, // After check should be true
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.session.IsExpired(); got != tt.want {
				t.Errorf("Session.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_IsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		session Session
		want    bool
	}{
		{
			name: "valid session",
			session: Session{
				Token:     "validtoken",
				UserID:    "user123",
				IsActive:  true,
				ExpiresAt: now.Add(time.Hour),
			},
			want: true,
		},
		{
			name: "missing token",
			session: Session{
				UserID:    "user123",
				IsActive:  true,
				ExpiresAt: now.Add(time.Hour),
			},
			want: false,
		},
		{
			name: "missing user ID",
			session: Session{
				Token:     "validtoken",
				IsActive:  true,
				ExpiresAt: now.Add(time.Hour),
			},
			want: false,
		},
		{
			name: "inactive session",
			session: Session{
				Token:     "validtoken",
				UserID:    "user123",
				IsActive:  false,
				ExpiresAt: now.Add(time.Hour),
			},
			want: false,
		},
		{
			name: "expired session",
			session: Session{
				Token:     "validtoken",
				UserID:    "user123",
				IsActive:  true,
				ExpiresAt: now.Add(-time.Hour),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.session.IsValid(); got != tt.want {
				t.Errorf("Session.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_RemainingTime(t *testing.T) {
	now := time.Now()
	hour := time.Hour

	tests := []struct {
		name    string
		session Session
		want    time.Duration
	}{
		{
			name: "one hour remaining",
			session: Session{
				ExpiresAt: now.Add(hour),
			},
			want: hour,
		},
		{
			name: "expired session",
			session: Session{
				ExpiresAt: now.Add(-hour),
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.session.RemainingTime()
			// Allow for small timing differences (within 1 second)
			if got < tt.want-time.Second || got > tt.want+time.Second {
				t.Errorf("Session.RemainingTime() = %v, want approximately %v", got, tt.want)
			}
		})
	}
}

func TestSession_WithUpdatedLastSeen(t *testing.T) {
	original := &Session{
		Token:      "token123",
		UserID:     "user123",
		LastSeenAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	updated := original.WithUpdatedLastSeen()

	// Check immutability - original should not be modified
	if original.LastSeenAt.After(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("Original session was modified (not immutable)")
	}

	// Check that new session has updated time
	if !updated.LastSeenAt.After(original.LastSeenAt) {
		t.Error("Updated session should have newer LastSeenAt")
	}

	// Check that other fields are copied
	if updated.Token != original.Token || updated.UserID != original.UserID {
		t.Error("Other fields should be copied to updated session")
	}
}

func TestToken_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name  string
		token Token
		want  bool
	}{
		{
			name: "not expired",
			token: Token{
				ExpiresAt: now.Add(time.Hour),
			},
			want: false,
		},
		{
			name: "expired",
			token: Token{
				ExpiresAt: now.Add(-time.Hour),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.IsExpired(); got != tt.want {
				t.Errorf("Token.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_IsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name  string
		token Token
		want  bool
	}{
		{
			name: "valid token",
			token: Token{
				Value:     "validtoken",
				ExpiresAt: now.Add(time.Hour),
				IsUsed:    false,
			},
			want: true,
		},
		{
			name: "expired token",
			token: Token{
				Value:     "validtoken",
				ExpiresAt: now.Add(-time.Hour),
				IsUsed:    false,
			},
			want: false,
		},
		{
			name: "used token",
			token: Token{
				Value:     "validtoken",
				ExpiresAt: now.Add(time.Hour),
				IsUsed:    true,
			},
			want: false,
		},
		{
			name: "empty value",
			token: Token{
				Value:     "",
				ExpiresAt: now.Add(time.Hour),
				IsUsed:    false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.IsValid(); got != tt.want {
				t.Errorf("Token.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_MarkAsUsed(t *testing.T) {
	original := &Token{
		Value:  "token123",
		IsUsed: false,
		UsedAt: nil,
	}

	used := original.MarkAsUsed()

	// Check immutability - original should not be modified
	if original.IsUsed || original.UsedAt != nil {
		t.Error("Original token was modified (not immutable)")
	}

	// Check that new token is marked as used
	if !used.IsUsed || used.UsedAt == nil {
		t.Error("New token should be marked as used with timestamp")
	}

	// Check that other fields are copied
	if used.Value != original.Value {
		t.Error("Other fields should be copied to new token")
	}
}

func TestSecurityEvent_IsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name  string
		event SecurityEvent
		want  bool
	}{
		{
			name: "valid event",
			event: SecurityEvent{
				Type:      EventTypeLogin,
				IPAddress: "192.168.1.1",
				Timestamp: now,
			},
			want: true,
		},
		{
			name: "missing type",
			event: SecurityEvent{
				IPAddress: "192.168.1.1",
				Timestamp: now,
			},
			want: false,
		},
		{
			name: "missing IP address",
			event: SecurityEvent{
				Type:      EventTypeLogin,
				Timestamp: now,
			},
			want: false,
		},
		{
			name: "zero timestamp",
			event: SecurityEvent{
				Type:      EventTypeLogin,
				IPAddress: "192.168.1.1",
				Timestamp: time.Time{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.event.IsValid(); got != tt.want {
				t.Errorf("SecurityEvent.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRole_HasPermission(t *testing.T) {
	role := Role{
		Permissions: []Permission{
			PermissionReadUsers,
			PermissionWriteUsers,
		},
	}

	tests := []struct {
		name       string
		permission Permission
		want       bool
	}{
		{
			name:       "has permission",
			permission: PermissionReadUsers,
			want:       true,
		},
		{
			name:       "does not have permission",
			permission: PermissionDeleteUsers,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := role.HasPermission(tt.permission); got != tt.want {
				t.Errorf("Role.HasPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRole_IsValid(t *testing.T) {
	tests := []struct {
		name string
		role Role
		want bool
	}{
		{
			name: "valid role",
			role: Role{
				Name:        "admin",
				Permissions: []Permission{PermissionReadUsers},
				IsActive:    true,
			},
			want: true,
		},
		{
			name: "missing name",
			role: Role{
				Permissions: []Permission{PermissionReadUsers},
				IsActive:    true,
			},
			want: false,
		},
		{
			name: "no permissions",
			role: Role{
				Name:     "admin",
				IsActive: true,
			},
			want: false,
		},
		{
			name: "inactive role",
			role: Role{
				Name:        "admin",
				Permissions: []Permission{PermissionReadUsers},
				IsActive:    false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.role.IsValid(); got != tt.want {
				t.Errorf("Role.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPasswordPolicy_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		policy PasswordPolicy
		want   bool
	}{
		{
			name: "valid policy",
			policy: PasswordPolicy{
				MinLength: 8,
			},
			want: true,
		},
		{
			name: "minimum length too short",
			policy: PasswordPolicy{
				MinLength: 3,
			},
			want: false,
		},
		{
			name: "minimum length too long",
			policy: PasswordPolicy{
				MinLength: 200,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.IsValid(); got != tt.want {
				t.Errorf("PasswordPolicy.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultPasswordPolicy(t *testing.T) {
	policy := DefaultPasswordPolicy()

	if !policy.IsValid() {
		t.Error("Default password policy should be valid")
	}

	// Check expected defaults
	if policy.MinLength != 8 {
		t.Errorf("Expected MinLength=8, got %d", policy.MinLength)
	}

	if !policy.RequireUppercase || !policy.RequireLowercase || !policy.RequireNumbers {
		t.Error("Default policy should require uppercase, lowercase, and numbers")
	}

	if !policy.PreventCommon || !policy.PreventUserInfo {
		t.Error("Default policy should prevent common passwords and user info")
	}
}

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()

	// Check that all values are reasonable
	if config.LoginAttempts <= 0 || config.LoginAttempts > 100 {
		t.Errorf("LoginAttempts should be reasonable, got %d", config.LoginAttempts)
	}

	if config.LoginWindow <= 0 {
		t.Errorf("LoginWindow should be positive, got %v", config.LoginWindow)
	}

	if config.APIRequestsPerHour <= 0 {
		t.Errorf("APIRequestsPerHour should be positive, got %d", config.APIRequestsPerHour)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (len(substr) == 0 || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Benchmark tests for performance-critical operations
func BenchmarkSession_IsValid(b *testing.B) {
	session := Session{
		Token:     "validtoken",
		UserID:    "user123",
		IsActive:  true,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.IsValid()
	}
}

func BenchmarkRole_HasPermission(b *testing.B) {
	role := Role{
		Permissions: []Permission{
			PermissionReadUsers,
			PermissionWriteUsers,
			PermissionDeleteUsers,
			PermissionReadSessions,
			PermissionManageRoles,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		role.HasPermission(PermissionManageRoles)
	}
}
