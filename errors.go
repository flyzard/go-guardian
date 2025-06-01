package guardian

import "errors"

// Common errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidEmail       = errors.New("invalid email")
	ErrWeakPassword       = errors.New("password too weak")
	ErrAccountLocked      = errors.New("account locked")
	ErrTooManyRequests    = errors.New("too many requests")
	ErrInvalidCaptcha     = errors.New("invalid captcha")
	ErrMFARequired        = errors.New("multi-factor authentication required")
	ErrInvalidMFACode     = errors.New("invalid MFA code")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrRoleNotFound       = errors.New("role not found")
	ErrPermissionNotFound = errors.New("permission not found")
	ErrInvalidCSRFToken   = errors.New("invalid CSRF token")
	ErrSessionExpired     = errors.New("session expired")
	ErrInvalidAPIKey      = errors.New("invalid API key")
	ErrEncryptionFailed   = errors.New("encryption failed")
	ErrDecryptionFailed   = errors.New("decryption failed")
)
