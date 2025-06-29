package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

type Token struct {
	Value     string
	UserID    int64
	Purpose   string // "email_verification" or "password_reset"
	ExpiresAt time.Time
}

// GenerateToken creates a secure random token
func GenerateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Service) CreateVerificationToken(userID int64) (*Token, error) {
	if !s.features.EmailVerification {
		return nil, ErrFeatureDisabled
	}

	token := &Token{
		Value:     GenerateToken(),
		UserID:    userID,
		Purpose:   "email_verification",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	query := fmt.Sprintf(`
        INSERT INTO %s (%s, %s, %s, %s)
        VALUES (?, ?, ?, ?)
    `, s.tables.Tokens, s.columns.TokenValue, s.columns.TokenUserID,
		s.columns.TokenPurpose, s.columns.TokenExpires)

	_, err := s.db.Exec(query, token.Value, token.UserID, token.Purpose, token.ExpiresAt)

	return token, err
}

func (s *Service) CreatePasswordResetToken(email string) (*Token, error) {
	if !s.features.PasswordReset {
		return nil, ErrFeatureDisabled
	}

	user, err := s.findUserByEmail(email)
	if err != nil {
		return nil, err
	}

	token := &Token{
		Value:     GenerateToken(),
		UserID:    user.ID,
		Purpose:   "password_reset",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	query := fmt.Sprintf(`
        INSERT INTO %s (%s, %s, %s, %s)
        VALUES (?, ?, ?, ?)
    `, s.tables.Tokens, s.columns.TokenValue, s.columns.TokenUserID,
		s.columns.TokenPurpose, s.columns.TokenExpires)

	_, err = s.db.Exec(query, token.Value, token.UserID, token.Purpose, token.ExpiresAt)

	return token, err
}

func (s *Service) ValidateToken(value, purpose string) (*Token, error) {
	// Check if the feature requiring this token is enabled
	if purpose == "email_verification" && !s.features.EmailVerification {
		return nil, ErrFeatureDisabled
	}
	if purpose == "password_reset" && !s.features.PasswordReset {
		return nil, ErrFeatureDisabled
	}

	var token Token
	query := fmt.Sprintf(`
        SELECT %s, %s, %s, %s
        FROM %s
        WHERE %s = ? AND %s = ? AND %s > ?
        LIMIT 1
    `, s.columns.TokenValue, s.columns.TokenUserID, s.columns.TokenPurpose, s.columns.TokenExpires,
		s.tables.Tokens,
		s.columns.TokenValue, s.columns.TokenPurpose, s.columns.TokenExpires)

	err := s.db.QueryRow(query, value, purpose, time.Now()).Scan(
		&token.Value,
		&token.UserID,
		&token.Purpose,
		&token.ExpiresAt,
	)

	if err != nil {
		return nil, err
	}

	// Delete token after use
	deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE %s = ?", s.tables.Tokens, s.columns.TokenValue)
	s.db.Exec(deleteQuery, value)

	return &token, nil
}

// VerifyUserEmail marks a user as verified (if email verification is enabled)
func (s *Service) VerifyUserEmail(userID int64) error {
	if !s.features.EmailVerification {
		return ErrFeatureDisabled
	}

	query := fmt.Sprintf("UPDATE %s SET %s = 1 WHERE %s = ?",
		s.tables.Users, s.columns.UserVerified, s.columns.UserID)
	_, err := s.db.Exec(query, userID)
	return err
}
