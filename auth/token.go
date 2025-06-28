package auth

import (
	"crypto/rand"
	"encoding/hex"
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
	token := &Token{
		Value:     GenerateToken(),
		UserID:    userID,
		Purpose:   "email_verification",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	_, err := s.db.Exec(`
        INSERT INTO tokens (token, user_id, purpose, expires_at)
        VALUES (?, ?, ?, ?)
    `, token.Value, token.UserID, token.Purpose, token.ExpiresAt)

	return token, err
}

func (s *Service) CreatePasswordResetToken(email string) (*Token, error) {
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

	_, err = s.db.Exec(`
        INSERT INTO tokens (token, user_id, purpose, expires_at)
        VALUES (?, ?, ?, ?)
    `, token.Value, token.UserID, token.Purpose, token.ExpiresAt)

	return token, err
}

func (s *Service) ValidateToken(value, purpose string) (*Token, error) {
	var token Token
	err := s.db.QueryRow(`
        SELECT token, user_id, purpose, expires_at
        FROM tokens
        WHERE token = ? AND purpose = ? AND expires_at > ?
        LIMIT 1
    `, value, purpose, time.Now()).Scan(
		&token.Value,
		&token.UserID,
		&token.Purpose,
		&token.ExpiresAt,
	)

	if err != nil {
		return nil, err
	}

	// Delete token after use
	s.db.Exec("DELETE FROM tokens WHERE token = ?", value)

	return &token, nil
}
