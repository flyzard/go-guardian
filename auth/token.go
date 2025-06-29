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
	token := &Token{
		Value:     GenerateToken(),
		UserID:    userID,
		Purpose:   "email_verification",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	query := fmt.Sprintf(`
        INSERT INTO %s (token, user_id, purpose, expires_at)
        VALUES (?, ?, ?, ?)
    `, s.tables.Tokens)

	_, err := s.db.Exec(query, token.Value, token.UserID, token.Purpose, token.ExpiresAt)

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

	query := fmt.Sprintf(`
        INSERT INTO %s (token, user_id, purpose, expires_at)
        VALUES (?, ?, ?, ?)
    `, s.tables.Tokens)

	_, err = s.db.Exec(query, token.Value, token.UserID, token.Purpose, token.ExpiresAt)

	return token, err
}

func (s *Service) ValidateToken(value, purpose string) (*Token, error) {
	var token Token
	query := fmt.Sprintf(`
        SELECT token, user_id, purpose, expires_at
        FROM %s
        WHERE token = ? AND purpose = ? AND expires_at > ?
        LIMIT 1
    `, s.tables.Tokens)

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
	deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE token = ?", s.tables.Tokens)
	s.db.Exec(deleteQuery, value)

	return &token, nil
}
