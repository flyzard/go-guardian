package auth

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserNotVerified    = errors.New("email not verified")
)

type Service struct {
	store sessions.Store
	db    *sql.DB
}

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Verified     bool
	CreatedAt    time.Time
}

func NewService(store sessions.Store, db *sql.DB) *Service {
	return &Service{
		store: store,
		db:    db,
	}
}

func (s *Service) Login(w http.ResponseWriter, r *http.Request, email, password string) error {
	// Find user
	user, err := s.findUserByEmail(email)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidCredentials
		}
		return err
	}

	// Check password
	if !CheckPasswordHash(password, user.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Check if verified
	if !user.Verified {
		return ErrUserNotVerified
	}

	// Create new session
	session, _ := s.store.New(r, "auth-session")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email

	// Regenerate session ID for security
	session.Options.MaxAge = 1800 // 30 minutes

	return session.Save(r, w)
}

func (s *Service) Logout(w http.ResponseWriter, r *http.Request) error {
	session, err := s.store.Get(r, "auth-session")
	if err != nil {
		return err
	}

	// Delete session
	session.Options.MaxAge = -1
	return session.Save(r, w)
}

func (s *Service) Register(email, password string) (*User, error) {
	// Check if user exists
	existing, _ := s.findUserByEmail(email)
	if existing != nil {
		return nil, errors.New("email already registered")
	}

	// Hash password
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Insert user
	result, err := s.db.Exec(`
        INSERT INTO users (email, password_hash, verified, created_at)
        VALUES (?, ?, ?, ?)
    `, email, hash, false, time.Now())

	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()

	return &User{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		Verified:     false,
		CreatedAt:    time.Now(),
	}, nil
}

func (s *Service) GetUser(r *http.Request) (*User, error) {
	session, err := s.store.Get(r, "auth-session")
	if err != nil {
		return nil, err
	}

	userID, ok := session.Values["user_id"].(int64)
	if !ok {
		return nil, ErrUserNotFound
	}

	return s.findUserByID(userID)
}

func (s *Service) findUserByEmail(email string) (*User, error) {
	var user User
	err := s.db.QueryRow(`
        SELECT id, email, password_hash, verified, created_at
        FROM users
        WHERE email = ?
        LIMIT 1
    `, email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Verified, &user.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *Service) findUserByID(id int64) (*User, error) {
	var user User
	err := s.db.QueryRow(`
        SELECT id, email, password_hash, verified, created_at
        FROM users
        WHERE id = ?
        LIMIT 1
    `, id).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Verified, &user.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &user, nil
}
