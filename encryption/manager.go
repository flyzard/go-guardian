// Package encryption provides utilities for secure encryption and decryption
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// Manager handles encryption operations
type Manager struct {
	key []byte
	gcm cipher.AEAD
}

// NewManager creates a new encryption manager
func NewManager(key []byte) *Manager {
	if len(key) != 32 {
		panic("encryption key must be exactly 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	return &Manager{
		key: key,
		gcm: gcm,
	}
}

// Encrypt encrypts plaintext using AES-GCM
func (m *Manager) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, m.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := m.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (m *Manager) Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := m.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := m.gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// HashPassword creates a secure hash of a password using PBKDF2
func (m *Manager) HashPassword(password string, salt []byte) string {
	if salt == nil {
		salt = make([]byte, 16)
		rand.Read(salt)
	}

	hash := pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)

	// Combine salt and hash
	combined := append(salt, hash...)
	return base64.StdEncoding.EncodeToString(combined)
}

// VerifyPassword verifies a password against its hash
func (m *Manager) VerifyPassword(password, hash string) bool {
	data, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}

	if len(data) != 48 { // 16 bytes salt + 32 bytes hash
		return false
	}

	salt := data[:16]
	expectedHash := data[16:]

	actualHash := pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)

	// Constant time comparison
	if len(expectedHash) != len(actualHash) {
		return false
	}

	var result byte
	for i := 0; i < len(expectedHash); i++ {
		result |= expectedHash[i] ^ actualHash[i]
	}

	return result == 0
}

// GenerateRandomBytes generates cryptographically secure random bytes
func (m *Manager) GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	return bytes, err
}

// GenerateRandomString generates a random base64 encoded string
func (m *Manager) GenerateRandomString(length int) (string, error) {
	bytes, err := m.GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// SecureCompare performs a constant-time comparison of two strings
func (m *Manager) SecureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := range len(a) {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// DeriveKey derives a key from a password using PBKDF2
func (m *Manager) DeriveKey(password string, salt []byte, iterations, keyLength int) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha256.New)
}
