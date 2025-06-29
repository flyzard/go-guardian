package auth

import (
	"errors"
)

type Role struct {
	ID          int64
	Name        string
	Permissions []string
}

type Permission struct {
	ID   int64
	Name string
}

var (
	ErrUnauthorized = errors.New("unauthorized")
)

// Add to User struct in auth.go:
// RoleID int64

func (s *Service) GetUserRole(userID int64) (*Role, error) {
	var role Role
	err := s.db.QueryRow(`
		SELECT r.id, r.name 
		FROM roles r
		JOIN users u ON u.role_id = r.id
		WHERE u.id = ?
	`, userID).Scan(&role.ID, &role.Name)

	if err != nil {
		return nil, err
	}

	// Load permissions
	rows, err := s.db.Query(`
		SELECT p.name 
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = ?
	`, role.ID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err == nil {
			role.Permissions = append(role.Permissions, perm)
		}
	}

	return &role, nil
}

func (s *Service) UserHasPermission(userID int64, permission string) bool {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) 
		FROM users u
		JOIN role_permissions rp ON rp.role_id = u.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE u.id = ? AND p.name = ?
	`, userID, permission).Scan(&count)

	return err == nil && count > 0
}
