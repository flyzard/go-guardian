package auth

import (
	"errors"
	"fmt"
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
	query := fmt.Sprintf(`
		SELECT r.id, r.name 
		FROM %s r
		JOIN %s u ON u.role_id = r.id
		WHERE u.id = ?
	`, s.tables.Roles, s.tables.Users)

	err := s.db.QueryRow(query, userID).Scan(&role.ID, &role.Name)

	if err != nil {
		return nil, err
	}

	// Load permissions
	permQuery := fmt.Sprintf(`
		SELECT p.name 
		FROM %s p
		JOIN %s rp ON rp.permission_id = p.id
		WHERE rp.role_id = ?
	`, s.tables.Permissions, s.tables.RolePermissions)

	rows, err := s.db.Query(permQuery, role.ID)

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
	query := fmt.Sprintf(`
		SELECT COUNT(*) 
		FROM %s u
		JOIN %s rp ON rp.role_id = u.role_id
		JOIN %s p ON p.id = rp.permission_id
		WHERE u.id = ? AND p.name = ?
	`, s.tables.Users, s.tables.RolePermissions, s.tables.Permissions)

	err := s.db.QueryRow(query, userID, permission).Scan(&count)

	return err == nil && count > 0
}
