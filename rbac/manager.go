package rbac

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Manager handles role-based access control
type Manager struct {
	db *gorm.DB
}

// NewManager creates a new RBAC manager
func NewManager(db *gorm.DB) *Manager {
	return &Manager{
		db: db,
	}
}

// CreateRole creates a new role
func (m *Manager) CreateRole(name, description string) (*Role, error) {
	role := &Role{
		ID:          uuid.New(),
		Name:        name,
		Description: description,
	}

	if err := m.db.Create(role).Error; err != nil {
		return nil, err
	}

	return role, nil
}

// CreatePermission creates a new permission
func (m *Manager) CreatePermission(name, description string) (*Permission, error) {
	permission := &Permission{
		ID:          uuid.New(),
		Name:        name,
		Description: description,
	}

	if err := m.db.Create(permission).Error; err != nil {
		return nil, err
	}

	return permission, nil
}

// AssignRoleToUser assigns a role to a user
func (m *Manager) AssignRoleToUser(userID, roleID uuid.UUID) error {
	userRole := &UserRole{
		ID:     uuid.New(),
		UserID: userID,
		RoleID: roleID,
	}

	return m.db.Create(userRole).Error
}

// AssignPermissionToRole assigns a permission to a role
func (m *Manager) AssignPermissionToRole(roleID, permissionID uuid.UUID) error {
	rolePermission := &RolePermission{
		ID:           uuid.New(),
		RoleID:       roleID,
		PermissionID: permissionID,
	}

	return m.db.Create(rolePermission).Error
}

// UserHasRole checks if a user has a specific role
func (m *Manager) UserHasRole(userID uuid.UUID, roleName string) bool {
	var count int64
	m.db.Table("user_roles").
		Joins("JOIN roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ? AND roles.name = ?", userID, roleName).
		Count(&count)

	return count > 0
}

// UserHasPermission checks if a user has a specific permission
func (m *Manager) UserHasPermission(userID uuid.UUID, permissionName string) bool {
	var count int64
	m.db.Table("user_roles").
		Joins("JOIN role_permissions ON user_roles.role_id = role_permissions.role_id").
		Joins("JOIN permissions ON role_permissions.permission_id = permissions.id").
		Where("user_roles.user_id = ? AND permissions.name = ?", userID, permissionName).
		Count(&count)

	return count > 0
}

// RequireRole middleware that requires a specific role
func (m *Manager) RequireRole(roleName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			c.Abort()
			return
		}

		uid, ok := userID.(uuid.UUID)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID"})
			c.Abort()
			return
		}

		if !m.UserHasRole(uid, roleName) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequirePermission middleware that requires a specific permission
func (m *Manager) RequirePermission(permissionName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			c.Abort()
			return
		}

		uid, ok := userID.(uuid.UUID)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID"})
			c.Abort()
			return
		}

		if !m.UserHasPermission(uid, permissionName) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetUserRoles returns all roles for a user
func (m *Manager) GetUserRoles(userID uuid.UUID) ([]Role, error) {
	var roles []Role
	err := m.db.Table("roles").
		Joins("JOIN user_roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Find(&roles).Error

	return roles, err
}

// GetUserPermissions returns all permissions for a user
func (m *Manager) GetUserPermissions(userID uuid.UUID) ([]Permission, error) {
	var permissions []Permission
	err := m.db.Table("permissions").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("JOIN user_roles ON role_permissions.role_id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Distinct().
		Find(&permissions).Error

	return permissions, err
}
