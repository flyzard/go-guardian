package rbac

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Role represents a role in the RBAC system
type Role struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	Name        string    `gorm:"uniqueIndex;not null" json:"name"`
	Description string    `gorm:"type:text" json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Permission represents a permission in the RBAC system
type Permission struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	Name        string    `gorm:"uniqueIndex;not null" json:"name"`
	Description string    `gorm:"type:text" json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserRole represents the many-to-many relationship between users and roles
type UserRole struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null" json:"user_id"`
	RoleID    uuid.UUID `gorm:"type:uuid;not null" json:"role_id"`
	Role      Role      `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// RolePermission represents the many-to-many relationship between roles and permissions
type RolePermission struct {
	ID           uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	RoleID       uuid.UUID  `gorm:"type:uuid;not null" json:"role_id"`
	PermissionID uuid.UUID  `gorm:"type:uuid;not null" json:"permission_id"`
	Role         Role       `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	Permission   Permission `gorm:"foreignKey:PermissionID" json:"permission,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// BeforeCreate sets the ID for new records
func (r *Role) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

func (p *Permission) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

func (ur *UserRole) BeforeCreate(tx *gorm.DB) error {
	if ur.ID == uuid.Nil {
		ur.ID = uuid.New()
	}
	return nil
}

func (rp *RolePermission) BeforeCreate(tx *gorm.DB) error {
	if rp.ID == uuid.Nil {
		rp.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for Role
func (Role) TableName() string {
	return "roles"
}

// TableName returns the table name for Permission
func (Permission) TableName() string {
	return "permissions"
}

// TableName returns the table name for UserRole
func (UserRole) TableName() string {
	return "user_roles"
}

// TableName returns the table name for RolePermission
func (RolePermission) TableName() string {
	return "role_permissions"
}
