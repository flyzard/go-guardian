package tests

import (
	"os"
	"testing"

	guardian "github.com/flyzard/go-guardian"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type RBACTestSuite struct {
	suite.Suite
	guardian *guardian.Guardian
}

func (suite *RBACTestSuite) SetupSuite() {
	suite.guardian = guardian.New().
		WithDatabase("test_rbac.db").
		WithDebug(true)

	err := suite.guardian.Initialize()
	assert.NoError(suite.T(), err)
}

func (suite *RBACTestSuite) TearDownSuite() {
	suite.guardian.Close()
	os.Remove("test_rbac.db")
}

func (suite *RBACTestSuite) TestCreateRole() {
	role, err := suite.guardian.RBAC().CreateRole("test_role", "Test Role")
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), role)
	assert.Equal(suite.T(), "test_role", role.Name)
	assert.Equal(suite.T(), "Test Role", role.Description)
}

func (suite *RBACTestSuite) TestCreatePermission() {
	permission, err := suite.guardian.RBAC().CreatePermission("test_permission", "Test Permission")
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), permission)
	assert.Equal(suite.T(), "test_permission", permission.Name)
}

func (suite *RBACTestSuite) TestAssignPermissionToRole() {
	role, _ := suite.guardian.RBAC().CreateRole("admin", "Administrator")
	permission, _ := suite.guardian.RBAC().CreatePermission("read", "Read access")

	err := suite.guardian.RBAC().AssignPermissionToRole(role.ID, permission.ID)
	assert.NoError(suite.T(), err)
}

func (suite *RBACTestSuite) TestAssignRoleToUser() {
	role, _ := suite.guardian.RBAC().CreateRole("user", "Regular User")
	userID := uuid.New()

	err := suite.guardian.RBAC().AssignRoleToUser(userID, role.ID)
	assert.NoError(suite.T(), err)

	hasRole := suite.guardian.RBAC().UserHasRole(userID, "user")
	assert.True(suite.T(), hasRole)
}

func (suite *RBACTestSuite) TestUserHasPermission() {
	// Create role and permission
	role, _ := suite.guardian.RBAC().CreateRole("editor", "Editor")
	permission, _ := suite.guardian.RBAC().CreatePermission("write", "Write access")

	// Assign permission to role
	suite.guardian.RBAC().AssignPermissionToRole(role.ID, permission.ID)

	// Assign role to user
	userID := uuid.New()
	suite.guardian.RBAC().AssignRoleToUser(userID, role.ID)

	// Check permission
	hasPermission := suite.guardian.RBAC().UserHasPermission(userID, "write")
	assert.True(suite.T(), hasPermission)

	// Check non-existent permission
	hasNonExistent := suite.guardian.RBAC().UserHasPermission(userID, "delete")
	assert.False(suite.T(), hasNonExistent)
}

func TestRBACTestSuite(t *testing.T) {
	suite.Run(t, new(RBACTestSuite))
}
