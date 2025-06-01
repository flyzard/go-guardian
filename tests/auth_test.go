package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	guardian "github.com/flyzard/go-guardian"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type AuthTestSuite struct {
	suite.Suite
	guardian *guardian.Guardian
	router   *gin.Engine
}

func (suite *AuthTestSuite) SetupSuite() {
	gin.SetMode(gin.TestMode)

	// Create test database
	suite.guardian = guardian.New().
		WithDatabase("test_auth.db").
		WithJWTSecret("test-secret").
		WithDebug(true)

	err := suite.guardian.Initialize()
	assert.NoError(suite.T(), err)

	// Setup test router
	suite.router = gin.New()
	auth := suite.guardian.Auth().EnableRegistration()

	suite.router.POST("/register", auth.Register())
	suite.router.POST("/login", auth.Login())
	suite.router.POST("/logout", auth.Logout())

	protected := suite.router.Group("/api")
	protected.Use(suite.guardian.RequireAuth())
	protected.GET("/profile", func(c *gin.Context) {
		user, _ := guardian.GetCurrentUser(c)
		c.JSON(200, gin.H{"user": user})
	})
}

func (suite *AuthTestSuite) TearDownSuite() {
	suite.guardian.Close()
	os.Remove("test_auth.db")
}

func (suite *AuthTestSuite) TestUserRegistration() {
	registerData := map[string]string{
		"email":            "test@example.com",
		"password":         "password123",
		"password_confirm": "password123",
		"first_name":       "Test",
		"last_name":        "User",
	}

	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response, "token")
	assert.Contains(suite.T(), response, "user")
}

func (suite *AuthTestSuite) TestUserLogin() {
	// First register a user
	suite.TestUserRegistration()

	loginData := map[string]string{
		"email":    "test@example.com",
		"password": "password123",
	}

	jsonData, _ := json.Marshal(loginData)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), response, "token")
}

func (suite *AuthTestSuite) TestInvalidLogin() {
	loginData := map[string]string{
		"email":    "nonexistent@example.com",
		"password": "wrongpassword",
	}

	jsonData, _ := json.Marshal(loginData)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
}

func (suite *AuthTestSuite) TestProtectedRoute() {
	// Login and get token
	suite.TestUserRegistration()

	loginData := map[string]string{
		"email":    "test@example.com",
		"password": "password123",
	}

	jsonData, _ := json.Marshal(loginData)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	var loginResponse map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &loginResponse)
	token := loginResponse["token"].(string)

	// Access protected route with token
	req, _ = http.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w = httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
}

func (suite *AuthTestSuite) TestProtectedRouteWithoutToken() {
	req, _ := http.NewRequest("GET", "/api/profile", nil)

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
}

func TestAuthTestSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}
