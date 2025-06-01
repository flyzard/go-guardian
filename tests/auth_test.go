package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

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
}

func (suite *AuthTestSuite) SetupTest() {
	// Create test database with unique name for each test
	timestamp := time.Now().UnixNano()
	dbName := fmt.Sprintf("test_auth_%d.db", timestamp)

	// Create test database
	suite.guardian = guardian.New().
		WithDatabase(dbName).
		WithJWTSecret("test-secret-32-characters-long!").
		WithEncryptionKey("default-encryption-key-32-chars!").
		WithDebug(true)

	err := suite.guardian.Initialize()
	if err != nil {
		suite.T().Fatalf("Failed to initialize Guardian: %v", err)
	}

	// Setup test router
	suite.router = gin.New()

	// Check if auth manager exists
	authManager := suite.guardian.Auth()
	if authManager == nil {
		suite.T().Fatal("Auth manager is nil after initialization")
	}

	auth := authManager.EnableRegistration()

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

func (suite *AuthTestSuite) TearDownTest() {
	if suite.guardian != nil {
		// Get the database path before closing
		dbPath := suite.guardian.Config().DatabasePath
		suite.guardian.Close()
		// Clean up the test database file
		os.Remove(dbPath)
	}
}

func (suite *AuthTestSuite) TearDownSuite() {
	// Clean up any remaining files
	os.Remove("test_auth.db")
}

func (suite *AuthTestSuite) TestUserRegistration() {
	registerData := map[string]string{
		"email":            fmt.Sprintf("registration_%d@example.com", time.Now().UnixNano()),
		"password":         "password123",
		"password_confirm": "password123",
		"first_name":       "Registration",
		"last_name":        "Test",
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
	uniqueEmail := fmt.Sprintf("login_%d@example.com", time.Now().UnixNano())
	registerData := map[string]string{
		"email":            uniqueEmail,
		"password":         "password123",
		"password_confirm": "password123",
		"first_name":       "Login",
		"last_name":        "Test",
	}

	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	// Now test login
	loginData := map[string]string{
		"email":    uniqueEmail,
		"password": "password123",
	}

	jsonData, _ = json.Marshal(loginData)
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
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
	// First register a user
	uniqueEmail := fmt.Sprintf("protected_%d@example.com", time.Now().UnixNano())
	registerData := map[string]string{
		"email":            uniqueEmail,
		"password":         "password123",
		"password_confirm": "password123",
		"first_name":       "Protected",
		"last_name":        "Test",
	}

	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	// Login and get token
	loginData := map[string]string{
		"email":    uniqueEmail,
		"password": "password123",
	}

	jsonData, _ = json.Marshal(loginData)
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
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
