package captcha

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mojocn/base64Captcha"
)

// Manager handles captcha operations
type Manager struct {
	store  base64Captcha.Store
	driver base64Captcha.Driver
}

// Config holds captcha configuration
type Config struct {
	Height   int
	Width    int
	Length   int
	MaxSkew  float64
	DotCount int
}

// NewManager creates a new captcha manager
func NewManager() *Manager {
	// Configure captcha
	driver := base64Captcha.NewDriverDigit(80, 240, 5, 0.7, 80)
	store := base64Captcha.DefaultMemStore

	return &Manager{
		store:  store,
		driver: driver,
	}
}

// CaptchaResponse represents a captcha response
type CaptchaResponse struct {
	CaptchaID   string `json:"captcha_id"`
	CaptchaB64s string `json:"captcha_b64s"`
}

// GenerateCaptcha generates a new captcha
func (m *Manager) GenerateCaptcha() (*CaptchaResponse, error) {
	captcha := base64Captcha.NewCaptcha(m.driver, m.store)
	id, b64s, _, err := captcha.Generate()
	if err != nil {
		return nil, err
	}

	return &CaptchaResponse{
		CaptchaID:   id,
		CaptchaB64s: b64s,
	}, nil
}

// VerifyCaptcha verifies a captcha answer
func (m *Manager) VerifyCaptcha(id, answer string) bool {
	return m.store.Verify(id, answer, true)
}

// CaptchaMiddleware provides captcha validation middleware
func (m *Manager) CaptchaMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		captchaID := c.PostForm("captcha_id")
		captchaAnswer := c.PostForm("captcha_answer")

		if captchaID == "" || captchaAnswer == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Captcha ID and answer are required",
			})
			c.Abort()
			return
		}

		if !m.VerifyCaptcha(captchaID, captchaAnswer) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid captcha",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GenerateCaptchaHandler returns a handler for generating captcha
func (m *Manager) GenerateCaptchaHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		captcha, err := m.GenerateCaptcha()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate captcha",
			})
			return
		}

		c.JSON(http.StatusOK, captcha)
	}
}

// VerifyCaptchaHandler returns a handler for verifying captcha
func (m *Manager) VerifyCaptchaHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			CaptchaID string `json:"captcha_id" binding:"required"`
			Answer    string `json:"answer" binding:"required"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		valid := m.VerifyCaptcha(request.CaptchaID, request.Answer)
		c.JSON(http.StatusOK, gin.H{"valid": valid})
	}
}

// WithConfig configures the captcha manager
func (m *Manager) WithConfig(config *Config) *Manager {
	if config != nil {
		m.driver = base64Captcha.NewDriverDigit(
			config.Height,
			config.Width,
			config.Length,
			config.MaxSkew,
			config.DotCount,
		)
	}
	return m
}
