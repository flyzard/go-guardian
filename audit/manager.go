// Package audit provides functionality for logging and managing audit events in a web application.
package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"slices"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Manager handles audit logging
type Manager struct {
	db     *gorm.DB
	config *Config
}

// Config holds audit configuration
type Config struct {
	LogRequests      bool
	LogResponses     bool
	LogHeaders       bool
	LogBody          bool
	MaxBodySize      int
	ExcludePaths     []string
	IncludeOnlyPaths []string
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	UserID       *uuid.UUID `gorm:"type:uuid" json:"user_id,omitempty"`
	Action       string     `gorm:"not null" json:"action"`
	Resource     string     `json:"resource"`
	Method       string     `json:"method"`
	Path         string     `json:"path"`
	IP           string     `json:"ip"`
	UserAgent    string     `gorm:"type:text" json:"user_agent"`
	Headers      string     `gorm:"type:text" json:"headers,omitempty"`
	RequestBody  string     `gorm:"type:text" json:"request_body,omitempty"`
	ResponseBody string     `gorm:"type:text" json:"response_body,omitempty"`
	StatusCode   int        `json:"status_code"`
	Duration     int64      `json:"duration"` // in milliseconds
	CreatedAt    time.Time  `json:"created_at"`
}

// NewManager creates a new audit manager
func NewManager(db *gorm.DB) *Manager {
	config := &Config{
		LogRequests:  true,
		LogResponses: false,
		LogHeaders:   true,
		LogBody:      false,
		MaxBodySize:  1024 * 10, // 10KB
		ExcludePaths: []string{"/health", "/metrics"},
	}

	return &Manager{
		db:     db,
		config: config,
	}
}

// LogEvent logs a custom audit event
func (m *Manager) LogEvent(userID *uuid.UUID, action, resource string, metadata map[string]interface{}) error {
	metadataJSON, _ := json.Marshal(metadata)

	auditLog := AuditLog{
		ID:          uuid.New(),
		UserID:      userID,
		Action:      action,
		Resource:    resource,
		RequestBody: string(metadataJSON),
		CreatedAt:   time.Now(),
	}

	return m.db.Create(&auditLog).Error
}

// AuditMiddleware provides audit logging middleware
func (m *Manager) AuditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Skip excluded paths
		for _, path := range m.config.ExcludePaths {
			if c.Request.URL.Path == path {
				c.Next()
				return
			}
		}

		// Check include-only paths
		if len(m.config.IncludeOnlyPaths) > 0 {
			included := slices.Contains(m.config.IncludeOnlyPaths, c.Request.URL.Path)
			if !included {
				c.Next()
				return
			}
		}

		// Get user ID if available
		var userID *uuid.UUID
		if uid, exists := c.Get("user_id"); exists {
			if id, ok := uid.(uuid.UUID); ok {
				userID = &id
			}
		}

		// Capture request data
		var requestBody string
		var headers string

		if m.config.LogHeaders {
			headersMap := make(map[string]string)
			for k, v := range c.Request.Header {
				if len(v) > 0 {
					// Don't log sensitive headers
					if k != "Authorization" && k != "Cookie" {
						headersMap[k] = v[0]
					}
				}
			}
			headersJSON, _ := json.Marshal(headersMap)
			headers = string(headersJSON)
			if m.config.LogBody && c.Request.ContentLength > 0 && c.Request.ContentLength < int64(m.config.MaxBodySize) {
				if body, err := c.GetRawData(); err == nil {
					requestBody = string(body)
					// Reset body for downstream handlers
					c.Request.Body = io.NopCloser(bytes.NewReader(body))
				}
			}
		}

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start).Milliseconds()

		// Create audit log
		auditLog := AuditLog{
			ID:          uuid.New(),
			UserID:      userID,
			Action:      c.Request.Method,
			Resource:    c.Request.URL.Path,
			Method:      c.Request.Method,
			Path:        c.Request.URL.Path,
			IP:          c.ClientIP(),
			UserAgent:   c.Request.UserAgent(),
			Headers:     headers,
			RequestBody: requestBody,
			StatusCode:  c.Writer.Status(),
			Duration:    duration,
			CreatedAt:   time.Now(),
		}

		// Log asynchronously to avoid blocking
		go func() {
			m.db.Create(&auditLog)
		}()
	}
}

// GetUserAuditLogs returns audit logs for a specific user
func (m *Manager) GetUserAuditLogs(userID uuid.UUID, limit, offset int) ([]AuditLog, error) {
	var logs []AuditLog
	err := m.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error

	return logs, err
}

// GetAuditLogs returns audit logs with optional filters
func (m *Manager) GetAuditLogs(filters map[string]interface{}, limit, offset int) ([]AuditLog, error) {
	var logs []AuditLog
	query := m.db.Model(&AuditLog{})

	for key, value := range filters {
		switch key {
		case "user_id":
			query = query.Where("user_id = ?", value)
		case "action":
			query = query.Where("action = ?", value)
		case "resource":
			query = query.Where("resource = ?", value)
		case "ip":
			query = query.Where("ip = ?", value)
		case "from_date":
			query = query.Where("created_at >= ?", value)
		case "to_date":
			query = query.Where("created_at <= ?", value)
		}
	}

	err := query.Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error

	return logs, err
}

// CleanupOldLogs removes old audit logs
func (m *Manager) CleanupOldLogs(olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	return m.db.Delete(&AuditLog{}, "created_at < ?", cutoff).Error
}

// GetAuditStats returns audit statistics
func (m *Manager) GetAuditStats(since time.Time) (map[string]int64, error) {
	stats := make(map[string]int64)

	// Total events
	var total int64
	if err := m.db.Model(&AuditLog{}).Where("created_at >= ?", since).Count(&total).Error; err != nil {
		return nil, err
	}
	stats["total_events"] = total

	// Events by action
	var actionStats []struct {
		Action string
		Count  int64
	}
	if err := m.db.Model(&AuditLog{}).
		Select("action, count(*) as count").
		Where("created_at >= ?", since).
		Group("action").
		Find(&actionStats).Error; err != nil {
		return nil, err
	}

	for _, stat := range actionStats {
		stats["action_"+stat.Action] = stat.Count
	}

	// Unique users
	var uniqueUsers int64
	if err := m.db.Model(&AuditLog{}).
		Where("created_at >= ? AND user_id IS NOT NULL", since).
		Distinct("user_id").
		Count(&uniqueUsers).Error; err != nil {
		return nil, err
	}
	stats["unique_users"] = uniqueUsers

	return stats, nil
}

// BeforeCreate sets the ID for new audit logs
func (al *AuditLog) BeforeCreate(_ *gorm.DB) error {
	if al.ID == uuid.Nil {
		al.ID = uuid.New()
	}
	return nil
}

// TableName returns the table name for AuditLog
func (AuditLog) TableName() string {
	return "audit_logs"
}
