package response

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"

	"github.com/flyzard/go-guardian/htmx"
)

// pool for response builders to reduce allocations
var builderPool = sync.Pool{
	New: func() interface{} {
		return &Builder{
			headers: make(map[string]string),
		}
	},
}

// Builder implements the Response interface with automatic context detection
type Builder struct {
	w          http.ResponseWriter
	r          *http.Request
	htmxWriter *htmx.ResponseWriter
	status     int
	headers    map[string]string
	content    strings.Builder
	sent       bool
	isJSON     bool
}

// New creates a new response builder with automatic context detection
func New(w http.ResponseWriter, r *http.Request) Response {
	b := builderPool.Get().(*Builder)
	b.reset(w, r)
	
	// Auto-detect HTMX requests and wrap response writer
	if htmx.IsRequest(r) {
		b.htmxWriter = htmx.NewResponseWriter(w, r)
	}
	
	return b
}

// reset prepares a builder for reuse
func (b *Builder) reset(w http.ResponseWriter, r *http.Request) {
	b.w = w
	b.r = r
	b.htmxWriter = nil
	b.status = http.StatusOK
	b.content.Reset()
	b.sent = false
	b.isJSON = false
	
	// Clear headers map
	for k := range b.headers {
		delete(b.headers, k)
	}
	
	// Set default content type based on Accept header
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		b.headers["Content-Type"] = "application/json"
		b.isJSON = true
	} else {
		b.headers["Content-Type"] = "text/html; charset=utf-8"
	}
}

// Status sets the HTTP status code
func (b *Builder) Status(code int) Response {
	if !b.sent {
		b.status = code
	}
	return b
}

// Header adds a header to the response
func (b *Builder) Header(key, value string) Response {
	if !b.sent {
		b.headers[key] = value
	}
	return b
}

// ContentType sets the Content-Type header
func (b *Builder) ContentType(contentType string) Response {
	b.headers["Content-Type"] = contentType
	b.isJSON = strings.Contains(contentType, "application/json")
	return b
}

// JSON sends a JSON response
func (b *Builder) JSON(data any) Response {
	b.headers["Content-Type"] = "application/json"
	b.isJSON = true
	
	jsonData, err := json.Marshal(data)
	if err != nil {
		b.status = http.StatusInternalServerError
		b.content.WriteString(`{"error":"Failed to marshal JSON"}`)
		return b
	}
	
	b.content.Write(jsonData)
	return b
}

// HTML sends an HTML response
func (b *Builder) HTML(content string) Response {
	b.headers["Content-Type"] = "text/html; charset=utf-8"
	b.isJSON = false
	b.content.WriteString(content)
	return b
}

// Text sends a plain text response
func (b *Builder) Text(content string) Response {
	b.headers["Content-Type"] = "text/plain; charset=utf-8"
	b.isJSON = false
	b.content.WriteString(content)
	return b
}

// Error sends an error response with appropriate formatting
func (b *Builder) Error(err error) Response {
	// Check if error implements StatusCoder interface
	if sc, ok := err.(interface{ StatusCode() int }); ok {
		return b.ErrorWithStatus(err, sc.StatusCode())
	}
	
	// Default to 500 for generic errors
	return b.ErrorWithStatus(err, http.StatusInternalServerError)
}

// ErrorWithStatus sends an error with specific status code
func (b *Builder) ErrorWithStatus(err error, status int) Response {
	b.status = status
	
	// Handle based on content type and request type
	if b.isJSON || (b.r != nil && wantsJSON(b.r)) {
		// JSON error response
		errorData := map[string]any{
			"error": err.Error(),
		}
		
		// Check for WebError type from web package
		// Using reflection to avoid import cycle
		if errType := reflect.TypeOf(err); errType != nil {
			if typeField, ok := getFieldValue(reflect.ValueOf(err), "Type"); ok {
				errorData["type"] = fmt.Sprintf("%v", typeField)
			}
			if detailsField, ok := getFieldValue(reflect.ValueOf(err), "Details"); ok {
				if details := fmt.Sprintf("%v", detailsField); details != "" {
					errorData["details"] = details
				}
			}
			if fieldField, ok := getFieldValue(reflect.ValueOf(err), "Field"); ok {
				if field := fmt.Sprintf("%v", fieldField); field != "" {
					errorData["field"] = field
				}
			}
		}
		
		return b.JSON(errorData)
	}
	
	// HTML error response
	if b.htmxWriter != nil {
		// For HTMX requests, retarget errors to body
		b.htmxWriter.RetargetError("body", htmx.SwapInnerHTML)
	}
	
	// Build HTML error content
	alertType := "danger"
	details := ""
	
	// Check for structured error using reflection
	if errType := reflect.TypeOf(err); errType != nil {
		if typeField, ok := getFieldValue(reflect.ValueOf(err), "Type"); ok {
			alertType = errorTypeToAlertType(fmt.Sprintf("%v", typeField))
		}
		if detailsField, ok := getFieldValue(reflect.ValueOf(err), "Details"); ok {
			details = fmt.Sprintf("%v", detailsField)
		}
	}
	
	html := fmt.Sprintf(`<div class="alert alert-%s">`, alertType)
	html += fmt.Sprintf(`<strong>%s</strong>`, err.Error())
	if details != "" {
		html += fmt.Sprintf(`<p class="alert-details">%s</p>`, details)
	}
	html += `</div>`
	b.content.WriteString(html)
	
	return b
}

// Send writes the response to the client
func (b *Builder) Send() error {
	if b.sent {
		return fmt.Errorf("response already sent")
	}
	
	// Set headers
	for key, value := range b.headers {
		b.w.Header().Set(key, value)
	}
	
	// Use HTMX writer if available
	writer := b.w
	if b.htmxWriter != nil {
		writer = b.htmxWriter
	}
	
	// Write status
	writer.WriteHeader(b.status)
	
	// Write content
	if b.content.Len() > 0 {
		_, err := writer.Write([]byte(b.content.String()))
		if err != nil {
			return err
		}
	}
	
	b.sent = true
	
	// Return builder to pool for reuse
	builderPool.Put(b)
	
	return nil
}

// Helper functions

// wantsJSON checks if the client wants JSON response
func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") ||
		strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

// getFieldValue safely gets a field value from a struct using reflection
func getFieldValue(v reflect.Value, fieldName string) (interface{}, bool) {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, false
	}
	field := v.FieldByName(fieldName)
	if !field.IsValid() {
		return nil, false
	}
	return field.Interface(), true
}

// errorTypeToAlertType converts error type to alert type
func errorTypeToAlertType(errorType string) string {
	switch errorType {
	case "validation", "bad_request":
		return "warning"
	case "timeout":
		return "info"
	default:
		return "danger"
	}
}