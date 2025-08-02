package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ResponseBuilder provides a fluent interface for building HTTP responses
type ResponseBuilder struct {
	w          http.ResponseWriter
	statusCode int
	headers    map[string]string
	content    strings.Builder
}

// NewResponse creates a new response builder
func NewResponse(w http.ResponseWriter) *ResponseBuilder {
	return &ResponseBuilder{
		w:          w,
		statusCode: http.StatusOK,
		headers: map[string]string{
			"Content-Type": "text/html",
		},
	}
}

// Status sets the HTTP status code
func (b *ResponseBuilder) Status(code int) *ResponseBuilder {
	b.statusCode = code
	return b
}

// Header adds a header to the response
func (b *ResponseBuilder) Header(key, value string) *ResponseBuilder {
	b.headers[key] = value
	return b
}

// ContentType sets the content type
func (b *ResponseBuilder) ContentType(contentType string) *ResponseBuilder {
	b.headers["Content-Type"] = contentType
	return b
}

// JSON sets the content type to JSON and marshals the data
func (b *ResponseBuilder) JSON(data any) *ResponseBuilder {
	b.headers["Content-Type"] = "application/json"
	jsonData, err := json.Marshal(data)
	if err != nil {
		b.Error("Failed to marshal JSON", http.StatusInternalServerError)
		return b
	}
	b.content.Write(jsonData)
	return b
}

// HTML adds raw HTML content
func (b *ResponseBuilder) HTML(html string) *ResponseBuilder {
	b.content.WriteString(html)
	return b
}

// Text adds plain text content
func (b *ResponseBuilder) Text(text string) *ResponseBuilder {
	b.headers["Content-Type"] = "text/plain"
	b.content.WriteString(text)
	return b
}

// Alert adds an alert box to the response
func (b *ResponseBuilder) Alert(alertType AlertType, message string) *ResponseBuilder {
	icon := alertType.Icon()
	b.content.WriteString(fmt.Sprintf(`<div class="alert alert-%s">
		<strong>%s</strong> %s
	</div>`, alertType, icon, message))
	return b
}

// AlertWithTitle adds an alert box with a custom title
func (b *ResponseBuilder) AlertWithTitle(alertType AlertType, title, message string) *ResponseBuilder {
	b.content.WriteString(fmt.Sprintf(`<div class="alert alert-%s">
		<strong>%s:</strong> %s
	</div>`, alertType, title, message))
	return b
}

// AlertWithDetails adds an alert box with additional details
func (b *ResponseBuilder) AlertWithDetails(alertType AlertType, icon, title, details string) *ResponseBuilder {
	b.content.WriteString(fmt.Sprintf(`<div class="alert alert-%s">
		<strong>%s %s</strong>
		<p class="alert-details">%s</p>
	</div>`, alertType, icon, title, details))
	return b
}

// Success adds a success alert
func (b *ResponseBuilder) Success(message string) *ResponseBuilder {
	return b.Alert(AlertSuccess, message)
}

// Error adds an error alert and sets the status code
func (b *ResponseBuilder) Error(message string, statusCode int) *ResponseBuilder {
	b.statusCode = statusCode
	return b.Alert(AlertDanger, message)
}

// Warning adds a warning alert
func (b *ResponseBuilder) Warning(message string) *ResponseBuilder {
	return b.Alert(AlertWarning, message)
}

// Info adds an info alert
func (b *ResponseBuilder) Info(message string) *ResponseBuilder {
	return b.Alert(AlertInfo, message)
}

// WebError handles structured web errors
func (b *ResponseBuilder) WebError(err error) *ResponseBuilder {
	webErr, ok := IsWebError(err)
	if !ok {
		// Handle non-WebError types
		b.statusCode = http.StatusInternalServerError
		return b.Alert(AlertDanger, err.Error())
	}

	b.statusCode = webErr.StatusCode
	
	// Choose appropriate alert type based on error type
	alertType := AlertDanger
	switch webErr.Type {
	case ErrorTypeValidation, ErrorTypeBadRequest:
		alertType = AlertWarning
	case ErrorTypeTimeout:
		alertType = AlertInfo
	}

	if webErr.Details != "" {
		return b.AlertWithDetails(alertType, alertType.Icon(), webErr.Message, webErr.Details)
	}
	return b.Alert(alertType, webErr.Message)
}

// Table adds a data table to the response
func (b *ResponseBuilder) Table(table *Table) *ResponseBuilder {
	b.content.WriteString(table.Build())
	return b
}

// HTMX-specific methods

// HTMXRedirect sets headers for HTMX client-side redirect
func (b *ResponseBuilder) HTMXRedirect(url string) *ResponseBuilder {
	b.headers["HX-Redirect"] = url
	return b
}

// HTMXRefresh triggers a page refresh for HTMX
func (b *ResponseBuilder) HTMXRefresh() *ResponseBuilder {
	b.headers["HX-Refresh"] = "true"
	return b
}

// HTMXRetarget changes the target element for HTMX swap
func (b *ResponseBuilder) HTMXRetarget(selector string) *ResponseBuilder {
	b.headers["HX-Retarget"] = selector
	return b
}

// HTMXReswap changes the swap method for HTMX
func (b *ResponseBuilder) HTMXReswap(method string) *ResponseBuilder {
	b.headers["HX-Reswap"] = method
	return b
}

// HTMXTrigger triggers HTMX events
func (b *ResponseBuilder) HTMXTrigger(events string) *ResponseBuilder {
	b.headers["HX-Trigger"] = events
	return b
}

// HTMXPushURL sets the URL to push to browser history
func (b *ResponseBuilder) HTMXPushURL(url string) *ResponseBuilder {
	b.headers["HX-Push-Url"] = url
	return b
}

// Send writes the response to the ResponseWriter
func (b *ResponseBuilder) Send() {
	// Set headers
	for key, value := range b.headers {
		b.w.Header().Set(key, value)
	}

	// Set status code
	b.w.WriteHeader(b.statusCode)

	// Write content
	b.w.Write([]byte(b.content.String()))
}

// AlertType represents the type of alert
type AlertType string

const (
	AlertSuccess AlertType = "success"
	AlertDanger  AlertType = "danger"
	AlertWarning AlertType = "warning"
	AlertInfo    AlertType = "info"
)

// Icon returns the icon for the alert type
func (a AlertType) Icon() string {
	switch a {
	case AlertSuccess:
		return "✓"
	case AlertDanger:
		return "✗"
	case AlertWarning:
		return "⚠"
	case AlertInfo:
		return "ℹ"
	default:
		return ""
	}
}

// Table represents a data table
type Table struct {
	headers []string
	rows    [][]string
	classes map[int]map[int]string // row -> col -> class
	id      string
	class   string
}

// NewTable creates a new table
func NewTable(headers ...string) *Table {
	return &Table{
		headers: headers,
		classes: make(map[int]map[int]string),
	}
}

// SetID sets the table ID
func (t *Table) SetID(id string) *Table {
	t.id = id
	return t
}

// SetClass sets the table CSS class
func (t *Table) SetClass(class string) *Table {
	t.class = class
	return t
}

// AddRow adds a row to the table
func (t *Table) AddRow(cells ...string) *Table {
	t.rows = append(t.rows, cells)
	return t
}

// AddRowWithClasses adds a row with specific cell classes
func (t *Table) AddRowWithClasses(cells []string, classes map[int]string) *Table {
	rowIndex := len(t.rows)
	t.rows = append(t.rows, cells)
	if classes != nil {
		t.classes[rowIndex] = classes
	}
	return t
}

// Build generates the HTML for the table
func (t *Table) Build() string {
	var html strings.Builder

	tableClass := "table"
	if t.class != "" {
		tableClass = t.class
	}

	html.WriteString(fmt.Sprintf(`<table class="%s"`, tableClass))
	if t.id != "" {
		html.WriteString(fmt.Sprintf(` id="%s"`, t.id))
	}
	html.WriteString(`>`)
	html.WriteString("<thead><tr>")

	// Headers
	for _, header := range t.headers {
		html.WriteString(fmt.Sprintf("<th>%s</th>", header))
	}
	html.WriteString("</tr></thead><tbody>")

	// Rows
	if len(t.rows) == 0 {
		colspan := len(t.headers)
		html.WriteString(fmt.Sprintf(`<tr><td colspan="%d" class="text-center">No data available</td></tr>`, colspan))
	} else {
		for rowIdx, row := range t.rows {
			html.WriteString("<tr>")
			for colIdx, cell := range row {
				class := ""
				if rowClasses, hasRow := t.classes[rowIdx]; hasRow {
					if cellClass, hasCell := rowClasses[colIdx]; hasCell {
						class = fmt.Sprintf(` class="%s"`, cellClass)
					}
				}
				html.WriteString(fmt.Sprintf("<td%s>%s</td>", class, cell))
			}
			html.WriteString("</tr>")
		}
	}

	html.WriteString("</tbody></table>")
	return html.String()
}

// Helper functions

// IsHTMX checks if the request is from HTMX
func IsHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// IsBoosted checks if the request is HTMX boosted
func IsBoosted(r *http.Request) bool {
	return r.Header.Get("HX-Boosted") == "true"
}

// IsHTMXWithTarget checks if the request is from HTMX with a specific target
func IsHTMXWithTarget(r *http.Request, target string) bool {
	return IsHTMX(r) && r.Header.Get("HX-Target") == target
}