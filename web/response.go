package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/flyzard/go-guardian/web/notification"
	guardianTemplate "github.com/flyzard/go-guardian/web/template"
)

// ResponseBuilder provides a fluent interface for building HTTP responses
type ResponseBuilder struct {
	w               http.ResponseWriter
	statusCode      int
	headers         map[string]string
	content         strings.Builder
	templateManager *guardianTemplate.Manager
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

// HTMLTemplate adds HTML template content
func (b *ResponseBuilder) HTMLTemplate(html template.HTML) *ResponseBuilder {
	b.content.WriteString(string(html))
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

// AlertWithIcon adds an alert box with a custom icon
func (b *ResponseBuilder) AlertWithIcon(alertType AlertType, icon, message string) *ResponseBuilder {
	b.content.WriteString(fmt.Sprintf(`<div class="alert alert-%s">
		<strong>%s</strong> %s
	</div>`, alertType, icon, message))
	return b
}

// Success adds a success alert
func (b *ResponseBuilder) Success(message string) *ResponseBuilder {
	return b.Alert(AlertSuccess, message)
}

// SuccessWithDetails adds a success alert with a title and details
func (b *ResponseBuilder) SuccessWithDetails(title, details string) *ResponseBuilder {
	return b.AlertWithDetails(AlertSuccess, "✓", title, details)
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

// Info adds an info alert with a custom icon
func (b *ResponseBuilder) Info(icon, message string) *ResponseBuilder {
	return b.AlertWithIcon(AlertInfo, icon, message)
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

// Toast creates a toast notification that auto-dismisses after the specified duration
func (b *ResponseBuilder) Toast(toastType, message string, duration int) *ResponseBuilder {
	// Generate unique ID for the toast
	toastID := fmt.Sprintf("toast-%d", time.Now().UnixNano())

	// Build toast HTML with auto-dismiss
	b.content.WriteString(fmt.Sprintf(`
	<div id="%s" class="toast toast-%s" style="animation-duration: %dms">
		<div class="toast-content">%s</div>
		<script>
			setTimeout(function() {
				document.getElementById('%s').remove();
			}, %d);
		</script>
	</div>`, toastID, toastType, duration, message, toastID, duration))

	// Set HTMX headers to append to toast container
	b.headers["HX-Retarget"] = "#toast-container"
	b.headers["HX-Reswap"] = "beforeend"

	return b
}

// ToastSuccess creates a success toast notification
func (b *ResponseBuilder) ToastSuccess(message string) *ResponseBuilder {
	toast := notification.NewToast(notification.ToastSuccess, message)
	b.content.WriteString(toast.Build())
	
	// Set HTMX headers to append to toast container
	b.headers["HX-Retarget"] = "#toast-container"
	b.headers["HX-Reswap"] = "beforeend"
	
	return b
}

// ToastError creates an error toast notification
func (b *ResponseBuilder) ToastError(message string) *ResponseBuilder {
	toast := notification.NewToast(notification.ToastError, message)
	b.content.WriteString(toast.Build())
	
	// Set HTMX headers to append to toast container
	b.headers["HX-Retarget"] = "#toast-container"
	b.headers["HX-Reswap"] = "beforeend"
	
	return b
}

// ToastWarning creates a warning toast notification
func (b *ResponseBuilder) ToastWarning(message string) *ResponseBuilder {
	toast := notification.NewToast(notification.ToastWarning, message)
	b.content.WriteString(toast.Build())
	
	// Set HTMX headers to append to toast container
	b.headers["HX-Retarget"] = "#toast-container"
	b.headers["HX-Reswap"] = "beforeend"
	
	return b
}

// ToastInfo creates an info toast notification
func (b *ResponseBuilder) ToastInfo(message string) *ResponseBuilder {
	toast := notification.NewToast(notification.ToastInfo, message)
	b.content.WriteString(toast.Build())
	
	// Set HTMX headers to append to toast container
	b.headers["HX-Retarget"] = "#toast-container"
	b.headers["HX-Reswap"] = "beforeend"
	
	return b
}

// ToastWithAction creates a toast with an action button
func (b *ResponseBuilder) ToastWithAction(toastType notification.ToastType, message, actionText, actionURL string) *ResponseBuilder {
	toast := notification.NewToast(toastType, message)
	toast.WithAction(notification.Action{
		Text:   actionText,
		URL:    actionURL,
		Method: "GET",
	})
	
	b.content.WriteString(toast.Build())
	
	// Set HTMX headers to append to toast container
	b.headers["HX-Retarget"] = "#toast-container"
	b.headers["HX-Reswap"] = "beforeend"
	
	return b
}

// ToastBuilder returns a toast builder for more complex toasts
func (b *ResponseBuilder) ToastBuilder(toastType notification.ToastType, message string) *notification.ToastBuilder {
	return notification.NewToastBuilder(toastType, message)
}

// AddToast adds a pre-built toast to the response
func (b *ResponseBuilder) AddToast(toast *notification.Toast) *ResponseBuilder {
	b.content.WriteString(toast.Build())
	
	// Set HTMX headers to append to toast container
	b.headers["HX-Retarget"] = "#toast-container"
	b.headers["HX-Reswap"] = "beforeend"
	
	return b
}

// AlertWithActions adds an enhanced alert with action buttons
func (b *ResponseBuilder) AlertWithActions(alertType AlertType, title, message string, actions ...notification.Action) *ResponseBuilder {
	alert := notification.NewEnhancedAlert(string(alertType), title, message)
	for _, action := range actions {
		alert.WithAction(action)
	}
	
	b.content.WriteString(alert.Build())
	return b
}

// AlertDismissible adds a dismissible alert
func (b *ResponseBuilder) AlertDismissible(alertType AlertType, message string) *ResponseBuilder {
	alert := notification.NewEnhancedAlert(string(alertType), "", message)
	b.content.WriteString(alert.Build())
	return b
}

// HTMXPushURL sets the URL to push to browser history
func (b *ResponseBuilder) HTMXPushURL(url string) *ResponseBuilder {
	b.headers["HX-Push-Url"] = url
	return b
}

// StatusItem adds a status item (for status grids)
func (b *ResponseBuilder) StatusItem(label, value string, valueClass string) *ResponseBuilder {
	if valueClass != "" {
		b.content.WriteString(fmt.Sprintf(`
		<div class="status-item">
			<div class="status-label">%s</div>
			<div class="status-value %s">%s</div>
		</div>`, label, valueClass, value))
	} else {
		b.content.WriteString(fmt.Sprintf(`
		<div class="status-item">
			<div class="status-label">%s</div>
			<div class="status-value">%s</div>
		</div>`, label, value))
	}
	return b
}

// TableRow adds a single table row
func (b *ResponseBuilder) TableRow(cells ...string) *ResponseBuilder {
	b.content.WriteString("<tr>")
	for _, cell := range cells {
		b.content.WriteString(fmt.Sprintf("<td>%s</td>", cell))
	}
	b.content.WriteString("</tr>")
	return b
}

// TableRowWithClasses adds a table row with specific cell classes
func (b *ResponseBuilder) TableRowWithClasses(cells []string, classes map[int]string) *ResponseBuilder {
	b.content.WriteString("<tr>")
	for idx, cell := range cells {
		if class, hasClass := classes[idx]; hasClass {
			b.content.WriteString(fmt.Sprintf(`<td class="%s">%s</td>`, class, cell))
		} else {
			b.content.WriteString(fmt.Sprintf("<td>%s</td>", cell))
		}
	}
	b.content.WriteString("</tr>")
	return b
}

// EmptyTableRow adds an empty table row with a message
func (b *ResponseBuilder) EmptyTableRow(message string, colspan int) *ResponseBuilder {
	b.content.WriteString(fmt.Sprintf(`<tr><td colspan="%d" class="text-center">%s</td></tr>`, colspan, message))
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

// FormatTimestamp formats a Unix timestamp to Berlin time
func FormatTimestamp(timestamp int64) string {
	if timestamp == 0 {
		return "N/A"
	}
	berlinLocation, _ := time.LoadLocation("Europe/Berlin")
	return time.Unix(timestamp, 0).In(berlinLocation).Format("2006-01-02 15:04:05")
}

// FormatDateTime formats a Unix timestamp to Berlin date and time
func FormatDateTime(timestamp int64) string {
	if timestamp == 0 {
		return "N/A"
	}
	berlinLocation, _ := time.LoadLocation("Europe/Berlin")
	return time.Unix(timestamp, 0).In(berlinLocation).Format("2006-01-02 15:04")
}

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

// Template Methods

// WithTemplateManager sets the template manager for rendering templates
func (b *ResponseBuilder) WithTemplateManager(tm *guardianTemplate.Manager) *ResponseBuilder {
	b.templateManager = tm
	return b
}

// Template renders a template by name with the given data
func (b *ResponseBuilder) Template(name string, data interface{}) *ResponseBuilder {
	if b.templateManager == nil {
		b.Error("Template manager not configured", http.StatusInternalServerError)
		return b
	}

	err := b.templateManager.Render(&b.content, name, data)
	if err != nil {
		b.Error(fmt.Sprintf("Failed to render template: %v", err), http.StatusInternalServerError)
	}
	return b
}

// Partial renders a partial template within a template set
func (b *ResponseBuilder) Partial(templateSet, partialName string, data interface{}) *ResponseBuilder {
	if b.templateManager == nil {
		b.Error("Template manager not configured", http.StatusInternalServerError)
		return b
	}

	err := b.templateManager.RenderPartial(&b.content, templateSet, partialName, data)
	if err != nil {
		b.Error(fmt.Sprintf("Failed to render partial: %v", err), http.StatusInternalServerError)
	}
	return b
}

// HTMXPartial renders a template as an HTMX partial response
func (b *ResponseBuilder) HTMXPartial(template string, data interface{}) *ResponseBuilder {
	// Mark as HTMX partial response
	b.headers["HX-Retarget"] = "this"
	b.headers["HX-Reswap"] = "outerHTML"

	if b.templateManager == nil {
		b.Error("Template manager not configured", http.StatusInternalServerError)
		return b
	}

	err := b.templateManager.Render(&b.content, template, data)
	if err != nil {
		b.Error(fmt.Sprintf("Failed to render HTMX partial: %v", err), http.StatusInternalServerError)
	}
	return b
}

// Component renders a component by name with properties
func (b *ResponseBuilder) Component(name string, props map[string]any) *ResponseBuilder {
	// This would require component registry to be accessible
	// For now, we'll add this as a placeholder
	b.content.WriteString(fmt.Sprintf("<!-- Component: %s -->", name))
	return b
}

// Layout starts a layout-based render
func (b *ResponseBuilder) Layout(name string) *guardianTemplate.Layout {
	if b.templateManager == nil {
		return nil
	}
	return b.templateManager.NewLayout(name)
}
