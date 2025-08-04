package response

import (
	"fmt"
	"strings"

	"github.com/flyzard/go-guardian/htmx"
	"github.com/flyzard/go-guardian/web/notification"
)

// NotificationResponse extends Response with notification methods
type NotificationResponse interface {
	Response
	
	// Alert methods
	Alert(alertType string, message string) Response
	Success(message string) Response
	Warning(message string) Response
	Info(message string) Response
	Danger(message string) Response
	
	// Toast methods
	Toast(toastType notification.ToastType, message string) Response
	ToastSuccess(message string) Response
	ToastError(message string) Response
	ToastWarning(message string) Response
	ToastInfo(message string) Response
}

// Ensure Builder implements NotificationResponse
var _ NotificationResponse = (*Builder)(nil)

// Alert adds an alert to the response
func (b *Builder) Alert(alertType string, message string) Response {
	html := fmt.Sprintf(`<div class="alert alert-%s">%s</div>`, alertType, message)
	b.content.WriteString(html)
	return b
}

// Success adds a success alert
func (b *Builder) Success(message string) Response {
	return b.Alert("success", message)
}

// Warning adds a warning alert
func (b *Builder) Warning(message string) Response {
	return b.Alert("warning", message)
}

// Info adds an info alert
func (b *Builder) Info(message string) Response {
	return b.Alert("info", message)
}

// Danger adds a danger alert
func (b *Builder) Danger(message string) Response {
	return b.Alert("danger", message)
}

// Toast adds a toast notification
func (b *Builder) Toast(toastType notification.ToastType, message string) Response {
	toast := notification.NewToast(toastType, message)
	b.content.WriteString(toast.Build())
	
	// Set HTMX headers for toast container
	if b.htmxWriter != nil {
		b.htmxWriter.Retarget("#toast-container")
		b.htmxWriter.Reswap("beforeend")
	} else if b.w != nil {
		htmx.SetRetarget(b.w, "#toast-container")
		htmx.SetReswap(b.w, "beforeend")
	}
	
	return b
}

// ToastSuccess creates a success toast
func (b *Builder) ToastSuccess(message string) Response {
	return b.Toast(notification.ToastSuccess, message)
}

// ToastError creates an error toast
func (b *Builder) ToastError(message string) Response {
	return b.Toast(notification.ToastError, message)
}

// ToastWarning creates a warning toast
func (b *Builder) ToastWarning(message string) Response {
	return b.Toast(notification.ToastWarning, message)
}

// ToastInfo creates an info toast
func (b *Builder) ToastInfo(message string) Response {
	return b.Toast(notification.ToastInfo, message)
}

// Advanced notification builder for complex cases
type NotificationBuilder struct {
	b *Builder
}

// Notification returns a notification builder for advanced cases
func (b *Builder) Notification() *NotificationBuilder {
	return &NotificationBuilder{b: b}
}

// AlertWithActions adds an alert with action buttons
func (n *NotificationBuilder) AlertWithActions(alertType, title, message string, actions ...notification.Action) Response {
	alert := notification.NewEnhancedAlert(alertType, title, message)
	for _, action := range actions {
		alert.WithAction(action)
	}
	n.b.content.WriteString(alert.Build())
	return n.b
}

// ToastWithAction adds a toast with an action button
func (n *NotificationBuilder) ToastWithAction(toastType notification.ToastType, message, actionText, actionURL string) Response {
	toast := notification.NewToast(toastType, message)
	toast.WithAction(notification.Action{
		Text:   actionText,
		URL:    actionURL,
		Method: "GET",
	})
	
	n.b.content.WriteString(toast.Build())
	
	// Set HTMX headers for toast container
	if n.b.htmxWriter != nil {
		n.b.htmxWriter.Retarget("#toast-container")
		n.b.htmxWriter.Reswap("beforeend")
	}
	
	return n.b
}

// Helper to create alert HTML with icons
func createAlert(alertType, message string, icon string) string {
	var html strings.Builder
	html.WriteString(fmt.Sprintf(`<div class="alert alert-%s">`, alertType))
	if icon != "" {
		html.WriteString(fmt.Sprintf(`<strong>%s</strong> `, icon))
	}
	html.WriteString(message)
	html.WriteString(`</div>`)
	return html.String()
}