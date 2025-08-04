package notification

import (
	"fmt"
	"strings"
)

// EnhancedAlert represents an alert with actions
type EnhancedAlert struct {
	Type       string
	Title      string
	Message    string
	Actions    []Action
	Dismissible bool
	Icon       string
}

// NewEnhancedAlert creates a new enhanced alert
func NewEnhancedAlert(alertType, title, message string) *EnhancedAlert {
	return &EnhancedAlert{
		Type:        alertType,
		Title:       title,
		Message:     message,
		Dismissible: true,
	}
}

// WithIcon sets a custom icon
func (a *EnhancedAlert) WithIcon(icon string) *EnhancedAlert {
	a.Icon = icon
	return a
}

// WithAction adds an action button
func (a *EnhancedAlert) WithAction(action Action) *EnhancedAlert {
	a.Actions = append(a.Actions, action)
	return a
}

// NotDismissible makes the alert permanent
func (a *EnhancedAlert) NotDismissible() *EnhancedAlert {
	a.Dismissible = false
	return a
}

// Build generates the HTML for the alert
func (a *EnhancedAlert) Build() string {
	var builder strings.Builder
	
	// Determine icon if not set
	icon := a.Icon
	if icon == "" {
		icon = a.getDefaultIcon()
	}
	
	// Build alert HTML
	builder.WriteString(fmt.Sprintf(`<div class="alert alert-%s">`, a.Type))
	
	// Header with icon and title
	builder.WriteString(`<div class="alert-header">`)
	if icon != "" {
		builder.WriteString(fmt.Sprintf(`<span class="alert-icon">%s</span>`, icon))
	}
	if a.Title != "" {
		builder.WriteString(fmt.Sprintf(`<strong>%s</strong>`, a.Title))
	}
	
	// Dismiss button
	if a.Dismissible {
		builder.WriteString(`<button class="alert-close" onclick="this.parentElement.parentElement.remove()">×</button>`)
	}
	builder.WriteString(`</div>`)
	
	// Message
	if a.Message != "" {
		builder.WriteString(fmt.Sprintf(`<p class="alert-message">%s</p>`, a.Message))
	}
	
	// Actions
	if len(a.Actions) > 0 {
		builder.WriteString(`<div class="alert-actions">`)
		for _, action := range a.Actions {
			class := action.Class
			if class == "" {
				class = "alert-action"
			}
			
			if action.URL != "" {
				// HTMX action
				method := strings.ToLower(action.Method)
				if method == "" {
					method = "get"
				}
				builder.WriteString(fmt.Sprintf(
					`<button class="%s" hx-%s="%s" hx-target="body">%s</button>`,
					class, method, action.URL, action.Text,
				))
			} else if action.OnClick != "" {
				// JavaScript action
				builder.WriteString(fmt.Sprintf(
					`<button class="%s" onclick="%s">%s</button>`,
					class, action.OnClick, action.Text,
				))
			}
		}
		builder.WriteString(`</div>`)
	}
	
	builder.WriteString(`</div>`)
	
	return builder.String()
}

// getDefaultIcon returns the default icon for the alert type
func (a *EnhancedAlert) getDefaultIcon() string {
	switch a.Type {
	case "success":
		return "✓"
	case "danger", "error":
		return "✗"
	case "warning":
		return "⚠"
	case "info":
		return "ℹ"
	default:
		return ""
	}
}

// Predefined alert actions for common scenarios

// DismissAction creates a dismiss action
func DismissAction() Action {
	return Action{
		Text:    "Dismiss",
		OnClick: "this.closest('.alert').remove()",
		Class:   "btn-secondary",
	}
}

// RetryAction creates a retry action with HTMX
func RetryAction(url string) Action {
	return Action{
		Text:   "Retry",
		URL:    url,
		Method: "POST",
		Class:  "btn-primary",
	}
}

// ViewDetailsAction creates a view details action
func ViewDetailsAction(url string) Action {
	return Action{
		Text:   "View Details",
		URL:    url,
		Method: "GET",
		Class:  "btn-info",
	}
}

// UndoAction creates an undo action
func UndoAction(url string) Action {
	return Action{
		Text:   "Undo",
		URL:    url,
		Method: "POST",
		Class:  "btn-warning",
	}
}