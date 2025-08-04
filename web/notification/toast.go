package notification

import (
	"fmt"
	"strings"
	"time"
)

// ToastType represents the type of toast notification
type ToastType string

const (
	ToastSuccess ToastType = "success"
	ToastError   ToastType = "error"
	ToastWarning ToastType = "warning"
	ToastInfo    ToastType = "info"
)

// ToastPosition represents where toasts appear on screen
type ToastPosition string

const (
	TopRight    ToastPosition = "top-right"
	TopLeft     ToastPosition = "top-left"
	BottomRight ToastPosition = "bottom-right"
	BottomLeft  ToastPosition = "bottom-left"
)

// Toast represents a toast notification
type Toast struct {
	ID       string
	Type     ToastType
	Message  string
	Duration int // milliseconds
	Actions  []Action
}

// Action represents an action button in a notification
type Action struct {
	Text    string
	URL     string
	Method  string // GET, POST, etc
	Class   string // CSS class for styling
	OnClick string // JavaScript function name
}

// NewToast creates a new toast notification
func NewToast(toastType ToastType, message string) *Toast {
	return &Toast{
		ID:       fmt.Sprintf("toast-%d", time.Now().UnixNano()),
		Type:     toastType,
		Message:  message,
		Duration: 5000, // Default 5 seconds
	}
}

// WithDuration sets the toast duration
func (t *Toast) WithDuration(duration int) *Toast {
	t.Duration = duration
	return t
}

// WithAction adds an action button to the toast
func (t *Toast) WithAction(action Action) *Toast {
	t.Actions = append(t.Actions, action)
	return t
}

// Build generates the HTML for the toast
func (t *Toast) Build() string {
	var builder strings.Builder
	
	// Icon mapping
	icon := t.getIcon()
	
	// Build toast HTML
	builder.WriteString(fmt.Sprintf(`<div id="%s" class="toast toast-%s" style="animation-duration: %dms">`, t.ID, t.Type, t.Duration))
	builder.WriteString(`<div class="toast-content">`)
	builder.WriteString(fmt.Sprintf(`<span class="toast-icon">%s</span>`, icon))
	builder.WriteString(fmt.Sprintf(`<span class="toast-message">%s</span>`, t.Message))
	
	// Add actions if any
	if len(t.Actions) > 0 {
		builder.WriteString(`<div class="toast-actions">`)
		for _, action := range t.Actions {
			if action.URL != "" {
				// HTMX action
				builder.WriteString(fmt.Sprintf(
					`<button class="toast-action %s" hx-%s="%s" hx-target="body">%s</button>`,
					action.Class, strings.ToLower(action.Method), action.URL, action.Text,
				))
			} else if action.OnClick != "" {
				// JavaScript action
				builder.WriteString(fmt.Sprintf(
					`<button class="toast-action %s" onclick="%s">%s</button>`,
					action.Class, action.OnClick, action.Text,
				))
			}
		}
		builder.WriteString(`</div>`)
	}
	
	builder.WriteString(`</div>`)
	
	// Close button
	builder.WriteString(fmt.Sprintf(`<button class="toast-close" onclick="document.getElementById('%s').remove()">×</button>`, t.ID))
	
	// Auto-dismiss script
	builder.WriteString(fmt.Sprintf(`
		<script>
			setTimeout(function() {
				var el = document.getElementById('%s');
				if (el) el.remove();
			}, %d);
		</script>`, t.ID, t.Duration))
	
	builder.WriteString(`</div>`)
	
	return builder.String()
}

// getIcon returns the appropriate icon for the toast type
func (t *Toast) getIcon() string {
	switch t.Type {
	case ToastSuccess:
		return "✓"
	case ToastError:
		return "✗"
	case ToastWarning:
		return "⚠"
	case ToastInfo:
		return "ℹ"
	default:
		return ""
	}
}

// ToastBuilder provides a fluent interface for building toasts
type ToastBuilder struct {
	toast *Toast
}

// NewToastBuilder creates a new toast builder
func NewToastBuilder(toastType ToastType, message string) *ToastBuilder {
	return &ToastBuilder{
		toast: NewToast(toastType, message),
	}
}

// Duration sets the toast duration
func (b *ToastBuilder) Duration(ms int) *ToastBuilder {
	b.toast.Duration = ms
	return b
}

// Action adds an action to the toast
func (b *ToastBuilder) Action(text, url string) *ToastBuilder {
	b.toast.WithAction(Action{
		Text:   text,
		URL:    url,
		Method: "GET",
	})
	return b
}

// PostAction adds a POST action to the toast
func (b *ToastBuilder) PostAction(text, url string) *ToastBuilder {
	b.toast.WithAction(Action{
		Text:   text,
		URL:    url,
		Method: "POST",
	})
	return b
}

// JSAction adds a JavaScript action to the toast
func (b *ToastBuilder) JSAction(text, onClick string) *ToastBuilder {
	b.toast.WithAction(Action{
		Text:    text,
		OnClick: onClick,
	})
	return b
}

// Build returns the toast
func (b *ToastBuilder) Build() *Toast {
	return b.toast
}