package table

import (
	"fmt"
	"html"
	"time"
)

// Formatter provides cell formatting functions
type Formatter struct {
	dateFormat     string
	timeFormat     string
	datetimeFormat string
	timezone       *time.Location
}

// NewFormatter creates a new formatter with default settings
func NewFormatter() *Formatter {
	loc, _ := time.LoadLocation("UTC")
	return &Formatter{
		dateFormat:     "2006-01-02",
		timeFormat:     "15:04:05",
		datetimeFormat: "2006-01-02 15:04:05",
		timezone:       loc,
	}
}

// SetTimezone sets the timezone for time formatting
func (f *Formatter) SetTimezone(tz string) error {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return err
	}
	f.timezone = loc
	return nil
}

// SetDateFormat sets the date format
func (f *Formatter) SetDateFormat(format string) {
	f.dateFormat = format
}

// SetTimeFormat sets the time format
func (f *Formatter) SetTimeFormat(format string) {
	f.timeFormat = format
}

// SetDateTimeFormat sets the datetime format
func (f *Formatter) SetDateTimeFormat(format string) {
	f.datetimeFormat = format
}

// Status formats a status value with appropriate styling
func (f *Formatter) Status(status string, style ...string) Cell {
	class := "badge"
	
	// Default status classes
	switch status {
	case "active", "online", "success", "completed":
		class += " badge-success"
	case "inactive", "offline", "error", "failed":
		class += " badge-danger"
	case "pending", "warning", "processing":
		class += " badge-warning"
	case "unknown", "n/a":
		class += " badge-secondary"
	default:
		class += " badge-info"
	}
	
	// Override with custom style if provided
	if len(style) > 0 {
		class = style[0]
	}
	
	return Cell{
		Content: fmt.Sprintf(`<span class="%s">%s</span>`, class, html.EscapeString(status)),
		IsHTML:  true,
	}
}

// Badge creates a badge cell
func (f *Formatter) Badge(text, badgeClass string) Cell {
	return Cell{
		Content: fmt.Sprintf(`<span class="badge %s">%s</span>`, badgeClass, html.EscapeString(text)),
		IsHTML:  true,
	}
}

// Link formats a link
func (f *Formatter) Link(text, href string, attributes ...map[string]string) Cell {
	attrs := ""
	if len(attributes) > 0 {
		for key, value := range attributes[0] {
			attrs += fmt.Sprintf(` %s="%s"`, key, html.EscapeString(value))
		}
	}
	
	return Cell{
		Content: fmt.Sprintf(`<a href="%s"%s>%s</a>`, html.EscapeString(href), attrs, html.EscapeString(text)),
		IsHTML:  true,
	}
}

// Button formats a button
func (f *Formatter) Button(text, action string, btnClass ...string) Cell {
	class := "btn btn-sm btn-primary"
	if len(btnClass) > 0 {
		class = btnClass[0]
	}
	
	return Cell{
		Content: fmt.Sprintf(`<button class="%s" data-action="%s">%s</button>`, 
			class, html.EscapeString(action), html.EscapeString(text)),
		IsHTML: true,
	}
}

// Icon formats an icon
func (f *Formatter) Icon(iconClass string, text ...string) Cell {
	content := fmt.Sprintf(`<i class="%s"></i>`, iconClass)
	if len(text) > 0 {
		content += " " + html.EscapeString(text[0])
	}
	
	return Cell{
		Content: content,
		IsHTML:  true,
	}
}

// Progress formats a progress bar
func (f *Formatter) Progress(value, max int, showLabel ...bool) Cell {
	percentage := 0
	if max > 0 {
		percentage = (value * 100) / max
	}
	
	label := ""
	if len(showLabel) > 0 && showLabel[0] {
		label = fmt.Sprintf(`%d%%`, percentage)
	}
	
	return Cell{
		Content: fmt.Sprintf(`<div class="progress">
			<div class="progress-bar" style="width: %d%%">%s</div>
		</div>`, percentage, label),
		IsHTML: true,
	}
}

// Date formats a time as date
func (f *Formatter) Date(t time.Time) Cell {
	return Cell{
		Content: t.In(f.timezone).Format(f.dateFormat),
	}
}

// Time formats a time as time only
func (f *Formatter) Time(t time.Time) Cell {
	return Cell{
		Content: t.In(f.timezone).Format(f.timeFormat),
	}
}

// DateTime formats a time as datetime
func (f *Formatter) DateTime(t time.Time) Cell {
	return Cell{
		Content: t.In(f.timezone).Format(f.datetimeFormat),
	}
}

// UnixTime formats a unix timestamp
func (f *Formatter) UnixTime(timestamp int64, format ...string) Cell {
	t := time.Unix(timestamp, 0)
	if len(format) > 0 {
		return Cell{Content: t.In(f.timezone).Format(format[0])}
	}
	return f.DateTime(t)
}

// RelativeTime formats time as relative (e.g., "5 minutes ago")
func (f *Formatter) RelativeTime(t time.Time) Cell {
	duration := time.Since(t)
	
	var text string
	switch {
	case duration < time.Minute:
		text = "just now"
	case duration < time.Hour:
		minutes := int(duration.Minutes())
		if minutes == 1 {
			text = "1 minute ago"
		} else {
			text = fmt.Sprintf("%d minutes ago", minutes)
		}
	case duration < 24*time.Hour:
		hours := int(duration.Hours())
		if hours == 1 {
			text = "1 hour ago"
		} else {
			text = fmt.Sprintf("%d hours ago", hours)
		}
	case duration < 7*24*time.Hour:
		days := int(duration.Hours() / 24)
		if days == 1 {
			text = "1 day ago"
		} else {
			text = fmt.Sprintf("%d days ago", days)
		}
	default:
		text = t.In(f.timezone).Format(f.dateFormat)
	}
	
	return Cell{
		Content: text,
		Attributes: map[string]string{
			"title": t.In(f.timezone).Format(f.datetimeFormat),
		},
	}
}

// Currency formats a number as currency
func (f *Formatter) Currency(amount float64, symbol ...string) Cell {
	curr := "$"
	if len(symbol) > 0 {
		curr = symbol[0]
	}
	
	return Cell{
		Content: fmt.Sprintf("%s%.2f", curr, amount),
		Class:   "text-right",
	}
}

// Number formats a number with thousand separators
func (f *Formatter) Number(n interface{}, decimals ...int) Cell {
	format := "%d"
	if len(decimals) > 0 && decimals[0] > 0 {
		format = fmt.Sprintf("%%.%df", decimals[0])
	}
	
	return Cell{
		Content: fmt.Sprintf(format, n),
		Class:   "text-right",
	}
}

// Percentage formats a percentage
func (f *Formatter) Percentage(value float64, decimals ...int) Cell {
	format := "%.0f%%"
	if len(decimals) > 0 {
		format = fmt.Sprintf("%%.%df%%%%", decimals[0])
	}
	
	return Cell{
		Content: fmt.Sprintf(format, value),
		Class:   "text-right",
	}
}

// Boolean formats a boolean value
func (f *Formatter) Boolean(value bool, trueText, falseText string) Cell {
	text := falseText
	class := "text-danger"
	
	if value {
		text = trueText
		class = "text-success"
	}
	
	return Cell{
		Content: fmt.Sprintf(`<span class="%s">%s</span>`, class, html.EscapeString(text)),
		IsHTML:  true,
	}
}

// Checkbox formats a checkbox
func (f *Formatter) Checkbox(checked bool, name ...string) Cell {
	checkedAttr := ""
	if checked {
		checkedAttr = " checked"
	}
	
	nameAttr := ""
	if len(name) > 0 {
		nameAttr = fmt.Sprintf(` name="%s"`, html.EscapeString(name[0]))
	}
	
	return Cell{
		Content: fmt.Sprintf(`<input type="checkbox"%s%s>`, nameAttr, checkedAttr),
		IsHTML:  true,
		Class:   "text-center",
	}
}

// Actions formats action buttons
func (f *Formatter) Actions(actions ...Action) Cell {
	var buttons string
	for _, action := range actions {
		btnClass := "btn btn-sm " + action.Class
		if action.Class == "" {
			btnClass = "btn btn-sm btn-secondary"
		}
		
		attrs := ""
		for key, value := range action.Attributes {
			attrs += fmt.Sprintf(` data-%s="%s"`, key, html.EscapeString(value))
		}
		
		if action.Icon != "" {
			buttons += fmt.Sprintf(`<button class="%s" data-action="%s"%s><i class="%s"></i> %s</button> `,
				btnClass, action.Name, attrs, action.Icon, html.EscapeString(action.Label))
		} else {
			buttons += fmt.Sprintf(`<button class="%s" data-action="%s"%s>%s</button> `,
				btnClass, action.Name, attrs, html.EscapeString(action.Label))
		}
	}
	
	return Cell{
		Content: fmt.Sprintf(`<div class="btn-group">%s</div>`, buttons),
		IsHTML:  true,
		Class:   "actions",
	}
}

// Action represents an action button
type Action struct {
	Name       string
	Label      string
	Icon       string
	Class      string
	Attributes map[string]string
}

// Truncate truncates text to a maximum length
func (f *Formatter) Truncate(text string, maxLength int) Cell {
	if len(text) <= maxLength {
		return Cell{Content: text}
	}
	
	truncated := text[:maxLength-3] + "..."
	return Cell{
		Content: truncated,
		Attributes: map[string]string{
			"title": text,
		},
	}
}

// Code formats text as code
func (f *Formatter) Code(text string) Cell {
	return Cell{
		Content: fmt.Sprintf(`<code>%s</code>`, html.EscapeString(text)),
		IsHTML:  true,
	}
}

// Pre formats text as preformatted
func (f *Formatter) Pre(text string) Cell {
	return Cell{
		Content: fmt.Sprintf(`<pre>%s</pre>`, html.EscapeString(text)),
		IsHTML:  true,
	}
}

// Image formats an image
func (f *Formatter) Image(src, alt string, width ...int) Cell {
	w := ""
	if len(width) > 0 {
		w = fmt.Sprintf(` width="%d"`, width[0])
	}
	
	return Cell{
		Content: fmt.Sprintf(`<img src="%s" alt="%s"%s>`, 
			html.EscapeString(src), html.EscapeString(alt), w),
		IsHTML: true,
	}
}

// Custom allows custom HTML content
func (f *Formatter) Custom(html string) Cell {
	return Cell{
		Content: html,
		IsHTML:  true,
	}
}