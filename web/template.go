package web

import (
	"html/template"
	"net/http"
	"path/filepath"
)

// TemplateData represents data passed to templates
type TemplateData map[string]any

// Render renders a template with the given data
func (h *Handler) Render(w http.ResponseWriter, r *http.Request, tmpl string, data TemplateData) error {
	if data == nil {
		data = make(TemplateData)
	}

	// Add common data
	if user, _ := h.GetUser(r); user != nil {
		data["User"] = user
	}

	// Add CSRF token
	if token := r.Header.Get("X-CSRF-Token"); token != "" {
		data["CSRFToken"] = token
	} else if cookie, err := r.Cookie("csrf_token"); err == nil {
		data["CSRFToken"] = cookie.Value
	}

	// HTMX partial rendering
	if h.IsHTMX(r) {
		return h.renderPartial(w, tmpl, data)
	}

	return h.renderFull(w, tmpl, data)
}

func (h *Handler) renderPartial(w http.ResponseWriter, tmpl string, data TemplateData) error {
	t, err := h.loadTemplate(tmpl)
	if err != nil {
		return err
	}
	return t.ExecuteTemplate(w, "content", data)
}

func (h *Handler) renderFull(w http.ResponseWriter, tmpl string, data TemplateData) error {
	t, err := h.loadTemplate("templates/layout/base.html", tmpl)
	if err != nil {
		return err
	}
	return t.ExecuteTemplate(w, "layout", data)
}

func (h *Handler) loadTemplate(files ...string) (*template.Template, error) {
	// In production, cache templates
	if !h.development {
		h.templatesMu.RLock()
		key := filepath.Join(files...)
		if t, ok := h.templates[key]; ok {
			h.templatesMu.RUnlock()
			return t, nil
		}
		h.templatesMu.RUnlock()
	}

	// Parse templates
	t, err := template.ParseFiles(files...)
	if err != nil {
		return nil, err
	}

	// Cache in production
	if !h.development {
		h.templatesMu.Lock()
		h.templates[filepath.Join(files...)] = t
		h.templatesMu.Unlock()
	}

	return t, nil
}
