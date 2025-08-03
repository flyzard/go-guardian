package template

import (
	"fmt"
	"html/template"
	"strings"
)

// HTMXExtensions provides HTMX-specific template functions and components
type HTMXExtensions struct {
	registry *ComponentRegistry
}

// NewHTMXExtensions creates HTMX template extensions
func NewHTMXExtensions(registry *ComponentRegistry) *HTMXExtensions {
	ext := &HTMXExtensions{
		registry: registry,
	}

	// Register HTMX-specific functions
	registry.manager.AddFunc("hxGet", ext.hxGet)
	registry.manager.AddFunc("hxPost", ext.hxPost)
	registry.manager.AddFunc("hxPut", ext.hxPut)
	registry.manager.AddFunc("hxDelete", ext.hxDelete)
	registry.manager.AddFunc("hxPatch", ext.hxPatch)
	registry.manager.AddFunc("hxTrigger", ext.hxTrigger)
	registry.manager.AddFunc("hxTarget", ext.hxTarget)
	registry.manager.AddFunc("hxSwap", ext.hxSwap)
	registry.manager.AddFunc("hxBoost", ext.hxBoost)
	registry.manager.AddFunc("hxPushUrl", ext.hxPushUrl)
	registry.manager.AddFunc("hxConfirm", ext.hxConfirm)
	registry.manager.AddFunc("hxDisable", ext.hxDisable)
	registry.manager.AddFunc("hxIndicator", ext.hxIndicator)
	registry.manager.AddFunc("hxHeaders", ext.hxHeaders)
	registry.manager.AddFunc("hxParams", ext.hxParams)
	registry.manager.AddFunc("hxVals", ext.hxVals)
	registry.manager.AddFunc("hxExt", ext.hxExt)
	registry.manager.AddFunc("hxSse", ext.hxSse)
	registry.manager.AddFunc("hxWs", ext.hxWs)
	registry.manager.AddFunc("hxSelect", ext.hxSelect)
	registry.manager.AddFunc("hxSelectOob", ext.hxSelectOob)

	// Register HTMX components
	ext.registerComponents()

	return ext
}

// HTMX attribute functions

func (h *HTMXExtensions) hxGet(url string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-get="%s"`, url))
}

func (h *HTMXExtensions) hxPost(url string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-post="%s"`, url))
}

func (h *HTMXExtensions) hxPut(url string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-put="%s"`, url))
}

func (h *HTMXExtensions) hxDelete(url string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-delete="%s"`, url))
}

func (h *HTMXExtensions) hxPatch(url string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-patch="%s"`, url))
}

func (h *HTMXExtensions) hxTrigger(trigger string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-trigger="%s"`, trigger))
}

func (h *HTMXExtensions) hxTarget(target string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-target="%s"`, target))
}

func (h *HTMXExtensions) hxSwap(swap string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-swap="%s"`, swap))
}

func (h *HTMXExtensions) hxBoost(boost bool) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-boost="%t"`, boost))
}

func (h *HTMXExtensions) hxPushUrl(url string) template.HTMLAttr {
	if url == "true" || url == "false" {
		return template.HTMLAttr(fmt.Sprintf(`hx-push-url="%s"`, url))
	}
	return template.HTMLAttr(fmt.Sprintf(`hx-push-url="%s"`, url))
}

func (h *HTMXExtensions) hxConfirm(message string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-confirm="%s"`, message))
}

func (h *HTMXExtensions) hxDisable() template.HTMLAttr {
	return template.HTMLAttr(`hx-disable`)
}

func (h *HTMXExtensions) hxIndicator(selector string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-indicator="%s"`, selector))
}

func (h *HTMXExtensions) hxHeaders(headers map[string]string) template.HTMLAttr {
	pairs := make([]string, 0, len(headers))
	for k, v := range headers {
		pairs = append(pairs, fmt.Sprintf(`"%s": "%s"`, k, v))
	}
	return template.HTMLAttr(fmt.Sprintf(`hx-headers='{%s}'`, strings.Join(pairs, ", ")))
}

func (h *HTMXExtensions) hxParams(params string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-params="%s"`, params))
}

func (h *HTMXExtensions) hxVals(vals map[string]interface{}) template.HTMLAttr {
	pairs := make([]string, 0, len(vals))
	for k, v := range vals {
		pairs = append(pairs, fmt.Sprintf(`"%s": "%v"`, k, v))
	}
	return template.HTMLAttr(fmt.Sprintf(`hx-vals='{%s}'`, strings.Join(pairs, ", ")))
}

func (h *HTMXExtensions) hxExt(extensions ...string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-ext="%s"`, strings.Join(extensions, ",")))
}

func (h *HTMXExtensions) hxSse(url string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-sse="%s"`, url))
}

func (h *HTMXExtensions) hxWs(url string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-ws="%s"`, url))
}

func (h *HTMXExtensions) hxSelect(selector string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-select="%s"`, selector))
}

func (h *HTMXExtensions) hxSelectOob(selector string) template.HTMLAttr {
	return template.HTMLAttr(fmt.Sprintf(`hx-select-oob="%s"`, selector))
}

// registerComponents registers HTMX-specific components
func (h *HTMXExtensions) registerComponents() error {
	// Live Search component
	err := h.registry.Register("htmx-search", ComponentDefinition{
		Template: `<div class="htmx-search {{ .Props.class }}">
			<input type="search" 
				class="form-control {{ .Props.inputClass }}"
				name="{{ .Props.name }}"
				placeholder="{{ .Props.placeholder }}"
				hx-get="{{ .Props.url }}"
				hx-trigger="{{ .Props.trigger }}"
				hx-target="{{ .Props.target }}"
				hx-indicator="{{ .Props.indicator }}"
				{{ if .Props.pushUrl }}hx-push-url="true"{{ end }}
				{{ if .Props.minLength }}hx-trigger="keyup changed delay:{{ .Props.delay }} from:input[value.length>={{ .Props.minLength }}]"{{ end }}>
			{{ if .Props.indicator }}
			<div class="{{ .Props.indicator }} htmx-indicator">
				{{ if .Props.indicatorContent }}
					{{ .Props.indicatorContent | safeHTML }}
				{{ else }}
					<span class="spinner-border spinner-border-sm" role="status">
						<span class="sr-only">Searching...</span>
					</span>
				{{ end }}
			</div>
			{{ end }}
		</div>`,
		RequiredProps: []string{"name", "url", "target"},
		DefaultProps: map[string]interface{}{
			"trigger":     "keyup changed delay:500ms",
			"placeholder": "Search...",
			"class":       "",
			"inputClass":  "",
			"pushUrl":     false,
			"delay":       "500ms",
			"minLength":   0,
		},
	})
	if err != nil {
		return err
	}

	// Infinite Scroll component
	err = h.registry.Register("htmx-infinite-scroll", ComponentDefinition{
		Template: `<div class="htmx-infinite-scroll {{ .Props.class }}"
			hx-get="{{ .Props.url }}"
			hx-trigger="{{ .Props.trigger }}"
			hx-swap="{{ .Props.swap }}"
			{{ if .Props.indicator }}hx-indicator="{{ .Props.indicator }}"{{ end }}>
			{{ slot "content" .Slots }}
			{{ if .Props.showLoader }}
			<div class="htmx-infinite-scroll-loader {{ .Props.loaderClass }}">
				{{ if .Props.loaderContent }}
					{{ .Props.loaderContent | safeHTML }}
				{{ else }}
					<div class="text-center p-4">
						<span class="spinner-border" role="status">
							<span class="sr-only">Loading...</span>
						</span>
					</div>
				{{ end }}
			</div>
			{{ end }}
		</div>`,
		RequiredProps: []string{"url"},
		DefaultProps: map[string]interface{}{
			"trigger":     "revealed",
			"swap":        "afterend",
			"class":       "",
			"showLoader":  true,
			"loaderClass": "",
		},
	})
	if err != nil {
		return err
	}

	// Click to Edit component
	err = h.registry.Register("htmx-click-edit", ComponentDefinition{
		Template: `<div class="htmx-click-edit {{ .Props.class }}">
			<div class="htmx-click-edit-display"
				hx-get="{{ .Props.editUrl }}"
				hx-trigger="click"
				hx-swap="outerHTML"
				style="cursor: pointer;">
				{{ if .Props.value }}
					{{ .Props.value }}
				{{ else }}
					<span class="text-muted">{{ .Props.emptyText }}</span>
				{{ end }}
				{{ if .Props.showIcon }}
					<i class="fas fa-edit ml-2 text-muted"></i>
				{{ end }}
			</div>
		</div>`,
		RequiredProps: []string{"editUrl"},
		DefaultProps: map[string]interface{}{
			"emptyText": "Click to edit",
			"showIcon":  true,
			"class":     "",
		},
	})
	if err != nil {
		return err
	}

	// Polling component
	err = h.registry.Register("htmx-poll", ComponentDefinition{
		Template: `<div class="htmx-poll {{ .Props.class }}"
			hx-get="{{ .Props.url }}"
			hx-trigger="every {{ .Props.interval }}"
			hx-swap="{{ .Props.swap }}"
			{{ if .Props.target }}hx-target="{{ .Props.target }}"{{ end }}>
			{{ slot "content" .Slots }}
		</div>`,
		RequiredProps: []string{"url", "interval"},
		DefaultProps: map[string]interface{}{
			"swap":  "innerHTML",
			"class": "",
		},
	})
	if err != nil {
		return err
	}

	// Form component with HTMX
	err = h.registry.Register("htmx-form", ComponentDefinition{
		Template: `<form class="{{ .Props.class }}"
			hx-{{ .Props.method }}="{{ .Props.url }}"
			{{ if .Props.target }}hx-target="{{ .Props.target }}"{{ end }}
			{{ if .Props.swap }}hx-swap="{{ .Props.swap }}"{{ end }}
			{{ if .Props.indicator }}hx-indicator="{{ .Props.indicator }}"{{ end }}
			{{ if .Props.confirm }}hx-confirm="{{ .Props.confirm }}"{{ end }}
			{{ if .Props.pushUrl }}hx-push-url="true"{{ end }}
			{{ if .Props.boost }}hx-boost="true"{{ end }}
			{{ range $k, $v := .Props.attrs }}{{ $k }}="{{ $v }}" {{ end }}>
			{{ if .Props.csrf }}
				<input type="hidden" name="{{ .Props.csrfName }}" value="{{ .Props.csrfValue }}">
			{{ end }}
			{{ slot "fields" .Slots }}
			{{ if .Props.showButtons }}
			<div class="form-group {{ .Props.buttonGroupClass }}">
				<button type="submit" class="btn btn-{{ .Props.submitVariant }}">
					{{ if .Props.submitIcon }}<i class="fas fa-{{ .Props.submitIcon }} mr-2"></i>{{ end }}
					{{ .Props.submitText }}
				</button>
				{{ if .Props.showCancel }}
				<button type="button" class="btn btn-{{ .Props.cancelVariant }}">
					{{ .Props.cancelText }}
				</button>
				{{ end }}
			</div>
			{{ end }}
			{{ if .Props.indicator }}
			<div class="{{ .Props.indicator }} htmx-indicator">
				{{ if .Props.indicatorContent }}
					{{ .Props.indicatorContent | safeHTML }}
				{{ else }}
					<span class="spinner-border spinner-border-sm" role="status">
						<span class="sr-only">Processing...</span>
					</span>
				{{ end }}
			</div>
			{{ end }}
		</form>`,
		RequiredProps: []string{"url"},
		DefaultProps: map[string]interface{}{
			"method":           "post",
			"class":            "",
			"csrf":             false,
			"csrfName":         "_csrf",
			"showButtons":      true,
			"buttonGroupClass": "mt-3",
			"submitText":       "Submit",
			"submitVariant":    "primary",
			"cancelText":       "Cancel",
			"cancelVariant":    "secondary",
			"showCancel":       false,
			"attrs":            map[string]string{},
		},
	})
	if err != nil {
		return err
	}

	// Delete button with confirmation
	err = h.registry.Register("htmx-delete-button", ComponentDefinition{
		Template: `<button type="button"
			class="btn btn-{{ .Props.variant }} {{ .Props.size }} {{ .Props.class }}"
			hx-delete="{{ .Props.url }}"
			hx-confirm="{{ .Props.confirmText }}"
			{{ if .Props.target }}hx-target="{{ .Props.target }}"{{ end }}
			{{ if .Props.swap }}hx-swap="{{ .Props.swap }}"{{ end }}
			{{ if .Props.indicator }}hx-indicator="{{ .Props.indicator }}"{{ end }}
			{{ range $k, $v := .Props.attrs }}{{ $k }}="{{ $v }}" {{ end }}>
			{{ if .Props.icon }}<i class="fas fa-{{ .Props.icon }} {{ if .Props.text }}mr-2{{ end }}"></i>{{ end }}
			{{ .Props.text }}
		</button>`,
		RequiredProps: []string{"url"},
		DefaultProps: map[string]interface{}{
			"variant":     "danger",
			"size":        "",
			"class":       "",
			"confirmText": "Are you sure you want to delete this item?",
			"icon":        "trash",
			"text":        "Delete",
			"attrs":       map[string]string{},
		},
	})

	return err
}

// HTMXBuilder provides a fluent API for building HTMX elements
type HTMXBuilder struct {
	tag        string
	attrs      map[string]string
	content    string
	classes    []string
	htmxAttrs  map[string]string
}

// NewHTMXBuilder creates a new HTMX element builder
func NewHTMXBuilder(tag string) *HTMXBuilder {
	return &HTMXBuilder{
		tag:       tag,
		attrs:     make(map[string]string),
		htmxAttrs: make(map[string]string),
		classes:   []string{},
	}
}

// Get sets hx-get attribute
func (b *HTMXBuilder) Get(url string) *HTMXBuilder {
	b.htmxAttrs["hx-get"] = url
	return b
}

// Post sets hx-post attribute
func (b *HTMXBuilder) Post(url string) *HTMXBuilder {
	b.htmxAttrs["hx-post"] = url
	return b
}

// Put sets hx-put attribute
func (b *HTMXBuilder) Put(url string) *HTMXBuilder {
	b.htmxAttrs["hx-put"] = url
	return b
}

// Delete sets hx-delete attribute
func (b *HTMXBuilder) Delete(url string) *HTMXBuilder {
	b.htmxAttrs["hx-delete"] = url
	return b
}

// Trigger sets hx-trigger attribute
func (b *HTMXBuilder) Trigger(trigger string) *HTMXBuilder {
	b.htmxAttrs["hx-trigger"] = trigger
	return b
}

// Target sets hx-target attribute
func (b *HTMXBuilder) Target(target string) *HTMXBuilder {
	b.htmxAttrs["hx-target"] = target
	return b
}

// Swap sets hx-swap attribute
func (b *HTMXBuilder) Swap(swap string) *HTMXBuilder {
	b.htmxAttrs["hx-swap"] = swap
	return b
}

// Indicator sets hx-indicator attribute
func (b *HTMXBuilder) Indicator(indicator string) *HTMXBuilder {
	b.htmxAttrs["hx-indicator"] = indicator
	return b
}

// Confirm sets hx-confirm attribute
func (b *HTMXBuilder) Confirm(message string) *HTMXBuilder {
	b.htmxAttrs["hx-confirm"] = message
	return b
}

// Class adds CSS classes
func (b *HTMXBuilder) Class(classes ...string) *HTMXBuilder {
	b.classes = append(b.classes, classes...)
	return b
}

// Attr adds a regular HTML attribute
func (b *HTMXBuilder) Attr(key, value string) *HTMXBuilder {
	b.attrs[key] = value
	return b
}

// Content sets the element content
func (b *HTMXBuilder) Content(content string) *HTMXBuilder {
	b.content = content
	return b
}

// Build generates the HTML
func (b *HTMXBuilder) Build() template.HTML {
	// Combine classes
	if len(b.classes) > 0 {
		b.attrs["class"] = strings.Join(b.classes, " ")
	}

	// Build attributes
	var attrs []string
	for k, v := range b.attrs {
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, k, v))
	}
	for k, v := range b.htmxAttrs {
		attrs = append(attrs, fmt.Sprintf(`%s="%s"`, k, v))
	}

	attrString := ""
	if len(attrs) > 0 {
		attrString = " " + strings.Join(attrs, " ")
	}

	// Build HTML
	if b.content == "" {
		return template.HTML(fmt.Sprintf(`<%s%s />`, b.tag, attrString))
	}

	return template.HTML(fmt.Sprintf(`<%s%s>%s</%s>`, b.tag, attrString, b.content, b.tag))
}