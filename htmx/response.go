package htmx

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ResponseWriter wraps http.ResponseWriter with HTMX helpers
type ResponseWriter struct {
	http.ResponseWriter
	request *http.Request
}

// NewResponseWriter creates a new HTMX-aware response writer
func NewResponseWriter(w http.ResponseWriter, r *http.Request) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		request:        r,
	}
}

// Redirect performs an HTMX-aware redirect
func (w *ResponseWriter) Redirect(url string, statusCode ...int) {
	if IsRequest(w.request) {
		// For HTMX requests, use HX-Redirect header
		w.Header().Set(HeaderRedirect, url)
		w.WriteHeader(http.StatusOK)
	} else {
		// For regular requests, use standard redirect
		code := http.StatusSeeOther
		if len(statusCode) > 0 {
			code = statusCode[0]
		}
		http.Redirect(w.ResponseWriter, w.request, url, code)
	}
}

// Refresh triggers a full page refresh
func (w *ResponseWriter) Refresh() {
	w.Header().Set(HeaderRefresh, "true")
}

// Location performs a client-side redirect without full page reload
func (w *ResponseWriter) Location(path string) {
	w.Header().Set(HeaderLocation, path)
}

// PushURL pushes a new URL into browser history
func (w *ResponseWriter) PushURL(url string) {
	w.Header().Set(HeaderPushURL, url)
}

// ReplaceURL replaces the current URL in browser history
func (w *ResponseWriter) ReplaceURL(url string) {
	w.Header().Set(HeaderReplaceURL, url)
}

// Reswap overrides the swap behavior
func (w *ResponseWriter) Reswap(swapMethod string) {
	w.Header().Set(HeaderReswap, swapMethod)
}

// Retarget overrides the target element
func (w *ResponseWriter) Retarget(target string) {
	w.Header().Set(HeaderRetarget, target)
}

// Reselect overrides the element selection
func (w *ResponseWriter) Reselect(selector string) {
	w.Header().Set(HeaderReselect, selector)
}

// Trigger triggers events on the client
func (w *ResponseWriter) Trigger(events string) {
	w.Header().Set(HeaderResponseTrigger, events)
}

// TriggerAfterSettle triggers events after settle phase
func (w *ResponseWriter) TriggerAfterSettle(events string) {
	w.Header().Set(HeaderResponseTriggerAfterSettle, events)
}

// TriggerAfterSwap triggers events after swap phase
func (w *ResponseWriter) TriggerAfterSwap(events string) {
	w.Header().Set(HeaderResponseTriggerAfterSwap, events)
}

// TriggerEvent triggers a single event with optional detail
func (w *ResponseWriter) TriggerEvent(name string, detail interface{}) error {
	if detail == nil {
		w.Trigger(name)
		return nil
	}
	
	// For events with details, we need to JSON encode
	eventData := map[string]interface{}{
		name: detail,
	}
	
	data, err := json.Marshal(eventData)
	if err != nil {
		return err
	}
	
	w.Trigger(string(data))
	return nil
}

// TriggerEvents triggers multiple events
func (w *ResponseWriter) TriggerEvents(events map[string]interface{}) error {
	if len(events) == 0 {
		return nil
	}
	
	// Simple events without details
	simpleEvents := []string{}
	complexEvents := map[string]interface{}{}
	
	for name, detail := range events {
		if detail == nil {
			simpleEvents = append(simpleEvents, name)
		} else {
			complexEvents[name] = detail
		}
	}
	
	// Handle simple events
	if len(simpleEvents) > 0 && len(complexEvents) == 0 {
		w.Trigger(strings.Join(simpleEvents, ","))
		return nil
	}
	
	// Handle complex events
	if len(complexEvents) > 0 {
		data, err := json.Marshal(complexEvents)
		if err != nil {
			return err
		}
		w.Trigger(string(data))
	}
	
	return nil
}

// SetCSRFToken sets the CSRF token in response headers
func (w *ResponseWriter) SetCSRFToken(token string) {
	w.Header().Set(HeaderCSRFToken, token)
}

// SetCSRFToken sets HTMX CSRF token header on a standard ResponseWriter
func SetCSRFToken(w http.ResponseWriter, token string) {
	w.Header().Set(HeaderCSRFToken, token)
}

// RetargetError retargets errors to a specific element with error styling
func (w *ResponseWriter) RetargetError(target string, swapMethod string) {
	w.Retarget(target)
	w.Reswap(swapMethod)
}

// StopPolling sends a 286 status code to stop HTMX polling
func (w *ResponseWriter) StopPolling() {
	w.WriteHeader(286)
}

// Helper functions that work with standard http.ResponseWriter

// SetRedirect sets HTMX redirect header on a standard ResponseWriter
func SetRedirect(w http.ResponseWriter, url string) {
	w.Header().Set(HeaderRedirect, url)
}

// SetRefresh sets HTMX refresh header on a standard ResponseWriter
func SetRefresh(w http.ResponseWriter) {
	w.Header().Set(HeaderRefresh, "true")
}

// SetLocation sets HTMX location header on a standard ResponseWriter
func SetLocation(w http.ResponseWriter, path string) {
	w.Header().Set(HeaderLocation, path)
}

// SetPushURL sets HTMX push URL header on a standard ResponseWriter
func SetPushURL(w http.ResponseWriter, url string) {
	w.Header().Set(HeaderPushURL, url)
}

// SetTrigger sets HTMX trigger header on a standard ResponseWriter
func SetTrigger(w http.ResponseWriter, events string) {
	w.Header().Set(HeaderResponseTrigger, events)
}

// SetRetarget sets HTMX retarget header on a standard ResponseWriter
func SetRetarget(w http.ResponseWriter, target string) {
	w.Header().Set(HeaderRetarget, target)
}

// SetReswap sets HTMX reswap header on a standard ResponseWriter
func SetReswap(w http.ResponseWriter, swapMethod string) {
	w.Header().Set(HeaderReswap, swapMethod)
}