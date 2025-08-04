package htmx

import (
	"net/http"
	"strings"
)

// IsRequest checks if the request is from HTMX
func IsRequest(r *http.Request) bool {
	return r.Header.Get(HeaderRequest) == "true"
}

// IsBoosted checks if the request is HTMX boosted
func IsBoosted(r *http.Request) bool {
	return r.Header.Get(HeaderBoosted) == "true"
}

// IsHistoryRestore checks if this is a history restoration request
func IsHistoryRestore(r *http.Request) bool {
	return r.Header.Get(HeaderHistoryRestoreRequest) == "true"
}

// GetTrigger returns the id of the element that triggered the request
func GetTrigger(r *http.Request) string {
	return r.Header.Get(HeaderTrigger)
}

// GetTriggerName returns the name of the element that triggered the request
func GetTriggerName(r *http.Request) string {
	return r.Header.Get(HeaderTriggerName)
}

// GetTarget returns the id of the target element
func GetTarget(r *http.Request) string {
	return r.Header.Get(HeaderTarget)
}

// GetCurrentURL returns the current URL of the browser
func GetCurrentURL(r *http.Request) string {
	return r.Header.Get(HeaderCurrentURL)
}

// GetPrompt returns the user's response to hx-prompt
func GetPrompt(r *http.Request) string {
	return r.Header.Get(HeaderPrompt)
}

// IsRequestWithTarget checks if the request is from HTMX with a specific target
func IsRequestWithTarget(r *http.Request, target string) bool {
	return IsRequest(r) && GetTarget(r) == target
}

// IsRequestWithTrigger checks if the request is from HTMX with a specific trigger
func IsRequestWithTrigger(r *http.Request, trigger string) bool {
	return IsRequest(r) && GetTrigger(r) == trigger
}

// RequestInfo contains all HTMX request information
type RequestInfo struct {
	IsHTMX         bool
	IsBoosted      bool
	Target         string
	TriggerName    string
	TriggerID      string
	CurrentURL     string
	Prompt         string
	HistoryRestore bool
}

// GetRequestInfo extracts all HTMX information from the request
func GetRequestInfo(r *http.Request) *RequestInfo {
	return &RequestInfo{
		IsHTMX:         IsRequest(r),
		IsBoosted:      IsBoosted(r),
		Target:         GetTarget(r),
		TriggerName:    GetTriggerName(r),
		TriggerID:      GetTrigger(r),
		CurrentURL:     GetCurrentURL(r),
		Prompt:         GetPrompt(r),
		HistoryRestore: IsHistoryRestore(r),
	}
}

// IsPartialRequest checks if this is a partial content request (not boosted, not full page)
func IsPartialRequest(r *http.Request) bool {
	return IsRequest(r) && !IsBoosted(r) && !IsHistoryRestore(r)
}

// NeedsFullPage determines if a full page response is needed
func NeedsFullPage(r *http.Request) bool {
	// Not an HTMX request, or is boosted, or is history restore
	return !IsRequest(r) || IsBoosted(r) || IsHistoryRestore(r)
}

// PreferredSwapMethod returns the preferred swap method based on the target
func PreferredSwapMethod(r *http.Request) string {
	target := GetTarget(r)
	
	// Common patterns
	switch {
	case target == "":
		return SwapInnerHTML
	case strings.HasSuffix(target, "-modal"):
		return SwapOuterHTML
	case strings.HasSuffix(target, "-list"):
		return SwapInnerHTML
	case strings.HasSuffix(target, "-form"):
		return SwapOuterHTML
	default:
		return SwapInnerHTML
	}
}