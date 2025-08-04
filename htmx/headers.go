package htmx

// Request headers sent by HTMX
const (
	// HeaderRequest indicates this is an HTMX request
	HeaderRequest = "HX-Request"
	
	// HeaderBoosted indicates this is a boosted request (follows links/forms)
	HeaderBoosted = "HX-Boosted"
	
	// HeaderTrigger contains the id of the element that triggered the request
	HeaderTrigger = "HX-Trigger"
	
	// HeaderTriggerName contains the name of the element that triggered the request
	HeaderTriggerName = "HX-Trigger-Name"
	
	// HeaderTarget contains the id of the target element
	HeaderTarget = "HX-Target"
	
	// HeaderCurrentURL contains the current URL of the browser
	HeaderCurrentURL = "HX-Current-URL"
	
	// HeaderPrompt contains the user's response to hx-prompt
	HeaderPrompt = "HX-Prompt"
	
	// HeaderHistoryRestoreRequest indicates this is a history restoration request
	HeaderHistoryRestoreRequest = "HX-History-Restore-Request"
)

// Response headers that can be set by the server
const (
	// HeaderRedirect triggers a client-side redirect
	HeaderRedirect = "HX-Redirect"
	
	// HeaderRefresh triggers a client-side full page refresh
	HeaderRefresh = "HX-Refresh"
	
	// HeaderLocation allows you to do a client-side redirect that does not do a full page reload
	HeaderLocation = "HX-Location"
	
	// HeaderPushURL pushes a new URL into the browser history
	HeaderPushURL = "HX-Push-Url"
	
	// HeaderReplaceURL replaces the current URL in the browser history
	HeaderReplaceURL = "HX-Replace-Url"
	
	// HeaderReswap allows you to override the swap behavior
	HeaderReswap = "HX-Reswap"
	
	// HeaderRetarget allows you to override the target element
	HeaderRetarget = "HX-Retarget"
	
	// HeaderReselect allows you to override the element selection
	HeaderReselect = "HX-Reselect"
	
	// HeaderResponseTrigger triggers events on the client
	HeaderResponseTrigger = "HX-Trigger"
	
	// HeaderResponseTriggerAfterSettle triggers events after the settle phase
	HeaderResponseTriggerAfterSettle = "HX-Trigger-After-Settle"
	
	// HeaderResponseTriggerAfterSwap triggers events after the swap phase
	HeaderResponseTriggerAfterSwap = "HX-Trigger-After-Swap"
)

// CSRF header for HTMX requests
const (
	// HeaderCSRFToken is the header used to send CSRF tokens
	HeaderCSRFToken = "X-CSRF-Token"
)

// Common HTMX attribute values
const (
	// SwapInnerHTML replaces the inner html of the target element (default)
	SwapInnerHTML = "innerHTML"
	
	// SwapOuterHTML replaces the entire target element
	SwapOuterHTML = "outerHTML"
	
	// SwapBeforeBegin inserts before the target element
	SwapBeforeBegin = "beforebegin"
	
	// SwapAfterBegin inserts after the first child of the target
	SwapAfterBegin = "afterbegin"
	
	// SwapBeforeEnd inserts before the last child of the target
	SwapBeforeEnd = "beforeend"
	
	// SwapAfterEnd inserts after the target element
	SwapAfterEnd = "afterend"
	
	// SwapDelete deletes the target element
	SwapDelete = "delete"
	
	// SwapNone does not swap content
	SwapNone = "none"
)