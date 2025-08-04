package response

import (
	"net/http"
)

// HTTPError sends an error response using http.Error semantics
func HTTPError(w http.ResponseWriter, r *http.Request, message string, code int) {
	New(w, r).
		Status(code).
		Text(message).
		Send()
}

// JSONResponse sends a JSON response
func JSONResponse(w http.ResponseWriter, r *http.Request, data any, status int) error {
	return New(w, r).
		Status(status).
		JSON(data).
		Send()
}

// HTMLResponse sends an HTML response
func HTMLResponse(w http.ResponseWriter, r *http.Request, html string, status int) error {
	return New(w, r).
		Status(status).
		HTML(html).
		Send()
}

// ErrorResponse sends an error response with appropriate formatting
func ErrorResponse(w http.ResponseWriter, r *http.Request, err error) error {
	return New(w, r).
		Error(err).
		Send()
}

// SuccessResponse sends a success response
func SuccessResponse(w http.ResponseWriter, r *http.Request, message string) error {
	builder := New(w, r).Status(http.StatusOK)
	
	// Check if JSON is wanted
	if wantsJSON(r) {
		return builder.JSON(map[string]string{"message": message}).Send()
	}
	
	// Otherwise send HTML success alert
	return builder.(*Builder).Success(message).Send()
}

// RedirectResponse performs an HTTP redirect (HTMX-aware)
func RedirectResponse(w http.ResponseWriter, r *http.Request, url string, status int) {
	// Let HTMX ResponseWriter handle the redirect logic
	builder := New(w, r).(*Builder)
	if builder.htmxWriter != nil {
		builder.htmxWriter.Redirect(url, status)
	} else {
		http.Redirect(w, r, url, status)
	}
}