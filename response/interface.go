package response

import "net/http"

// Response provides a unified interface for building HTTP responses
type Response interface {
	// Status sets the HTTP status code
	Status(code int) Response
	
	// Header adds a header to the response
	Header(key, value string) Response
	
	// ContentType sets the Content-Type header
	ContentType(contentType string) Response
	
	// JSON sends a JSON response
	JSON(data any) Response
	
	// HTML sends an HTML response
	HTML(content string) Response
	
	// Text sends a plain text response
	Text(content string) Response
	
	// Error sends an error response
	Error(err error) Response
	
	// ErrorWithStatus sends an error with specific status code
	ErrorWithStatus(err error, status int) Response
	
	// Send writes the response to the client
	Send() error
}

// ResponseFunc is a function that returns a Response
type ResponseFunc func(w http.ResponseWriter, r *http.Request) Response

// Option is a function that configures a Response
type Option func(Response) Response

// ErrorHandler handles errors in a consistent way
type ErrorHandler interface {
	HandleError(w http.ResponseWriter, r *http.Request, err error)
}

// Responder is implemented by types that can write themselves as HTTP responses
type Responder interface {
	Respond(w http.ResponseWriter, r *http.Request) error
}