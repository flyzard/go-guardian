// File: auth/session_notes.go
package auth

// Session Security Notes:
//
// Gorilla sessions has some limitations regarding session regeneration:
// 1. It creates cookies even for empty sessions (by design)
// 2. Session regeneration requires manual deletion of old sessions
// 3. There's no built-in server-side session storage/expiration
//
// For production use, consider:
// - Implementing server-side session storage (Redis/Database)
// - Adding session fingerprinting (IP, User-Agent)
// - Implementing proper session regeneration on privilege changes
// - Adding server-side session expiration tracking
//
// The current implementation provides:
// - Secure cookie settings (HttpOnly, Secure, SameSite)
// - Basic session regeneration
// - CSRF protection through double-submit cookies
