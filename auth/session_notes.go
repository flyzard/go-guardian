// File: auth/session_notes.go
package auth

// Session Security Notes:
//
// Guardian supports multiple session backends:
//
// 1. Cookie Sessions (Default):
//    - Uses gorilla/sessions CookieStore
//    - Data stored in encrypted cookies on client side
//    - Limited to 4KB size
//    - No server-side storage needed
//    - Survives server restarts
//    - Scales infinitely
//
// 2. In-Memory Sessions:
//    - Data stored in server memory
//    - No size limitations
//    - Lost on server restart
//    - Doesn't scale across multiple servers
//    - Good for development/single-server deployments
//
// 3. Database Sessions (Future):
//    - Data stored in database
//    - Persistent across restarts
//    - Scales across multiple servers
//    - Requires sessions table
//    - Can query active sessions
//
// Security considerations:
// - All backends use secure session IDs
// - Cookie sessions are encrypted with the SessionKey
// - HttpOnly, Secure, and SameSite flags are set by default
// - Session regeneration on privilege changes recommended
// - Consider session fingerprinting for additional security
//
// The sessions table in the schema is ONLY required if using
// database session backend. Cookie and memory backends do not
// need any database tables for session storage.
