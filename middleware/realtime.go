package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// RealtimeConfig holds configuration for realtime middleware
type RealtimeConfig struct {
	// WebSocket settings
	EnableWebSocket     bool
	WebSocketPath       string
	ReadBufferSize      int
	WriteBufferSize     int
	HandshakeTimeout    time.Duration
	
	// Server-Sent Events settings
	EnableSSE           bool
	SSEPath             string
	SSEHeartbeatInterval time.Duration
	
	// Authentication
	RequireAuth         bool
	
	// CORS settings for WebSocket
	CheckOrigin         func(r *http.Request) bool
}

// DefaultRealtimeConfig returns default realtime configuration
func DefaultRealtimeConfig() RealtimeConfig {
	return RealtimeConfig{
		EnableWebSocket:     true,
		WebSocketPath:       "/ws",
		ReadBufferSize:      1024,
		WriteBufferSize:     1024,
		HandshakeTimeout:    10 * time.Second,
		EnableSSE:           true,
		SSEPath:             "/events",
		SSEHeartbeatInterval: 30 * time.Second,
		RequireAuth:         true,
		CheckOrigin: func(r *http.Request) bool {
			// In production, implement proper origin checking
			return true
		},
	}
}

// Realtime creates middleware for handling realtime connections
func Realtime(config RealtimeConfig) func(http.Handler) http.Handler {
	upgrader := websocket.Upgrader{
		ReadBufferSize:    config.ReadBufferSize,
		WriteBufferSize:   config.WriteBufferSize,
		HandshakeTimeout:  config.HandshakeTimeout,
		CheckOrigin:       config.CheckOrigin,
	}
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle WebSocket upgrade
			if config.EnableWebSocket && r.URL.Path == config.WebSocketPath {
				handleWebSocket(w, r, &upgrader, config)
				return
			}
			
			// Handle Server-Sent Events
			if config.EnableSSE && r.URL.Path == config.SSEPath {
				handleSSE(w, r, config)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// handleWebSocket handles WebSocket connections
func handleWebSocket(w http.ResponseWriter, r *http.Request, upgrader *websocket.Upgrader, config RealtimeConfig) {
	// Check authentication if required
	if config.RequireAuth {
		// TODO: Implement auth check using Guardian's auth system
		// For now, we'll assume it's handled by other middleware
	}
	
	// Upgrade connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}
	defer conn.Close()
	
	// Create context for this connection
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	
	// Handle WebSocket connection
	handleWSConnection(ctx, conn)
}

// handleSSE handles Server-Sent Events connections
func handleSSE(w http.ResponseWriter, r *http.Request, config RealtimeConfig) {
	// Check authentication if required
	if config.RequireAuth {
		// TODO: Implement auth check using Guardian's auth system
	}
	
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable Nginx buffering
	
	// Create flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	
	// Create context for this connection
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	
	// Handle SSE connection
	handleSSEConnection(ctx, w, flusher, config)
}

// handleWSConnection manages a WebSocket connection
func handleWSConnection(ctx context.Context, conn *websocket.Conn) {
	// Set up ping/pong handlers
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	
	// Start ping ticker
	ticker := time.NewTicker(54 * time.Second)
	defer ticker.Stop()
	
	// Message handling loop
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()
	
	// Read messages
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				// Log error in production
			}
			break
		}
		
		// Handle message based on type
		if messageType == websocket.TextMessage {
			// Process text message
			// In production, implement message routing
			response := fmt.Sprintf("Echo: %s", message)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(response)); err != nil {
				break
			}
		}
	}
}

// handleSSEConnection manages an SSE connection
func handleSSEConnection(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, config RealtimeConfig) {
	// Send initial connection event
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"connected\"}\n\n")
	flusher.Flush()
	
	// Create heartbeat ticker
	heartbeat := time.NewTicker(config.SSEHeartbeatInterval)
	defer heartbeat.Stop()
	
	// Message loop
	for {
		select {
		case <-ctx.Done():
			// Send close event
			fmt.Fprintf(w, "event: close\ndata: {\"status\":\"closing\"}\n\n")
			flusher.Flush()
			return
			
		case <-heartbeat.C:
			// Send heartbeat
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

// WebSocketHub manages WebSocket connections
type WebSocketHub struct {
	connections map[*websocket.Conn]bool
	broadcast   chan []byte
	register    chan *websocket.Conn
	unregister  chan *websocket.Conn
}

// NewWebSocketHub creates a new WebSocket hub
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		connections: make(map[*websocket.Conn]bool),
		broadcast:   make(chan []byte),
		register:    make(chan *websocket.Conn),
		unregister:  make(chan *websocket.Conn),
	}
}

// Run starts the hub's event loop
func (h *WebSocketHub) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// Close all connections
			for conn := range h.connections {
				conn.Close()
			}
			return
			
		case conn := <-h.register:
			h.connections[conn] = true
			
		case conn := <-h.unregister:
			if _, ok := h.connections[conn]; ok {
				delete(h.connections, conn)
				conn.Close()
			}
			
		case message := <-h.broadcast:
			// Send to all connected clients
			for conn := range h.connections {
				if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
					h.unregister <- conn
				}
			}
		}
	}
}

// Broadcast sends a message to all connected clients
func (h *WebSocketHub) Broadcast(message []byte) {
	h.broadcast <- message
}

// SSEBroadcaster manages SSE connections
type SSEBroadcaster struct {
	clients     map[chan string]bool
	broadcast   chan string
	register    chan chan string
	unregister  chan chan string
}

// NewSSEBroadcaster creates a new SSE broadcaster
func NewSSEBroadcaster() *SSEBroadcaster {
	return &SSEBroadcaster{
		clients:    make(map[chan string]bool),
		broadcast:  make(chan string),
		register:   make(chan chan string),
		unregister: make(chan chan string),
	}
}

// Run starts the broadcaster's event loop
func (b *SSEBroadcaster) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// Close all client channels
			for client := range b.clients {
				close(client)
			}
			return
			
		case client := <-b.register:
			b.clients[client] = true
			
		case client := <-b.unregister:
			if _, ok := b.clients[client]; ok {
				delete(b.clients, client)
				close(client)
			}
			
		case message := <-b.broadcast:
			// Send to all clients
			for client := range b.clients {
				select {
				case client <- message:
				default:
					// Client is slow, remove it
					b.unregister <- client
				}
			}
		}
	}
}

// Broadcast sends an event to all connected clients
func (b *SSEBroadcaster) Broadcast(event, data string) {
	message := fmt.Sprintf("event: %s\ndata: %s\n\n", event, data)
	b.broadcast <- message
}

// StreamSSE handles an individual SSE client connection
func (b *SSEBroadcaster) StreamSSE(w http.ResponseWriter, r *http.Request) {
	// Set headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	
	// Create client channel
	client := make(chan string)
	b.register <- client
	
	// Remove client on disconnect
	defer func() {
		b.unregister <- client
	}()
	
	// Get flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	
	// Send initial connection
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"connected\"}\n\n")
	flusher.Flush()
	
	// Stream events
	for {
		select {
		case <-r.Context().Done():
			return
		case message := <-client:
			fmt.Fprint(w, message)
			flusher.Flush()
		}
	}
}