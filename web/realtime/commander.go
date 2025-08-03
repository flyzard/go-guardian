// Package realtime provides real-time data handling patterns for web applications
package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Command represents a generic command to be executed
type Command struct {
	ID        string         `json:"id,omitempty"`
	Type      string         `json:"type"`
	Timestamp int64          `json:"timestamp"`
	Data      map[string]any `json:"data,omitempty"`
}

// Response represents a generic command response
type Response struct {
	ID        string          `json:"id,omitempty"`
	Type      string          `json:"type"`
	Success   bool            `json:"success"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
	Timestamp int64           `json:"timestamp"`
}

// Publisher defines the interface for publishing commands
type Publisher interface {
	Publish(topic string, data any) error
}

// PublisherWithResponse defines the interface for publishing and waiting for responses
type PublisherWithResponse interface {
	Publisher
	PublishAndWaitForResponse(topic string, data any, responseKey string, timeout time.Duration) (json.RawMessage, error)
}

// Commander provides a high-level interface for executing commands with responses
type Commander struct {
	publisher PublisherWithResponse
	mu        sync.RWMutex
	pending   map[string]chan Response
}

// NewCommander creates a new commander instance
func NewCommander(publisher PublisherWithResponse) *Commander {
	return &Commander{
		publisher: publisher,
		pending:   make(map[string]chan Response),
	}
}

// Execute sends a command and waits for a response
func (c *Commander) Execute(_ context.Context, topic string, cmd Command, responseKey string, timeout time.Duration) (*Response, error) {
	// Ensure command has timestamp
	if cmd.Timestamp == 0 {
		cmd.Timestamp = time.Now().Unix()
	}

	// Generate command ID if not provided
	if cmd.ID == "" {
		cmd.ID = generateCommandID()
	}

	// Create response channel
	respChan := make(chan Response, 1)
	c.mu.Lock()
	c.pending[cmd.ID] = respChan
	c.mu.Unlock()

	// Cleanup on exit
	defer func() {
		c.mu.Lock()
		delete(c.pending, cmd.ID)
		c.mu.Unlock()
		close(respChan)
	}()

	// Publish command
	responseData, err := c.publisher.PublishAndWaitForResponse(topic, cmd, responseKey, timeout)
	if err != nil {
		return nil, fmt.Errorf("command execution failed: %w", err)
	}

	// Create response
	resp := &Response{
		ID:        cmd.ID,
		Type:      cmd.Type,
		Success:   true,
		Data:      responseData,
		Timestamp: time.Now().Unix(),
	}

	return resp, nil
}

// ExecuteSimple executes a simple command without complex command structure
func (c *Commander) ExecuteSimple(ctx context.Context, topic string, commandType string, data map[string]any, responseKey string, timeout time.Duration) (json.RawMessage, error) {
	cmd := Command{
		Type:      commandType,
		Timestamp: time.Now().Unix(),
		Data:      data,
	}

	resp, err := c.Execute(ctx, topic, cmd, responseKey, timeout)
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// StandardCommand creates a standard command structure
func StandardCommand(cmdType string) Command {
	return Command{
		Type:      cmdType,
		Timestamp: time.Now().Unix(),
		Data:      make(map[string]any),
	}
}

// StandardCommandWithData creates a standard command with additional data
func StandardCommandWithData(cmdType string, data map[string]any) Command {
	return Command{
		Type:      cmdType,
		Timestamp: time.Now().Unix(),
		Data:      data,
	}
}

// generateCommandID generates a unique command ID
func generateCommandID() string {
	return fmt.Sprintf("cmd_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}

// CommandBuilder provides a fluent interface for building commands
type CommandBuilder struct {
	cmd Command
}

// NewCommandBuilder creates a new command builder
func NewCommandBuilder(cmdType string) *CommandBuilder {
	return &CommandBuilder{
		cmd: Command{
			Type:      cmdType,
			Timestamp: time.Now().Unix(),
			Data:      make(map[string]any),
		},
	}
}

// WithID sets the command ID
func (b *CommandBuilder) WithID(id string) *CommandBuilder {
	b.cmd.ID = id
	return b
}

// WithData adds a key-value pair to the command data
func (b *CommandBuilder) WithData(key string, value any) *CommandBuilder {
	b.cmd.Data[key] = value
	return b
}

// WithDataMap adds multiple key-value pairs to the command data
func (b *CommandBuilder) WithDataMap(data map[string]any) *CommandBuilder {
	for k, v := range data {
		b.cmd.Data[k] = v
	}
	return b
}

// Build returns the constructed command
func (b *CommandBuilder) Build() Command {
	return b.cmd
}
