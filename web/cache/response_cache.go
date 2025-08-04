package cache

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// CachedResponse represents a cached response with metadata
type CachedResponse struct {
	Data      json.RawMessage
	Timestamp time.Time
	TTL       time.Duration
}

// IsExpired checks if the cached response has expired
func (cr *CachedResponse) IsExpired() bool {
	return time.Since(cr.Timestamp) > cr.TTL
}

// ResponseCache provides caching for command responses
type ResponseCache struct {
	mu    sync.RWMutex
	cache map[string]*CachedResponse

	// Cleanup settings
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewResponseCache creates a new response cache
func NewResponseCache(cleanupInterval time.Duration) *ResponseCache {
	rc := &ResponseCache{
		cache:           make(map[string]*CachedResponse),
		cleanupInterval: cleanupInterval,
		stopCleanup:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go rc.cleanupRoutine()

	return rc
}

// Get retrieves a cached response
func (rc *ResponseCache) Get(key string) (json.RawMessage, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	cached, exists := rc.cache[key]
	if !exists || cached.IsExpired() {
		return nil, false
	}

	return cached.Data, true
}

// Set stores a response in the cache
func (rc *ResponseCache) Set(key string, data json.RawMessage, ttl time.Duration) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.cache[key] = &CachedResponse{
		Data:      data,
		Timestamp: time.Now(),
		TTL:       ttl,
	}
}

// Delete removes a response from the cache
func (rc *ResponseCache) Delete(key string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	delete(rc.cache, key)
}

// Clear removes all responses from the cache
func (rc *ResponseCache) Clear() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.cache = make(map[string]*CachedResponse)
}

// Size returns the number of cached responses
func (rc *ResponseCache) Size() int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	return len(rc.cache)
}

// Stop stops the cleanup routine
func (rc *ResponseCache) Stop() {
	close(rc.stopCleanup)
}

// cleanupRoutine periodically removes expired entries
func (rc *ResponseCache) cleanupRoutine() {
	ticker := time.NewTicker(rc.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rc.cleanup()
		case <-rc.stopCleanup:
			return
		}
	}
}

// cleanup removes expired entries
func (rc *ResponseCache) cleanup() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	for key, cached := range rc.cache {
		if cached.IsExpired() {
			delete(rc.cache, key)
		}
	}
}

// CachedCommander wraps a Commander with response caching
type CachedCommander struct {
	*Commander
	cache *ResponseCache
}

// NewCachedCommander creates a new cached commander
func NewCachedCommander(publisher PublisherWithResponse) *CachedCommander {
	return &CachedCommander{
		Commander: NewCommander(publisher),
		cache:     NewResponseCache(5 * time.Minute),
	}
}

// ExecuteWithCache executes a command with caching
func (cc *CachedCommander) ExecuteWithCache(ctx context.Context, topic string, cmd Command, responseKey string, timeout time.Duration, cacheTTL time.Duration) (*Response, error) {
	// Generate cache key
	cacheKey := generateCacheKey(topic, cmd)

	// Check cache first
	if cachedData, found := cc.cache.Get(cacheKey); found {
		return &Response{
			ID:        cmd.ID,
			Type:      cmd.Type,
			Success:   true,
			Data:      cachedData,
			Timestamp: time.Now().Unix(),
		}, nil
	}

	// Execute command
	resp, err := cc.Execute(ctx, topic, cmd, responseKey, timeout)
	if err != nil {
		return nil, err
	}

	// Cache successful response
	if resp.Success && cacheTTL > 0 {
		cc.cache.Set(cacheKey, resp.Data, cacheTTL)
	}

	return resp, nil
}

// InvalidateCache invalidates cached responses for a topic pattern
func (cc *CachedCommander) InvalidateCache(_ string) {
	// For simplicity, clear all cache
	// In production, implement pattern matching
	cc.cache.Clear()
}

// Stop stops the cached commander and its cleanup routine
func (cc *CachedCommander) Stop() {
	cc.cache.Stop()
}

// generateCacheKey generates a cache key for a command
func generateCacheKey(topic string, cmd Command) string {
	// Simple implementation - in production, use a proper hash
	return topic + ":" + cmd.Type
}
