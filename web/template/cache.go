package template

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Cache provides template caching functionality
type Cache struct {
	store      map[string]*CacheEntry
	mu         sync.RWMutex
	ttl        time.Duration
	maxSize    int
	currentSize int
}

// CacheEntry represents a cached template render
type CacheEntry struct {
	Content    []byte
	Hash       string
	CreatedAt  time.Time
	AccessedAt time.Time
	Size       int
	Hits       int64
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	TTL     time.Duration
	MaxSize int // Max size in bytes
}

// NewCache creates a new template cache
func NewCache(config CacheConfig) *Cache {
	if config.TTL == 0 {
		config.TTL = 5 * time.Minute
	}
	if config.MaxSize == 0 {
		config.MaxSize = 100 * 1024 * 1024 // 100MB default
	}

	cache := &Cache{
		store:   make(map[string]*CacheEntry),
		ttl:     config.TTL,
		maxSize: config.MaxSize,
	}

	// Start cleanup routine
	go cache.cleanup()

	return cache
}

// Get retrieves a cached render
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.store[key]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Since(entry.CreatedAt) > c.ttl {
		return nil, false
	}

	// Update access time and hits
	entry.AccessedAt = time.Now()
	entry.Hits++

	// Return a copy to prevent mutations
	content := make([]byte, len(entry.Content))
	copy(content, entry.Content)

	return content, true
}

// Set stores a rendered template in cache
func (c *Cache) Set(key string, content []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	size := len(content)

	// Check if we need to evict entries
	if c.currentSize+size > c.maxSize {
		c.evictLRU(size)
	}

	// Create cache entry
	entry := &CacheEntry{
		Content:    content,
		Hash:       c.hash(content),
		CreatedAt:  time.Now(),
		AccessedAt: time.Now(),
		Size:       size,
		Hits:       0,
	}

	// If replacing existing entry, update size
	if existing, exists := c.store[key]; exists {
		c.currentSize -= existing.Size
	}

	c.store[key] = entry
	c.currentSize += size
}

// Delete removes an entry from cache
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.store[key]; exists {
		c.currentSize -= entry.Size
		delete(c.store, key)
	}
}

// Clear removes all entries from cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.store = make(map[string]*CacheEntry)
	c.currentSize = 0
}

// Stats returns cache statistics
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := CacheStats{
		Entries:     len(c.store),
		Size:        c.currentSize,
		MaxSize:     c.maxSize,
		TTL:         c.ttl,
	}

	for _, entry := range c.store {
		stats.TotalHits += entry.Hits
	}

	if stats.Entries > 0 {
		stats.AvgHits = float64(stats.TotalHits) / float64(stats.Entries)
	}

	return stats
}

// CacheStats holds cache statistics
type CacheStats struct {
	Entries     int
	Size        int
	MaxSize     int
	TTL         time.Duration
	TotalHits   int64
	AvgHits     float64
}

// evictLRU evicts least recently used entries to make space
func (c *Cache) evictLRU(needed int) {
	type lruEntry struct {
		key        string
		accessedAt time.Time
		size       int
	}

	// Build list of entries sorted by access time
	entries := make([]lruEntry, 0, len(c.store))
	for key, entry := range c.store {
		entries = append(entries, lruEntry{
			key:        key,
			accessedAt: entry.AccessedAt,
			size:       entry.Size,
		})
	}

	// Sort by access time (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].accessedAt.After(entries[j].accessedAt) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Evict entries until we have enough space
	freed := 0
	for _, entry := range entries {
		if freed >= needed {
			break
		}
		delete(c.store, entry.key)
		c.currentSize -= entry.size
		freed += entry.size
	}
}

// cleanup runs periodically to remove expired entries
func (c *Cache) cleanup() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.store {
			if now.Sub(entry.CreatedAt) > c.ttl {
				c.currentSize -= entry.Size
				delete(c.store, key)
			}
		}
		c.mu.Unlock()
	}
}

// hash generates a hash of content for validation
func (c *Cache) hash(content []byte) string {
	h := md5.New()
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// CachedManager wraps a Manager with caching
type CachedManager struct {
	*Manager
	cache *Cache
}

// NewCachedManager creates a manager with caching enabled
func NewCachedManager(config Config, cacheConfig CacheConfig) *CachedManager {
	return &CachedManager{
		Manager: NewManager(config),
		cache:   NewCache(cacheConfig),
	}
}

// Render renders a template with caching
func (m *CachedManager) Render(w io.Writer, name string, data interface{}) error {
	// Generate cache key
	key := m.cacheKey(name, data)

	// Check cache
	if content, found := m.cache.Get(key); found {
		_, err := w.Write(content)
		return err
	}

	// Render to buffer
	var buf bytes.Buffer
	err := m.Manager.Render(&buf, name, data)
	if err != nil {
		return err
	}

	content := buf.Bytes()

	// Store in cache
	m.cache.Set(key, content)

	// Write to output
	_, err = w.Write(content)
	return err
}

// InvalidateCache invalidates cache entries for a template
func (m *CachedManager) InvalidateCache(pattern string) {
	m.cache.mu.Lock()
	defer m.cache.mu.Unlock()

	for key := range m.cache.store {
		if strings.Contains(key, pattern) {
			delete(m.cache.store, key)
		}
	}
}

// cacheKey generates a cache key for template + data
func (m *CachedManager) cacheKey(name string, data interface{}) string {
	h := md5.New()
	h.Write([]byte(name))
	h.Write([]byte(fmt.Sprintf("%#v", data)))
	return hex.EncodeToString(h.Sum(nil))
}

// Middleware provides HTTP middleware for template caching
func (m *CachedManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add cache control headers
		if m.development {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		} else {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(m.cache.ttl.Seconds())))
		}

		next.ServeHTTP(w, r)
	})
}