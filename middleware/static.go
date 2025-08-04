package middleware

import (
	"compress/gzip"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// StaticConfig holds configuration for static file serving
type StaticConfig struct {
	// Root directory for static files
	Root string
	// Index file name (default: "index.html")
	Index string
	// Allow directory browsing (default: false)
	Browse bool
	// Cache max-age in seconds (default: 0)
	MaxAge int
	// Enable gzip compression (default: false)
	Compress bool
	// MIME types to compress (default: common text types)
	CompressTypes []string
	// Custom 404 file to serve when file not found
	NotFoundFile string
	// Patterns to ignore (e.g., ".git", "*.log")
	IgnorePatterns []string
}

// DefaultStaticConfig returns a default static configuration
func DefaultStaticConfig() StaticConfig {
	return StaticConfig{
		Index:  "index.html",
		Browse: false,
		CompressTypes: []string{
			"text/css",
			"text/javascript",
			"application/javascript",
			"text/html",
			"text/plain",
			"application/json",
			"application/xml",
			"image/svg+xml",
		},
	}
}

// Static creates a middleware for serving static files
func Static(urlPrefix string, config StaticConfig) func(http.Handler) http.Handler {
	// Apply defaults
	if config.Index == "" {
		config.Index = "index.html"
	}
	if config.Root == "" {
		config.Root = "."
	}

	// Clean the root path
	config.Root = filepath.Clean(config.Root)

	// Create a map of compress types for faster lookup
	compressMap := make(map[string]bool)
	for _, ct := range config.CompressTypes {
		compressMap[ct] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only handle requests with the URL prefix
			if !strings.HasPrefix(r.URL.Path, urlPrefix) {
				next.ServeHTTP(w, r)
				return
			}

			// Strip the URL prefix to get the file path
			path := strings.TrimPrefix(r.URL.Path, urlPrefix)
			path = strings.TrimPrefix(path, "/")

			// Clean the path to prevent directory traversal
			path = filepath.Clean("/" + path)[1:] // Remove leading slash after cleaning

			// Check if path matches any ignore patterns
			for _, pattern := range config.IgnorePatterns {
				if matched, _ := filepath.Match(pattern, path); matched {
					w.WriteHeader(http.StatusNotFound)
					return
				}
			}

			// Construct full file path
			fullPath := filepath.Join(config.Root, path)

			// Ensure the full path is still within the root directory
			absRoot, _ := filepath.Abs(config.Root)
			absPath, _ := filepath.Abs(fullPath)
			if !strings.HasPrefix(absPath, absRoot) {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			// Get file info
			info, err := os.Stat(fullPath)
			if err != nil {
				if os.IsNotExist(err) && config.NotFoundFile != "" {
					// Serve custom 404 file
					notFoundPath := filepath.Join(config.Root, config.NotFoundFile)
					http.ServeFile(w, r, notFoundPath)
					return
				}
				http.NotFound(w, r)
				return
			}

			// Handle directory requests
			if info.IsDir() {
				// Try to serve index file
				indexPath := filepath.Join(fullPath, config.Index)
				if indexInfo, err := os.Stat(indexPath); err == nil && !indexInfo.IsDir() {
					fullPath = indexPath
					info = indexInfo
				} else {
					// Directory browsing not allowed
					http.NotFound(w, r)
					return
				}
			}

			// Set security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")

			// Set cache headers
			if config.MaxAge > 0 {
				w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", config.MaxAge))
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}

			// Generate ETag
			etag := generateETag(info)
			w.Header().Set("ETag", etag)

			// Check If-None-Match
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}

			// Set Last-Modified
			modTime := info.ModTime().UTC()
			w.Header().Set("Last-Modified", modTime.Format(http.TimeFormat))

			// Check If-Modified-Since
			if ifModSince := r.Header.Get("If-Modified-Since"); ifModSince != "" {
				if t, err := time.Parse(http.TimeFormat, ifModSince); err == nil {
					if modTime.Before(t) || modTime.Equal(t) {
						w.WriteHeader(http.StatusNotModified)
						return
					}
				}
			}

			// Open the file
			file, err := os.Open(fullPath)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			defer file.Close()

			// Detect content type
			contentType := detectContentType(fullPath, file)
			w.Header().Set("Content-Type", contentType)

			// Check if we should compress
			shouldCompress := config.Compress &&
				compressMap[contentType] &&
				strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")

			// Handle range requests
			if r.Header.Get("Range") != "" && !shouldCompress {
				// Let http.ServeContent handle range requests
				http.ServeContent(w, r, info.Name(), modTime, file)
				return
			}

			// Set Content-Length if not compressing
			if !shouldCompress {
				w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
			}

			// Serve the file
			if shouldCompress {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Del("Content-Length") // Remove content-length for compressed response

				gz := gzip.NewWriter(w)
				defer gz.Close()

				io.Copy(gz, file)
			} else {
				io.Copy(w, file)
			}
		})
	}
}

// generateETag creates an ETag based on file modification time and size
func generateETag(info os.FileInfo) string {
	data := fmt.Sprintf("%d-%d", info.ModTime().Unix(), info.Size())
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf(`"%x"`, hash)
}

// detectContentType detects the MIME type of a file
func detectContentType(path string, file *os.File) string {
	// First try by extension
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".html", ".htm":
		return "text/html"
	case ".xml":
		return "application/xml"
	case ".txt":
		return "text/plain"
	case ".svg":
		return "image/svg+xml"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".ico":
		return "image/x-icon"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".otf":
		return "font/otf"
	case ".eot":
		return "application/vnd.ms-fontobject"
	}

	// Fall back to content sniffing
	buffer := make([]byte, 512)
	n, _ := file.Read(buffer)
	file.Seek(0, 0) // Reset file position

	contentType := http.DetectContentType(buffer[:n])
	return contentType
}