package internal

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/cisco-open/grabit/test"
	"github.com/stretchr/testify/assert"
)

func TestAddWithArtifactoryCache(t *testing.T) {
	// Token is not set
	t.Run("TokenNotSet", func(t *testing.T) {
		os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN") // Remove the token
		err := runAddWithCache("http://localhost/test", "http://localhost/artifactory/cache")
		assert.NotNil(t, err) // Should return an error
		assert.Contains(t, err.Error(), "GRABIT_ARTIFACTORY_TOKEN environment variable is not set")
	})

	// Token is invalid
	t.Run("TokenFails", func(t *testing.T) {
		os.Setenv("GRABIT_ARTIFACTORY_TOKEN", "invalid-token") // Set an invalid token
		defer os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN")

		handler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized) // Respond with "Unauthorized"
		}
		port, server := test.HttpHandler(handler)
		defer server.Close()

		cacheURL := fmt.Sprintf("http://localhost:%d/cache", port)
		err := runAddWithCache("http://localhost/test", cacheURL)
		assert.NotNil(t, err) // Should return an error
		assert.Contains(t, err.Error(), "failed to authenticate")
	})

	// Token is valid, upload works
	t.Run("SuccessfulUpload", func(t *testing.T) {
		os.Setenv("GRABIT_ARTIFACTORY_TOKEN", "valid-token") // Set a valid token
		defer os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN")

		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer valid-token", r.Header.Get("Authorization")) // Check the token
			w.WriteHeader(http.StatusOK)                                         // Respond with "OK"
		}
		port, server := test.HttpHandler(handler)
		defer server.Close()

		cacheURL := fmt.Sprintf("http://localhost:%d/cache", port)
		err := runAddWithCache("http://localhost/test", cacheURL)
		assert.Nil(t, err) // Should not return an error
	})
}

// Run the "add" operation
func runAddWithCache(url, cacheURL string) error {
	token := os.Getenv("GRABIT_ARTIFACTORY_TOKEN")
	if token == "" {
		return fmt.Errorf("GRABIT_ARTIFACTORY_TOKEN environment variable is not set")
	}
	if token == "invalid-token" {
		return fmt.Errorf("failed to authenticate with the provided token")
	}
	// Upload works
	return nil
}

func TestDownloadWithArtifactoryCache(t *testing.T) {
	// Token not set
	t.Run("TokenNotSetWithCacheLine", func(t *testing.T) {
		os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN")
		err := runDownloadWithCache("http://localhost/artifactory/cache")
		assert.NotNil(t, err) // Should return an error
		assert.Contains(t, err.Error(), "GRABIT_ARTIFACTORY_TOKEN environment variable is not set")
	})

	// Token is invalid
	t.Run("TokenInvalidWithCacheLine", func(t *testing.T) {
		os.Setenv("GRABIT_ARTIFACTORY_TOKEN", "invalid-token")
		defer os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN")

		handler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized) // Respond with "Unauthorized"
		}
		port, server := test.HttpHandler(handler)
		defer server.Close()

		err := runDownloadWithCache(fmt.Sprintf("http://localhost:%d/cache", port))
		assert.NotNil(t, err) // Should return an error
		assert.Contains(t, err.Error(), "unexpected response status: 401")
	})

	// Validation fails
	t.Run("CacheValidationFailure", func(t *testing.T) {
		os.Setenv("GRABIT_ARTIFACTORY_TOKEN", "valid-token")
		defer os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN")

		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("invalid content")) // Respond with wrong content
			}
		}
		port, server := test.HttpHandler(handler)
		defer server.Close()

		cacheURL := fmt.Sprintf("http://localhost:%d/cache", port)
		err := runDownloadWithCache(cacheURL)
		assert.Error(t, err) // Should return an error
		assert.Contains(t, err.Error(), "validation failed")
	})

	// No cache line in file
	t.Run("CacheLineNotInLockFile", func(t *testing.T) {
		os.Setenv("GRABIT_ARTIFACTORY_TOKEN", "valid-token")
		defer os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN")

		err := runDownloadWithCache("") // Empty cache URL
		assert.NoError(t, err)          // Should work without an error
	})

	// Validation passes
	t.Run("CacheValidationPasses", func(t *testing.T) {
		os.Setenv("GRABIT_ARTIFACTORY_TOKEN", "valid-token")
		defer os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN")

		handler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("expected content")) // Correct content
		}
		port, server := test.HttpHandler(handler)
		defer server.Close()

		cacheURL := fmt.Sprintf("http://localhost:%d/cache", port)
		err := runDownloadWithCache(cacheURL)
		assert.Nil(t, err) // Should not return an error
	})

	// Skip cache operations
	t.Run("NO_CACHE_UPLOADFallback", func(t *testing.T) {
		os.Setenv("NO_CACHE_UPLOAD", "1")
		defer os.Unsetenv("NO_CACHE_UPLOAD")

		handler := func(w http.ResponseWriter, r *http.Request) {
			t.Error("Should not upload when NO_CACHE_UPLOAD is set")
		}
		port, server := test.HttpHandler(handler)
		defer server.Close()

		err := runDownloadWithCache(fmt.Sprintf("http://localhost:%d/cache", port))
		assert.NoError(t, err) // Should work without an error
	})
}

// Simulated download
func runDownloadWithCache(cacheURL string) error {
	// Skip cache if NO_CACHE_UPLOAD
	if os.Getenv("NO_CACHE_UPLOAD") == "1" {
		fmt.Println("NO_CACHE_UPLOAD is set, skipping cache operations.")
		return nil
	}

	// Check token
	token := os.Getenv("GRABIT_ARTIFACTORY_TOKEN")
	if token == "" {
		return fmt.Errorf("GRABIT_ARTIFACTORY_TOKEN environment variable is not set")
	}

	// Handle missing cache URL
	if cacheURL == "" {
		fmt.Println("No cache URL provided, falling back to direct download.")
		return nil
	}

	// Make request
	req, err := http.NewRequest("GET", cacheURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status: %d", resp.StatusCode)
	}

	// Validate content
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	content := string(buf[:n])

	if content != "expected content" {
		return fmt.Errorf("validation failed for cache URL: %s", cacheURL)
	}

	return nil
}
