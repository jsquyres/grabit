// artifactory_test.go
package internal

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/cisco-open/grabit/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddWithArtifactoryCache(t *testing.T) {
	t.Run("TokenNotSet", func(t *testing.T) {
		os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN")

		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`test content`))
		}
		port, server := test.HttpHandler(handler)
		defer server.Close()

		path := test.TmpFile(t, "")
		lock, err := NewLock(path, true)
		require.NoError(t, err)

		// Use a testing server
		sourceURL := fmt.Sprintf("http://localhost:%d/test.txt", port)
		cacheURL := fmt.Sprintf("http://localhost:%d", port)

		err = lock.AddResource([]string{sourceURL}, "sha256", []string{}, "", cacheURL)
		assert.Contains(t, err.Error(), "GRABIT_ARTIFACTORY_TOKEN environment variable is not set")
	})
}
func TestDownloadWithArtifactoryCache(t *testing.T) {
	t.Run("NO_CACHE_UPLOAD", func(t *testing.T) {
		// Turn on NO_CACHE_UPLOAD setting
		os.Setenv("NO_CACHE_UPLOAD", "1")
		defer os.Unsetenv("NO_CACHE_UPLOAD")

		testContent := []byte("test content")
		hash := sha256.Sum256(testContent)
		expectedHash := "sha256-" + base64.StdEncoding.EncodeToString(hash[:])

		// Start a test server
		uploadAttempted := false
		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" {
				uploadAttempted = true
				t.Error("Should not attempt upload when NO_CACHE_UPLOAD is set")
			}
			w.Write(testContent)
		}
		port, server := test.HttpHandler(handler)
		defer server.Close()

		// Make a test folder
		tmpDir := test.TmpDir(t)

		// Make a test lock file with a cache URL and correct hash
		lockContent := fmt.Sprintf(`[[Resource]]
            Urls = ['http://localhost:%d/test.txt']
            Integrity = '%s'
            CacheUri = 'http://localhost:%d/cache'`, port, expectedHash, port)

		// Set up the lock file
		lockPath := test.TmpFile(t, lockContent)
		lock, err := NewLock(lockPath, false)
		require.NoError(t, err)

		// Check the download process
		err = lock.Download(tmpDir, []string{}, []string{}, "")
		assert.NoError(t, err)

		// Make sure no upload happened
		assert.False(t, uploadAttempted)

		// Make sure the file downloaded properly
		downloadedFile := filepath.Join(tmpDir, "test.txt")
		assert.FileExists(t, downloadedFile)

		// Make sure the content is the same
		content, err := os.ReadFile(downloadedFile)
		require.NoError(t, err)
		assert.Equal(t, testContent, content)
	})
}

func TestDeleteWithArtifactoryCache(t *testing.T) {
	t.Run("SuccessfulDelete", func(t *testing.T) {
		os.Setenv("GRABIT_ARTIFACTORY_TOKEN", "test-token")
		defer os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN")

		// Start the test server
		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" {
				w.WriteHeader(http.StatusOK)
			}
		}
		port, server := test.HttpHandler(handler)
		defer server.Close()

		url := fmt.Sprintf("http://localhost:%d/test.txt", port)
		cacheUrl := fmt.Sprintf("http://localhost:%d", port)

		tmpDir := test.TmpDir(t)
		lockContent := fmt.Sprintf(`[[Resource]]
            Urls = ['%s']
            Integrity = 'sha256-test'
            CacheUri = '%s'`, url, cacheUrl)

		lockPath := filepath.Join(tmpDir, "grabit.lock")
		err := os.WriteFile(lockPath, []byte(lockContent), 0644)
		require.NoError(t, err)

		lock, err := NewLock(lockPath, false)
		require.NoError(t, err)

		// Keep the starting state
		err = lock.Save()
		require.NoError(t, err)

		lock.DeleteResource(url)

		// Keep the updates
		err = lock.Save()
		require.NoError(t, err)

		// Make sure the resource was deleted
		newLock, err := NewLock(lockPath, false)
		require.NoError(t, err)
		assert.Equal(t, 0, len(newLock.conf.Resource))
	})
}
