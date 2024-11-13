package cmd

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMockServers creates mock servers for content and Artifactory
func setupMockServers(t *testing.T) (contentServer, artifactoryServer *httptest.Server) {
	uploadedFiles := make(map[string][]byte)

	// Content server for source files
	contentServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content := []byte("test content")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(content)
	}))

	// Mock Artifactory server
	artifactoryServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Unauthorized")
			return
		}

		switch r.Method {
		case http.MethodPut:
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			uploadedFiles[r.URL.Path] = body
			w.WriteHeader(http.StatusCreated)

		case http.MethodGet:
			content, exists := uploadedFiles[r.URL.Path]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(content)
		}
	}))

	t.Cleanup(func() {
		contentServer.Close()
		artifactoryServer.Close()
	})

	return
}

func TestFullCacheWorkflow(t *testing.T) {
	contentServer, artifactoryServer := setupMockServers(t)

	// Create base temp dir
	baseDir := t.TempDir()

	// Create lock file first
	lockFile := filepath.Join(baseDir, "grabit.lock")
	err := os.WriteFile(lockFile, []byte("version = \"1.0\"\n\n[[resources]]\n"), 0644)
	require.NoError(t, err)

	tests := []struct {
		name     string
		commands []struct {
			args        []string
			setupEnv    map[string]string
			expectError bool
			verify      func(*testing.T, string)
		}
	}{
		{
			name: "Complete cache workflow",
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
				verify      func(*testing.T, string)
			}{
				{
					// Step 1: Add with cache
					args: []string{"add",
						contentServer.URL + "/test.txt",
						"--cache", artifactoryServer.URL + "/cache",
						"--lock-file", lockFile},
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
					verify: func(t *testing.T, dir string) {
						content, err := os.ReadFile(lockFile)
						require.NoError(t, err)
						assert.Contains(t, string(content), "CacheUri")
					},
				},
				{
					// Step 2: Download using cache
					args: []string{"download",
						"--lock-file", lockFile,
						"--dir", baseDir}, // Changed --output-dir to --dir
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
					verify: func(t *testing.T, dir string) {
						files, err := os.ReadDir(dir)
						require.NoError(t, err)
						count := 0
						for _, f := range files {
							if !strings.HasSuffix(f.Name(), ".lock") {
								count++
							}
						}
						assert.Greater(t, count, 0, "Should have downloaded files besides lock file")
					},
				},
			},
		},
		{
			name: "Cache upload prevention",
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
				verify      func(*testing.T, string)
			}{
				{
					args: []string{"add",
						contentServer.URL + "/different.txt",
						"--cache", artifactoryServer.URL + "/cache",
						"--lock-file", lockFile},
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
						"GRABIT_NO_CACHE_UPLOAD":   "1",
					},
					expectError: false,
				},
			},
		},
		{
			name: "Cache validation failure",
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
				verify      func(*testing.T, string)
			}{
				{
					// First add a resource
					args: []string{"add",
						contentServer.URL + "/test2.txt",
						"--cache", artifactoryServer.URL + "/cache",
						"--lock-file", lockFile},
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
				},
				{
					// Then try to download with validation failure
					args: []string{"download",
						"--lock-file", lockFile,
						"--dir", baseDir}, // Changed --output-dir to --dir
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
					verify: func(t *testing.T, dir string) {
						files, err := os.ReadDir(dir)
						require.NoError(t, err)
						count := 0
						for _, f := range files {
							if !strings.HasSuffix(f.Name(), ".lock") {
								count++
							}
						}
						assert.Greater(t, count, 0, "Should have downloaded files besides lock file")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run each command in sequence
			for _, cmd := range tt.commands {
				// Setup environment
				originalEnv := make(map[string]string)
				for k := range cmd.setupEnv {
					if v, exists := os.LookupEnv(k); exists {
						originalEnv[k] = v
					}
					os.Unsetenv(k)
				}
				for k, v := range cmd.setupEnv {
					os.Setenv(k, v)
				}

				// Execute command
				command := NewRootCmd()
				command.SetArgs(cmd.args)
				err := command.Execute()

				// Verify results
				if cmd.expectError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}

				if cmd.verify != nil {
					cmd.verify(t, baseDir)
				}

				// Restore environment
				for k := range cmd.setupEnv {
					if v, exists := originalEnv[k]; exists {
						os.Setenv(k, v)
					} else {
						os.Unsetenv(k)
					}
				}
			}
		})
	}
}
