package cmd

import (
	"fmt"
 feature/artifactory-delete

	"io/ioutil"
 feature/artifactory-upload
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
 feature/artifactory-delete
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrabitRequirements(t *testing.T) {
	// Setup test servers
	contentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test content"))
	}))
	defer contentServer.Close()

	artifactoryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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
 feature/artifactory-upload
		token := r.Header.Get("Authorization")
		if token != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Unauthorized")
			return
		}
 feature/artifactory-delete
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			w.Write([]byte("test content"))
		}
	}))
	defer artifactoryServer.Close()


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
 feature/artifactory-upload

	tests := []struct {
		name     string
		commands []struct {
			args        []string
			setupEnv    map[string]string
			expectError bool
 feature/artifactory-delete
			errorMsg    string
		}
	}{
		{
			name: "Token validation",
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
				errorMsg    string
			}{
				{
					args:        []string{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},
					setupEnv:    map[string]string{},
					expectError: true,
					errorMsg:    "GRABIT_ARTIFACTORY_TOKEN must be set when using cache",
				},
			},
		},
		{
			name: "Cache download flow",

			verify      func(*testing.T, string)
		}
	}{
		{
			name: "Complete cache workflow",
 feature/artifactory-upload
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
 feature/artifactory-delete
				errorMsg    string
			}{
				{
					args: []string{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},

				verify      func(*testing.T, string)
			}{
				{
					// Step 1: Add with cache
					args: []string{"add",
						contentServer.URL + "/test.txt",
						"--cache", artifactoryServer.URL + "/cache",
						"--lock-file", lockFile},
 feature/artifactory-upload
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
 feature/artifactory-delete
				},
				{
					args: []string{"download", "--lock-file", "LOCKFILE"},
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
				},
			},
		},
		{
			name: "Fallback to source",
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
				errorMsg    string
			}{
				{
					args: []string{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},

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
 feature/artifactory-upload
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
 feature/artifactory-delete
				},
				{
					args:        []string{"download", "--lock-file", "LOCKFILE"},
					setupEnv:    map[string]string{},
					expectError: false,
				},
			},
		},
		{
			name: "NO_CACHE_UPLOAD behavior",

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
 feature/artifactory-upload
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
 feature/artifactory-delete
				errorMsg    string
			}{
				{
					args: []string{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
						"NO_CACHE_UPLOAD":          "1",

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
 feature/artifactory-upload
					},
					expectError: false,
				},
			},
		},
		{
 feature/artifactory-delete
			name: "Multiple URLs with cache",

			name: "Cache validation failure",
 feature/artifactory-upload
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
 feature/artifactory-delete
				errorMsg    string
			}{
				{
					args: []string{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "SOURCE_URL2", "--cache", "CACHE_URL"},

				verify      func(*testing.T, string)
			}{
				{
					// First add a resource
					args: []string{"add",
						contentServer.URL + "/test2.txt",
						"--cache", artifactoryServer.URL + "/cache",
						"--lock-file", lockFile},
 feature/artifactory-upload
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
				},
				{
 feature/artifactory-delete
					args: []string{"download", "--lock-file", "LOCKFILE"},

					// Then try to download with validation failure
					args: []string{"download",
						"--lock-file", lockFile,
						"--dir", baseDir}, // Changed --output-dir to --dir
 feature/artifactory-upload
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
 feature/artifactory-delete
				},
			},
		},
		{
			name: "Invalid URLs",
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
				errorMsg    string
			}{
				{
					args: []string{"add", "--lock-file", "LOCKFILE", "INVALID_URL", "--cache", "CACHE_URL"},
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: true,
					errorMsg:    "failed to download",

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
 feature/artifactory-upload
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
 feature/artifactory-delete
			// Setup test directory
			tmpDir := t.TempDir()
			lockFile := filepath.Join(tmpDir, "grabit.lock")

			for _, cmd := range tt.commands {
				// Clear environment
				if os.Getenv("GRABIT_ARTIFACTORY_TOKEN") != "" {
					os.Unsetenv("GRABIT_ARTIFACTORY_TOKEN")
				}

				// Setup environment
				origEnv := make(map[string]string)
				for k, v := range cmd.setupEnv {
					if oldVal, exists := os.LookupEnv(k); exists {
						origEnv[k] = oldVal
					}
					os.Setenv(k, v)
				}

				// Replace placeholders
				args := make([]string, len(cmd.args))
				for i, arg := range cmd.args {
					switch arg {
					case "SOURCE_URL":
						args[i] = contentServer.URL + "/test.txt"
					case "SOURCE_URL2":
						args[i] = contentServer.URL + "/test2.txt"
					case "INVALID_URL":
						args[i] = "http://invalid-url/file.txt"
					case "CACHE_URL":
						args[i] = artifactoryServer.URL + "/grabit-local"
					case "LOCKFILE":
						args[i] = lockFile
					default:
						args[i] = arg
					}
				}

				// Execute command
				c := NewRootCmd()
				c.SetArgs(args)
				err := c.Execute()

				// Verify result
				if cmd.expectError {
					assert.Error(t, err, "Expected an error but got none")
					if cmd.errorMsg != "" {
						assert.Contains(t, err.Error(), cmd.errorMsg)
					}

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
 feature/artifactory-upload
				} else {
					assert.NoError(t, err)
				}

 feature/artifactory-delete
				// Restore environment
				for k := range cmd.setupEnv {
					if originalVal, exists := origEnv[k]; exists {
						os.Setenv(k, originalVal)

				if cmd.verify != nil {
					cmd.verify(t, baseDir)
				}

				// Restore environment
				for k := range cmd.setupEnv {
					if v, exists := originalEnv[k]; exists {
						os.Setenv(k, v)
 feature/artifactory-upload
					} else {
						os.Unsetenv(k)
					}
				}
			}
		})
	}
}
