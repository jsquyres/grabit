package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		token := r.Header.Get("Authorization")
		if token != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Unauthorized")
			return
		}
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			w.Write([]byte("test content"))
		}
	}))
	defer artifactoryServer.Close()

	tests := []struct {
		name     string
		commands []struct {
			args        []string
			setupEnv    map[string]string
			expectError bool
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
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
				errorMsg    string
			}{
				{
					args: []string{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
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
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
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
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
				errorMsg    string
			}{
				{
					args: []string{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
						"NO_CACHE_UPLOAD":          "1",
					},
					expectError: false,
				},
			},
		},
		{
			name: "Multiple URLs with cache",
			commands: []struct {
				args        []string
				setupEnv    map[string]string
				expectError bool
				errorMsg    string
			}{
				{
					args: []string{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "SOURCE_URL2", "--cache", "CACHE_URL"},
					setupEnv: map[string]string{
						"GRABIT_ARTIFACTORY_TOKEN": "test-token",
					},
					expectError: false,
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
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
				} else {
					assert.NoError(t, err)
				}

				// Restore environment
				for k := range cmd.setupEnv {
					if originalVal, exists := origEnv[k]; exists {
						os.Setenv(k, originalVal)
					} else {
						os.Unsetenv(k)
					}
				}
			}
		})
	}
}
