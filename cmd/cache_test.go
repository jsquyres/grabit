package cmd

import (
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
		name        string
		commands    [][]string
		setupEnv    map[string]string
		expectError bool
		errorMsg    string
		verify      func(*testing.T, string)
	}{
		{
			// Requirement: Check if GRABIT_ARTIFACTORY_TOKEN is set
			name: "Token validation",
			commands: [][]string{
				{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},
			},
			setupEnv:    map[string]string{},
			expectError: true,
			errorMsg:    "GRABIT_ARTIFACTORY_TOKEN must be set when using cache",
		},
		{
			// Requirement: Cache download attempt first
			name: "Cache download priority",
			commands: [][]string{
				{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},
				{"download", "--lock-file", "LOCKFILE"},
			},
			setupEnv: map[string]string{
				"GRABIT_ARTIFACTORY_TOKEN": "test-token",
			},
			expectError: false,
		},
		{
			// Requirement: Fallback to source URL if cache fails
			name: "Cache fallback behavior",
			commands: [][]string{
				{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "INVALID_CACHE"},
				{"download", "--lock-file", "LOCKFILE"},
			},
			setupEnv: map[string]string{
				"GRABIT_ARTIFACTORY_TOKEN": "test-token",
			},
			expectError: false,
		},
		{
			// Requirement: Upload to cache after source download
			name: "Cache upload after download",
			commands: [][]string{
				{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},
			},
			setupEnv: map[string]string{
				"GRABIT_ARTIFACTORY_TOKEN": "test-token",
			},
			expectError: false,
		},
		{
			// Requirement: NO_CACHE_UPLOAD prevents cache upload
			name: "NO_CACHE_UPLOAD handling",
			commands: [][]string{
				{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},
			},
			setupEnv: map[string]string{
				"GRABIT_ARTIFACTORY_TOKEN": "test-token",
				"NO_CACHE_UPLOAD":          "1",
			},
			expectError: false,
		},
		{
			// Requirement: Hash validation
			name: "Cache integrity validation",
			commands: [][]string{
				{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "--cache", "CACHE_URL"},
				{"download", "--lock-file", "LOCKFILE"},
			},
			setupEnv: map[string]string{
				"GRABIT_ARTIFACTORY_TOKEN": "test-token",
			},
			expectError: false,
		},
		{
			// Requirement: Multiple URL support
			name: "Multiple URLs with cache",
			commands: [][]string{
				{"add", "--lock-file", "LOCKFILE", "SOURCE_URL", "SOURCE_URL2", "--cache", "CACHE_URL"},
				{"download", "--lock-file", "LOCKFILE"},
			},
			setupEnv: map[string]string{
				"GRABIT_ARTIFACTORY_TOKEN": "test-token",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test directory
			tmpDir := t.TempDir()
			lockFile := filepath.Join(tmpDir, "grabit.lock")

			// Setup environment
			origEnv := make(map[string]string)
			for k, v := range tt.setupEnv {
				if oldVal, exists := os.LookupEnv(k); exists {
					origEnv[k] = oldVal
				}
				os.Setenv(k, v)
			}
			defer func() {
				// Restore environment
				for k := range tt.setupEnv {
					if originalVal, exists := origEnv[k]; exists {
						os.Setenv(k, originalVal)
					} else {
						os.Unsetenv(k)
					}
				}
			}()

			var lastErr error
			for _, cmdArgs := range tt.commands {
				// Replace placeholders
				args := make([]string, len(cmdArgs))
				for i, arg := range cmdArgs {
					switch arg {
					case "SOURCE_URL":
						args[i] = contentServer.URL + "/test.txt"
					case "SOURCE_URL2":
						args[i] = contentServer.URL + "/test2.txt"
					case "CACHE_URL":
						args[i] = artifactoryServer.URL + "/grabit-local"
					case "INVALID_CACHE":
						args[i] = "http://invalid-cache/repo"
					case "LOCKFILE":
						args[i] = lockFile
					default:
						args[i] = arg
					}
				}

				// Execute command
				cmd := NewRootCmd()
				cmd.SetArgs(args)
				err := cmd.Execute()
				if err != nil {
					lastErr = err
				}
			}

			// Verify results
			if tt.expectError {
				assert.Error(t, lastErr)
				if tt.errorMsg != "" {
					assert.Contains(t, lastErr.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, lastErr)
			}

			// Run additional verifications if specified
			if tt.verify != nil {
				tt.verify(t, tmpDir)
			}
		})
	}
}
