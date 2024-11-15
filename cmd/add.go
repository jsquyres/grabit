// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.
package cmd

import (
 feature/artifactory-delete
	"bytes"

 feature/artifactory-upload
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

 feature/artifactory-delete

	"github.com/carlmjohnson/requests"
 feature/artifactory-upload
	"github.com/cisco-open/grabit/internal"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func addAdd(cmd *cobra.Command) {
	addCmd := &cobra.Command{
		Use:   "add [url]",
		Short: "Add new resource",
		Args:  cobra.MinimumNArgs(1),
		RunE:  runAdd,
	}

	addCmd.Flags().String("cache", "", "Artifactory cache URL")
	addCmd.Flags().String("algo", internal.RecommendedAlgo, "Integrity algorithm")
	addCmd.Flags().String("filename", "", "Target file name")
	addCmd.Flags().StringArray("tag", []string{}, "Resource tags")

	cmd.AddCommand(addCmd)
}

// cmd/add.go
func runAdd(cmd *cobra.Command, args []string) error {
	// Get flags
 feature/artifactory-delete
	lockFile, err := cmd.Flags().GetString("lock-file")

	cache, err := cmd.Flags().GetString("cache")
 feature/artifactory-upload
	if err != nil {
		return err
	}

 feature/artifactory-delete

	// Check GRABIT_ARTIFACTORY_TOKEN if cache specified
	var token string // Declare token once
	if cache != "" {
		token = os.Getenv("GRABIT_ARTIFACTORY_TOKEN") // Use = instead of :=
		if token == "" {
			return fmt.Errorf("GRABIT_ARTIFACTORY_TOKEN must be set when using cache")
		}
	}

	// Download the file
	ctx := context.Background()
	tempFile, err := internal.GetUrltoTempFile(args[0], ctx)
	if err != nil {
		return fmt.Errorf("failed to download resource: %w", err)
	}
	defer os.Remove(tempFile)

	// Get hash of file
	hash, err := internal.GetFileHash(tempFile)
	if err != nil {
		return fmt.Errorf("failed to calculate file hash: %w", err)
	}

	// Handle cache if specified
	var cachePath string
	if cache != "" {

		// Ensure cache URL ends with a single /
		cache = strings.TrimSuffix(cache, "/") + "/"
		cachePath = cache + hash

		if err := uploadToArtifactory(tempFile, cachePath, token); err != nil {
			return fmt.Errorf("failed to upload to Artifactory: %w", err)
		}
		log.Debug().Str("path", cachePath).Msg("Successfully uploaded to cache")
	}

	// Add to lock file
	lockFile, err := cmd.Flags().GetString("lock-file")
	if err != nil {
		return err
	}

 feature/artifactory-upload
	algo, err := cmd.Flags().GetString("algo")
	if err != nil {
		return err
	}

	tags, err := cmd.Flags().GetStringArray("tag")
	if err != nil {
		return err
	}

	filename, err := cmd.Flags().GetString("filename")
	if err != nil {
		return err
	}

 feature/artifactory-delete
	cache, err := cmd.Flags().GetString("cache")

	lock, err := internal.NewLock(lockFile, true)
 feature/artifactory-upload
	if err != nil {
		return err
	}

 feature/artifactory-delete
	// Check for GRABIT_ARTIFACTORY_TOKEN if cache is specified
	if cache != "" {
		token := os.Getenv("GRABIT_ARTIFACTORY_TOKEN")
		if token == "" {
			return fmt.Errorf("GRABIT_ARTIFACTORY_TOKEN must be set when using cache")
		}
	}

	// Create or open lock file
	lock, err := internal.NewLock(lockFile, true)

	if err := lock.AddResourceWithCache(args, algo, tags, filename, cachePath); err != nil {
		return fmt.Errorf("failed to add resource to lock file: %w", err)
	}

	return lock.Save()
}

// Modified to take token as parameter per Dr. Squyres' feedback
func uploadToArtifactory(filePath, cacheUrl, token string) error {
	fileData, err := ioutil.ReadFile(filePath)
 feature/artifactory-upload
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

 feature/artifactory-delete
	// Download file first
	ctx := context.Background()
	tempFile, err := internal.GetUrltoTempFile(args[0], ctx)
	if err != nil {
		return fmt.Errorf("failed to download resource: %w", err)
	}
	defer os.Remove(tempFile)

	// Calculate hash for integrity and cache path
	hash, err := internal.GetFileHash(tempFile)
	if err != nil {
		return fmt.Errorf("failed to calculate file hash: %w", err)
	}

	// Handle cache if specified
	var cachePath string
	if cache != "" {
		// Ensure cache URL ends with a single /
		cache = strings.TrimSuffix(cache, "/") + "/"
		cachePath = cache + hash

		log.Debug().
			Str("path", cachePath).
			Msg("Uploading to Artifactory cache")

		if err := uploadToArtifactory(tempFile, cachePath); err != nil {
			log.Debug().
				Err(err).
				Str("path", cachePath).
				Msg("Failed to upload to cache")
			// Continue without cache - this is not a fatal error
		} else {
			log.Debug().
				Str("path", cachePath).
				Msg("Successfully uploaded to cache")
		}
	}

	// Add resource to lock file
	if err := lock.AddResourceWithCache(args, algo, tags, filename, cachePath); err != nil {
		return fmt.Errorf("failed to add resource to lock file: %w", err)
	}

	return lock.Save()
}

func uploadToArtifactory(filePath, cacheUrl string) error {
	token := os.Getenv("GRABIT_ARTIFACTORY_TOKEN")
	if token == "" {
		return fmt.Errorf("GRABIT_ARTIFACTORY_TOKEN must be set")
	}

	// Read file content
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Create request
	req, err := http.NewRequest(http.MethodPut, cacheUrl, bytes.NewReader(fileData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(fileData)))

	// Make request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload to Artifactory: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("upload failed (status %d): %s", resp.StatusCode, string(body))
	}

	err = requests.URL(cacheUrl).
		Method(http.MethodPut).
		Header("Authorization", "Bearer "+token).
		Header("Content-Type", "application/octet-stream").
		BodyBytes(fileData).
		Fetch(context.Background())

	if err != nil {
		return fmt.Errorf("failed to upload to Artifactory: %w", err)
	}
 feature/artifactory-upload

	return nil
}
