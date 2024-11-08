// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.
package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

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

func runAdd(cmd *cobra.Command, args []string) error {
	// Get flags
	lockFile, err := cmd.Flags().GetString("lock-file")
	if err != nil {
		return err
	}

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

	cache, err := cmd.Flags().GetString("cache")
	if err != nil {
		return err
	}

	// Check for GRABIT_ARTIFACTORY_TOKEN if cache is specified
	if cache != "" {
		token := os.Getenv("GRABIT_ARTIFACTORY_TOKEN")
		if token == "" {
			return fmt.Errorf("GRABIT_ARTIFACTORY_TOKEN must be set when using cache")
		}
	}

	// Create or open lock file
	lock, err := internal.NewLock(lockFile, true)
	if err != nil {
		return err
	}

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

	return nil
}
