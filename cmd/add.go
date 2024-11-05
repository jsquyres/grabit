// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.
package cmd

import (
	"bytes"
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
		Args:  cobra.ExactArgs(1),
		RunE:  runAdd,
	}

	addCmd.Flags().String("algo", internal.RecommendedAlgo, "Integrity algorithm")
	addCmd.Flags().String("filename", "", "Target file name to use when downloading the resource")
	addCmd.Flags().StringArray("tag", []string{}, "Resource tags")
	addCmd.Flags().String("cache", "", "URL of Artifactory cache")

	cmd.AddCommand(addCmd)
}

func runAdd(cmd *cobra.Command, args []string) error {
	// Get flags
	lockFile, err := cmd.Flags().GetString("lock-file")
	if err != nil {
		return fmt.Errorf("failed to get lock-file flag: %w", err)
	}

	algo, err := cmd.Flags().GetString("algo")
	if err != nil {
		return fmt.Errorf("failed to get algo flag: %w", err)
	}

	tags, err := cmd.Flags().GetStringArray("tag")
	if err != nil {
		return fmt.Errorf("failed to get tag flag: %w", err)
	}

	filename, err := cmd.Flags().GetString("filename")
	if err != nil {
		return fmt.Errorf("failed to get filename flag: %w", err)
	}

	cache, err := cmd.Flags().GetString("cache")
	if err != nil {
		return fmt.Errorf("failed to get cache flag: %w", err)
	}

	// Validate cache configuration
	if cache != "" {
		// If cache URL is provided, authentication is required
		token := os.Getenv("ARTIFACTORY_TOKEN")
		if token == "" {
			return fmt.Errorf("ARTIFACTORY_TOKEN must be set when using cache")
		}
		log.Debug().
			Str("cache_url", cache).
			Msg("Artifactory cache configured")
	}

	// Create or open lock file
	lock, err := internal.NewLock(lockFile, true)
	if err != nil {
		return fmt.Errorf("failed to create/open lock file: %w", err)
	}

	// Check if resource is local file
	isLocal := !strings.HasPrefix(args[0], "http://") && !strings.HasPrefix(args[0], "https://")
	if isLocal && cache != "" {
		log.Debug().
			Str("file", args[0]).
			Str("cache", cache).
			Msg("Uploading local file to Artifactory")

		if err := uploadToArtifactory(args[0], cache); err != nil {
			return fmt.Errorf("failed to upload to Artifactory: %w", err)
		}
	}

	// Add resource to lock file
	if err := lock.AddResourceWithCache(args, algo, tags, filename, cache); err != nil {
		return fmt.Errorf("failed to add resource: %w", err)
	}

	// Save changes
	if err := lock.Save(); err != nil {
		return fmt.Errorf("failed to save lock file: %w", err)
	}

	log.Debug().
		Str("url", args[0]).
		Str("cache", cache).
		Msg("Resource added successfully")

	return nil
}

// uploadToArtifactory uploads a file to Artifactory
func uploadToArtifactory(filePath, cacheUrl string) error {
	// Get authentication token
	token := os.Getenv("ARTIFACTORY_TOKEN")
	if token == "" {
		return fmt.Errorf("ARTIFACTORY_TOKEN is not set")
	}

	// Read file
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

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("upload failed (status %d): %s", resp.StatusCode, string(body))
	}

	log.Debug().
		Str("file", filePath).
		Str("url", cacheUrl).
		Msg("File uploaded to Artifactory")

	return nil
}
