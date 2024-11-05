// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.

package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http" // Import for HTTP requests
	"os"       // Import for environment variables
	"strings"

	"github.com/cisco-open/grabit/internal"
	"github.com/rs/zerolog/log" // Import for logging (debug statements)
	"github.com/spf13/cobra"
)

func addAdd(cmd *cobra.Command) {
	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Add new resource",
		Args:  cobra.MinimumNArgs(1),
		RunE:  runAdd,
	}
	addCmd.Flags().String("algo", internal.RecommendedAlgo, "Integrity algorithm")
	addCmd.Flags().String("filename", "", "Target file name to use when downloading the resource")
	addCmd.Flags().StringArray("tag", []string{}, "Resource tags")
	addCmd.Flags().String("integrity", "", "Integrity hash of the resource (Hex format or SRI format)")
	addCmd.Flags().String("cache", "", "URL of Artifactory cache to store the resource") // New cache flag

	cmd.AddCommand(addCmd)
}
func runAdd(cmd *cobra.Command, args []string) error {
	// Check if the input is a URL or a file path
	isRemote := strings.HasPrefix(args[0], "http://") || strings.HasPrefix(args[0], "https://")

	lockFile, err := cmd.Flags().GetString("lock-file")
	if err != nil {
		return err
	}
	lock, err := internal.NewLock(lockFile, true)
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

	// Check if ARTIFACTORY_TOKEN is set if cache URL is provided
	token := os.Getenv("ARTIFACTORY_TOKEN")
	if token == "" && cache != "" {
		log.Warn().Msg("ARTIFACTORY_TOKEN is not set; cache upload may fail if authentication is required.")
	}

	// If it's a local file path and cache URL is provided, upload the file
	if !isRemote && cache != "" {
		err := uploadToArtifactory(args[0], cache, token)
		if err != nil {
			return fmt.Errorf("failed to upload to Artifactory: %w", err)
		}
		log.Info().Msgf("Successfully uploaded resource to Artifactory: %s", cache)
	}

	// Add the resource to lock file, including the cache URL if specified
	err = lock.AddResourceWithCache(args, algo, tags, filename, cache)
	if err != nil {
		return err
	}

	// Save the lock file
	err = lock.Save()
	if err != nil {
		return err
	}

	log.Info().Msg("Resource added successfully")
	return nil
}

// uploadToArtifactory uploads the file at `filePath` to the Artifactory `cacheUrl` using the provided `token`.
func uploadToArtifactory(filePath, cacheUrl, token string) error {
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file for upload: %w", err)
	}

	// Create a new HTTP request
	req, err := http.NewRequest("PUT", cacheUrl, bytes.NewReader(fileData))
	if err != nil {
		return fmt.Errorf("failed to create upload request: %w", err)
	}

	// Set headers
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(fileData)))

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute upload request: %w", err)
	}
	defer resp.Body.Close()

	// Check if upload was successful
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("upload to Artifactory failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
