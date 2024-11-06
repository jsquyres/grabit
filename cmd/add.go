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

	"github.com/cisco-open/grabit/internal"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func addAdd(cmd *cobra.Command) {
	addCmd := &cobra.Command{
		Use:   "add [url]",
		Short: "Add new resource",
		Args:  cobra.MinimumNArgs(1), // Keeping MinimumNArgs as multiple URLs are allowed
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

	// Check cache configuration first
	if cache != "" {
		token := os.Getenv("ARTIFACTORY_TOKEN")
		if token == "" {
			return fmt.Errorf("ARTIFACTORY_TOKEN must be set when using cache")
		}
	}

	// Create or open lock file
	lock, err := internal.NewLock(lockFile, true)
	if err != nil {
		return err
	}

	// If cache is specified, download and upload to Artifactory first
	if cache != "" {
		log.Debug().Msg("Downloading resource for cache")
		// Download the file first
		tempFile, err := internal.GetUrltoTempFile(args[0], context.Background())
		if err != nil {
			return fmt.Errorf("failed to download resource: %w", err)
		}
		defer os.Remove(tempFile)

		// Upload to Artifactory
		log.Debug().Msg("Uploading to Artifactory cache")
		if err := uploadToArtifactory(tempFile, cache); err != nil {
			return fmt.Errorf("failed to upload to cache: %w", err)
		}
	}

	// Add resource to lock file
	if err := lock.AddResourceWithCache(args, algo, tags, filename, cache); err != nil {
		return err
	}

	// Save changes
	if err := lock.Save(); err != nil {
		return err
	}

	log.Debug().Msg("Resource added successfully")
	return nil
}

// uploadToArtifactory uploads a file to Artifactory
func uploadToArtifactory(filePath, cacheUrl string) error {
	token := os.Getenv("ARTIFACTORY_TOKEN")
	if token == "" {
		return fmt.Errorf("ARTIFACTORY_TOKEN must be set")
	}

	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, cacheUrl, bytes.NewReader(fileData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(fileData)))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("upload failed (status %d): %s", resp.StatusCode, string(body))
	}

	log.Debug().Msg("File uploaded to Artifactory")
	return nil
}
