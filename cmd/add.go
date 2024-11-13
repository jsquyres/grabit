// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.
package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/carlmjohnson/requests"
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
	cache, err := cmd.Flags().GetString("cache")
	if err != nil {
		return err
	}

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

	lock, err := internal.NewLock(lockFile, true)
	if err != nil {
		return err
	}

	if err := lock.AddResourceWithCache(args, algo, tags, filename, cachePath); err != nil {
		return fmt.Errorf("failed to add resource to lock file: %w", err)
	}

	return lock.Save()
}

// Modified to take token as parameter per Dr. Squyres' feedback
func uploadToArtifactory(filePath, cacheUrl, token string) error {
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
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

	return nil
}
