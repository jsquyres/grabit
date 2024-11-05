// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.

package cmd

import (
	"fmt" // Import for formatted I/O
	"os"  // Import for environment variables

	"github.com/cisco-open/grabit/internal"
	"github.com/rs/zerolog/log" // Import for logging (debug statements)
	"github.com/spf13/cobra"
)

func addDownload(cmd *cobra.Command) {
	downloadCmd := &cobra.Command{
		Use:   "download",
		Short: "Download defined resources",
		Args:  cobra.NoArgs,
		RunE:  runFetch,
	}
	downloadCmd.Flags().String("dir", ".", "Target directory where to store the files")
	downloadCmd.Flags().StringArray("tag", []string{}, "Only download the resources with the given tag")
	downloadCmd.Flags().StringArray("notag", []string{}, "Only download the resources without the given tag")
	downloadCmd.Flags().String("perm", "", "Optional permissions for the downloaded files (e.g. '644')")
	cmd.AddCommand(downloadCmd)
}

func runFetch(cmd *cobra.Command, args []string) error {
	// Retrieve flags
	lockFile, err := cmd.Flags().GetString("lock-file")
	if err != nil {
		return err
	}

	// Open lock file as a local file, not a URL
	lock, err := internal.NewLock(lockFile, false)
	if err != nil {
		return fmt.Errorf("failed to open lock file '%s': %w", lockFile, err)
	}

	dir, err := cmd.Flags().GetString("dir")
	if err != nil {
		return err
	}
	tags, err := cmd.Flags().GetStringArray("tag")
	if err != nil {
		return err
	}
	notags, err := cmd.Flags().GetStringArray("notag")
	if err != nil {
		return err
	}
	perm, err := cmd.Flags().GetString("perm")
	if err != nil {
		return err
	}

	// Ensure ARTIFACTORY_TOKEN is set if cache URLs require it (new part starts here)
	token := os.Getenv("ARTIFACTORY_TOKEN")
	if token == "" {
		log.Warn().Msg("ARTIFACTORY_TOKEN is not set; any cache URLs requiring authentication may fail.")
	} else {
		log.Debug().Msg("ARTIFACTORY_TOKEN is set; proceeding with potential cache authentication.")
	}
	// New part ends here

	// Proceed with the downloading logic
	err = lock.Download(dir, tags, notags, perm)
	if err != nil {
		return fmt.Errorf("failed to download resources: %w", err)
	}

	log.Info().Msg("Download completed successfully")
	return nil
}
