// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.

package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/carlmjohnson/requests"
	"github.com/rs/zerolog/log"
)

// Resource represents an external resource to be downloaded.
type Resource struct {
	Urls      []string
	Integrity string
	Tags      []string `toml:",omitempty"`
	Filename  string   `toml:",omitempty"`
	CacheUri  string   `toml:",omitempty"`
}

// NewResourceFromUrl creates a new Resource struct given a list of URLs, integrity algorithm, tags, and filename.
func NewResourceFromUrl(urls []string, algo string, tags []string, filename string) (*Resource, error) {
	if len(urls) < 1 {
		return nil, fmt.Errorf("empty url list")
	}
	url := urls[0]
	ctx := context.Background()

	log.Debug().Str("URL", url).Msg("Initializing resource from URL")

	path, err := GetUrltoTempFile(url, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get url: %s", err)
	}
	defer os.Remove(path)
	integrity, err := getIntegrityFromFile(path, algo)
	if err != nil {
		return nil, fmt.Errorf("failed to compute resource integrity: %s", err)
	}
	return &Resource{Urls: urls, Integrity: integrity, Tags: tags, Filename: filename}, nil
}

// getUrl downloads the given resource and returns the path to it.
func getUrl(u string, fileName string, ctx context.Context) (string, error) {
	_, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("invalid url '%s': %s", u, err)
	}

	req := requests.URL(u).
		Header("Accept", "*/*").
		ToFile(fileName)

	// Add authorization header if the URL matches the CacheUri and ARTIFACTORY_TOKEN is set.
	token := os.Getenv("ARTIFACTORY_TOKEN")
	if token != "" {
		authHeader := "Bearer " + token
		req = req.Header("Authorization", authHeader)
		log.Debug().Str("Authorization", authHeader).Msg("Adding Authorization header for request")
	}

	log.Debug().Str("URL", u).Msg("Downloading resource")
	err = req.Fetch(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to download '%s': %s", u, err)
	}
	log.Debug().Str("URL", u).Msg("Download completed successfully")
	return fileName, nil
}

// GetUrlToDir downloads the given resource to the given directory.
func GetUrlToDir(u string, targetDir string, ctx context.Context) (string, error) {
	h := sha256.New()
	h.Write([]byte(u))
	fileName := filepath.Join(targetDir, fmt.Sprintf(".%s", hex.EncodeToString(h.Sum(nil))))

	log.Info().Str("URL", u).Msg("Downloading URL to directory")

	return getUrl(u, fileName, ctx)
}

// GetUrltoTempFile downloads the given resource to a temporary file.
func GetUrltoTempFile(u string, ctx context.Context) (string, error) {
	file, err := os.CreateTemp("", "prefix")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create temporary file")
	}
	fileName := file.Name()
	return getUrl(u, fileName, ctx)
}

func (l *Resource) Download(dir string, mode os.FileMode, ctx context.Context) error {
	var token string
	var err error

	// Get the authentication token if CacheUri is set
	if l.CacheUri != "" {
		token, err = getAuthToken()
		if err != nil {
			return fmt.Errorf("cache URI specified but ARTIFACTORY_TOKEN is missing: %w", err)
		}
	}

	algo, err := getAlgoFromIntegrity(l.Integrity)
	if err != nil {
		return err
	}

	integrityHex, err := convertHashToHex(l.Integrity)
	if err != nil {
		log.Error().Err(err).Msg("Failed to convert integrity hash to Hex")
		return err
	}

	// Try downloading from the cache first if CacheUri is provided
	if l.CacheUri != "" {
		log.Debug().Str("CacheUri", l.CacheUri).Msg("Attempting download from cache")

		// Attempt to download from cache with the token
		lpath, err := downloadWithToken(l.CacheUri, dir, ctx, token)
		if err == nil {
			// Declare integrityErr to hold the result of integrity check
			integrityErr := checkIntegrityFromFile(lpath, algo, integrityHex, l.CacheUri)
			if integrityErr == nil {
				log.Debug().Str("CacheUri", l.CacheUri).Msg("Successfully downloaded from cache")
				return renameAndSetPermission(lpath, getLocalFileName(l.CacheUri), mode)
			}
			log.Error().Err(integrityErr).Str("CacheUri", l.CacheUri).Msg("Integrity check failed for cached file")
		} else {
			log.Error().Err(err).Str("CacheUri", l.CacheUri).Msg("Download from cache failed, trying original URLs")
		}
	}

	// Attempt downloading from the original URLs if cache download fails
	for _, u := range l.Urls {
		log.Debug().Str("URL", u).Msg("Attempting download from URL")
		lpath, err := GetUrlToDir(u, dir, ctx)
		if err != nil {
			log.Error().Err(err).Str("URL", u).Msg("Download failed, trying next URL")
			continue
		}

		if err = checkIntegrityFromFile(lpath, algo, l.Integrity, u); err != nil {
			log.Error().Err(err).Str("Path", lpath).Msg("Integrity check failed")
			return err
		}

		localName := l.Filename
		if localName == "" {
			localName = path.Base(u)
		}

		resPath := filepath.Join(dir, localName)
		log.Debug().Str("Path", resPath).Msg("Moving file to final location")

		if err = renameAndSetPermission(lpath, resPath, mode); err != nil {
			log.Error().Err(err).Msg("Failed to setup file")
			return err
		}

		return nil // Successful download and integrity check
	}

	return fmt.Errorf("no valid URLs to download")
}

// END: Integration of getAuthToken and downloadWithToken logic in Download function

// Contains checks if the given URL is part of the resource URLs.
func (l *Resource) Contains(url string) bool {
	for _, u := range l.Urls {
		if u == url {
			return true
		}
	}
	return false
}

// Helper function to rename and set file permission.
func renameAndSetPermission(src, dest string, mode os.FileMode) error {
	err := os.Rename(src, dest)
	if err != nil {
		return fmt.Errorf("failed to rename file: %v", err)
	}

	if mode != NoFileMode {
		err = os.Chmod(dest, mode)
		if err != nil {
			return fmt.Errorf("failed to set file permissions: %v", err)
		}
	}

	return nil
}

// Helper function to get local filename from the CacheUri.
func getLocalFileName(cacheUri string) string {
	return filepath.Base(cacheUri)
}

// BEGIN: New helper function to download with token
// downloadWithToken downloads a file from a URL with an optional authorization token
func downloadWithToken(url, targetDir string, ctx context.Context, token string) (string, error) {
	fileName := filepath.Join(targetDir, filepath.Base(url))
	req := requests.URL(url).
		Header("Accept", "*/*").
		ToFile(fileName)

	// Add Authorization header if a token is provided
	if token != "" {
		req = req.Header("Authorization", token)
	}

	// Perform the download
	log.Debug().Str("URL", url).Msg("Downloading with token")
	if err := req.Fetch(ctx); err != nil {
		return "", fmt.Errorf("failed to download '%s': %w", url, err)
	}
	log.Debug().Str("URL", url).Msg("Download completed successfully")
	return fileName, nil
}

// END: New helper function to download with token
