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
	"strings"

	"github.com/carlmjohnson/requests"
	"github.com/rs/zerolog/log"
)

type Resource struct {
	Urls      []string
	Integrity string
	Tags      []string `toml:",omitempty"`
	Filename  string   `toml:",omitempty"`
	CacheUri  string   `toml:",omitempty"`
}

func NewResourceFromUrl(urls []string, algo string, tags []string, filename string) (*Resource, error) {
	if len(urls) < 1 {
		return nil, fmt.Errorf("empty url list")
	}
	url := urls[0]
	ctx := context.Background()

	path, err := GetUrltoTempFile(url, ctx)
	if err != nil {
		return nil, err // Pass through the error from getUrl
	}
	defer os.Remove(path)

	integrity, err := getIntegrityFromFile(path, algo)
	if err != nil {
		return nil, err
	}

	return &Resource{
		Urls:      urls,
		Integrity: integrity,
		Tags:      tags,
		Filename:  filename,
	}, nil
}

func getUrl(u string, fileName string, ctx context.Context) (string, error) {
	if _, err := url.Parse(u); err != nil {
		return "", fmt.Errorf("failed to download '%s': invalid URL", u)
	}

	req := requests.URL(u).
		Header("Accept", "*/*").
		ToFile(fileName)

	// Only add authentication for Artifactory URLs
	if strings.Contains(u, "artifactory") {
		token := os.Getenv("ARTIFACTORY_TOKEN")
		if token != "" {
			req = req.Header("Authorization", "Bearer "+token)
		}
	}

	err := req.Fetch(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to download '%s': %v", u, err)
	}
	log.Debug().Msg("Download completed")
	return fileName, nil
}

func GetUrlToDir(u string, targetDir string, ctx context.Context) (string, error) {
	h := sha256.New()
	h.Write([]byte(u))
	fileName := filepath.Join(targetDir, fmt.Sprintf(".%s", hex.EncodeToString(h.Sum(nil))))
	return getUrl(u, fileName, ctx)
}

func GetUrltoTempFile(u string, ctx context.Context) (string, error) {
	file, err := os.CreateTemp("", "prefix")
	if err != nil {
		return "", err
	}
	fileName := file.Name()
	return getUrl(u, fileName, ctx)
}

func (r *Resource) Contains(url string) bool {
	for _, u := range r.Urls {
		if u == url {
			return true
		}
	}
	return false
}

func (r *Resource) Download(dir string, mode os.FileMode, ctx context.Context) error {
	// Try cache first if available
	if r.CacheUri != "" {
		token := os.Getenv("ARTIFACTORY_TOKEN")
		if token == "" {
			return fmt.Errorf("ARTIFACTORY_TOKEN required for cache download")
		}

		log.Debug().Str("CacheUri", r.CacheUri).Msg("Attempting cache download")
		lpath, err := downloadWithToken(r.CacheUri, dir, ctx, token)
		if err == nil {
			if err := checkIntegrityFromFile(lpath, "sha256", r.Integrity, r.CacheUri); err == nil {
				return renameAndSetPermission(lpath, getLocalFileName(r.CacheUri), mode)
			}
		}
		log.Debug().Msg("Cache download failed, trying direct download")
	}

	// Try each original URL
	for _, u := range r.Urls {
		log.Debug().Str("URL", u).Msg("Attempting download")
		lpath, err := GetUrlToDir(u, dir, ctx)
		if err != nil {
			log.Debug().Str("URL", u).Msg("Download failed, trying next URL")
			continue
		}

		if err = checkIntegrityFromFile(lpath, "sha256", r.Integrity, u); err != nil {
			return err
		}

		localName := r.Filename
		if localName == "" {
			localName = path.Base(u)
		}

		resPath := filepath.Join(dir, localName)
		if err = renameAndSetPermission(lpath, resPath, mode); err != nil {
			return err
		}

		return nil
	}

	return fmt.Errorf("all downloads failed")
}

func downloadWithToken(url, targetDir string, ctx context.Context, token string) (string, error) {
	fileName := filepath.Join(targetDir, filepath.Base(url))
	req := requests.URL(url).
		Header("Accept", "*/*").
		Header("Authorization", "Bearer "+token).
		ToFile(fileName)

	if err := req.Fetch(ctx); err != nil {
		return "", err
	}

	return fileName, nil
}

func renameAndSetPermission(src, dest string, mode os.FileMode) error {
	if err := os.Rename(src, dest); err != nil {
		return err
	}

	if mode != NoFileMode {
		return os.Chmod(dest, mode)
	}
	return nil
}

func getLocalFileName(cacheUri string) string {
	return filepath.Base(cacheUri)
}
