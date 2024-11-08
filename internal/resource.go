// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.
package internal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
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
	ctx := context.Background()

	path, err := GetUrltoTempFile(urls[0], ctx)
	if err != nil {
		return nil, err
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
	return getUrl(u, file.Name(), ctx)
}

func GetFileHash(filePath string) (string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil)), nil
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
	if r.CacheUri != "" {
		token := os.Getenv("GRABIT_ARTIFACTORY_TOKEN")
		if token == "" {
			log.Debug().Msg("GRABIT_ARTIFACTORY_TOKEN not set, skipping cache")
		} else {
			log.Debug().Msg("Attempting cache download")
			if err := r.downloadFromCache(dir, mode, ctx); err == nil {
				return nil
			} else if !strings.Contains(err.Error(), "integrity check failed") {
				log.Debug().Err(err).Msg("Cache download failed, trying original URL")
			}
		}
	}

	if err := r.downloadFromSource(dir, mode, ctx); err != nil {
		return err
	}

	// Upload to cache if configured
	if r.CacheUri != "" && os.Getenv("NO_CACHE_UPLOAD") == "" {
		token := os.Getenv("GRABIT_ARTIFACTORY_TOKEN")
		if token != "" {
			if err := r.uploadToCache(dir, ctx); err != nil {
				log.Debug().Err(err).Msg("Failed to upload to cache")
			}
		}
	}

	return nil
}

func (r *Resource) downloadFromCache(dir string, mode os.FileMode, ctx context.Context) error {
	token := os.Getenv("GRABIT_ARTIFACTORY_TOKEN")
	if token == "" {
		return fmt.Errorf("GRABIT_ARTIFACTORY_TOKEN must be set for cache operations")
	}

	log.Debug().Str("cache", r.CacheUri).Msg("Attempting cache download")
	tempFile, err := downloadWithToken(r.CacheUri, dir, ctx, token)
	if err != nil {
		return err
	}

	if err := checkIntegrityFromFile(tempFile, "sha256", r.Integrity, r.CacheUri); err != nil {
		os.Remove(tempFile)
		log.Debug().Msg("Cache integrity validation failed")
		return err
	}

	return renameAndSetPermission(tempFile, filepath.Join(dir, getLocalFileName(r.CacheUri)), mode)
}

func (r *Resource) downloadFromSource(dir string, mode os.FileMode, ctx context.Context) error {
	var lastErr error
	for _, u := range r.Urls {
		log.Debug().Str("url", u).Msg("Attempting download from source")
		tempFile, err := GetUrlToDir(u, dir, ctx)
		if err != nil {
			lastErr = err
			log.Debug().Err(err).Msg("Download failed, trying next URL")
			continue
		}

		if err := checkIntegrityFromFile(tempFile, "sha256", r.Integrity, u); err != nil {
			return err
		}

		localName := r.Filename
		if localName == "" {
			localName = path.Base(u)
		}

		return renameAndSetPermission(tempFile, filepath.Join(dir, localName), mode)
	}

	return fmt.Errorf("failed to download from any source: %v", lastErr)
}

func (r *Resource) uploadToCache(dir string, ctx context.Context) error {
	token := os.Getenv("GRABIT_ARTIFACTORY_TOKEN")
	if token == "" {
		return fmt.Errorf("GRABIT_ARTIFACTORY_TOKEN must be set for cache operations")
	}

	filePath := filepath.Join(dir, getLocalFileName(r.CacheUri))
	hash, err := GetFileHash(filePath)
	if err != nil {
		return err
	}

	// Clean the base URI and use hash as filename
	baseUri := strings.TrimSuffix(r.CacheUri, "/")
	cachePath := fmt.Sprintf("%s/%s", baseUri, hash)

	log.Debug().
		Str("cachePath", cachePath).
		Msg("Uploading to cache")

	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Use simple http.NewRequest for more control over the request
	req, err := http.NewRequest(http.MethodPut, cachePath, bytes.NewReader(fileData))
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

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("upload failed (status %d): %s", resp.StatusCode, string(body))
	}

	log.Debug().Str("path", cachePath).Msg("File uploaded to cache")
	return nil
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
