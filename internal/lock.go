// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.

package internal

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog/log"
)

// Lock represents a grabit lockfile.
type Lock struct {
	path string
	conf config
}

type config struct {
	Resource []Resource
}

// NewLock creates a new lock file instance
func NewLock(path string, newOk bool) (*Lock, error) {
	_, error := os.Stat(path)
	if os.IsNotExist(error) {
		if newOk {
			return &Lock{path: path, conf: config{Resource: []Resource{}}}, nil
		} else {
			return nil, fmt.Errorf("file '%s' does not exist", path)
		}
	}

	var conf config
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := toml.NewDecoder(file)
	if err := d.Decode(&conf); err != nil {
		return nil, fmt.Errorf("failed to decode lock file: %w", err)
	}

	return &Lock{path: path, conf: conf}, nil
}

// AddResource adds a resource without cache
func (l *Lock) AddResource(paths []string, algo string, tags []string, filename string) error {
	return l.AddResourceWithCache(paths, algo, tags, filename, "")
}

// AddResourceWithCache adds a resource with cache
func (l *Lock) AddResourceWithCache(paths []string, algo string, tags []string, filename string, cacheUri string) error {
	for _, u := range paths {
		if l.Contains(u) {
			return fmt.Errorf("resource '%s' is already present", u)
		}
	}

	log.Debug().
		Strs("paths", paths).
		Str("algo", algo).
		Strs("tags", tags).
		Str("filename", filename).
		Str("cache_uri", cacheUri).
		Msg("Adding new resource")

	r, err := NewResourceFromUrlWithCache(paths, algo, tags, filename, cacheUri)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create resource")
		return fmt.Errorf("failed to create resource: %w", err)
	}

	l.conf.Resource = append(l.conf.Resource, *r)
	return nil
}

// NewResourceFromUrlWithCache creates a new Resource with cache URI
func NewResourceFromUrlWithCache(paths []string, algo string, tags []string, filename string, cacheUri string) (*Resource, error) {
	r, err := NewResourceFromUrl(paths, algo, tags, filename)
	if err != nil {
		return nil, err
	}
	r.CacheUri = cacheUri
	return r, nil
}

// DeleteResource removes a resource from the lock file
func (l *Lock) DeleteResource(path string) {
	log.Debug().Str("path", path).Msg("Deleting resource")

	newStatements := []Resource{}
	for _, r := range l.conf.Resource {
		if !r.Contains(path) {
			newStatements = append(newStatements, r)
		}
	}

	removed := len(l.conf.Resource) - len(newStatements)
	l.conf.Resource = newStatements

	log.Debug().Int("removed", removed).Msg("Resources deleted")
}

const NoFileMode = os.FileMode(0)

// strToFileMode converts a string to a os.FileMode
func strToFileMode(perm string) (os.FileMode, error) {
	if perm == "" {
		return NoFileMode, nil
	}
	parsed, err := strconv.ParseUint(perm, 8, 32)
	if err != nil {
		return NoFileMode, fmt.Errorf("invalid permission format: %w", err)
	}
	return os.FileMode(parsed), nil
}

// identifyHashFormat identifies the hash format
func identifyHashFormat(hash string) string {
	if strings.HasPrefix(hash, "sha256-") {
		return "SRI"
	} else if len(hash) == 64 {
		return "Hex"
	} else if len(hash) == 44 {
		return "Base64"
	}
	return "Unknown"
}

// convertHashToHex converts a given hash to Hex format for consistent comparison
func convertHashToHex(hash string) (string, error) {
	format := identifyHashFormat(hash)

	switch format {
	case "Hex":
		return hash, nil
	case "Base64":
		decoded, err := base64.StdEncoding.DecodeString(hash)
		if err != nil {
			return "", fmt.Errorf("failed to decode Base64 hash: %w", err)
		}
		return hex.EncodeToString(decoded), nil
	case "SRI":
		base64Part := strings.TrimPrefix(hash, "sha256-")
		decoded, err := base64.StdEncoding.DecodeString(base64Part)
		if err != nil {
			return "", fmt.Errorf("failed to decode SRI hash: %w", err)
		}
		return hex.EncodeToString(decoded), nil
	default:
		return "", fmt.Errorf("unknown hash format")
	}
}

// Download gets all the resources in this lock file
func (l *Lock) Download(dir string, tags []string, notags []string, perm string) error {
	// Validate directory
	if stat, err := os.Stat(dir); err != nil || !stat.IsDir() {
		return fmt.Errorf("'%s' is not a directory", dir)
	}

	// Parse permissions
	mode, err := strToFileMode(perm)
	if err != nil {
		return fmt.Errorf("'%s' is not a valid permission definition", perm)
	}

	// Filter resources
	filteredResources := l.filterResources(tags, notags)
	if len(filteredResources) == 0 {
		return fmt.Errorf("nothing to download")
	}

	// Download concurrently
	return l.downloadResources(filteredResources, dir, mode)
}

// filterResources filters resources based on tags
func (l *Lock) filterResources(tags, notags []string) []Resource {
	// Filter by required tags
	tagFiltered := l.filterByTags(tags)
	// Filter out excluded tags
	return l.filterByNotTags(tagFiltered, notags)
}

func (l *Lock) filterByTags(tags []string) []Resource {
	if len(tags) == 0 {
		return l.conf.Resource
	}

	filtered := []Resource{}
	for _, r := range l.conf.Resource {
		if hasAllTags(r.Tags, tags) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (l *Lock) filterByNotTags(resources []Resource, notags []string) []Resource {
	if len(notags) == 0 {
		return resources
	}

	filtered := []Resource{}
	for _, r := range resources {
		if !hasAnyTag(r.Tags, notags) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func hasAllTags(resourceTags, requiredTags []string) bool {
	for _, required := range requiredTags {
		hasTag := false
		for _, tag := range resourceTags {
			if required == tag {
				hasTag = true
				break
			}
		}
		if !hasTag {
			return false
		}
	}
	return true
}

func hasAnyTag(resourceTags, excludedTags []string) bool {
	for _, excluded := range excludedTags {
		for _, tag := range resourceTags {
			if excluded == tag {
				return true
			}
		}
	}
	return false
}

// downloadResources downloads resources concurrently
func (l *Lock) downloadResources(resources []Resource, dir string, mode os.FileMode) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	total := len(resources)
	errorCh := make(chan error, total)

	for _, r := range resources {
		resource := r
		go func() {
			errorCh <- resource.Download(dir, mode, ctx)
		}()
	}

	var errs []error
	success := 0

	for i := 0; i < total; i++ {
		if err := <-errorCh; err != nil {
			errs = append(errs, err)
		} else {
			success++
		}
	}

	log.Debug().
		Int("total", total).
		Int("success", success).
		Int("failed", len(errs)).
		Msg("Download operation completed")

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// Save persists the lock file to disk
func (l *Lock) Save() error {
	log.Debug().Str("path", l.path).Msg("Saving lock file")

	res, err := toml.Marshal(l.conf)
	if err != nil {
		return fmt.Errorf("failed to marshal lock file: %w", err)
	}

	file, err := os.Create(l.path)
	if err != nil {
		return fmt.Errorf("failed to create lock file: %w", err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	if _, err := w.Write(res); err != nil {
		return fmt.Errorf("failed to write lock file: %w", err)
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush lock file: %w", err)
	}

	log.Debug().Msg("Lock file saved successfully")
	return nil
}

// Contains checks if a URL exists in the lock file
func (l *Lock) Contains(url string) bool {
	for _, r := range l.conf.Resource {
		for _, u := range r.Urls {
			if url == u {
				return true
			}
		}
	}
	return false
}
