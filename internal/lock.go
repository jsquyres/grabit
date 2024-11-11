// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.
package internal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog/log"
)

// Keeping COMMENT_PREFIX as requested in review
const COMMENT_PREFIX = "//"

type Lock struct {
	path string
	conf config
}

type config struct {
	Resource []Resource
}

func NewLock(path string, newOk bool) (*Lock, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		if newOk {
			return &Lock{
				path: path,
				conf: config{Resource: []Resource{}},
			}, nil
		}
		return nil, fmt.Errorf("lock file '%s' does not exist", path)
	}

	var conf config
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := toml.NewDecoder(file).Decode(&conf); err != nil {
		return nil, err
	}

	return &Lock{path: path, conf: conf}, nil
}

func (l *Lock) AddResource(paths []string, algo string, tags []string, filename string) error {
	return l.AddResourceWithCache(paths, algo, tags, filename, "")
}

func (l *Lock) AddResourceWithCache(paths []string, algo string, tags []string, filename string, cacheUri string) error {
	// Check for duplicate resources
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
		return err
	}

	l.conf.Resource = append(l.conf.Resource, *r)
	return nil
}

func NewResourceFromUrlWithCache(paths []string, algo string, tags []string, filename string, cacheUri string) (*Resource, error) {
	r, err := NewResourceFromUrl(paths, algo, tags, filename)
	if err != nil {
		return nil, err
	}
	r.CacheUri = cacheUri
	return r, nil
}

func (l *Lock) DeleteResource(path string) {
	log.Debug().Str("path", path).Msg("Deleting resource")

	newResources := []Resource{}
	for _, r := range l.conf.Resource {
		if !r.Contains(path) {
			newResources = append(newResources, r)
		} else if r.Contains(path) && r.CacheUri != "" {
			token := os.Getenv("GRABIT_ARTIFACTORY_TOKEN")
			if token == "" {
				fmt.Println("Warning: Unable to delete from Artifcatory: GRABIT_ARTIFACTORY_TOKEN not set.")
				continue
			}
			err := deleteCache(r.CacheUri, token)
			if err != nil {
				fmt.Println("Warning: Unable to delete from Artifcatory:", err)
			}
		}
	}

	removed := len(l.conf.Resource) - len(newResources)
	l.conf.Resource = newResources

	log.Debug().Int("removed", removed).Msg("Resources deleted")
}

func deleteCache(url, token string) error {
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	return nil
}

const NoFileMode = os.FileMode(0)

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

func (l *Lock) Download(dir string, tags []string, notags []string, perm string) error {
	if stat, err := os.Stat(dir); err != nil || !stat.IsDir() {
		return fmt.Errorf("'%s' is not a directory", dir)
	}

	mode, err := strToFileMode(perm)
	if err != nil {
		return err
	}

	resources := l.filterResources(tags, notags)
	if len(resources) == 0 {
		return fmt.Errorf("no resources to download")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	return l.downloadResources(resources, dir, mode, ctx)
}

func (l *Lock) filterResources(tags, notags []string) []Resource {
	if len(tags) == 0 && len(notags) == 0 {
		return l.conf.Resource
	}

	var filtered []Resource
	for _, r := range l.conf.Resource {
		if hasAllTags(r.Tags, tags) && !hasAnyTag(r.Tags, notags) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func hasAllTags(resourceTags, requiredTags []string) bool {
	if len(requiredTags) == 0 {
		return true
	}

	for _, required := range requiredTags {
		found := false
		for _, tag := range resourceTags {
			if required == tag {
				found = true
				break
			}
		}
		if !found {
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

func (l *Lock) downloadResources(resources []Resource, dir string, mode os.FileMode, ctx context.Context) error {
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

func (l *Lock) Save() error {
	log.Debug().Str("path", l.path).Msg("Saving lock file")

	data, err := toml.Marshal(l.conf)
	if err != nil {
		return err
	}

	file, err := os.Create(l.path)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return err
	}

	log.Debug().Msg("Lock file saved")
	return nil
}

func (l *Lock) Contains(url string) bool {
	for _, r := range l.conf.Resource {
		if r.Contains(url) {
			return true
		}
	}
	return false
}
