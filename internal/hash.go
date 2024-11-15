// Copyright (c) 2023 Cisco Systems, Inc. and its affiliates
// All rights reserved.
package internal

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

// Constants for hash formats
const (
	FormatSRI    = "SRI"
	FormatHex    = "HEX"
	FormatBase64 = "BASE64"
)

var (
	// Available hash algorithms
	algos = map[string]Hasher{
		"sha1":   sha1.New,
		"sha256": sha256.New,
		"sha384": sha512.New384,
		"sha512": sha512.New,
	}

	RecommendedAlgo = "sha256"
	allAlgos        string
)

// Hasher defines a function that returns a hash.Hash
type Hasher func() hash.Hash

// Hash struct encapsulates a hashing algorithm
type Hash struct {
	algo string
	hash Hasher
}

// Init initializes the available algorithms
func init() {
	initAlgoList()
}

// initAlgoList initializes the list of available algorithms
func initAlgoList() {
	algoNames := make([]string, 0, len(algos))
	foundRecommendedAlgo := false

	for algo := range algos {
		algoNames = append(algoNames, algo)
		if RecommendedAlgo == algo {
			foundRecommendedAlgo = true
		}
	}

	allAlgos = strings.Join(algoNames, ", ")
	if !foundRecommendedAlgo {
		panic(fmt.Sprintf("cannot find recommended algorithm '%s'", RecommendedAlgo))
	}
}

// NewHash creates a new Hash instance
func NewHash(algo string) (*Hash, error) {
	hash, ok := algos[algo]
	if !ok {
		return nil, fmt.Errorf("unknown hash algorithm '%s' (available: %s)", algo, allAlgos)
	}
	return &Hash{algo: algo, hash: hash}, nil
}

// getAuthToken retrieves the Artifactory token
func getAuthToken() (string, error) {
	token := os.Getenv("ARTIFACTORY_TOKEN")
	if token == "" {
		return "", fmt.Errorf("ARTIFACTORY_TOKEN is not set")
	}
	return "Bearer " + token, nil
}

// HashFormat represents the format of a hash string
type HashFormat struct {
	Format    string
	Algorithm string
	Value     string
}

// ParseHash parses a hash string into its components
func ParseHash(hash string) (*HashFormat, error) {
	// Check for SRI format
	if strings.Contains(hash, "-") {
		parts := strings.SplitN(hash, "-", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid SRI format")
		}
		return &HashFormat{
			Format:    FormatSRI,
			Algorithm: parts[0],
			Value:     parts[1],
		}, nil
	}

	// Determine format based on content
	if len(hash) == 64 && isHex(hash) {
		return &HashFormat{
			Format:    FormatHex,
			Algorithm: RecommendedAlgo,
			Value:     hash,
		}, nil
	}

	if isBase64(hash) {
		return &HashFormat{
			Format:    FormatBase64,
			Algorithm: RecommendedAlgo,
			Value:     hash,
		}, nil
	}

	return nil, fmt.Errorf("unknown hash format")
}

// NormalizeHash converts any hash format to SRI format
func NormalizeHash(hash string) (string, error) {
	format, err := ParseHash(hash)
	if err != nil {
		return "", fmt.Errorf("failed to parse hash: %w", err)
	}

	switch format.Format {
	case FormatSRI:
		return hash, nil
	case FormatHex:
		decoded, err := hex.DecodeString(format.Value)
		if err != nil {
			return "", fmt.Errorf("invalid hex hash: %w", err)
		}
		b64 := base64.StdEncoding.EncodeToString(decoded)
		return fmt.Sprintf("%s-%s", format.Algorithm, b64), nil
	case FormatBase64:
		return fmt.Sprintf("%s-%s", format.Algorithm, format.Value), nil
	default:
		return "", fmt.Errorf("unsupported hash format")
	}
}

// CompareHash compares two hashes in any format
func (h *Hash) CompareHash(expected string, actual []byte) (bool, error) {
	// Normalize expected hash
	expectedNorm, err := NormalizeHash(expected)
	if err != nil {
		return false, fmt.Errorf("invalid expected hash: %w", err)
	}

	// Compute actual hash
	hasher := h.hash()
	hasher.Write(actual)
	actualBytes := hasher.Sum(nil)
	actualB64 := base64.StdEncoding.EncodeToString(actualBytes)
	actualSRI := fmt.Sprintf("%s-%s", h.algo, actualB64)

	return expectedNorm == actualSRI, nil
}

// VerifyFileIntegrity verifies a file's integrity
func (h *Hash) VerifyFileIntegrity(path string, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	match, err := h.CompareHash(expected, data)
	if err != nil {
		return fmt.Errorf("failed to compare hashes: %w", err)
	}

	if !match {
		return fmt.Errorf("integrity check failed")
	}

	return nil
}

// Helper functions
func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s)%2 == 0
}

func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}
