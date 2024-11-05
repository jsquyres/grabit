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
	"os"
	"strings"
)

// getAuthToken retrieves the ARTIFACTORY_TOKEN from environment variables.
// Returns the token with "Bearer" prefix or an error if the token is not set.
func getAuthToken() (string, error) {
	token := os.Getenv("ARTIFACTORY_TOKEN")
	if token == "" {
		return "", fmt.Errorf("ARTIFACTORY_TOKEN is not set")
	}
	return "Bearer " + token, nil
}

var algos = map[string]Hasher{
	"sha1":   sha1.New,
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

var RecommendedAlgo = "sha256"

// Hasher defines a function that returns a hash.Hash.
type Hasher func() hash.Hash

// Hash struct encapsulates a hashing algorithm.
type Hash struct {
	algo string
	hash Hasher
}

// Initialize the available algorithms list.
var allAlgos string

// init initializes the list of available algorithms.
func init() {
	initAlgoList()
}

// initAlgoList initializes the list of available algorithms and verifies the recommended algorithm.
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

// NewHash creates a new Hash instance with the specified algorithm.
func NewHash(algo string) (*Hash, error) {
	hash, ok := algos[algo]
	if !ok {
		return nil, fmt.Errorf("unknown hash algorithm '%s' (available algorithms: %s)", algo, allAlgos)
	}
	return &Hash{algo: algo, hash: hash}, nil
}

// decodeIntegrity decodes a hash from a hex or base64 encoding, depending on its format.
func decodeIntegrity(integrity string) ([]byte, error) {
	// Detect encoding based on the integrity string length and prefix.
	if strings.HasPrefix(integrity, "sha256-") {
		// If it's prefixed with 'sha256-', treat it as base64 encoded (SRI format).
		base64Part := strings.TrimPrefix(integrity, "sha256-")
		return base64.StdEncoding.DecodeString(base64Part)
	} else if len(integrity) == 64 {
		// Treat as hex encoded hash (commonly used in sha256).
		return hex.DecodeString(integrity)
	} else if len(integrity) == 44 {
		// Treat as base64 encoded hash.
		return base64.StdEncoding.DecodeString(integrity)
	}
	return nil, fmt.Errorf("unknown integrity format: %s", integrity)
}

// CompareHash compares a provided integrity hash with a computed hash for verification.
func (h *Hash) CompareHash(integrity string, data []byte) (bool, error) {
	// Decode the integrity hash based on its format
	expectedHash, err := decodeIntegrity(integrity)
	if err != nil {
		return false, fmt.Errorf("failed to decode integrity hash: %w", err)
	}

	// Compute the actual hash for the provided data
	hasher := h.hash()
	hasher.Write(data)
	actualHash := hasher.Sum(nil)

	// Compare computed hash with the expected hash
	return string(actualHash) == string(expectedHash), nil
}
