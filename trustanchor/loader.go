// Package trustanchor loads root trust-anchor certificates from a file, a
// directory of files, or a provided embedded default.
//
// Roots may be supplied as PEM ("CERTIFICATE" blocks), raw DER, or base64-encoded
// DER. Load returns the raw DER bytes for each root certificate found, in the
// order they were encountered.
package trustanchor

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// certExtensions are the file extensions recognized when loading a directory.
var certExtensions = map[string]bool{
	".pem":    true,
	".der":    true,
	".crt":    true,
	".base64": true,
}

// Load returns root certificates (as raw DER bytes, one slice per root) from,
// in order of precedence:
//  1. an explicit path — a single certificate file (.pem/.der/.crt/.base64) or
//     a directory containing such files; or
//  2. the provided embeddedDefault bytes (interpreted as a single file's
//     content: PEM, DER, or base64-DER).
//
// An empty path with a nil embeddedDefault returns an error. A non-existent
// path returns the underlying os.Stat error.
func Load(path string, embeddedDefault []byte) ([][]byte, error) {
	if path == "" {
		if len(embeddedDefault) == 0 {
			return nil, errors.New("trustanchor.Load: no path provided and no embedded default")
		}
		roots, err := decodeRoots(embeddedDefault)
		if err != nil {
			return nil, fmt.Errorf("trustanchor.Load: failed to decode embedded default: %w", err)
		}
		return roots, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("trustanchor.Load: %w", err)
	}

	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("trustanchor.Load: read directory %q: %w", path, err)
		}
		var roots [][]byte
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if !certExtensions[strings.ToLower(filepath.Ext(e.Name()))] {
				continue
			}
			data, err := os.ReadFile(filepath.Join(path, e.Name()))
			if err != nil {
				return nil, fmt.Errorf("trustanchor.Load: read %q: %w", e.Name(), err)
			}
			decoded, err := decodeRoots(data)
			if err != nil {
				return nil, fmt.Errorf("trustanchor.Load: decode %q: %w", e.Name(), err)
			}
			roots = append(roots, decoded...)
		}
		if len(roots) == 0 {
			return nil, fmt.Errorf("trustanchor.Load: no certificate files found in directory %q", path)
		}
		return roots, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trustanchor.Load: read %q: %w", path, err)
	}
	roots, err := decodeRoots(data)
	if err != nil {
		return nil, fmt.Errorf("trustanchor.Load: decode %q: %w", path, err)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("trustanchor.Load: no certificates found in %q", path)
	}
	return roots, nil
}

// decodeRoots decodes one or more certificates from a byte slice, accepting PEM
// (one or more CERTIFICATE blocks), raw DER, or base64-encoded DER. Returns the
// raw DER bytes for each certificate found.
func decodeRoots(data []byte) ([][]byte, error) {
	// PEM path: one or more CERTIFICATE blocks.
	if block, rest := pem.Decode(data); block != nil {
		var roots [][]byte
		if block.Type == "CERTIFICATE" {
			roots = append(roots, block.Bytes)
		}
		// Decode any remaining blocks.
		for {
			b, r := pem.Decode(rest)
			if b == nil {
				break
			}
			if b.Type == "CERTIFICATE" {
				roots = append(roots, b.Bytes)
			}
			rest = r
		}
		if len(roots) > 0 {
			return roots, nil
		}
	}

	// Base64 path: the whole blob decodes to DER. Try standard then URL encoding.
	if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil && looksLikeDER(dec) {
		return [][]byte{dec}, nil
	}
	if dec, err := base64.URLEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil && looksLikeDER(dec) {
		return [][]byte{dec}, nil
	}
	if dec, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil && looksLikeDER(dec) {
		return [][]byte{dec}, nil
	}

	// Raw DER path.
	if looksLikeDER(data) {
		return [][]byte{data}, nil
	}

	return nil, errors.New("unrecognized certificate encoding (expected PEM, DER, or base64-DER)")
}

// looksLikeDER applies a light heuristic: a DER SEQUENCE starts with 0x30.
func looksLikeDER(b []byte) bool {
	return len(b) > 0 && b[0] == 0x30
}
