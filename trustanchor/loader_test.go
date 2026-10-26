package trustanchor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// genKey returns an ephemeral ECDSA P-256 key for test certificate generation.
func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return priv
}

// selfSignedDER builds a real self-signed DER cert using an ephemeral ECDSA key.
func selfSignedDER(t *testing.T, cn string) []byte {
	t.Helper()
	priv := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	return der
}

// TestLoad_DERFile verifies a single DER file is loaded as one root.
func TestLoad_DERFile(t *testing.T) {
	der := selfSignedDER(t, "root.der")
	dir := t.TempDir()
	path := filepath.Join(dir, "root.der")
	require.NoError(t, os.WriteFile(path, der, 0644))

	roots, err := Load(path, nil)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.Equal(t, der, roots[0])
}

// TestLoad_PEMFile verifies a PEM-encoded certificate file is decoded to DER.
func TestLoad_PEMFile(t *testing.T) {
	der := selfSignedDER(t, "root.pem")
	dir := t.TempDir()
	path := filepath.Join(dir, "root.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644))

	roots, err := Load(path, nil)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.Equal(t, der, roots[0])
}

// TestLoad_Base64File verifies a base64-DER file is decoded to DER.
func TestLoad_Base64File(t *testing.T) {
	der := selfSignedDER(t, "root.base64")
	dir := t.TempDir()
	path := filepath.Join(dir, "root.base64")
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(der)), 0644))

	roots, err := Load(path, nil)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.Equal(t, der, roots[0])
}

// TestLoad_RawStdBase64File verifies an unpadded standard-base64 DER file
// is decoded to DER.
func TestLoad_RawStdBase64File(t *testing.T) {
	der := selfSignedDER(t, "root.rawstd")
	dir := t.TempDir()
	path := filepath.Join(dir, "root.base64")
	require.NoError(t, os.WriteFile(path, []byte(base64.RawStdEncoding.EncodeToString(der)), 0644))

	roots, err := Load(path, nil)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.Equal(t, der, roots[0])
}

// TestLoad_WrappedBase64File verifies a line-wrapped base64-DER file (as
// emitted by `base64` or `openssl base64`) is decoded to DER. Go's base64
// decoder skips \r and \n, so no extra whitespace handling is needed.
func TestLoad_WrappedBase64File(t *testing.T) {
	der := selfSignedDER(t, "root.wrapped")
	enc := base64.StdEncoding.EncodeToString(der)
	var wrapped strings.Builder
	for i := 0; i < len(enc); i += 64 {
		wrapped.WriteString(enc[i:min(i+64, len(enc))])
		wrapped.WriteString("\r\n")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "root.base64")
	require.NoError(t, os.WriteFile(path, []byte(wrapped.String()), 0644))

	roots, err := Load(path, nil)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.Equal(t, der, roots[0])
}

// TestLoad_RawURLBase64File verifies an unpadded URL-safe-base64 DER file
// is decoded to DER.
func TestLoad_RawURLBase64File(t *testing.T) {
	der := selfSignedDER(t, "root.rawurl")
	dir := t.TempDir()
	path := filepath.Join(dir, "root.base64")
	require.NoError(t, os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(der)), 0644))

	roots, err := Load(path, nil)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.Equal(t, der, roots[0])
}

// TestLoad_Directory verifies a directory of cert files loads all roots.
func TestLoad_Directory(t *testing.T) {
	der1 := selfSignedDER(t, "root1")
	der2 := selfSignedDER(t, "root2")
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.der"), der1, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der2}), 0644))
	// Non-cert file ignored.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("ignore me"), 0644))

	roots, err := Load(dir, nil)
	require.NoError(t, err)
	require.Len(t, roots, 2)

	// Order is not guaranteed; collect and compare as a set.
	got := map[string]bool{}
	for _, r := range roots {
		got[string(r)] = true
	}
	require.True(t, got[string(der1)])
	require.True(t, got[string(der2)])
}

// TestLoad_EmptyPathEmbeddedDefault verifies the embedded default is returned
// when path is empty.
func TestLoad_EmptyPathEmbeddedDefault(t *testing.T) {
	embedded := selfSignedDER(t, "embedded")
	roots, err := Load("", embedded)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.Equal(t, embedded, roots[0])
}

// TestLoad_NonexistentPath verifies a non-existent path (without a fallback)
// returns an error.
func TestLoad_NonexistentPath(t *testing.T) {
	_, err := Load("/this/does/not/exist", nil)
	require.Error(t, err)
}

// TestLoad_RejectsInvalidCertificates verifies that candidates which decode
// but do not parse as X.509 certificates are rejected, and that the error
// names the source.
func TestLoad_RejectsInvalidCertificates(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		content []byte
	}{
		{name: "raw DER 0x30", file: "root.der", content: []byte{0x30}},
		{name: "base64 MA==", file: "root.base64", content: []byte("MA==")},
		{
			name:    "PEM CERTIFICATE with garbage bytes",
			file:    "root.pem",
			content: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.file)
			require.NoError(t, os.WriteFile(path, tc.content, 0644))

			roots, err := Load(path, nil)
			require.Error(t, err)
			require.Nil(t, roots)
			require.Contains(t, err.Error(), path)

			roots, err = Load(dir, nil)
			require.Error(t, err)
			require.Nil(t, roots)
			require.Contains(t, err.Error(), tc.file)

			roots, err = Load("", tc.content)
			require.Error(t, err)
			require.Nil(t, roots)
			require.Contains(t, err.Error(), "embedded default")
		})
	}
}

// TestLoad_RejectsInvalidPEMAmongValid verifies a single invalid CERTIFICATE
// block fails the whole PEM bundle rather than being silently kept.
func TestLoad_RejectsInvalidPEMAmongValid(t *testing.T) {
	der := selfSignedDER(t, "good")
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30}})...)
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	require.NoError(t, os.WriteFile(path, bundle, 0644))

	_, err := Load(path, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), path)
}
