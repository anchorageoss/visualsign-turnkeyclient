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
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, &priv.PublicKey, priv)
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
