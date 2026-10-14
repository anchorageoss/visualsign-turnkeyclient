package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// zeroReader yields an endless stream of zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func writeTempResponse(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "response.json")
	require.NoError(t, os.WriteFile(path, body, 0o600))
	return path
}

func runVerifyResponse(t *testing.T, args ...string) error {
	t.Helper()
	return VerifyResponseCommand().Run(context.Background(), append([]string{"verify-response"}, args...))
}

func TestVerifyResponseCommandNeedsNoAPICredentials(t *testing.T) {
	cmd := VerifyResponseCommand()
	require.Equal(t, "verify-response", cmd.Name)

	required := map[string]bool{}
	for _, flag := range cmd.Flags {
		if f, ok := flag.(*cli.StringFlag); ok {
			required[f.Name] = f.Required
		}
	}
	require.True(t, required["response-file"])
	require.True(t, required["unsigned-payload"])
	for _, name := range []string{"host", "organization-id", "key-name"} {
		_, present := required[name]
		require.False(t, present, "verify-response must not take --%s", name)
	}
}

func TestVerifyResponseVerifiesCapturedNSMResponse(t *testing.T) {
	path := writeTempResponse(t, testdata.TVCResponseNSMJSON)
	err := runVerifyResponse(t,
		"--response-file", path,
		"--unsigned-payload", testdata.TVCResponseNSMUnsignedPayload,
	)
	require.NoError(t, err)
}

func TestVerifyResponseRejectsWrongRequestPayload(t *testing.T) {
	path := writeTempResponse(t, testdata.TVCResponseNSMJSON)
	err := runVerifyResponse(t, "--response-file", path, "--unsigned-payload", "0x02")
	require.Error(t, err)
	require.ErrorContains(t, err, "verification failed")
}

func TestVerifyResponseRejectsTamperedSignature(t *testing.T) {
	var captured struct {
		Response struct {
			ParsedTransaction struct {
				Signature struct {
					Signature string `json:"signature"`
				} `json:"signature"`
			} `json:"parsedTransaction"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(testdata.TVCResponseNSMJSON, &captured))
	sig := captured.Response.ParsedTransaction.Signature.Signature
	require.NotEmpty(t, sig)
	require.Contains(t, string(testdata.TVCResponseNSMJSON), sig)

	flipped := "0"
	if sig[len(sig)-1] == '0' {
		flipped = "1"
	}
	tampered := strings.Replace(string(testdata.TVCResponseNSMJSON), sig, sig[:len(sig)-1]+flipped, 1)

	err := runVerifyResponse(t,
		"--response-file", writeTempResponse(t, []byte(tampered)),
		"--unsigned-payload", testdata.TVCResponseNSMUnsignedPayload,
	)
	require.ErrorContains(t, err, "signature verification failed")
}

func TestVerifyResponseRejectsUnexpectedPCR(t *testing.T) {
	err := runVerifyResponse(t,
		"--response-file", writeTempResponse(t, testdata.TVCResponseNSMJSON),
		"--unsigned-payload", testdata.TVCResponseNSMUnsignedPayload,
		"--pcrs", "0:"+strings.Repeat("00", 48),
	)
	require.Error(t, err)
}

func TestVerifyResponseRejectsErrorResponse(t *testing.T) {
	err := runVerifyResponse(t,
		"--response-file", writeTempResponse(t, []byte(`{"error":"payment required"}`)),
		"--unsigned-payload", testdata.TVCResponseNSMUnsignedPayload,
	)
	require.ErrorContains(t, err, "payment required")
}

func TestReadResponseFile(t *testing.T) {
	path := writeTempResponse(t, []byte("hello"))
	got, err := readResponseFile(path, nil)
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))

	got, err = readResponseFile("-", bytes.NewReader([]byte("from stdin")))
	require.NoError(t, err)
	require.Equal(t, "from stdin", string(got))

	_, err = readResponseFile(filepath.Join(t.TempDir(), "missing.json"), nil)
	require.ErrorContains(t, err, "failed to open response file")

	_, err = readResponseFile("-", zeroReader{})
	require.ErrorContains(t, err, "response exceeds")
}
