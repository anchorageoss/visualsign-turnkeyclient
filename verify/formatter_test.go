package verify

import (
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
	"github.com/stretchr/testify/require"
)

func TestNewFormatter(t *testing.T) {
	formatter := NewFormatter()
	require.NotNil(t, formatter)
}

func TestFormatPCRValues(t *testing.T) {
	formatter := NewFormatter()

	t.Run("basic PCR formatting", func(t *testing.T) {
		pcrs := map[uint][]byte{
			0: {0x01, 0x02, 0x03},
			1: {0x04, 0x05, 0x06},
		}

		result := formatter.FormatPCRValues(pcrs, "Test PCRs", "")
		require.NotEmpty(t, result)
		require.Contains(t, result, "Test PCRs")
		require.Contains(t, result, "010203")
		require.Contains(t, result, "040506")
	})

	t.Run("empty PCRs", func(t *testing.T) {
		pcrs := map[uint][]byte{}
		result := formatter.FormatPCRValues(pcrs, "Empty PCRs", "")
		require.NotEmpty(t, result)
	})

	t.Run("with indent", func(t *testing.T) {
		pcrs := map[uint][]byte{
			0: {0xaa, 0xbb},
		}
		result := formatter.FormatPCRValues(pcrs, "Indented", "  ")
		require.Contains(t, result, "  ")
	})

	t.Run("zero PCR values", func(t *testing.T) {
		pcrs := map[uint][]byte{
			0: {0x00, 0x00, 0x00},
		}
		result := formatter.FormatPCRValues(pcrs, "Zeros", "")
		require.NotEmpty(t, result)
	})

	t.Run("PCR 3 with label", func(t *testing.T) {
		pcrs := map[uint][]byte{
			3: {0xaa, 0xbb, 0xcc},
		}
		result := formatter.FormatPCRValues(pcrs, "PCR3 Test", "")
		require.Contains(t, result, "Hash of the AWS Role")
		require.Contains(t, result, "aabbcc")
	})

	t.Run("PCR 4 with legacy label", func(t *testing.T) {
		pcrs := map[uint][]byte{
			4: {0x11, 0x22, 0x33},
		}
		result := formatter.FormatPCRValues(pcrs, "PCR4 Test", "")
		require.Contains(t, result, "legacy")
		require.Contains(t, result, "112233")
	})

	t.Run("consecutive all-zero PCRs", func(t *testing.T) {
		zeroPCR := make([]byte, 48) // All zeros
		pcrs := map[uint][]byte{
			5:  zeroPCR,
			6:  zeroPCR,
			7:  zeroPCR,
			10: {0xaa}, // Non-zero
		}
		result := formatter.FormatPCRValues(pcrs, "Zero Range", "")
		require.Contains(t, result, "all zeros")
		require.Contains(t, result, "PCR[10]")
		require.Contains(t, result, "aa")
	})

	t.Run("all PCR types", func(t *testing.T) {
		pcrs := map[uint][]byte{
			0:  {0x01},
			1:  {0x02},
			2:  {0x03},
			3:  {0x04},
			4:  {0x05},
			15: {0x0f},
		}
		result := formatter.FormatPCRValues(pcrs, "All Types", "  ")
		require.Contains(t, result, "QoS hash")
		require.Contains(t, result, "Hash of the AWS Role")
		require.Contains(t, result, "legacy")
		require.Contains(t, result, "  ")
	})
}

func TestFormatManifest(t *testing.T) {
	formatter := NewFormatter()

	t.Run("basic manifest", func(t *testing.T) {
		m := &manifest.Manifest{
			Namespace: manifest.Namespace{
				Name:  "test",
				Nonce: 1,
			},
			Pivot: manifest.PivotConfig{
				Restart: manifest.RestartPolicyNever,
				Args:    []string{},
			},
			ManifestSet: manifest.ManifestSet{
				Threshold: 2,
				Members:   []manifest.QuorumMember{},
			},
			ShareSet: manifest.ShareSet{
				Threshold: 3,
				Members:   []manifest.QuorumMember{},
			},
		}

		result := formatter.FormatManifest(m)
		require.NotEmpty(t, result)
		require.Contains(t, result, "test")
		require.Contains(t, result, "threshold: 2")
		require.Contains(t, result, "threshold: 3")
	})

	t.Run("manifest with members", func(t *testing.T) {
		longPubKey := make([]byte, 33) // Longer than 16 chars when hex encoded
		for i := range longPubKey {
			longPubKey[i] = byte(i)
		}

		m := &manifest.Manifest{
			Namespace: manifest.Namespace{
				Name:      "production",
				Nonce:     42,
				QuorumKey: []byte{0xaa, 0xbb},
			},
			Pivot: manifest.PivotConfig{
				Hash:    [32]byte{0x01, 0x02},
				Restart: manifest.RestartPolicyAlways,
				Args:    []string{"--verbose", "--port=8080"},
			},
			ManifestSet: manifest.ManifestSet{
				Threshold: 2,
				Members: []manifest.QuorumMember{
					{Alias: "member1", PubKey: longPubKey},
					{Alias: "member2", PubKey: []byte{0x11, 0x22}},
				},
			},
			ShareSet: manifest.ShareSet{
				Threshold: 3,
				Members: []manifest.QuorumMember{
					{Alias: "share1", PubKey: []byte{0x33}},
				},
			},
			Enclave: manifest.NitroConfig{
				Pcr0:      []byte{0xaa},
				Pcr1:      []byte{0xbb},
				Pcr2:      []byte{0xcc},
				Pcr3:      []byte{0xdd},
				QosCommit: "abc123",
			},
		}

		result := formatter.FormatManifest(m)
		require.NotEmpty(t, result)
		require.Contains(t, result, "production")
		require.Contains(t, result, "42")
		require.Contains(t, result, "member1")
		require.Contains(t, result, "member2")
		require.Contains(t, result, "share1")
		require.Contains(t, result, "...") // Truncated long pub key
		require.Contains(t, result, "abc123")
		require.Contains(t, result, "--verbose")
		require.Contains(t, result, "Always")
	})
}

func TestFormatMembers(t *testing.T) {
	formatter := NewFormatter()

	t.Run("format quorum members", func(t *testing.T) {
		members := []manifest.QuorumMember{
			{Alias: "member1", PubKey: []byte{0x01, 0x02}},
			{Alias: "member2", PubKey: []byte{0x03, 0x04}},
		}

		result := formatter.FormatMembers(members)
		require.Len(t, result, 2)
		require.Equal(t, "member1", result[0]["alias"])
		require.Equal(t, "0102", result[0]["pubKey"])
	})

	t.Run("empty members", func(t *testing.T) {
		members := []manifest.QuorumMember{}
		result := formatter.FormatMembers(members)
		require.Len(t, result, 0)
	})
}

func TestFormatPatchMembers(t *testing.T) {
	formatter := NewFormatter()

	t.Run("format patch members", func(t *testing.T) {
		members := []manifest.MemberPubKey{
			{PubKey: []byte{0xaa, 0xbb}},
			{PubKey: []byte{0xcc, 0xdd}},
		}

		result := formatter.FormatPatchMembers(members)
		require.Len(t, result, 2)
		require.Equal(t, "aabb", result[0]["pubKey"])
		require.Equal(t, "ccdd", result[1]["pubKey"])
	})

	t.Run("empty members", func(t *testing.T) {
		members := []manifest.MemberPubKey{}
		result := formatter.FormatPatchMembers(members)
		require.Len(t, result, 0)
	})
}

func TestFormatApprovals(t *testing.T) {
	formatter := NewFormatter()

	t.Run("format approvals", func(t *testing.T) {
		approvals := []manifest.Approval{
			{
				Signature: []byte{0x11, 0x22},
				Member:    manifest.QuorumMember{Alias: "approver1", PubKey: []byte{0x33, 0x44}},
			},
		}

		result := formatter.FormatApprovals(approvals)
		require.Len(t, result, 1)
		require.Equal(t, "1122", result[0]["signature"])
		memberMap := result[0]["member"].(map[string]string)
		require.Equal(t, "approver1", memberMap["alias"])
	})

	t.Run("empty approvals", func(t *testing.T) {
		approvals := []manifest.Approval{}
		result := formatter.FormatApprovals(approvals)
		require.Len(t, result, 0)
	})
}

func TestFormatVerificationResult(t *testing.T) {
	formatter := NewFormatter()

	t.Run("basic verification result", func(t *testing.T) {
		result := &VerifyResult{
			AttestationValid: true,
			SignablePayload:  "test-payload",
			PublicKeyHex:     "pubkey",
			SignatureHex:     "signature",
			MessageHex:       "message",
			ModuleID:         "module-123",
			PCRs: map[uint][]byte{
				0: {0x01},
			},
		}

		formatted := formatter.FormatVerificationResult(result)
		require.NotNil(t, formatted)
		require.Equal(t, true, formatted["attestationValid"])
		require.Equal(t, "test-payload", formatted["signablePayload"])
		require.Equal(t, "pubkey", formatted["publicKey"])
	})

	t.Run("verification result with QoS manifest", func(t *testing.T) {
		result := &VerifyResult{
			AttestationValid: true,
			SignablePayload:  "test-payload",
			PublicKeyHex:     "pubkey",
			SignatureHex:     "signature",
			MessageHex:       "message",
			ModuleID:         "module-123",
			QosManifestHash:  "abc123",
			PivotBinaryHash:  "def456",
		}

		formatted := formatter.FormatVerificationResult(result)
		require.NotNil(t, formatted)
		require.Equal(t, "abc123", formatted["qosManifest"])
		require.Equal(t, "def456", formatted["pivotBinaryHash"])
	})

	t.Run("verification result with PCR4", func(t *testing.T) {
		result := &VerifyResult{
			AttestationValid: true,
			SignablePayload:  "test-payload",
			PublicKeyHex:     "pubkey",
			SignatureHex:     "signature",
			MessageHex:       "message",
			ModuleID:         "module-123",
			PCR4:             "pcr4value",
		}

		formatted := formatter.FormatVerificationResult(result)
		require.NotNil(t, formatted)
		require.Equal(t, "pcr4value", formatted["pcr4"])
	})
}

func TestFormatManifestJSON(t *testing.T) {
	formatter := NewFormatter()

	t.Run("basic manifest JSON", func(t *testing.T) {
		m := &manifest.Manifest{
			Namespace: manifest.Namespace{
				Name:  "json-test",
				Nonce: 42,
			},
			Pivot: manifest.PivotConfig{
				Restart: manifest.RestartPolicyAlways,
			},
			ManifestSet: manifest.ManifestSet{
				Threshold: 1,
			},
		}

		result := formatter.FormatManifestJSON(m)
		require.NotNil(t, result)

		namespace := result["namespace"].(map[string]interface{})
		require.Equal(t, "json-test", namespace["name"])
		require.Equal(t, uint32(42), namespace["nonce"])
	})
}

func TestFormatManifestEnvelopeJSON(t *testing.T) {
	formatter := NewFormatter()

	t.Run("basic envelope JSON", func(t *testing.T) {
		env := &manifest.ManifestEnvelope{
			Manifest: manifest.Manifest{
				Namespace: manifest.Namespace{
					Name:  "envelope-test",
					Nonce: 99,
				},
			},
			ManifestSetApprovals: []manifest.Approval{},
		}

		result := formatter.FormatManifestEnvelopeJSON(env)
		require.NotNil(t, result)
		require.NotNil(t, result["manifest"])
	})

	t.Run("envelope with approvals", func(t *testing.T) {
		env := &manifest.ManifestEnvelope{
			Manifest: manifest.Manifest{
				Namespace: manifest.Namespace{Name: "test"},
			},
			ManifestSetApprovals: []manifest.Approval{
				{Signature: []byte{0xaa}, Member: manifest.QuorumMember{Alias: "signer"}},
			},
		}

		result := formatter.FormatManifestEnvelopeJSON(env)
		require.NotNil(t, result)
		approvals := result["manifestSetApprovals"].([]map[string]interface{})
		require.Len(t, approvals, 1)
	})
}

func TestFormatPCRValidationResults(t *testing.T) {
	formatter := NewFormatter()

	t.Run("empty results", func(t *testing.T) {
		result := formatter.FormatPCRValidationResults(nil, "")
		require.Empty(t, result)
	})

	t.Run("single pass", func(t *testing.T) {
		results := []PCRValidationResult{
			{Index: 0, Expected: "aabb", Actual: "aabb", Valid: true},
		}
		output := formatter.FormatPCRValidationResults(results, "")
		require.Contains(t, output, "PASS")
		require.Contains(t, output, "PCR[0]")
	})

	t.Run("single fail", func(t *testing.T) {
		results := []PCRValidationResult{
			{Index: 1, Expected: "aabb", Actual: "ccdd", Valid: false},
		}
		output := formatter.FormatPCRValidationResults(results, "")
		require.Contains(t, output, "FAIL")
		require.Contains(t, output, "PCR[1]")
	})

	t.Run("mixed results", func(t *testing.T) {
		results := []PCRValidationResult{
			{Index: 0, Expected: "aa", Actual: "aa", Valid: true},
			{Index: 2, Expected: "bb", Actual: "cc", Valid: false},
		}
		output := formatter.FormatPCRValidationResults(results, "  ")
		require.Contains(t, output, "PASS")
		require.Contains(t, output, "FAIL")
	})
}

func TestFormatVerificationResult_WithPCRValidations(t *testing.T) {
	formatter := NewFormatter()

	result := &VerifyResult{
		AttestationValid: true,
		SignablePayload:  "payload",
		PublicKeyHex:     "pub",
		SignatureHex:     "sig",
		MessageHex:       "msg",
		ModuleID:         "mod",
		SignatureValid:   true,
		Valid:            true,
		PCRValidationResults: []PCRValidationResult{
			{Index: 0, Expected: "aa", Actual: "aa", Valid: true},
		},
	}

	formatted := formatter.FormatVerificationResult(result)
	require.NotNil(t, formatted)

	validations, ok := formatted["pcrValidations"]
	require.True(t, ok)
	valSlice := validations.([]map[string]interface{})
	require.Len(t, valSlice, 1)
	require.Equal(t, uint(0), valSlice[0]["index"])
	require.Equal(t, true, valSlice[0]["valid"])
}
