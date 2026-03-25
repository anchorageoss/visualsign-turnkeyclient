package verify

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

// Formatter formats verification and manifest data for display
type Formatter struct{}

// NewFormatter creates a new formatter
func NewFormatter() *Formatter {
	return &Formatter{}
}

// FormatPCRValues formats PCR values with descriptive labels and proper formatting
func (f *Formatter) FormatPCRValues(pcrs map[uint][]byte, title string, indent string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "\n%s%s:\n", indent, title)

	// Helper function to check if PCR is all zeros
	isAllZeros := func(pcr []byte) bool {
		for _, b := range pcr {
			if b != 0 {
				return false
			}
		}
		return true
	}

	// PCR 0 and 1: QoS hash
	for idx := uint(0); idx <= 1; idx++ {
		if pcr, exists := pcrs[idx]; exists && len(pcr) > 0 {
			fmt.Fprintf(&sb, "%s    PCR[%d]: %s (QoS hash)\n", indent, idx, hex.EncodeToString(pcr))
		}
	}

	// PCR 2: General PCR
	if pcr, exists := pcrs[2]; exists && len(pcr) > 0 {
		fmt.Fprintf(&sb, "%s    PCR[2]: %s\n", indent, hex.EncodeToString(pcr))
	}

	// PCR 3: Hash of the AWS Role
	if pcr, exists := pcrs[3]; exists && len(pcr) > 0 {
		fmt.Fprintf(&sb, "%s    PCR[3]: %s (Hash of the AWS Role)\n", indent, hex.EncodeToString(pcr))
	}

	// PCR 4: Legacy
	if pcr, exists := pcrs[4]; exists && len(pcr) > 0 {
		fmt.Fprintf(&sb, "%s    PCR[4]: %s (legacy)\n", indent, hex.EncodeToString(pcr))
	}

	// PCR 5-15: Check if all are zeros and display accordingly
	var allZeroPCRs []uint
	var nonZeroPCRs []uint

	for idx := uint(5); idx <= 15; idx++ {
		if pcr, exists := pcrs[idx]; exists && len(pcr) > 0 {
			if isAllZeros(pcr) {
				allZeroPCRs = append(allZeroPCRs, idx)
			} else {
				nonZeroPCRs = append(nonZeroPCRs, idx)
			}
		}
	}

	// Display non-zero PCRs individually
	for _, idx := range nonZeroPCRs {
		if pcr, exists := pcrs[idx]; exists {
			fmt.Fprintf(&sb, "%s    PCR[%d]: %s\n", indent, idx, hex.EncodeToString(pcr))
		}
	}

	// Display all-zero PCRs as a range if there are any
	if len(allZeroPCRs) > 0 {
		zeroHash := "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

		for i := 0; i < len(allZeroPCRs); {
			start := allZeroPCRs[i]
			end := start

			// Find end of consecutive range
			for i+1 < len(allZeroPCRs) && allZeroPCRs[i+1] == end+1 {
				i++
				end = allZeroPCRs[i]
			}

			if start == end {
				fmt.Fprintf(&sb, "%s    PCR[%d]: %s (all zeros)\n", indent, start, zeroHash)
			} else {
				fmt.Fprintf(&sb, "%s    PCR[%d-%d]: %s (all zeros)\n", indent, start, end, zeroHash)
			}
			i++
		}
	}

	return sb.String()
}

// FormatManifest formats manifest details for display
func (f *Formatter) FormatManifest(m *manifest.Manifest) string {
	var sb strings.Builder

	sb.WriteString("Namespace:\n")
	fmt.Fprintf(&sb, "  Name: %s\n", m.Namespace.Name)
	fmt.Fprintf(&sb, "  Nonce: %d\n", m.Namespace.Nonce)
	fmt.Fprintf(&sb, "  Quorum Key: %s\n", hex.EncodeToString(m.Namespace.QuorumKey))

	sb.WriteString("\nPivot:\n")
	fmt.Fprintf(&sb, "  Hash: %s\n", hex.EncodeToString(m.Pivot.Hash[:]))
	fmt.Fprintf(&sb, "  Restart: %s\n", m.Pivot.Restart)
	fmt.Fprintf(&sb, "  Args: %v\n", m.Pivot.Args)

	fmt.Fprintf(&sb, "\nManifest Set (threshold: %d):\n", m.ManifestSet.Threshold)
	for i, member := range m.ManifestSet.Members {
		pubKeyStr := hex.EncodeToString(member.PubKey)
		if len(pubKeyStr) > 16 {
			pubKeyStr = pubKeyStr[:16] + "..."
		}
		fmt.Fprintf(&sb, "  Member %d: %s (%s)\n", i+1, member.Alias, pubKeyStr)
	}

	fmt.Fprintf(&sb, "\nShare Set (threshold: %d):\n", m.ShareSet.Threshold)
	for i, member := range m.ShareSet.Members {
		pubKeyStr := hex.EncodeToString(member.PubKey)
		if len(pubKeyStr) > 16 {
			pubKeyStr = pubKeyStr[:16] + "..."
		}
		fmt.Fprintf(&sb, "  Member %d: %s (%s)\n", i+1, member.Alias, pubKeyStr)
	}

	sb.WriteString("\nEnclave:\n")
	fmt.Fprintf(&sb, "  PCR0: %s\n", hex.EncodeToString(m.Enclave.Pcr0))
	fmt.Fprintf(&sb, "  PCR1: %s\n", hex.EncodeToString(m.Enclave.Pcr1))
	fmt.Fprintf(&sb, "  PCR2: %s\n", hex.EncodeToString(m.Enclave.Pcr2))
	fmt.Fprintf(&sb, "  PCR3: %s\n", hex.EncodeToString(m.Enclave.Pcr3))
	fmt.Fprintf(&sb, "  QoS Commit: %s\n", m.Enclave.QosCommit)

	return sb.String()
}

// FormatMembers formats QuorumMember array for output
func (f *Formatter) FormatMembers(members []manifest.QuorumMember) []map[string]string {
	result := make([]map[string]string, len(members))
	for i, m := range members {
		result[i] = map[string]string{
			"alias":  m.Alias,
			"pubKey": hex.EncodeToString(m.PubKey),
		}
	}
	return result
}

// FormatPatchMembers formats MemberPubKey array for output
func (f *Formatter) FormatPatchMembers(members []manifest.MemberPubKey) []map[string]string {
	result := make([]map[string]string, len(members))
	for i, m := range members {
		result[i] = map[string]string{
			"pubKey": hex.EncodeToString(m.PubKey),
		}
	}
	return result
}

// FormatApprovals formats Approval array for output
func (f *Formatter) FormatApprovals(approvals []manifest.Approval) []map[string]interface{} {
	result := make([]map[string]interface{}, len(approvals))
	for i, approval := range approvals {
		result[i] = map[string]interface{}{
			"signature": hex.EncodeToString(approval.Signature),
			"member": map[string]string{
				"alias":  approval.Member.Alias,
				"pubKey": hex.EncodeToString(approval.Member.PubKey),
			},
		}
	}
	return result
}

// FormatPCRValidationResults formats PCR validation results for display
func (f *Formatter) FormatPCRValidationResults(results []PCRValidationResult, indent string) string {
	if len(results) == 0 {
		return ""
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "\n%sPCR Validation Results:\n", indent)

	for _, result := range results {
		status := "✅ PASS"
		if !result.Valid {
			status = "❌ FAIL"
		}

		fmt.Fprintf(&sb, "%s  PCR[%d]: %s\n", indent, result.Index, status)
		fmt.Fprintf(&sb, "%s    Expected: %s\n", indent, result.Expected)
		fmt.Fprintf(&sb, "%s    Actual:   %s\n", indent, result.Actual)
	}

	return sb.String()
}

// FormatVerificationResult formats a verification result for display
func (f *Formatter) FormatVerificationResult(result *VerifyResult) map[string]interface{} {
	output := map[string]interface{}{
		"valid":            result.Valid,
		"attestationValid": result.AttestationValid,
		"signatureValid":   result.SignatureValid,
		"moduleId":         result.ModuleID,
		"publicKey":        result.PublicKeyHex,
		"signablePayload":  result.SignablePayload,
		"message":          result.MessageHex,
		"signature":        result.SignatureHex,
	}

	// Add optional fields if present
	if result.QosManifestHash != "" {
		output["qosManifest"] = result.QosManifestHash
		output["pivotBinaryHash"] = result.PivotBinaryHash
	}

	if result.PCR4 != "" {
		output["pcr4"] = result.PCR4
	}

	// Add PCR validation results if present
	if len(result.PCRValidationResults) > 0 {
		pcrResults := make([]map[string]interface{}, len(result.PCRValidationResults))
		for i, pcr := range result.PCRValidationResults {
			pcrResults[i] = map[string]interface{}{
				"index":    pcr.Index,
				"expected": pcr.Expected,
				"actual":   pcr.Actual,
				"valid":    pcr.Valid,
			}
		}
		output["pcrValidations"] = pcrResults
	}

	return output
}

// FormatManifestJSON formats manifest for JSON output
func (f *Formatter) FormatManifestJSON(m *manifest.Manifest) map[string]interface{} {
	return map[string]interface{}{
		"namespace": map[string]interface{}{
			"name":      m.Namespace.Name,
			"nonce":     m.Namespace.Nonce,
			"quorumKey": hex.EncodeToString(m.Namespace.QuorumKey),
		},
		"pivot": map[string]interface{}{
			"hash":    hex.EncodeToString(m.Pivot.Hash[:]),
			"restart": m.Pivot.Restart,
			"args":    m.Pivot.Args,
		},
		"manifestSet": map[string]interface{}{
			"threshold": m.ManifestSet.Threshold,
			"members":   f.FormatMembers(m.ManifestSet.Members),
		},
		"shareSet": map[string]interface{}{
			"threshold": m.ShareSet.Threshold,
			"members":   f.FormatMembers(m.ShareSet.Members),
		},
		"enclave": map[string]interface{}{
			"pcr0":               hex.EncodeToString(m.Enclave.Pcr0),
			"pcr1":               hex.EncodeToString(m.Enclave.Pcr1),
			"pcr2":               hex.EncodeToString(m.Enclave.Pcr2),
			"pcr3":               hex.EncodeToString(m.Enclave.Pcr3),
			"awsRootCertificate": hex.EncodeToString(m.Enclave.AwsRootCertificate),
			"qosCommit":          m.Enclave.QosCommit,
		},
		"patchSet": map[string]interface{}{
			"threshold": m.PatchSet.Threshold,
			"members":   f.FormatPatchMembers(m.PatchSet.Members),
		},
	}
}

// FormatManifestEnvelopeJSON formats manifest envelope for JSON output
func (f *Formatter) FormatManifestEnvelopeJSON(env *manifest.ManifestEnvelope) map[string]interface{} {
	return map[string]interface{}{
		"manifest":             f.FormatManifestJSON(&env.Manifest),
		"manifestSetApprovals": f.FormatApprovals(env.ManifestSetApprovals),
		"shareSetApprovals":    f.FormatApprovals(env.ShareSetApprovals),
	}
}
