// Package manifest provides types and parsing functions for QoS (QuorumOS) manifests.
//
// Manifests are Borsh-encoded security policies for AWS Nitro Enclaves running QuorumOS.
// They define the enclave's configuration, including binary hashes, PCR values, and
// quorum members authorized to update the manifest.
//
// # Manifest Structure
//
// A manifest contains:
//   - Namespace: Organization and application identifier
//   - Pivot: Binary hash and restart policy
//   - ManifestSet: Quorum members who can update the manifest
//   - ShareSet: Members holding key shares
//   - Enclave: Expected PCR values for attestation verification
//   - PatchSet: Members authorized to apply patches
//
// # Parsing
//
// Decode manifests using DecodeRawManifestFromBase64 or DecodeManifestEnvelopeFromFile:
//
//	manifest, manifestBytes, err := manifest.DecodeRawManifestFromBase64(base64String, manifest.V2)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Compute manifest hash and compare against attestation UserData:
//
//	hash := manifest.ComputeHash(manifestBytes)
//
// # Validation
//
// The manifest hash in the attestation's UserData field proves that the enclave is
// running the correct QuorumOS configuration. See README for detailed validation steps.
package manifest

import (
	"fmt"

	"github.com/near/borsh-go"
)

// RestartPolicy enum matching the Rust definition
type RestartPolicy uint8

const (
	RestartPolicyNever RestartPolicy = iota
	RestartPolicyAlways
)

// MarshalJSON converts RestartPolicy to JSON string format matching qos_client
func (r RestartPolicy) MarshalJSON() ([]byte, error) {
	switch r {
	case RestartPolicyNever:
		return []byte(`"Never"`), nil
	case RestartPolicyAlways:
		return []byte(`"Always"`), nil
	default:
		return []byte(fmt.Sprintf(`"Unknown(%d)"`, uint8(r))), nil
	}
}

// String converts RestartPolicy to string format
func (r RestartPolicy) String() string {
	switch r {
	case RestartPolicyNever:
		return "Never"
	case RestartPolicyAlways:
		return "Always"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(r))
	}
}

type Hash256 [32]byte

type Namespace struct {
	Name      string `borsh:"name"`
	Nonce     uint32 `borsh:"nonce"`
	QuorumKey []byte `borsh:"quorum_key"`
}

type NitroConfig struct {
	Pcr0               []byte `borsh:"pcr0"`
	Pcr1               []byte `borsh:"pcr1"`
	Pcr2               []byte `borsh:"pcr2"`
	Pcr3               []byte `borsh:"pcr3"`
	AwsRootCertificate []byte `borsh:"aws_root_certificate"`
	QosCommit          string `borsh:"qos_commit"`
}

// BridgeConfig is a Borsh enum (Rust tagged union) with variants:
//
//	0 = Server { port: u16, host: String }
//	1 = Client { port: u16, host: String }
type BridgeConfig struct {
	Enum   borsh.Enum `borsh_enum:"true" json:"-"`
	Server BridgeConfigServer
	Client BridgeConfigClient
}

type BridgeConfigServer struct {
	Port uint16 `borsh:"port" json:"port"`
	Host string `borsh:"host" json:"host"`
}

type BridgeConfigClient struct {
	Port uint16 `borsh:"port" json:"port"`
	Host string `borsh:"host" json:"host"`
}

type PivotConfig struct {
	Hash         Hash256        `borsh:"hash"`          // fixed 32 bytes
	Restart      RestartPolicy  `borsh:"restart"`       // enum as u8
	BridgeConfig []BridgeConfig `borsh:"bridge_config"` // v2: before args
	DebugMode    bool           `borsh:"debug_mode"`    // v2: before args
	Args         []string       `borsh:"args"`          // moved after bridge_config & debug_mode
}

type QuorumMember struct {
	Alias  string `borsh:"alias"`
	PubKey []byte `borsh:"pub_key"`
}

type ManifestSet struct {
	Threshold uint32         `borsh:"threshold"`
	Members   []QuorumMember `borsh:"members"`
}

type ShareSet struct {
	Threshold uint32         `borsh:"threshold"`
	Members   []QuorumMember `borsh:"members"`
}

type MemberPubKey struct {
	PubKey []byte `borsh:"pub_key"`
}

type PatchSet struct {
	Threshold uint32         `borsh:"threshold"`
	Members   []MemberPubKey `borsh:"members"`
}

type Manifest struct {
	Namespace   Namespace   `borsh:"namespace"`
	Pivot       PivotConfig `borsh:"pivot"`
	ManifestSet ManifestSet `borsh:"manifest_set"`
	ShareSet    ShareSet    `borsh:"share_set"`
	Enclave     NitroConfig `borsh:"enclave"`
	PatchSet    PatchSet    `borsh:"patch_set"`
}

// Approval structures for manifest envelope
type Approval struct {
	Signature []byte       `borsh:"signature"`
	Member    QuorumMember `borsh:"member"`
}

// ManifestEnvelope wraps the manifest with approval signatures
type ManifestEnvelope struct {
	Manifest             Manifest   `borsh:"manifest"`
	ManifestSetApprovals []Approval `borsh:"manifest_set_approvals"`
	ShareSetApprovals    []Approval `borsh:"share_set_approvals"`
}

// ManifestVersion indicates which Borsh layout to use for deserialization.
type ManifestVersion int

const (
	// ManifestVersionUnknown indicates that no manifest version was explicitly selected.
	ManifestVersionUnknown ManifestVersion = iota
	// V1 is the legacy layout (v1 API): PivotConfig has hash, restart, args only.
	V1
	// V2 is the current layout (v2 API): PivotConfig has hash, restart, bridge_config, debug_mode, args.
	V2
)

// --- V1 types for backward compatibility with v1 API ---

// PivotConfigV1 is the legacy pivot config: hash, restart, args (no bridge_config or debug_mode)
type PivotConfigV1 struct {
	Hash    Hash256       `borsh:"hash"`
	Restart RestartPolicy `borsh:"restart"`
	Args    []string      `borsh:"args"`
}

// ManifestV1 uses PivotConfigV1 (legacy layout)
type ManifestV1 struct {
	Namespace   Namespace     `borsh:"namespace"`
	Pivot       PivotConfigV1 `borsh:"pivot"`
	ManifestSet ManifestSet   `borsh:"manifest_set"`
	ShareSet    ShareSet      `borsh:"share_set"`
	Enclave     NitroConfig   `borsh:"enclave"`
	PatchSet    PatchSet      `borsh:"patch_set"`
}

// ManifestEnvelopeV1 wraps ManifestV1 with approval signatures (legacy layout)
type ManifestEnvelopeV1 struct {
	Manifest             ManifestV1 `borsh:"manifest"`
	ManifestSetApprovals []Approval `borsh:"manifest_set_approvals"`
	ShareSetApprovals    []Approval `borsh:"share_set_approvals"`
}

// ToManifest converts a legacy ManifestV1 to the current Manifest type
func (v1 *ManifestV1) ToManifest() Manifest {
	return Manifest{
		Namespace: v1.Namespace,
		Pivot: PivotConfig{
			Hash:    v1.Pivot.Hash,
			Restart: v1.Pivot.Restart,
			Args:    v1.Pivot.Args,
		},
		ManifestSet: v1.ManifestSet,
		ShareSet:    v1.ShareSet,
		Enclave:     v1.Enclave,
		PatchSet:    v1.PatchSet,
	}
}

// ToManifestEnvelope converts a legacy ManifestEnvelopeV1 to the current ManifestEnvelope type
func (v1 *ManifestEnvelopeV1) ToManifestEnvelope() ManifestEnvelope {
	m := v1.Manifest.ToManifest()
	return ManifestEnvelope{
		Manifest:             m,
		ManifestSetApprovals: v1.ManifestSetApprovals,
		ShareSetApprovals:    v1.ShareSetApprovals,
	}
}
