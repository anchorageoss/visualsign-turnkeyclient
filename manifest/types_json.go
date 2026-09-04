package manifest

import "encoding/hex"

// This file mirrors QuorumOS's JSON-only "v2" manifest schema
// (qos_core::protocol::services::boot::manifest::v2), field for field. It is
// a separate schema from this package's Borsh-oriented Manifest/ManifestV1
// types: QOS's JSON manifest drops patch_set and adds dns and pivot.env, so
// decoding it into the existing Manifest struct would silently misplace or
// drop fields.
//
// These types are never decoded via encoding/json.Unmarshal directly; see
// parser_json.go for the strict, duplicate-key-detecting decoder. They exist
// so the decoded manifest can be re-serialized (via CanonicalizeValue) to
// compute the QOS canonical JSON hash that binds to attestation UserData.

// ManifestJSONV2 is the QuorumOS JSON manifest schema ("v2"). Every field
// name below is the exact camelCase wire name QuorumOS's serde
// rename_all = "camelCase" produces.
type ManifestJSONV2 struct {
	// Version must be the literal string "v2"; any other value, or an absent
	// version field, is rejected during decode.
	Version     string            `json:"version"`
	Namespace   NamespaceJSON     `json:"namespace"`
	Pivot       PivotConfigJSONV2 `json:"pivot"`
	ManifestSet ManifestSetJSON   `json:"manifestSet"`
	ShareSet    ShareSetJSON      `json:"shareSet"`
	Enclave     NitroConfigJSON   `json:"enclave"`
	Dns         *DnsConfigJSON    `json:"dns,omitempty"`
}

// ManifestEnvelopeJSONV2 wraps ManifestJSONV2 with approval signatures.
type ManifestEnvelopeJSONV2 struct {
	Manifest             ManifestJSONV2 `json:"manifest"`
	ManifestSetApprovals []ApprovalJSON `json:"manifestSetApprovals"`
	ShareSetApprovals    []ApprovalJSON `json:"shareSetApprovals"`
}

// NamespaceJSON mirrors qos_core's Namespace in JSON form.
type NamespaceJSON struct {
	Name  string `json:"name"`
	Nonce uint32 `json:"nonce"`
	// QuorumKey is a lowercase hex-encoded public key.
	QuorumKey HexBytes `json:"quorumKey"`
}

// PivotConfigJSONV2 mirrors qos_core's v2::PivotConfigV2.
type PivotConfigJSONV2 struct {
	// Hash is the pivot binary's SHA-256 digest, lowercase hex, 32 bytes.
	Hash         HexBytes           `json:"hash"`
	Restart      RestartPolicy      `json:"restart"`
	BridgeConfig []BridgeConfigJSON `json:"bridgeConfig"`
	DebugMode    bool               `json:"debugMode"`
	Args         []string           `json:"args"`
	// Env is omitted from the wire form entirely when empty, matching QoS's
	// PivotEnv::is_empty skip_serializing_if.
	Env map[string]PivotEnvValueJSON `json:"env,omitempty"`
}

// BridgeConfigJSON mirrors qos_core's externally-tagged BridgeConfig enum
// (tag = "type"), whose two variants both camelCase-rename to lowercase:
// "server" and "client".
type BridgeConfigJSON struct {
	Type string `json:"type"`
	Port uint16 `json:"port"`
	// Host is required for the "server" variant, optional for "client".
	Host *string `json:"host,omitempty"`
}

const (
	BridgeConfigTypeServer = "server"
	BridgeConfigTypeClient = "client"
)

// PivotEnvValueJSON mirrors qos_core's externally-tagged PivotEnvValue enum,
// which today has a single variant, "plain".
type PivotEnvValueJSON struct {
	Plain *PivotEnvPlainValueJSON `json:"plain,omitempty"`
}

// PivotEnvPlainValueJSON mirrors qos_core's PivotEnvValue::Plain payload.
type PivotEnvPlainValueJSON struct {
	Value string `json:"value"`
}

// ManifestSetJSON mirrors qos_core's ManifestSet in JSON form.
type ManifestSetJSON struct {
	Threshold uint32             `json:"threshold"`
	Members   []QuorumMemberJSON `json:"members"`
}

// ShareSetJSON mirrors qos_core's ShareSet in JSON form.
type ShareSetJSON struct {
	Threshold uint32             `json:"threshold"`
	Members   []QuorumMemberJSON `json:"members"`
}

// QuorumMemberJSON mirrors qos_core's QuorumMember in JSON form.
type QuorumMemberJSON struct {
	Alias string `json:"alias"`
	// PubKey is a lowercase hex-encoded P256 public key.
	PubKey HexBytes `json:"pubKey"`
}

// NitroConfigJSON mirrors qos_core's NitroConfig in JSON form. All byte
// fields are lowercase hex, matching QoS's qos_hex::serde adapter.
type NitroConfigJSON struct {
	Pcr0               HexBytes `json:"pcr0"`
	Pcr1               HexBytes `json:"pcr1"`
	Pcr2               HexBytes `json:"pcr2"`
	Pcr3               HexBytes `json:"pcr3"`
	AwsRootCertificate HexBytes `json:"awsRootCertificate"`
	QosCommit          string   `json:"qosCommit"`
}

// DnsConfigJSON mirrors qos_core's v2::DnsConfig.
type DnsConfigJSON struct {
	Resolvers []string `json:"resolvers"`
}

// ApprovalJSON mirrors qos_core's Approval in JSON form.
type ApprovalJSON struct {
	// Signature is a lowercase hex-encoded P256 signature.
	Signature HexBytes         `json:"signature"`
	Member    QuorumMemberJSON `json:"member"`
}

// HexBytes is a byte slice that marshals as a lowercase hex string, matching
// QoS's #[serde(with = "qos_hex::serde")] byte fields. Decoding from JSON
// happens exclusively through parser_json.go's strict decoder (which
// validates hex strictly: even length, lowercase only); MarshalJSON exists
// so a decoded ManifestJSONV2 can be re-serialized for canonical hashing.
type HexBytes []byte

// MarshalJSON implements json.Marshaler.
func (h HexBytes) MarshalJSON() ([]byte, error) {
	dst := make([]byte, 2+hex.EncodedLen(len(h)))
	dst[0] = '"'
	dst[len(dst)-1] = '"'
	hex.Encode(dst[1:], h)
	return dst, nil
}
