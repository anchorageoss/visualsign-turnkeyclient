package manifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"unicode"
)

const maxJSONEnvelopeBytes = 4 << 20 // 4 MiB

// maxJSONNestingDepth bounds the recursion depth of decodeStrictValue and its
// callers. encoding/json's Decoder.Token() streaming API (unlike Unmarshal)
// has no built-in nesting-depth cap, so without an explicit limit a deeply
// nested but otherwise small JSON document can overflow the goroutine stack.
// Real manifest envelopes nest a handful of levels deep; 64 is generous
// headroom.
const maxJSONNestingDepth = 64

// nitroPCRLen is the fixed byte length of an AWS Nitro Enclave PCR value
// (a SHA-384 digest). Unlike quorumKey/pubKey/signature, whose byte length
// varies with the key/signature algorithm in use, every Nitro PCR is always
// this length, so it's safe to enforce as a fixed-size field.
const nitroPCRLen = 48

// REVIEW NOTE: this hand-rolled decoding layer (decodeStrictJSON below, plus
// checkAllowedFields/allowedFieldSet and the decodeXxxJSON/decodeXxxField
// helpers later in this file) largely reimplements what encoding/json's
// Unmarshal + Decoder.DisallowUnknownFields() already does against the
// tagged structs in types_json.go. The one gap stdlib can't cover is
// duplicate-key rejection (see decodeStrictJSON's doc comment) — that part
// alone justifies a custom pass. Flagged by code review as worth shrinking
// to: json.Unmarshal with DisallowUnknownFields() into the tagged structs,
// a small post-unmarshal required-field/enum/hex validator, and a
// standalone duplicate-key token-scan pre-pass, so the wire schema has one
// source of truth instead of two (struct tags vs. the allowedFieldSet /
// requiredField string literals below). Prasanna is taking a first pass at
// this restructuring separately — not applied as part of this change.
type strictObject struct {
	keys   []string
	values map[string]any
}

// decodeStrictJSON decodes data into a generic value tree (nil, bool,
// json.Number, string, []any, or *strictObject), rejecting duplicate object
// keys at every nesting depth and any trailing data after the top-level
// value. Unlike encoding/json's Unmarshal into a map, which silently keeps
// the last value for a duplicate key, this is safe to use on a trust
// boundary: a manifest envelope with a duplicate key is rejected outright
// rather than silently picking one of the two values.
//
// REVIEW NOTE (confirmed follow-up, not fixed here): encoding/json's string
// tokenizer is more lenient than qos_json/serde_json. Verified empirically:
// an unpaired UTF-16 surrogate escape (e.g. "\ud800") and a raw invalid
// UTF-8 byte sequence embedded directly in a JSON string both decode
// successfully here, silently substituted with U+FFFD, where serde_json
// would reject the input outright. Since the decoded Go string (not the
// raw input) is what both this tool hashes (via re-canonicalization) and
// displays, this doesn't break the "what you see is what's hashed"
// property this package otherwise defends (see validateDisplaySafeString),
// but it is a real interop/strictness gap: this client can accept and
// verify an envelope that the actual QuorumOS reference implementation
// would refuse to parse at all. Fixing it means validating strict UTF-8
// and surrogate-pair correctness on the raw bytes before tokenizing, which
// is more than a one-line change. Prasanna is tracking this as a follow-up
// separately — not applied as part of this change.
func decodeStrictJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	value, err := decodeStrictValue(dec, tok, 1)
	if err != nil {
		return nil, err
	}

	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing data after JSON value")
		}
		return nil, err
	}
	return value, nil
}

func decodeStrictValue(dec *json.Decoder, tok json.Token, depth int) (any, error) {
	if depth > maxJSONNestingDepth {
		return nil, fmt.Errorf("JSON nesting depth exceeds limit of %d", maxJSONNestingDepth)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return decodeStrictObject(dec, depth)
		case '[':
			return decodeStrictArray(dec, depth)
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter %q", t)
		}
	case nil, bool, json.Number, string:
		return t, nil
	default:
		return nil, fmt.Errorf("unexpected JSON token %T", tok)
	}
}

func decodeStrictObject(dec *json.Decoder, depth int) (*strictObject, error) {
	obj := &strictObject{values: map[string]any{}}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("expected JSON object key, got %v", keyTok)
		}
		if _, exists := obj.values[key]; exists {
			return nil, fmt.Errorf("duplicate object key %q", key)
		}

		valueTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		value, err := decodeStrictValue(dec, valueTok, depth+1)
		if err != nil {
			return nil, err
		}

		obj.keys = append(obj.keys, key)
		obj.values[key] = value
	}
	if _, err := dec.Token(); err != nil { // consume closing '}'
		return nil, err
	}
	return obj, nil
}

func decodeStrictArray(dec *json.Decoder, depth int) ([]any, error) {
	arr := []any{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		value, err := decodeStrictValue(dec, tok, depth+1)
		if err != nil {
			return nil, err
		}
		arr = append(arr, value)
	}
	if _, err := dec.Token(); err != nil { // consume closing ']'
		return nil, err
	}
	return arr, nil
}

func requireObject(v any, context string) (*strictObject, error) {
	obj, ok := v.(*strictObject)
	if !ok {
		return nil, fmt.Errorf("%s: expected a JSON object", context)
	}
	return obj, nil
}

// checkAllowedFields returns an error if obj carries any key outside
// allowed, mirroring serde's deny_unknown_fields.
func checkAllowedFields(obj *strictObject, allowed map[string]bool, context string) error {
	for _, k := range obj.keys {
		if !allowed[k] {
			return fmt.Errorf("%s: unknown field %q", context, k)
		}
	}
	return nil
}

func allowedFieldSet(fields ...string) map[string]bool {
	set := make(map[string]bool, len(fields))
	for _, f := range fields {
		set[f] = true
	}
	return set
}

// Allowed-field sets for strict JSON object decoding. These are read-only
// lookup tables, so they're computed once at package init rather than
// reallocated on every decode call (several of these run once per array
// element, e.g. per quorum member or approval).
var (
	quorumMemberAllowedFields     = allowedFieldSet("alias", "pubKey")
	memberSetAllowedFields        = allowedFieldSet("threshold", "members")
	namespaceAllowedFields        = allowedFieldSet("name", "nonce", "quorumKey")
	nitroConfigAllowedFields      = allowedFieldSet("pcr0", "pcr1", "pcr2", "pcr3", "awsRootCertificate", "qosCommit")
	dnsConfigAllowedFields        = allowedFieldSet("resolvers")
	bridgeConfigAllowedFields     = allowedFieldSet("type", "port", "host")
	pivotEnvValueAllowedFields    = allowedFieldSet("plain")
	pivotEnvPlainAllowedFields    = allowedFieldSet("value")
	pivotConfigAllowedFields      = allowedFieldSet("hash", "restart", "bridgeConfig", "debugMode", "args", "env")
	manifestAllowedFields         = allowedFieldSet("version", "namespace", "pivot", "manifestSet", "shareSet", "enclave", "dns")
	approvalAllowedFields         = allowedFieldSet("signature", "member")
	manifestEnvelopeAllowedFields = allowedFieldSet("manifest", "manifestSetApprovals", "shareSetApprovals")
)

func requiredField(obj *strictObject, key, context string) (any, error) {
	v, ok := obj.values[key]
	if !ok {
		return nil, fmt.Errorf("%s: missing required field %q", context, key)
	}
	return v, nil
}

// optionalField returns the field's value and true when present with a
// non-null value. A field present with an explicit JSON null is treated
// identically to an absent field: QOS canonical JSON drops null object
// members regardless, so both must decode (and hash) the same way.
func optionalField(obj *strictObject, key string) (any, bool) {
	v, ok := obj.values[key]
	if !ok || v == nil {
		return nil, false
	}
	return v, true
}

func decodeStringField(v any, context string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s: expected a JSON string", context)
	}
	if err := validateDisplaySafeString(s); err != nil {
		return "", fmt.Errorf("%s: %w", context, err)
	}
	return s, nil
}

// validateDisplaySafeString rejects characters that would let a manifest
// string control what a human sees when this tool renders the decoded
// manifest for visual verification before signing. The canonical hash still
// binds to the raw bytes regardless of this check, so this cannot be used to
// forge a signature; it exists solely to stop an attacker-controlled string
// from manipulating the human-readable display (terminal or --json) that a
// signer relies on to confirm what they're approving.
//
// This is deliberately built on Unicode's derived properties rather than an
// enumerated list of "invisible" codepoints. Two earlier passes at this
// function each hand-enumerated specific invisible/ignorable codepoints
// (variation selectors, Hangul fillers, Mongolian free variation selectors)
// and each was later shown to have gaps: a sibling codepoint the list
// happened to omit, a Unicode version bump that added a new member to an
// existing class, or an entire subclass (Khmer inherent vowels used as
// invisible markers, unassigned-but-reserved codepoints) that no hand-picked
// list could name in advance. Unicode defines a derived property,
// Default_Ignorable_Code_Point, specifically for "codepoints intended to
// have no visible glyph and be ignored by rendering" -- that is exactly the
// property this check needs, so it is used here (via Go's
// Other_Default_Ignorable_Code_Point table, plus the Variation_Selector
// table, which together make up Default_Ignorable_Code_Point) instead of
// trying to keep a manual enumeration complete by hand.
//
// Rejected classes:
//   - C0 controls (U+0000-U+001F), including ESC (enables ANSI escape
//     sequences such as erase-line/conceal) and CR/LF (line-injection).
//   - DEL (U+007F) and C1 controls (U+0080-U+009F).
//   - Unicode Format category (Cf): bidirectional control characters
//     (LRM/RLM/ALM, embedding/override, isolate), zero-width characters
//     (ZWSP, ZWNJ, ZWJ, word joiner, invisible math operators), soft hyphen,
//     Mongolian vowel separator, interlinear annotation controls, and the
//     Unicode Tag block (U+E0000-U+E007F), all of which can hide or
//     rearrange displayed text without being visible themselves.
//   - The Variation_Selector derived property: VS1-16 (U+FE00-U+FE0F),
//     VS17-256 (the Variation Selectors Supplement, U+E0100-U+E01EF), and
//     the Mongolian Free Variation Selectors (U+180B-U+180D, which includes
//     U+180F -- added to this class in Unicode 14.0, after an earlier
//     version of this check hard-coded a U+180B-U+180D range that stopped
//     one codepoint short). All of these are category Mn (not Cf) but can
//     alter or hide the rendering of the preceding character.
//   - The Other_Default_Ignorable_Code_Point derived property: the
//     Unicode-standard catch-all for codepoints intended to render as
//     nothing. This covers the Hangul filler characters (U+115F, U+1160,
//     U+3164, U+FFA0), the Khmer inherent vowels when used as invisible
//     markers (U+17B4, U+17B5), COMBINING GRAPHEME JOINER (U+034F), and
//     roughly 3769 further unassigned-but-reserved codepoints that a manual
//     list can never enumerate up front.
//   - Unicode line/paragraph separators (Zl/Zp: U+2028/U+2029), which many
//     renderers treat as line breaks, enabling line-injection identically to
//     CR/LF. These are structural line breaks, not "ignorable" in the
//     Unicode sense, so they need their own check rather than being
//     subsumed by Default_Ignorable_Code_Point.
func validateDisplaySafeString(s string) error {
	for _, r := range s {
		switch {
		case r <= 0x1f, r == 0x7f, (r >= 0x80 && r <= 0x9f):
			return fmt.Errorf("contains disallowed control character %U", r)
		case unicode.Is(unicode.Cf, r):
			return fmt.Errorf("contains disallowed format control character %U", r)
		case unicode.Is(unicode.Variation_Selector, r):
			return fmt.Errorf("contains disallowed variation selector %U", r)
		case unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
			return fmt.Errorf("contains disallowed default-ignorable character %U", r)
		case unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			return fmt.Errorf("contains disallowed line/paragraph separator %U", r)
		}
	}
	return nil
}

func decodeBoolField(v any, context string) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s: expected a JSON boolean", context)
	}
	return b, nil
}

func decodeArrayField(v any, context string) ([]any, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a JSON array", context)
	}
	return arr, nil
}

// decodeUint32Field decodes a QOS string_or_numeric field: either a JSON
// integer number or a decimal string are accepted; a fractional/exponent
// number is rejected.
func decodeUint32Field(v any, context string) (uint32, error) {
	var digits string
	switch t := v.(type) {
	case json.Number:
		if !isIntegerToken(t.String()) {
			return 0, fmt.Errorf("%s: non-integer numeric value %q", context, t.String())
		}
		digits = t.String()
	case string:
		if !isIntegerToken(t) || t[0] == '-' {
			return 0, fmt.Errorf("%s: invalid numeric string %q", context, t)
		}
		digits = t
	default:
		return 0, fmt.Errorf("%s: expected an integer or numeric string", context)
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", context, err)
	}
	return uint32(n), nil
}

func decodeUint16Field(v any, context string) (uint16, error) {
	n, err := decodeUint32Field(v, context)
	if err != nil {
		return 0, err
	}
	if n > 0xffff {
		return 0, fmt.Errorf("%s: value %d overflows a 16-bit field", context, n)
	}
	return uint16(n), nil
}

// decodeHexField decodes a lowercase hex string field. QoS encodes byte
// fields as lowercase hex (qos_hex::serde); this rejects uppercase, odd
// length, and non-hex characters. expectedLen of 0 means any length is
// accepted (a Vec<u8> field); a positive expectedLen enforces a fixed-size
// field like the 32-byte pivot hash.
func isLowercaseHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
}

func decodeHexField(v any, expectedLen int, context string) (HexBytes, error) {
	s, err := decodeStringField(v, context)
	if err != nil {
		return nil, err
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("%s: odd-length hex string", context)
	}
	for _, r := range s {
		if !isLowercaseHexDigit(r) {
			return nil, fmt.Errorf("%s: invalid hex string %q (must be lowercase hex)", context, s)
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", context, err)
	}
	if expectedLen > 0 && len(b) != expectedLen {
		return nil, fmt.Errorf("%s: expected %d bytes, got %d", context, expectedLen, len(b))
	}
	return HexBytes(b), nil
}

func decodeRestartPolicy(v any, context string) (RestartPolicy, error) {
	s, err := decodeStringField(v, context)
	if err != nil {
		return 0, err
	}
	switch s {
	case "Never":
		return RestartPolicyNever, nil
	case "Always":
		return RestartPolicyAlways, nil
	default:
		return 0, fmt.Errorf("%s: invalid restart policy %q (must be \"Never\" or \"Always\")", context, s)
	}
}

func decodeQuorumMemberJSON(v any, context string) (QuorumMemberJSON, error) {
	obj, err := requireObject(v, context)
	if err != nil {
		return QuorumMemberJSON{}, err
	}
	if err := checkAllowedFields(obj, quorumMemberAllowedFields, context); err != nil {
		return QuorumMemberJSON{}, err
	}

	aliasV, err := requiredField(obj, "alias", context)
	if err != nil {
		return QuorumMemberJSON{}, err
	}
	alias, err := decodeStringField(aliasV, context+".alias")
	if err != nil {
		return QuorumMemberJSON{}, err
	}

	pubKeyV, err := requiredField(obj, "pubKey", context)
	if err != nil {
		return QuorumMemberJSON{}, err
	}
	pubKey, err := decodeHexField(pubKeyV, 0, context+".pubKey")
	if err != nil {
		return QuorumMemberJSON{}, err
	}

	return QuorumMemberJSON{Alias: alias, PubKey: pubKey}, nil
}

func decodeMemberSetJSON(v any, context string) (threshold uint32, members []QuorumMemberJSON, err error) {
	obj, err := requireObject(v, context)
	if err != nil {
		return 0, nil, err
	}
	if err := checkAllowedFields(obj, memberSetAllowedFields, context); err != nil {
		return 0, nil, err
	}

	thresholdV, err := requiredField(obj, "threshold", context)
	if err != nil {
		return 0, nil, err
	}
	threshold, err = decodeUint32Field(thresholdV, context+".threshold")
	if err != nil {
		return 0, nil, err
	}

	membersV, err := requiredField(obj, "members", context)
	if err != nil {
		return 0, nil, err
	}
	membersArr, err := decodeArrayField(membersV, context+".members")
	if err != nil {
		return 0, nil, err
	}
	members = make([]QuorumMemberJSON, len(membersArr))
	for i, mv := range membersArr {
		member, err := decodeQuorumMemberJSON(mv, fmt.Sprintf("%s.members[%d]", context, i))
		if err != nil {
			return 0, nil, err
		}
		members[i] = member
	}
	return threshold, members, nil
}

func decodeNamespaceJSON(v any, context string) (NamespaceJSON, error) {
	obj, err := requireObject(v, context)
	if err != nil {
		return NamespaceJSON{}, err
	}
	if err := checkAllowedFields(obj, namespaceAllowedFields, context); err != nil {
		return NamespaceJSON{}, err
	}

	nameV, err := requiredField(obj, "name", context)
	if err != nil {
		return NamespaceJSON{}, err
	}
	name, err := decodeStringField(nameV, context+".name")
	if err != nil {
		return NamespaceJSON{}, err
	}

	nonceV, err := requiredField(obj, "nonce", context)
	if err != nil {
		return NamespaceJSON{}, err
	}
	nonce, err := decodeUint32Field(nonceV, context+".nonce")
	if err != nil {
		return NamespaceJSON{}, err
	}

	quorumKeyV, err := requiredField(obj, "quorumKey", context)
	if err != nil {
		return NamespaceJSON{}, err
	}
	quorumKey, err := decodeHexField(quorumKeyV, 0, context+".quorumKey")
	if err != nil {
		return NamespaceJSON{}, err
	}

	return NamespaceJSON{Name: name, Nonce: nonce, QuorumKey: quorumKey}, nil
}

func decodeNitroConfigJSON(v any, context string) (NitroConfigJSON, error) {
	obj, err := requireObject(v, context)
	if err != nil {
		return NitroConfigJSON{}, err
	}
	if err := checkAllowedFields(obj, nitroConfigAllowedFields, context); err != nil {
		return NitroConfigJSON{}, err
	}

	var cfg NitroConfigJSON
	for _, field := range []struct {
		name string
		dst  *HexBytes
		// expectedLen is 48 for PCRs (AWS Nitro PCRs are always SHA-384
		// digests) and 0 (any length) for awsRootCertificate, which is a
		// variable-length ASN.1 DER certificate.
		expectedLen int
	}{
		{"pcr0", &cfg.Pcr0, nitroPCRLen},
		{"pcr1", &cfg.Pcr1, nitroPCRLen},
		{"pcr2", &cfg.Pcr2, nitroPCRLen},
		{"pcr3", &cfg.Pcr3, nitroPCRLen},
		{"awsRootCertificate", &cfg.AwsRootCertificate, 0},
	} {
		fv, err := requiredField(obj, field.name, context)
		if err != nil {
			return NitroConfigJSON{}, err
		}
		b, err := decodeHexField(fv, field.expectedLen, context+"."+field.name)
		if err != nil {
			return NitroConfigJSON{}, err
		}
		*field.dst = b
	}

	commitV, err := requiredField(obj, "qosCommit", context)
	if err != nil {
		return NitroConfigJSON{}, err
	}
	commit, err := decodeStringField(commitV, context+".qosCommit")
	if err != nil {
		return NitroConfigJSON{}, err
	}
	cfg.QosCommit = commit

	return cfg, nil
}

func decodeDnsConfigJSON(v any, context string) (*DnsConfigJSON, error) {
	obj, err := requireObject(v, context)
	if err != nil {
		return nil, err
	}
	if err := checkAllowedFields(obj, dnsConfigAllowedFields, context); err != nil {
		return nil, err
	}

	resolversV, err := requiredField(obj, "resolvers", context)
	if err != nil {
		return nil, err
	}
	resolversArr, err := decodeArrayField(resolversV, context+".resolvers")
	if err != nil {
		return nil, err
	}
	resolvers := make([]string, len(resolversArr))
	for i, rv := range resolversArr {
		s, err := decodeStringField(rv, fmt.Sprintf("%s.resolvers[%d]", context, i))
		if err != nil {
			return nil, err
		}
		if net.ParseIP(s) == nil {
			return nil, fmt.Errorf("%s.resolvers[%d]: invalid IP address %q", context, i, s)
		}
		resolvers[i] = s
	}
	return &DnsConfigJSON{Resolvers: resolvers}, nil
}

func decodeBridgeConfigJSON(v any, context string) (BridgeConfigJSON, error) {
	obj, err := requireObject(v, context)
	if err != nil {
		return BridgeConfigJSON{}, err
	}
	if err := checkAllowedFields(obj, bridgeConfigAllowedFields, context); err != nil {
		return BridgeConfigJSON{}, err
	}

	typeV, err := requiredField(obj, "type", context)
	if err != nil {
		return BridgeConfigJSON{}, err
	}
	bridgeType, err := decodeStringField(typeV, context+".type")
	if err != nil {
		return BridgeConfigJSON{}, err
	}
	if bridgeType != BridgeConfigTypeServer && bridgeType != BridgeConfigTypeClient {
		return BridgeConfigJSON{}, fmt.Errorf("%s.type: invalid bridge config type %q (must be %q or %q)",
			context, bridgeType, BridgeConfigTypeServer, BridgeConfigTypeClient)
	}

	portV, err := requiredField(obj, "port", context)
	if err != nil {
		return BridgeConfigJSON{}, err
	}
	port, err := decodeUint16Field(portV, context+".port")
	if err != nil {
		return BridgeConfigJSON{}, err
	}

	hostV, hostPresent := optionalField(obj, "host")
	var host *string
	if hostPresent {
		h, err := decodeStringField(hostV, context+".host")
		if err != nil {
			return BridgeConfigJSON{}, err
		}
		host = &h
	} else if bridgeType == BridgeConfigTypeServer {
		return BridgeConfigJSON{}, fmt.Errorf("%s: missing required field \"host\" for bridge config type %q", context, BridgeConfigTypeServer)
	}

	return BridgeConfigJSON{Type: bridgeType, Port: port, Host: host}, nil
}

func decodePivotEnvJSON(v any, context string) (map[string]PivotEnvValueJSON, error) {
	obj, err := requireObject(v, context)
	if err != nil {
		return nil, err
	}
	env := make(map[string]PivotEnvValueJSON, len(obj.keys))
	for _, name := range obj.keys {
		if !isValidPivotEnvVarName(name) {
			return nil, fmt.Errorf("%s: invalid environment variable name %q", context, name)
		}
		valueContext := fmt.Sprintf("%s[%q]", context, name)
		valueObj, err := requireObject(obj.values[name], valueContext)
		if err != nil {
			return nil, err
		}
		if err := checkAllowedFields(valueObj, pivotEnvValueAllowedFields, valueContext); err != nil {
			return nil, err
		}
		plainV, err := requiredField(valueObj, "plain", valueContext)
		if err != nil {
			return nil, err
		}
		plainObj, err := requireObject(plainV, valueContext+".plain")
		if err != nil {
			return nil, err
		}
		if err := checkAllowedFields(plainObj, pivotEnvPlainAllowedFields, valueContext+".plain"); err != nil {
			return nil, err
		}
		valueV, err := requiredField(plainObj, "value", valueContext+".plain")
		if err != nil {
			return nil, err
		}
		value, err := decodeStringField(valueV, valueContext+".plain.value")
		if err != nil {
			return nil, err
		}
		env[name] = PivotEnvValueJSON{Plain: &PivotEnvPlainValueJSON{Value: value}}
	}
	return env, nil
}

// isValidPivotEnvVarName mirrors qos_core's PivotEnvVarName validation:
// [A-Za-z_][A-Za-z0-9_]*.
func isValidPivotEnvVarName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func decodePivotConfigJSONV2(v any, context string) (PivotConfigJSONV2, error) {
	obj, err := requireObject(v, context)
	if err != nil {
		return PivotConfigJSONV2{}, err
	}
	if err := checkAllowedFields(obj, pivotConfigAllowedFields, context); err != nil {
		return PivotConfigJSONV2{}, err
	}

	hashV, err := requiredField(obj, "hash", context)
	if err != nil {
		return PivotConfigJSONV2{}, err
	}
	hash, err := decodeHexField(hashV, 32, context+".hash")
	if err != nil {
		return PivotConfigJSONV2{}, err
	}

	restartV, err := requiredField(obj, "restart", context)
	if err != nil {
		return PivotConfigJSONV2{}, err
	}
	restart, err := decodeRestartPolicy(restartV, context+".restart")
	if err != nil {
		return PivotConfigJSONV2{}, err
	}

	bridgeConfigV, err := requiredField(obj, "bridgeConfig", context)
	if err != nil {
		return PivotConfigJSONV2{}, err
	}
	bridgeConfigArr, err := decodeArrayField(bridgeConfigV, context+".bridgeConfig")
	if err != nil {
		return PivotConfigJSONV2{}, err
	}
	bridgeConfig := make([]BridgeConfigJSON, len(bridgeConfigArr))
	for i, bv := range bridgeConfigArr {
		bc, err := decodeBridgeConfigJSON(bv, fmt.Sprintf("%s.bridgeConfig[%d]", context, i))
		if err != nil {
			return PivotConfigJSONV2{}, err
		}
		bridgeConfig[i] = bc
	}

	debugModeV, err := requiredField(obj, "debugMode", context)
	if err != nil {
		return PivotConfigJSONV2{}, err
	}
	debugMode, err := decodeBoolField(debugModeV, context+".debugMode")
	if err != nil {
		return PivotConfigJSONV2{}, err
	}

	argsV, err := requiredField(obj, "args", context)
	if err != nil {
		return PivotConfigJSONV2{}, err
	}
	argsArr, err := decodeArrayField(argsV, context+".args")
	if err != nil {
		return PivotConfigJSONV2{}, err
	}
	args := make([]string, len(argsArr))
	for i, av := range argsArr {
		s, err := decodeStringField(av, fmt.Sprintf("%s.args[%d]", context, i))
		if err != nil {
			return PivotConfigJSONV2{}, err
		}
		args[i] = s
	}

	var env map[string]PivotEnvValueJSON
	if envV, ok := optionalField(obj, "env"); ok {
		env, err = decodePivotEnvJSON(envV, context+".env")
		if err != nil {
			return PivotConfigJSONV2{}, err
		}
	}

	return PivotConfigJSONV2{
		Hash:         hash,
		Restart:      restart,
		BridgeConfig: bridgeConfig,
		DebugMode:    debugMode,
		Args:         args,
		Env:          env,
	}, nil
}

func decodeManifestJSONV2(v any, context string) (ManifestJSONV2, error) {
	obj, err := requireObject(v, context)
	if err != nil {
		return ManifestJSONV2{}, err
	}
	if err := checkAllowedFields(obj, manifestAllowedFields, context); err != nil {
		return ManifestJSONV2{}, err
	}

	versionV, err := requiredField(obj, "version", context)
	if err != nil {
		return ManifestJSONV2{}, err
	}
	version, err := decodeStringField(versionV, context+".version")
	if err != nil {
		return ManifestJSONV2{}, err
	}
	if version != "v2" {
		return ManifestJSONV2{}, fmt.Errorf("%s.version: manifest v2 requires version \"v2\", got %q", context, version)
	}

	namespaceV, err := requiredField(obj, "namespace", context)
	if err != nil {
		return ManifestJSONV2{}, err
	}
	namespace, err := decodeNamespaceJSON(namespaceV, context+".namespace")
	if err != nil {
		return ManifestJSONV2{}, err
	}

	pivotV, err := requiredField(obj, "pivot", context)
	if err != nil {
		return ManifestJSONV2{}, err
	}
	pivot, err := decodePivotConfigJSONV2(pivotV, context+".pivot")
	if err != nil {
		return ManifestJSONV2{}, err
	}

	manifestSetV, err := requiredField(obj, "manifestSet", context)
	if err != nil {
		return ManifestJSONV2{}, err
	}
	manifestSetThreshold, manifestSetMembers, err := decodeMemberSetJSON(manifestSetV, context+".manifestSet")
	if err != nil {
		return ManifestJSONV2{}, err
	}

	shareSetV, err := requiredField(obj, "shareSet", context)
	if err != nil {
		return ManifestJSONV2{}, err
	}
	shareSetThreshold, shareSetMembers, err := decodeMemberSetJSON(shareSetV, context+".shareSet")
	if err != nil {
		return ManifestJSONV2{}, err
	}

	enclaveV, err := requiredField(obj, "enclave", context)
	if err != nil {
		return ManifestJSONV2{}, err
	}
	enclave, err := decodeNitroConfigJSON(enclaveV, context+".enclave")
	if err != nil {
		return ManifestJSONV2{}, err
	}

	var dns *DnsConfigJSON
	if dnsV, ok := optionalField(obj, "dns"); ok {
		dns, err = decodeDnsConfigJSON(dnsV, context+".dns")
		if err != nil {
			return ManifestJSONV2{}, err
		}
	}

	return ManifestJSONV2{
		Version:     version,
		Namespace:   namespace,
		Pivot:       pivot,
		ManifestSet: ManifestSetJSON{Threshold: manifestSetThreshold, Members: manifestSetMembers},
		ShareSet:    ShareSetJSON{Threshold: shareSetThreshold, Members: shareSetMembers},
		Enclave:     enclave,
		Dns:         dns,
	}, nil
}

func decodeApprovalJSON(v any, context string) (ApprovalJSON, error) {
	obj, err := requireObject(v, context)
	if err != nil {
		return ApprovalJSON{}, err
	}
	if err := checkAllowedFields(obj, approvalAllowedFields, context); err != nil {
		return ApprovalJSON{}, err
	}

	sigV, err := requiredField(obj, "signature", context)
	if err != nil {
		return ApprovalJSON{}, err
	}
	signature, err := decodeHexField(sigV, 0, context+".signature")
	if err != nil {
		return ApprovalJSON{}, err
	}

	memberV, err := requiredField(obj, "member", context)
	if err != nil {
		return ApprovalJSON{}, err
	}
	member, err := decodeQuorumMemberJSON(memberV, context+".member")
	if err != nil {
		return ApprovalJSON{}, err
	}

	return ApprovalJSON{Signature: signature, Member: member}, nil
}

func decodeApprovalsJSON(v any, context string) ([]ApprovalJSON, error) {
	arr, err := decodeArrayField(v, context)
	if err != nil {
		return nil, err
	}
	approvals := make([]ApprovalJSON, len(arr))
	for i, av := range arr {
		a, err := decodeApprovalJSON(av, fmt.Sprintf("%s[%d]", context, i))
		if err != nil {
			return nil, err
		}
		approvals[i] = a
	}
	return approvals, nil
}

func decodeManifestEnvelopeJSONV2(obj *strictObject) (*ManifestEnvelopeJSONV2, error) {
	const context = "manifest envelope"
	if err := checkAllowedFields(obj, manifestEnvelopeAllowedFields, context); err != nil {
		return nil, err
	}

	manifestV, err := requiredField(obj, "manifest", context)
	if err != nil {
		return nil, err
	}
	manifest, err := decodeManifestJSONV2(manifestV, context+".manifest")
	if err != nil {
		return nil, err
	}

	manifestApprovalsV, err := requiredField(obj, "manifestSetApprovals", context)
	if err != nil {
		return nil, err
	}
	manifestApprovals, err := decodeApprovalsJSON(manifestApprovalsV, context+".manifestSetApprovals")
	if err != nil {
		return nil, err
	}

	shareApprovalsV, err := requiredField(obj, "shareSetApprovals", context)
	if err != nil {
		return nil, err
	}
	shareApprovals, err := decodeApprovalsJSON(shareApprovalsV, context+".shareSetApprovals")
	if err != nil {
		return nil, err
	}

	return &ManifestEnvelopeJSONV2{
		Manifest:             manifest,
		ManifestSetApprovals: manifestApprovals,
		ShareSetApprovals:    shareApprovals,
	}, nil
}

// CanonicalizeManifestJSONV2 re-serializes a decoded ManifestJSONV2 as QOS
// canonical JSON. This is the only representation that should ever be
// hashed and compared against attestation UserData for a JSON manifest.
func CanonicalizeManifestJSONV2(m *ManifestJSONV2) ([]byte, error) {
	return CanonicalizeValue(m)
}

// DecodeJSONManifestEnvelope strictly decodes a QOS JSON (v2) manifest
// envelope: no duplicate keys, no unknown fields, and manifest.version must
// be exactly "v2". It returns the typed envelope alongside the QOS canonical
// JSON bytes of the embedded manifest (manifestBytes), which is the only
// value that should be hashed and compared against attestation UserData.
func DecodeJSONManifestEnvelope(data []byte) (*ManifestEnvelopeJSONV2, []byte, error) {
	if len(data) > maxJSONEnvelopeBytes {
		return nil, nil, fmt.Errorf("qos json envelope too large: %d bytes exceeds %d byte limit", len(data), maxJSONEnvelopeBytes)
	}

	root, err := decodeStrictJSON(data)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid QOS JSON manifest envelope: %w", err)
	}
	obj, err := requireObject(root, "manifest envelope")
	if err != nil {
		return nil, nil, err
	}
	env, err := decodeManifestEnvelopeJSONV2(obj)
	if err != nil {
		return nil, nil, err
	}

	manifestBytes, err := CanonicalizeManifestJSONV2(&env.Manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to canonicalize QOS JSON manifest: %w", err)
	}
	return env, manifestBytes, nil
}

// ToManifest projects a JSON v2 manifest onto this package's Borsh-oriented
// Manifest type, for reporting/display purposes only (e.g. the CLI's default
// text output). This projection is lossy: it drops Dns and Pivot.Env, which
// have no home on Manifest, and reports an empty PatchSet, since the JSON
// schema does not have one. Never use this projection's re-serialization for
// hash binding; the canonical hash must come from CanonicalizeManifestJSONV2
// against the original ManifestJSONV2, not this struct.
func (m *ManifestJSONV2) ToManifest() Manifest {
	bridgeConfig := make([]BridgeConfig, len(m.Pivot.BridgeConfig))
	for i, bc := range m.Pivot.BridgeConfig {
		host := ""
		if bc.Host != nil {
			host = *bc.Host
		}
		switch bc.Type {
		case BridgeConfigTypeServer:
			bridgeConfig[i] = BridgeConfig{
				Enum:   0,
				Server: BridgeConfigServer{Port: bc.Port, Host: host},
			}
		case BridgeConfigTypeClient:
			bridgeConfig[i] = BridgeConfig{
				Enum:   1,
				Client: BridgeConfigClient{Port: bc.Port, Host: host},
			}
		}
	}

	var hash Hash256
	copy(hash[:], m.Pivot.Hash)

	return Manifest{
		Namespace: Namespace{
			Name:      m.Namespace.Name,
			Nonce:     m.Namespace.Nonce,
			QuorumKey: m.Namespace.QuorumKey,
		},
		Pivot: PivotConfig{
			Hash:         hash,
			Restart:      m.Pivot.Restart,
			BridgeConfig: bridgeConfig,
			DebugMode:    m.Pivot.DebugMode,
			Args:         m.Pivot.Args,
		},
		ManifestSet: ManifestSet{
			Threshold: m.ManifestSet.Threshold,
			Members:   ProjectQuorumMembers(m.ManifestSet.Members),
		},
		ShareSet: ShareSet{
			Threshold: m.ShareSet.Threshold,
			Members:   ProjectQuorumMembers(m.ShareSet.Members),
		},
		Enclave: NitroConfig{
			Pcr0:               m.Enclave.Pcr0,
			Pcr1:               m.Enclave.Pcr1,
			Pcr2:               m.Enclave.Pcr2,
			Pcr3:               m.Enclave.Pcr3,
			AwsRootCertificate: m.Enclave.AwsRootCertificate,
			QosCommit:          m.Enclave.QosCommit,
		},
	}
}

// ProjectQuorumMembers projects JSON v2 quorum members onto this package's
// Borsh-oriented QuorumMember type, for reporting/display purposes only.
func ProjectQuorumMembers(members []QuorumMemberJSON) []QuorumMember {
	out := make([]QuorumMember, len(members))
	for i, m := range members {
		out[i] = QuorumMember{Alias: m.Alias, PubKey: m.PubKey}
	}
	return out
}

// ToManifestEnvelope projects a JSON v2 manifest envelope onto this
// package's Borsh-oriented ManifestEnvelope type, for reporting/display
// purposes only. See ManifestJSONV2.ToManifest for the caveats that apply.
func (e *ManifestEnvelopeJSONV2) ToManifestEnvelope() ManifestEnvelope {
	return ManifestEnvelope{
		Manifest:             e.Manifest.ToManifest(),
		ManifestSetApprovals: ProjectApprovals(e.ManifestSetApprovals),
		ShareSetApprovals:    ProjectApprovals(e.ShareSetApprovals),
	}
}

// ProjectApprovals projects JSON v2 approvals onto this package's
// Borsh-oriented Approval type, for reporting/display purposes only.
func ProjectApprovals(approvals []ApprovalJSON) []Approval {
	out := make([]Approval, len(approvals))
	for i, a := range approvals {
		out[i] = Approval{
			Signature: a.Signature,
			Member:    QuorumMember{Alias: a.Member.Alias, PubKey: a.Member.PubKey},
		}
	}
	return out
}
