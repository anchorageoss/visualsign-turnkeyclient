package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"unicode/utf16"
)

// CanonicalizeJSON re-encodes JSON bytes as QOS canonical JSON, per QuorumOS's
// qos_json spec (a QOS-normalized RFC 8785-style canonicalization):
//
//   - Object properties are sorted recursively by their raw property name,
//     compared as UTF-16 code units.
//   - Integer JSON numbers canonicalize as base-10 integer strings (1 -> "1").
//     Non-integer numbers (1.0, 1e3, -0.5) are rejected outright.
//   - Object members whose value is null are dropped (field names provide
//     domain separation, so an unset field is safe to omit). Null values
//     inside arrays are preserved, since array positions are not.
//   - String escaping matches serde_json's default writer: the short escapes
//     for \b \t \n \f \r \" \\, \u00XX for other control characters, and no
//     other characters escaped (no HTML escaping, no forward-slash escaping).
//
// Because integers canonicalize as base-10 strings, a JSON number and a JSON
// string holding the same digits canonicalize to byte-identical output (for
// example, {"n":1} and {"n":"1"} both produce {"n":"1"}). This is required to
// match qos_json/serde_json's own canonical encoding and is not a defect in
// this port; callers must establish type safety (for example, by decoding
// into a strictly-typed schema, as this package's manifest decoder does)
// before treating canonical bytes as authoritative for anything
// security-sensitive.
//
// REVIEW NOTE: code review flagged this as a candidate to lean on an
// existing RFC 8785 (JCS) implementation (e.g. github.com/cyberphone/json-
// canonicalization or github.com/gowebpki/jcs) instead of the hand-rolled
// UTF-16 key sort (utf16Less) and string escaper (writeCanonicalString)
// below. Neither library is a drop-in as-is: this function deliberately
// diverges from strict RFC 8785 in the two ways documented above (base-10
// integer strings instead of ECMA-262 number-to-string, and dropped null
// members) to match qos_json/serde_json's actual output. Wrapping one of
// those libraries with overrides for number and null handling could still
// shrink the custom sort/escape logic while keeping a maintained reference
// implementation for the rest — worth revisiting, but not swapped in here.
// Prasanna is taking a first pass at this separately.
func CanonicalizeJSON(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("invalid JSON: unexpected trailing data")
		}
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var buf bytes.Buffer
	if err := writeCanonicalValue(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalizeValue marshals value to JSON using encoding/json, then
// canonicalizes the result as QOS canonical JSON.
func CanonicalizeValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal value: %w", err)
	}
	return CanonicalizeJSON(raw)
}

func writeCanonicalValue(w *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		w.WriteString("null")
		return nil
	case bool:
		if v {
			w.WriteString("true")
		} else {
			w.WriteString("false")
		}
		return nil
	case json.Number:
		return writeCanonicalNumber(w, v)
	case string:
		writeCanonicalString(w, v)
		return nil
	case []any:
		return writeCanonicalArray(w, v)
	case map[string]any:
		return writeCanonicalObject(w, v)
	default:
		return fmt.Errorf("QOS canonical JSON: unsupported value type %T", value)
	}
}

func writeCanonicalNumber(w *bytes.Buffer, n json.Number) error {
	if !isIntegerToken(n.String()) {
		return fmt.Errorf("QOS canonical JSON forbids non-integer JSON numbers: %s", n.String())
	}
	writeCanonicalString(w, n.String())
	return nil
}

// isIntegerToken reports whether s is a base-10 integer literal (an optional
// leading '-' followed by one or more digits), matching the RFC 8785 rule
// QOS uses to distinguish integer JSON numbers from ones that carry a
// fraction or exponent part.
func isIntegerToken(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' {
		i = 1
	}
	if i >= len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func writeCanonicalArray(w *bytes.Buffer, values []any) error {
	w.WriteByte('[')
	for i, v := range values {
		if i > 0 {
			w.WriteByte(',')
		}
		if err := writeCanonicalValue(w, v); err != nil {
			return err
		}
	}
	w.WriteByte(']')
	return nil
}

func writeCanonicalObject(w *bytes.Buffer, obj map[string]any) error {
	type entry struct {
		key   string
		value any
	}
	entries := make([]entry, 0, len(obj))
	for k, v := range obj {
		// Object members with a null value are unset fields; field-name domain
		// separation makes it safe to drop them before canonicalization.
		if v == nil {
			continue
		}
		entries = append(entries, entry{key: k, value: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		return utf16Less(entries[i].key, entries[j].key)
	})

	w.WriteByte('{')
	for i, e := range entries {
		if i > 0 {
			w.WriteByte(',')
		}
		writeCanonicalString(w, e.key)
		w.WriteByte(':')
		if err := writeCanonicalValue(w, e.value); err != nil {
			return err
		}
	}
	w.WriteByte('}')
	return nil
}

// utf16Less compares a and b by their raw, unescaped UTF-16 code units, per
// RFC 8785 section 3.2.3. This differs from Go's default byte-wise string
// comparison for any non-ASCII property name.
func utf16Less(a, b string) bool {
	au := utf16.Encode([]rune(a))
	bu := utf16.Encode([]rune(b))
	for i := 0; i < len(au) && i < len(bu); i++ {
		if au[i] != bu[i] {
			return au[i] < bu[i]
		}
	}
	return len(au) < len(bu)
}

const hexDigits = "0123456789abcdef"

// writeCanonicalString writes s as a JSON string using serde_json's default
// escaping: the short escapes for \b \t \n \f \r \" \\, \u00XX for other
// control characters, and every other character (including '/', and any
// non-ASCII character) written literally. This deliberately differs from
// Go's encoding/json, which HTML-escapes '<', '>', '&', U+2028, and U+2029 by
// default; QOS canonical JSON must not, since that divergence would change
// the hashed bytes relative to serde_json's output.
func writeCanonicalString(w *bytes.Buffer, s string) {
	w.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			w.WriteString(`\"`)
		case '\\':
			w.WriteString(`\\`)
		case '\b':
			w.WriteString(`\b`)
		case '\f':
			w.WriteString(`\f`)
		case '\n':
			w.WriteString(`\n`)
		case '\r':
			w.WriteString(`\r`)
		case '\t':
			w.WriteString(`\t`)
		default:
			if r < 0x20 {
				w.WriteString(`\u00`)
				w.WriteByte(hexDigits[(r>>4)&0xf])
				w.WriteByte(hexDigits[r&0xf])
				continue
			}
			w.WriteRune(r)
		}
	}
	w.WriteByte('"')
}
