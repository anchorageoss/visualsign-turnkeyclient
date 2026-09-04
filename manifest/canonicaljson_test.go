package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func canonicalizeString(t *testing.T, in string) string {
	t.Helper()
	out, err := CanonicalizeJSON([]byte(in))
	require.NoError(t, err)
	return string(out)
}

func TestCanonicalJSON(t *testing.T) {
	t.Run("integers_become_strings", func(t *testing.T) {
		assert.Equal(t, `{"n":"1"}`, canonicalizeString(t, `{"n":1}`))
		assert.Equal(t, `{"n":"-42"}`, canonicalizeString(t, `{"n":-42}`))
		assert.Equal(t, `{"n":"-9007199254740991"}`, canonicalizeString(t, `{"n":-9007199254740991}`))
	})

	t.Run("integer_number_and_matching_string_collide_by_design", func(t *testing.T) {
		// This equivalence is required to match qos_json/serde_json's own
		// canonical encoding (see the CanonicalizeJSON doc comment), so it is
		// an intended invariant, not an accidental side effect a future
		// refactor should be free to break in either direction.
		numberOut, err := CanonicalizeJSON([]byte(`{"n":1}`))
		require.NoError(t, err)
		stringOut, err := CanonicalizeJSON([]byte(`{"n":"1"}`))
		require.NoError(t, err)
		assert.Equal(t, string(numberOut), string(stringOut))
	})

	t.Run("rejects_non_integer_numbers", func(t *testing.T) {
		for _, in := range []string{`{"n":1.0}`, `{"n":1e3}`, `{"n":-0.5}`, `{"n":1e0}`} {
			_, err := CanonicalizeJSON([]byte(in))
			require.Error(t, err, in)
			assert.Contains(t, err.Error(), "non-integer")
		}
	})

	t.Run("drops_null_object_members", func(t *testing.T) {
		assert.Equal(t, `{"b":"1"}`, canonicalizeString(t, `{"a":null,"b":"1"}`))
		assert.Equal(t,
			`{"a":"1","items":[null,{"y":true}],"nested":{"y":"2"}}`,
			canonicalizeString(t, `{"b":null,"a":"1","nested":{"z":null,"y":"2"},"items":[null,{"x":null,"y":true}]}`))
	})

	t.Run("preserves_null_in_arrays", func(t *testing.T) {
		assert.Equal(t, `[null,"1"]`, canonicalizeString(t, `[null,"1"]`))
		assert.Equal(t,
			`{"items":[null,{"keep":"yes"},null]}`,
			canonicalizeString(t, `{"empty":null,"items":[null,{"drop":null,"keep":"yes"},null]}`))
	})

	t.Run("preserves_top_level_null", func(t *testing.T) {
		assert.Equal(t, `null`, canonicalizeString(t, `null`))
	})

	t.Run("sorts_keys_by_utf16_code_units", func(t *testing.T) {
		in := "{\n\t\"\\u20ac\": \"Euro Sign\",\n\t\"\\r\": \"Carriage Return\",\n\t\"\\ufb33\": \"Hebrew Letter Dalet With Dagesh\",\n\t\"1\": \"One\",\n\t\"\\ud83d\\ude00\": \"Emoji: Grinning Face\",\n\t\"\\u0080\": \"Control\",\n\t\"\\u00f6\": \"Latin Small Letter O With Diaeresis\"\n}"
		expected := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
		assert.Equal(t, expected, canonicalizeString(t, in))
	})

	t.Run("escaped_object_keys_sort_by_raw_key_and_remain_escaped", func(t *testing.T) {
		in := "{\"b\":\"plain\",\"\\n\":\"line feed\",\"\\r\":\"carriage return\",\"\\u0001\":\"control\"}"
		expected := "{\"\\u0001\":\"control\",\"\\n\":\"line feed\",\"\\r\":\"carriage return\",\"b\":\"plain\"}"
		assert.Equal(t, expected, canonicalizeString(t, in))
	})

	t.Run("string_escapes_match_serde", func(t *testing.T) {
		in := "{\"quote\":\"\\\"\",\"slash\":\"/\",\"control\":\"\\u0001\",\"line\":\"a\\nb\",\"unicode\":\"€\",\"poop\":\"💩\"}"
		expected := "{\"control\":\"\\u0001\",\"line\":\"a\\nb\",\"poop\":\"💩\",\"quote\":\"\\\"\",\"slash\":\"/\",\"unicode\":\"€\"}"
		assert.Equal(t, expected, canonicalizeString(t, in))
	})

	t.Run("preserves_empty_containers", func(t *testing.T) {
		assert.Equal(t,
			`{"empty_array":[],"empty_object":{}}`,
			canonicalizeString(t, `{"empty_object":{},"empty_array":[],"null_member":null}`))
	})

	t.Run("recursively_sorts_objects_without_reordering_arrays", func(t *testing.T) {
		assert.Equal(t,
			`{"a":[{"c":"3","d":"4"},"second",{"a":"1","b":"2"}],"z":{"a":"1","b":"2"}}`,
			canonicalizeString(t, `{"z":{"b":"2","a":"1"},"a":[{"d":"4","c":"3"},"second",{"b":"2","a":"1"}]}`))
	})

	t.Run("whitespace_and_order_are_ignored", func(t *testing.T) {
		in := "{\n  \"z\": [ true, false, null ],\n  \"a\": { \"b\": \"2\", \"a\": \"1\" }\n}"
		assert.Equal(t, `{"a":{"a":"1","b":"2"},"z":[true,false,null]}`, canonicalizeString(t, in))
	})

	t.Run("spec_vectors", func(t *testing.T) {
		vectors := []struct {
			name     string
			input    string
			expected string
			hash     string
		}{
			{
				name:     "empty_object",
				input:    `{}`,
				expected: `{}`,
				hash:     "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
			},
			{
				name:     "string_and_numeric_fields",
				input:    `{"version":"1","name":"test","threshold":"3"}`,
				expected: `{"name":"test","threshold":"3","version":"1"}`,
				hash:     "898eaf2263b3ca34a9fb0b59615a16e5819b43c53fabc44396f92128f72ccc7e",
			},
			{
				name:     "hex_byte_field",
				input:    `{"data":"deadbeef"}`,
				expected: `{"data":"deadbeef"}`,
				hash:     "03fe564ceddcb54a7a742bd7a4db57318a068cecd22ae44435ce68d35e754e13",
			},
		}
		for _, vector := range vectors {
			t.Run(vector.name, func(t *testing.T) {
				out, err := CanonicalizeJSON([]byte(vector.input))
				require.NoError(t, err)
				assert.Equal(t, vector.expected, string(out))
				sum := sha256.Sum256(out)
				assert.Equal(t, vector.hash, hex.EncodeToString(sum[:]))
			})
		}
	})

	t.Run("key_order_does_not_affect_hash", func(t *testing.T) {
		a := `{"version":"1","name":"test","threshold":"3"}`
		b := "{\n\t\"threshold\": \"3\",\n\t\"name\": \"test\",\n\t\"version\": \"1\"\n}"

		outA, err := CanonicalizeJSON([]byte(a))
		require.NoError(t, err)
		outB, err := CanonicalizeJSON([]byte(b))
		require.NoError(t, err)
		assert.Equal(t, outA, outB)

		sumA := sha256.Sum256(outA)
		assert.Equal(t, "898eaf2263b3ca34a9fb0b59615a16e5819b43c53fabc44396f92128f72ccc7e", hex.EncodeToString(sumA[:]))
	})

	t.Run("rejects_invalid_json", func(t *testing.T) {
		_, err := CanonicalizeJSON([]byte(`{not json`))
		require.Error(t, err)
	})

	t.Run("rejects_trailing_data", func(t *testing.T) {
		_, err := CanonicalizeJSON([]byte(`{}garbage`))
		require.Error(t, err)
	})
}

func TestCanonicalizeValue(t *testing.T) {
	t.Run("typed_struct_matches_raw_vector", func(t *testing.T) {
		type example struct {
			Version   string `json:"version"`
			Name      string `json:"name"`
			Threshold uint32 `json:"threshold"`
		}

		out, err := CanonicalizeValue(example{Version: "1", Name: "test", Threshold: 3})
		require.NoError(t, err)
		assert.Equal(t, `{"name":"test","threshold":"3","version":"1"}`, string(out))
	})

	t.Run("html_characters_are_not_escaped", func(t *testing.T) {
		type example struct {
			Name string `json:"name"`
		}

		out, err := CanonicalizeValue(example{Name: "<a>&b</a>"})
		require.NoError(t, err)
		assert.Equal(t, `{"name":"<a>&b</a>"}`, string(out))
	})
}

func FuzzCanonicalJSON(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"a":1,"b":null,"c":[1,2,3]}`)
	f.Add(`null`)
	f.Add(`{"a":"1.0"}`)
	f.Add(`[null,{"a":null}]`)

	f.Fuzz(func(t *testing.T, in string) {
		out, err := CanonicalizeJSON([]byte(in))
		if err != nil {
			return
		}
		out2, err := CanonicalizeJSON(out)
		require.NoError(t, err)
		assert.Equal(t, out, out2)
	})
}
