package manifest

import (
	"strings"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validEnvelopeJSON() string {
	hash := strings.Repeat("ab", 32)
	pubKey := strings.Repeat("02", 33)
	return `{
		"manifest": {
			"version": "v2",
			"namespace": {"name": "ns", "nonce": 1, "quorumKey": "` + pubKey + `"},
			"pivot": {
				"hash": "` + hash + `",
				"restart": "Never",
				"bridgeConfig": [],
				"debugMode": false,
				"args": []
			},
			"manifestSet": {"threshold": 1, "members": [{"alias": "a", "pubKey": "` + pubKey + `"}]},
			"shareSet": {"threshold": 1, "members": [{"alias": "a", "pubKey": "` + pubKey + `"}]},
			"enclave": {
				"pcr0": "00", "pcr1": "00", "pcr2": "00", "pcr3": "00",
				"awsRootCertificate": "00", "qosCommit": "c"
			}
		},
		"manifestSetApprovals": [],
		"shareSetApprovals": []
	}`
}

func injectDNS(envelopeJSON, rawDNS string) string {
	const marker = `}
		},
		"manifestSetApprovals"`
	replacement := `},
			"dns": ` + rawDNS + `
		},
		"manifestSetApprovals"`
	return strings.Replace(envelopeJSON, marker, replacement, 1)
}

func TestDecodeJSONEnvelope(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		env, manifestBytes, err := DecodeJSONManifestEnvelope(testdata.QosManifestEnvelopeV2JSON)
		require.NoError(t, err)
		require.NotNil(t, env)

		assert.Equal(t, "v2", env.Manifest.Version)
		assert.Equal(t, "synthetic-turnkey-namespace", env.Manifest.Namespace.Name)
		assert.Equal(t, uint32(7), env.Manifest.Namespace.Nonce)
		assert.Len(t, env.Manifest.ManifestSet.Members, 2)
		assert.Equal(t, "quorum-member-alpha", env.Manifest.ManifestSet.Members[0].Alias)
		assert.Equal(t, RestartPolicyAlways, env.Manifest.Pivot.Restart)
		assert.NotNil(t, env.Manifest.Pivot.Env["EXAMPLE_VAR"])

		expected := strings.TrimSuffix(string(testdata.QosManifestEnvelopeV2CanonicalJSON), "\n")
		assert.Equal(t, expected, string(manifestBytes))
	})

	t.Run("duplicate_key", func(t *testing.T) {
		t.Run("top_level", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(),
				`"shareSetApprovals": []`,
				`"shareSetApprovals": [], "shareSetApprovals": []`, 1)
			_, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "duplicate object key")
		})

		t.Run("nested", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(),
				`"debugMode": false,`,
				`"debugMode": false, "debugMode": true,`, 1)
			_, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "duplicate object key")
			assert.Contains(t, err.Error(), "debugMode")
		})
	})

	t.Run("unknown_field", func(t *testing.T) {
		t.Run("manifest", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(),
				`"version": "v2",`,
				`"version": "v2", "unexpectedField": true,`, 1)
			_, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unknown field")
			assert.Contains(t, err.Error(), "unexpectedField")
		})

		t.Run("pivot", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(),
				`"debugMode": false,`,
				`"debugMode": false, "unexpectedField": true,`, 1)
			_, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unknown field")
		})

		t.Run("dns", func(t *testing.T) {
			in := injectDNS(validEnvelopeJSON(), `{"resolvers": [], "unexpectedField": true}`)
			_, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unknown field")
			assert.Contains(t, err.Error(), "unexpectedField")
		})
	})

	t.Run("wrong_version", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			in   string
		}{
			{"v1", strings.Replace(validEnvelopeJSON(), `"version": "v2",`, `"version": "v1",`, 1)},
			{"v3", strings.Replace(validEnvelopeJSON(), `"version": "v2",`, `"version": "v3",`, 1)},
			{"missing", strings.Replace(validEnvelopeJSON(), `"version": "v2",`, ``, 1)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, _, err := DecodeJSONManifestEnvelope([]byte(tc.in))
				require.Error(t, err)
			})
		}
	})

	t.Run("hex_field_validation", func(t *testing.T) {
		validHash := strings.Repeat("ab", 32)

		for _, tc := range []struct {
			name string
			hash string
		}{
			{"odd_length", validHash[:len(validHash)-1]},
			{"non_hex", strings.Repeat("zz", 32)},
			{"uppercase", strings.ToUpper(validHash)},
			{"wrong_length", strings.Repeat("ab", 31)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				in := strings.Replace(validEnvelopeJSON(), `"hash": "`+validHash+`",`, `"hash": "`+tc.hash+`",`, 1)
				_, _, err := DecodeJSONManifestEnvelope([]byte(in))
				require.Error(t, err)
			})
		}
	})

	t.Run("bridge_config_variants", func(t *testing.T) {
		t.Run("server_requires_host", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(),
				`"bridgeConfig": [],`,
				`"bridgeConfig": [{"type": "server", "port": 3000}],`, 1)
			_, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "host")
		})

		t.Run("server_with_host_decodes", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(),
				`"bridgeConfig": [],`,
				`"bridgeConfig": [{"type": "server", "port": 3000, "host": "0.0.0.0"}],`, 1)
			env, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.NoError(t, err)
			require.Len(t, env.Manifest.Pivot.BridgeConfig, 1)
			assert.Equal(t, BridgeConfigTypeServer, env.Manifest.Pivot.BridgeConfig[0].Type)
			assert.Equal(t, uint16(3000), env.Manifest.Pivot.BridgeConfig[0].Port)
		})

		t.Run("client_host_optional", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(),
				`"bridgeConfig": [],`,
				`"bridgeConfig": [{"type": "client", "port": 4000}],`, 1)
			env, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.NoError(t, err)
			require.Len(t, env.Manifest.Pivot.BridgeConfig, 1)
			assert.Equal(t, BridgeConfigTypeClient, env.Manifest.Pivot.BridgeConfig[0].Type)
			assert.Nil(t, env.Manifest.Pivot.BridgeConfig[0].Host)
		})

		t.Run("invalid_type", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(),
				`"bridgeConfig": [],`,
				`"bridgeConfig": [{"type": "bogus", "port": 3000, "host": "0.0.0.0"}],`, 1)
			_, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.Error(t, err)
		})
	})

	t.Run("restart_policy", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			value   string
			wantErr bool
			want    RestartPolicy
		}{
			{name: "never", value: "Never", want: RestartPolicyNever},
			{name: "always", value: "Always", want: RestartPolicyAlways},
			{name: "invalid", value: "sometimes", wantErr: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				in := strings.Replace(validEnvelopeJSON(), `"restart": "Never",`, `"restart": "`+tc.value+`",`, 1)
				env, _, err := DecodeJSONManifestEnvelope([]byte(in))
				if tc.wantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tc.want, env.Manifest.Pivot.Restart)
			})
		}
	})

	t.Run("size_bound", func(t *testing.T) {
		oversized := make([]byte, maxJSONEnvelopeBytes+1)
		for i := range oversized {
			oversized[i] = ' '
		}
		_, _, err := DecodeJSONManifestEnvelope(oversized)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too large")
	})

	t.Run("display_unsafe_string_rejection", func(t *testing.T) {
		t.Run("ansi_escape_in_namespace_name", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(), `"name": "ns",`, `"name": "ns\u001b[2K\r",`, 1)
			_, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "disallowed control character")
		})

		t.Run("bidi_override_in_pivot_env_value", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(), `"args": []`,
				`"args": [], "env": {"EXAMPLE_VAR": {"plain": {"value": "safe\u202evalue"}}}`, 1)
			_, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "disallowed format control character")
		})

		t.Run("non_ascii_unicode_still_decodes", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(), `"name": "ns",`, `"name": "caf\u00e9-\u4e2d\u6587",`, 1)
			env, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.NoError(t, err)
			assert.Equal(t, "caf\u00e9-\u4e2d\u6587", env.Manifest.Namespace.Name)
		})

		t.Run("emoji_still_decodes", func(t *testing.T) {
			in := strings.Replace(validEnvelopeJSON(), `"name": "ns",`, `"name": "ns-😀",`, 1)
			env, _, err := DecodeJSONManifestEnvelope([]byte(in))
			require.NoError(t, err)
			assert.Equal(t, "ns-\U0001f600", env.Manifest.Namespace.Name)
		})

		// These are all rejected via the property-based checks in
		// validateDisplaySafeString (unicode.Cf, unicode.Variation_Selector,
		// unicode.Other_Default_Ignorable_Code_Point, unicode.Zl/Zp), not via
		// any hand-enumerated codepoint range. variation_selector,
		// variation_selector_supplement, mongolian_free_variation_selector,
		// and hangul_filler were previously caught by manual ranges that have
		// since been replaced by the equivalent, more complete property
		// checks; they are kept here as regression tests proving the property
		// checks still catch them.
		for _, tc := range []struct {
			name  string
			value string
		}{
			{name: "arabic_letter_mark", value: "ns\u061c"},
			{name: "zwnj", value: "ns\u200c"},
			{name: "zwj", value: "ns\u200d"},
			{name: "word_joiner", value: "ns\u2060"},
			{name: "soft_hyphen", value: "ns\u00ad"},
			{name: "mongolian_vowel_separator", value: "ns\u180e"},
			{name: "interlinear_annotation_anchor", value: "ns\ufff9"},
			{name: "tag_block", value: "ns\U000e0001"},
			{name: "byte_order_mark", value: "ns\ufeff"},
			{name: "variation_selector", value: "ns\ufe00"},
			{name: "variation_selector_supplement", value: "ns\U000e0100"},
			{name: "mongolian_free_variation_selector", value: "ns\u180b"},
			{name: "mongolian_free_variation_selector_four", value: "ns\u180f"},
			{name: "hangul_filler_choseong", value: "ns\u115f"},
			{name: "hangul_filler_jungseong", value: "ns\u1160"},
			{name: "hangul_filler", value: "ns\u3164"},
			{name: "hangul_filler_halfwidth", value: "ns\uffa0"},
			{name: "combining_grapheme_joiner", value: "ns\u034f"},
			{name: "khmer_vowel_inherent_aq", value: "ns\u17b4"},
			{name: "khmer_vowel_inherent_aa", value: "ns\u17b5"},
			{name: "line_separator", value: "ns\u2028"},
			{name: "paragraph_separator", value: "ns\u2029"},
		} {
			t.Run("rejects_"+tc.name, func(t *testing.T) {
				in := strings.Replace(validEnvelopeJSON(), `"name": "ns",`, `"name": "`+tc.value+`",`, 1)
				_, _, err := DecodeJSONManifestEnvelope([]byte(in))
				require.Error(t, err)
			})
		}
	})

	t.Run("null_optional_fields_equal_absent", func(t *testing.T) {
		absent := validEnvelopeJSON()
		null := injectDNS(validEnvelopeJSON(), `null`)

		_, absentBytes, err := DecodeJSONManifestEnvelope([]byte(absent))
		require.NoError(t, err)
		_, nullBytes, err := DecodeJSONManifestEnvelope([]byte(null))
		require.NoError(t, err)
		assert.Equal(t, absentBytes, nullBytes)
	})
}

func TestReserializeJSONV2(t *testing.T) {
	env, manifestBytes, err := DecodeJSONManifestEnvelope(testdata.QosManifestEnvelopeV2JSON)
	require.NoError(t, err)

	again, err := CanonicalizeManifestJSONV2(&env.Manifest)
	require.NoError(t, err)
	assert.Equal(t, manifestBytes, again, "canonicalizing an already-decoded manifest twice must be stable")
}

func TestDecodeStrictJSONNestingDepth(t *testing.T) {
	deepArray := func(n int) string {
		return strings.Repeat("[", n) + strings.Repeat("]", n)
	}

	t.Run("at_limit_succeeds", func(t *testing.T) {
		_, err := decodeStrictJSON([]byte(deepArray(maxJSONNestingDepth)))
		require.NoError(t, err)
	})

	t.Run("one_past_limit_is_rejected", func(t *testing.T) {
		_, err := decodeStrictJSON([]byte(deepArray(maxJSONNestingDepth + 1)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "JSON nesting depth exceeds limit")
	})

	t.Run("far_past_limit_is_rejected_without_crashing", func(t *testing.T) {
		// Proves the guard fires well beyond the cap too, not just at cap+1.
		// A few hundred levels is enough to demonstrate the depth check
		// short-circuits recursion; the real DoS was only observable at
		// millions of levels, which is unnecessary to reproduce here.
		_, err := decodeStrictJSON([]byte(deepArray(maxJSONNestingDepth + 500)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "JSON nesting depth exceeds limit")
	})
}

func FuzzDecodeJSONEnvelope(f *testing.F) {
	f.Add(validEnvelopeJSON())
	f.Add(string(testdata.QosManifestEnvelopeV2JSON))
	f.Add(`{}`)
	f.Add(`not json`)

	f.Fuzz(func(t *testing.T, in string) {
		_, _, _ = DecodeJSONManifestEnvelope([]byte(in))
	})
}
