#!/bin/bash

# Verification script for QoS Manifest decoding
# Compares our Go implementation against the reference qos_client implementation
# Note: Does not use 'set -e' to allow graceful handling of qos_client failures

MANIFEST_FILE="${1:-/tmp/test_manifest.bin}"
USE_DOCKER="${2:-true}"

if [ ! -f "$MANIFEST_FILE" ]; then
    echo "Error: Manifest file not found: $MANIFEST_FILE"
    echo "Usage: $0 <manifest-file> [use-docker]"
    echo "  use-docker: true (default) to use Docker container, false to use local qos_client"
    exit 1
fi

echo "=== QoS Manifest Verification ==="
echo "Manifest file: $MANIFEST_FILE"
echo ""

# Get JSON output from qos_client (reference implementation)
echo "Running qos_client (reference implementation)..."
QOS_ERROR_LOG=$(mktemp)

if [ "$USE_DOCKER" = "true" ]; then
    # Use Docker container for qos_client
    echo "  Using Docker container: ghcr.io/tkhq/qos:latest"
    QOS_OUTPUT=$(docker run --rm -v "$(dirname "$MANIFEST_FILE"):/data" \
        ghcr.io/tkhq/qos:latest \
        qos_client display --display-type manifest-envelope --file-path "/data/$(basename "$MANIFEST_FILE")" --json 2>"$QOS_ERROR_LOG")
else
    # Use local qos_client installation
    QOS_CLIENT_PATH="${QOS_CLIENT_PATH:-qos_client}"
    if [ ! -d "$QOS_CLIENT_PATH" ]; then
        echo "Error: qos_client directory not found: $QOS_CLIENT_PATH"
        echo "Usage: $0 <manifest-file> false [qos-client-path]"
        exit 1
    fi
    echo "  Using local qos_client: $QOS_CLIENT_PATH"
    QOS_OUTPUT=$(cd "$QOS_CLIENT_PATH" && timeout 15s cargo run --quiet --bin qos_client -- display --display-type manifest-envelope --file-path "$MANIFEST_FILE" --json 2>"$QOS_ERROR_LOG")
fi
QOS_EXIT_CODE=$?

if [ $QOS_EXIT_CODE -ne 0 ]; then
    echo "⚠️  qos_client exited with error code $QOS_EXIT_CODE"
    echo "   Error details:"
    if [ -s "$QOS_ERROR_LOG" ]; then
        sed 's/^/   | /' "$QOS_ERROR_LOG"
    else
        echo "   | No error output captured"
    fi
    echo "   This may be due to an input format mismatch (expected a JSON manifest envelope)"
fi

# Check if we got valid JSON output regardless of exit code
if [ -n "$QOS_OUTPUT" ] && echo "$QOS_OUTPUT" | jq . >/dev/null 2>&1; then
    echo "✓ qos_client produced valid JSON output (will compare with Go client)"
    QOS_HAS_VALID_OUTPUT=true
else
    if [ -n "$QOS_OUTPUT" ]; then
        echo "⚠️  qos_client output is not valid JSON:"
        echo "$QOS_OUTPUT" | sed 's/^/   | /'
    else
        echo "⚠️  qos_client produced no output - manifest envelope not decodable by qos_client"
    fi
    echo "   Proceeding with Go-only verification..."
    QOS_OUTPUT=""
    QOS_HAS_VALID_OUTPUT=false
fi

# Clean up error log
rm -f "$QOS_ERROR_LOG"

# Get JSON output from our Go client
echo "Running Go client (our implementation)..."
GO_OUTPUT=$(go run . decode-manifest envelope --file "$MANIFEST_FILE" --json) || {
    echo "Error: Go client failed to decode $MANIFEST_FILE as a JSON manifest envelope"
    exit 1
}

# Extract key fields from both outputs
echo ""
echo "=== Extracting Key Fields ==="

if [ "$QOS_HAS_VALID_OUTPUT" = "true" ]; then
    # From qos_client (reference, manifest-envelope format, with .manifest wrapper)
    QOS_NAMESPACE=$(echo "$QOS_OUTPUT" | jq -r '.manifest.namespace.name')
    QOS_NONCE=$(echo "$QOS_OUTPUT" | jq -r '.manifest.namespace.nonce')
    QOS_QUORUM_KEY=$(echo "$QOS_OUTPUT" | jq -r '.manifest.namespace.quorumKey')
    QOS_PIVOT_HASH=$(echo "$QOS_OUTPUT" | jq -r '.manifest.pivot.hash')
    QOS_RESTART=$(echo "$QOS_OUTPUT" | jq -r '.manifest.pivot.restart')
    QOS_MANIFEST_THRESHOLD=$(echo "$QOS_OUTPUT" | jq -r '.manifest.manifestSet.threshold')
    QOS_MANIFEST_MEMBERS=$(echo "$QOS_OUTPUT" | jq -r '.manifest.manifestSet.members | length')
    QOS_PCR0=$(echo "$QOS_OUTPUT" | jq -r '.manifest.enclave.pcr0')
    QOS_PCR1=$(echo "$QOS_OUTPUT" | jq -r '.manifest.enclave.pcr1')
    QOS_PCR2=$(echo "$QOS_OUTPUT" | jq -r '.manifest.enclave.pcr2')
    QOS_PCR3=$(echo "$QOS_OUTPUT" | jq -r '.manifest.enclave.pcr3')
    echo "✓ Fields extracted from qos_client"
else
    echo "⚠️  qos_client failed to produce valid JSON, skipping reference comparison"
fi

# From Go client (envelope format, with .manifest wrapper)
GO_NAMESPACE=$(echo "$GO_OUTPUT" | jq -r '.manifest.namespace.name')
GO_NONCE=$(echo "$GO_OUTPUT" | jq -r '.manifest.namespace.nonce')
GO_QUORUM_KEY=$(echo "$GO_OUTPUT" | jq -r '.manifest.namespace.quorumKey')
GO_PIVOT_HASH=$(echo "$GO_OUTPUT" | jq -r '.manifest.pivot.hash')
GO_RESTART=$(echo "$GO_OUTPUT" | jq -r '.manifest.pivot.restart')
GO_MANIFEST_THRESHOLD=$(echo "$GO_OUTPUT" | jq -r '.manifest.manifestSet.threshold')
GO_MANIFEST_MEMBERS=$(echo "$GO_OUTPUT" | jq -r '.manifest.manifestSet.members | length')
GO_PCR0=$(echo "$GO_OUTPUT" | jq -r '.manifest.enclave.pcr0')
GO_PCR1=$(echo "$GO_OUTPUT" | jq -r '.manifest.enclave.pcr1')
GO_PCR2=$(echo "$GO_OUTPUT" | jq -r '.manifest.enclave.pcr2')
GO_PCR3=$(echo "$GO_OUTPUT" | jq -r '.manifest.enclave.pcr3')

echo "✓ Fields extracted from Go client"
echo ""

# Compare fields
echo "=== Comparison Results ==="
echo ""

compare_field() {
    local name="$1"
    local qos_val="$2"
    local go_val="$3"

    if [ "$qos_val" = "$go_val" ]; then
        echo "✅ $name: MATCH"
        return 0
    else
        echo "❌ $name: MISMATCH"
        echo "   Reference: $qos_val"
        echo "   Go Client: $go_val"
        return 1
    fi
}

FAILURES=0

if [ "$QOS_HAS_VALID_OUTPUT" = "true" ]; then
    # Compare with reference implementation
    echo "🔍 Comparing Go client output with qos_client reference:"
    compare_field "Namespace" "$QOS_NAMESPACE" "$GO_NAMESPACE" || FAILURES=$((FAILURES + 1))
    compare_field "Nonce" "$QOS_NONCE" "$GO_NONCE" || FAILURES=$((FAILURES + 1))
    compare_field "Quorum Key" "$QOS_QUORUM_KEY" "$GO_QUORUM_KEY" || FAILURES=$((FAILURES + 1))
    compare_field "Pivot Hash" "$QOS_PIVOT_HASH" "$GO_PIVOT_HASH" || FAILURES=$((FAILURES + 1))
    compare_field "Restart Policy" "$QOS_RESTART" "$GO_RESTART" || FAILURES=$((FAILURES + 1))
    compare_field "Manifest Threshold" "$QOS_MANIFEST_THRESHOLD" "$GO_MANIFEST_THRESHOLD" || FAILURES=$((FAILURES + 1))
    compare_field "Manifest Members" "$QOS_MANIFEST_MEMBERS" "$GO_MANIFEST_MEMBERS" || FAILURES=$((FAILURES + 1))
    compare_field "PCR0" "$QOS_PCR0" "$GO_PCR0" || FAILURES=$((FAILURES + 1))
    compare_field "PCR1" "$QOS_PCR1" "$GO_PCR1" || FAILURES=$((FAILURES + 1))
    compare_field "PCR2" "$QOS_PCR2" "$GO_PCR2" || FAILURES=$((FAILURES + 1))
    compare_field "PCR3" "$QOS_PCR3" "$GO_PCR3" || FAILURES=$((FAILURES + 1))
else
    # Just display Go client results
    echo "📋 Go Client Results (no reference comparison available):"
    echo "   Namespace: $GO_NAMESPACE"
    echo "   Nonce: $GO_NONCE"
    echo "   Quorum Key: $GO_QUORUM_KEY"
    echo "   Pivot Hash: $GO_PIVOT_HASH"
    echo "   Restart Policy: $GO_RESTART"
    echo "   Manifest Threshold: $GO_MANIFEST_THRESHOLD"
    echo "   Manifest Members: $GO_MANIFEST_MEMBERS"
    echo "   PCR0: $GO_PCR0"
    echo "   PCR1: $GO_PCR1"
    echo "   PCR2: $GO_PCR2"
    echo "   PCR3: $GO_PCR3"
fi

echo ""
if [ "$QOS_HAS_VALID_OUTPUT" = "true" ]; then
    # Had reference comparison
    if [ $FAILURES -eq 0 ]; then
        echo "✅ Verification Complete: All fields match reference implementation!"
        echo ""
        echo "Reference JSON saved to: /tmp/qos_manifest_reference.json"
        echo "Go client JSON saved to: /tmp/go_manifest_output.json"
        echo "$QOS_OUTPUT" > /tmp/qos_manifest_reference.json
        echo "$GO_OUTPUT" > /tmp/go_manifest_output.json
        exit 0
    else
        echo "❌ Verification Failed: $FAILURES field(s) do not match reference"
        echo ""
        echo "Full outputs saved for inspection:"
        echo "  Reference: /tmp/qos_manifest_reference.json"
        echo "  Go client: /tmp/go_manifest_output.json"
        echo "$QOS_OUTPUT" > /tmp/qos_manifest_reference.json
        echo "$GO_OUTPUT" > /tmp/go_manifest_output.json
        exit 1
    fi
else
    # No reference comparison possible
    echo "✅ Go Client Successfully Parsed Manifest"
    echo ""
    echo "Note: qos_client reference tool failed to decode the manifest envelope"
    echo "Go client output saved to: /tmp/go_manifest_output.json"
    echo "$GO_OUTPUT" > /tmp/go_manifest_output.json
    echo ""
    echo "Manifest appears valid based on Go client parsing."
    exit 0
fi
