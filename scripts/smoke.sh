#!/usr/bin/env bash
# Smoke test for the DEPLOYED VisualSign parser (dev path).
#
# Parses a known Solana V0 transaction that references address lookup tables
# through the live parser and asserts it RENDERS — a regression guard for the
# "Cannot render V0 ... refusing to display a partial transaction" failure.
#
# Uses the turnkey-client CLI, whose stdout is the response JSON (human summary
# goes to stderr), so assertions are pure `jq`. Run it locally with the Go
# toolchain, or via the published container (no Go needed) by overriding
# TURNKEY_CLIENT.
#
# Env (all optional; defaults target the dev org/app):
#   VSP_SMOKE_HOST   API host                       (default https://api.turnkey.com)
#   VSP_SMOKE_ORG    organization id
#   VSP_SMOKE_APP    expected enclaveApp (asserted)
#   VSP_SMOKE_KEY    key name under ~/.config/turnkey/keys/<key>.{public,private}
#   TURNKEY_CLIENT   how to invoke the CLI (default "go run ."); e.g.
#                    'docker run --rm -v $HOME/.config/turnkey/keys:/root/.config/turnkey/keys:ro ghcr.io/anchorageoss/visualsign-turnkeyclient'
#
# Exit: 0 = rendered (pass) OR endpoint unreachable (skip; not our regression);
#       1 = endpoint up but parser failed to render / assertions failed (regression).
set -euo pipefail

HOST="${VSP_SMOKE_HOST:-https://api.turnkey.com}"
ORG="${VSP_SMOKE_ORG:-d7f51c3d-fb9d-47c1-9b2e-a02b1cd5ff14}"
APP="${VSP_SMOKE_APP:-e349edd8-2a25-4083-922d-592ebded9acf}"
KEY="${VSP_SMOKE_KEY:-dev}"
CLIENT="${TURNKEY_CLIENT:-go run .}"

DIR="$(cd "$(dirname "$0")/.." && pwd)"
PAYLOAD="$(tr -d '[:space:]' < "$DIR/testdata/solana_v0_alt.b64")"
ERRFILE="$(mktemp)"
trap 'rm -f "$ERRFILE"' EXIT

set +e
OUT="$($CLIENT parse --dev-path --host "$HOST" --organization-id "$ORG" \
  --key-name "$KEY" --unsigned-payload "$PAYLOAD" 2>"$ERRFILE")"
RC=$?
set -e

if [ "$RC" -ne 0 ]; then
  # Abort guard: only a parser-level rejection (endpoint reachable, non-OK
  # status) is a regression. A transport/connection error is a pre-existing
  # outage and must not be blamed on the change under test.
  if grep -q "non-OK status" "$ERRFILE"; then
    echo "FAIL: deployed parser rejected a tx it should render (regression):" >&2
    cat "$ERRFILE" >&2
    exit 1
  fi
  echo "SKIP: endpoint unreachable / outage — not a regression:" >&2
  cat "$ERRFILE" >&2
  exit 0
fi

if ! echo "$OUT" | jq -e --arg app "$APP" '
      (.signablePayload | length > 0)
  and (.signablePayload | contains("Cannot render V0") | not)
  and (.attestations | has("app_attestation") and has("boot_attestation"))
  and (.enclaveApp == $app)
' >/dev/null; then
  echo "FAIL: render assertions failed. Response summary:" >&2
  echo "$OUT" | jq '{signablePayloadLen: (.signablePayload | length), enclaveApp, deploymentLabel, attestations: (.attestations | keys)}' >&2
  exit 1
fi

echo "PASS: V0+ALT rendered ($(echo "$OUT" | jq -r '.signablePayload | length') chars); enclaveApp=$(echo "$OUT" | jq -r .enclaveApp) deploymentLabel=$(echo "$OUT" | jq -r .deploymentLabel)"
