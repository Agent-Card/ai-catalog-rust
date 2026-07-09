#!/usr/bin/env bash

# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# ---------------------------------------------------------------------------
# Prerequisites: cosign and oras must be on PATH (or set COSIGN_BIN / ORAS_BIN).
# ---------------------------------------------------------------------------
COSIGN_BIN="${COSIGN_BIN:-cosign}"
ORAS_BIN="${ORAS_BIN:-oras}"

: "${COSIGN_PASSWORD:=}"
export COSIGN_PASSWORD
export AI_CATALOG_COSIGN_BIN="$COSIGN_BIN"
export AI_CATALOG_ORAS_BIN="$ORAS_BIN"

TRUST_MANIFEST_ARTIFACT_TYPE="application/vnd.ai-catalog.trust-manifest.v1+json"
COSIGN_SIGNATURE_ARTIFACT_TYPE="application/vnd.ai-catalog.cosign.signature.v1"
COSIGN_PUBLIC_KEY_ARTIFACT_TYPE="application/vnd.ai-catalog.cosign.public-key.v1"

step() {
    echo
    echo "══════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "══════════════════════════════════════════════════════════════"
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: '$1' is required for this walkthrough" >&2
        exit 1
    fi
}

require_tool "$COSIGN_BIN"
require_tool "$ORAS_BIN"
require_tool cargo

# ---------------------------------------------------------------------------
# Helpers for parsing OCI manifests without jq
# ---------------------------------------------------------------------------

compact_json() {
    local payload="$1"
    payload="${payload//$'\n'/}"
    payload="${payload//$'\r'/}"
    printf '%s\n' "$payload"
}

first_digest_in_array() {
    local payload="$1"
    local array_key="$2"
    local compact remainder digest quote='"'

    compact="$(compact_json "$payload")"
    if [[ "$compact" != *"\"${array_key}\":["* ]]; then
        echo "missing array ${array_key}" >&2; exit 1
    fi
    remainder="${compact#*"\"${array_key}\":["}"
    if [[ "$remainder" != *'"digest":"'* ]]; then
        echo "missing digest in ${array_key}" >&2; exit 1
    fi
    remainder="${remainder#*'"digest":"'}"
    digest="${remainder%%${quote}*}"
    printf '%s\n' "$digest"
}

manifest_layer_digest() {
    first_digest_in_array "$1" "layers"
}

manifest_config_digest() {
    local manifest_json="$1"
    local compact quote='"'
    compact="$(compact_json "$manifest_json")"
    if [[ "$compact" != *'"config":{"'* ]]; then
        echo "missing config object in manifest" >&2; exit 1
    fi
    local remainder="${compact#*'"config":{"'}"
    # skip any keys before "digest"
    remainder="${remainder#*'"digest":"'}"
    printf '%s\n' "${remainder%%${quote}*}"
}

discover_referrer_digest_by_type() {
    local subject_ref="$1"
    local artifact_type="$2"
    local digest

    digest="$("$ORAS_BIN" discover \
        --oci-layout "$subject_ref" \
        --format go-template \
        --template "{{range .referrers}}{{if eq (index . \"artifactType\") \"$artifact_type\"}}{{println (index . \"digest\")}}{{end}}{{end}}")"
    digest="${digest%%$'\n'*}"

    if [[ -z "$digest" ]]; then
        echo "error: no referrer of type '$artifact_type' found" >&2; exit 1
    fi
    printf '%s\n' "$digest"
}

# ---------------------------------------------------------------------------
# Temp workspace
# ---------------------------------------------------------------------------
workspace_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_root="$(mktemp -d -t ai-catalog-trust-demo)"
catalog_json="$tmp_root/catalog.json"
layout_dir="$tmp_root/layout"
cosign_prefix="$tmp_root/cosign"
cosign_key="${cosign_prefix}.key"
cosign_pub="${cosign_prefix}.pub"

cleanup() { rm -rf "$tmp_root"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Catalog with two entries: one with a trust manifest, one without
# ---------------------------------------------------------------------------
cat > "$catalog_json" <<'EOF'
{
  "specVersion": "1.0",
  "host": {
    "displayName": "Demo Trust Publisher",
    "identifier": "did:web:demo.example.com",
    "trustManifest": {
      "identity": "did:web:demo.example.com"
    }
  },
  "entries": [
    {
      "identifier": "urn:demo:agent:trusted-v1",
      "displayName": "Trusted Demo Agent",
      "type": "application/a2a-agent-card+json",
      "description": "An A2A agent whose trust manifest will be signed in this walkthrough",
      "url": "https://example.com/agents/trusted-v1.json",
      "trustManifest": {
        "identity": "urn:demo:agent:trusted-v1",
        "trustSchema": {
          "identifier": "urn:ai-catalog:trust-schema:minimal:v1",
          "version": "1.0"
        }
      }
    },
    {
      "identifier": "urn:demo:model:unsigned",
      "displayName": "Unsigned Model",
      "type": "application/gguf",
      "description": "A model entry with no trust manifest — Minimal conformance only",
      "url": "https://example.com/models/unsigned.gguf"
    }
  ]
}
EOF

cd "$workspace_root"

# ── Step 1 ─────────────────────────────────────────────────────────────────
step "1. Validate the catalog"
cargo run -q -p ai-catalog-cli -- validate "$catalog_json"
echo "✓ catalog is spec-compliant"

# ── Step 2 ─────────────────────────────────────────────────────────────────
step "2. Inspect trust manifests BEFORE signing"
cargo run -q -p ai-catalog-cli -- trust inspect "$catalog_json"
echo
echo "→ host and first entry have trust manifests; neither has a signature yet"

# ── Step 3 ─────────────────────────────────────────────────────────────────
step "3. Generate an ephemeral Cosign key pair"
"$COSIGN_BIN" generate-key-pair --output-key-prefix "$cosign_prefix"
echo
echo "Generated:"
echo "  private key : $cosign_key"
echo "  public key  : $cosign_pub"
cat "$cosign_pub"

# ── Step 4 ─────────────────────────────────────────────────────────────────
step "4. Sign — export to OCI image layout with Cosign verification artifacts"
cargo run -q -p ai-catalog-cli -- \
    oci export-layout \
    --tag trust-demo \
    --cosign-key "$cosign_key" \
    --cosign-public-key "$cosign_pub" \
    "$catalog_json" \
    "$layout_dir"

echo
echo "OCI layout contents:"
find "$layout_dir" -type f | sort

# ── Step 5 ─────────────────────────────────────────────────────────────────
step "5. Inspect the root OCI manifest to find the signed entry"
root_manifest_json="$("$ORAS_BIN" manifest fetch --oci-layout "${layout_dir}:trust-demo")"
printf '%s\n' "$root_manifest_json"

entry_digest="$(first_digest_in_array "$root_manifest_json" "manifests")"
echo
echo "→ signed entry digest: $entry_digest"

# ── Step 6 ─────────────────────────────────────────────────────────────────
step "6. Discover referrers attached to the signed entry"
"$ORAS_BIN" discover \
    --oci-layout "${layout_dir}@${entry_digest}" \
    --format json | tee /dev/null
"$ORAS_BIN" discover \
    --oci-layout "${layout_dir}@${entry_digest}" \
    --format tree
echo
echo "→ three referrers expected: trust-manifest · cosign-signature · cosign-public-key"

# ── Step 7 ─────────────────────────────────────────────────────────────────
step "7. Extract the canonical trust manifest payload from the OCI layout"
tm_referrer_digest="$(discover_referrer_digest_by_type \
    "${layout_dir}@${entry_digest}" "$TRUST_MANIFEST_ARTIFACT_TYPE")"
tm_manifest_json="$("$ORAS_BIN" manifest fetch --oci-layout "${layout_dir}@${tm_referrer_digest}")"
# Trust manifest payload is stored in the OCI config blob (layers are empty for this referrer type)
tm_config_digest="$(manifest_config_digest "$tm_manifest_json")"

payload_file="$tmp_root/canonical-trust-manifest.json"
"$ORAS_BIN" blob fetch --oci-layout --output "$payload_file" "${layout_dir}@${tm_config_digest}"

echo "Canonical trust manifest (key-sorted JSON, no 'signature' field):"
cat "$payload_file"

# ── Step 8 ─────────────────────────────────────────────────────────────────
step "8. Extract the detached Cosign signature from the OCI layout"
sig_referrer_digest="$(discover_referrer_digest_by_type \
    "${layout_dir}@${entry_digest}" "$COSIGN_SIGNATURE_ARTIFACT_TYPE")"
sig_manifest_json="$("$ORAS_BIN" manifest fetch --oci-layout "${layout_dir}@${sig_referrer_digest}")"
sig_layer_digest="$(manifest_layer_digest "$sig_manifest_json")"

sig_file="$tmp_root/trust-manifest.sig"
"$ORAS_BIN" blob fetch --oci-layout --output "$sig_file" "${layout_dir}@${sig_layer_digest}"

echo "Detached signature (base64):"
cat "$sig_file"

# ── Step 9 ─────────────────────────────────────────────────────────────────
step "9. Verify the signature with Cosign"
echo "Running: cosign verify-blob --key cosign.pub --signature <sig> <payload>"
echo
if "$COSIGN_BIN" verify-blob \
    --key "$cosign_pub" \
    --signature "$sig_file" \
    "$payload_file"; then
    echo
    echo "✓ Signature is VALID — the trust manifest has not been tampered with"
else
    echo
    echo "✗ Signature verification FAILED" >&2
    exit 1
fi

# ── Step 10 ────────────────────────────────────────────────────────────────
step "10. Demonstrate tamper detection — modify the payload and re-verify"
tampered_file="$tmp_root/tampered-trust-manifest.json"
# Replace the identity value with a different string
sed 's/urn:demo:agent:trusted-v1/urn:attacker:agent:evil/g' "$payload_file" > "$tampered_file"

echo "Tampered payload:"
cat "$tampered_file"
echo

echo "Running verify against tampered payload (expect: FAIL):"
if "$COSIGN_BIN" verify-blob \
    --key "$cosign_pub" \
    --signature "$sig_file" \
    "$tampered_file" 2>&1; then
    echo "✗ Tamper detection failed — verification should have rejected the payload" >&2
    exit 1
else
    echo
    echo "✓ Tamper correctly detected — cosign rejected the modified manifest"
fi

# ── Step 11 ────────────────────────────────────────────────────────────────
step "11. Inspect trust manifests in the re-imported catalog"
roundtrip_json="$tmp_root/roundtrip.json"
cargo run -q -p ai-catalog-cli -- \
    oci unpack-layout --ref-name trust-demo "$layout_dir" > "$roundtrip_json"

cargo run -q -p ai-catalog-cli -- trust inspect "$roundtrip_json"
echo
echo "→ trust manifests are preserved after round-trip through OCI"
echo "→ cosign signature artifacts remain in the OCI layout as referrers"
echo "   (they are not embedded into the AI Catalog JSON format)"

step "Walkthrough complete"
echo "Summary:"
echo "  catalog validated            ✓"
echo "  trust manifests inspected    ✓"
echo "  cosign key pair generated    ✓"
echo "  trust manifests signed       ✓  (via oci export-layout --cosign-key)"
echo "  OCI referrer tree discovered ✓  (trust-manifest · signature · public-key)"
echo "  signature verified           ✓  (cosign verify-blob)"
echo "  tamper detection confirmed   ✓"
echo "  catalog round-tripped        ✓  (oci unpack-layout)"
echo
echo "Temporary files were written to: $tmp_root (deleted on exit)"
