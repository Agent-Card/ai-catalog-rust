#!/usr/bin/env bash

# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ORAS_BIN="${ORAS_BIN:-oras}"
COSIGN_BIN="${COSIGN_BIN:-cosign}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

: "${COSIGN_PASSWORD:=}"
export COSIGN_PASSWORD
export AI_CATALOG_COSIGN_BIN="$COSIGN_BIN"

TRUST_MANIFEST_ARTIFACT_TYPE="application/vnd.ai-catalog.trust-manifest.v1+json"
COSIGN_SIGNATURE_ARTIFACT_TYPE="application/vnd.ai-catalog.cosign.signature.v1"
COSIGN_PUBLIC_KEY_ARTIFACT_TYPE="application/vnd.ai-catalog.cosign.public-key.v1"

step() {
	echo
	echo "== $1 =="
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required for this walkthrough" >&2
    exit 1
  fi
}

assert_discovery_contains_verification_material() {
  printf '%s\n' "$1" | grep -Fq "$TRUST_MANIFEST_ARTIFACT_TYPE"
  printf '%s\n' "$1" | grep -Fq "$COSIGN_SIGNATURE_ARTIFACT_TYPE"
  printf '%s\n' "$1" | grep -Fq "$COSIGN_PUBLIC_KEY_ARTIFACT_TYPE"
}

require_tool "$ORAS_BIN"
require_tool "$COSIGN_BIN"
require_tool "$PYTHON_BIN"

referrer_digest_by_type() {
  local discovery_json="$1"
  local artifact_type="$2"

  JSON_INPUT="$discovery_json" "$PYTHON_BIN" - "$artifact_type" <<'PY'
import json
import os
import sys

artifact_type = sys.argv[1]
payload = json.loads(os.environ["JSON_INPUT"])

for referrer in payload.get("referrers", []):
    if referrer.get("artifactType") == artifact_type:
        digest = referrer.get("digest")
        if not digest:
            raise SystemExit(f"missing digest for artifact type {artifact_type}")
        print(digest)
        raise SystemExit(0)

raise SystemExit(f"missing referrer for artifact type {artifact_type}")
PY
}

manifest_layer_digest() {
  local manifest_json="$1"

  JSON_INPUT="$manifest_json" "$PYTHON_BIN" - <<'PY'
import json
import os
import sys

payload = json.loads(os.environ["JSON_INPUT"])
layers = payload.get("layers", [])

if not layers:
    raise SystemExit("manifest has no layers")

digest = layers[0].get("digest")
if not digest:
    raise SystemExit("manifest layer is missing digest")

print(digest)
PY
}

manifest_annotation() {
  local manifest_json="$1"
  local key="$2"

  JSON_INPUT="$manifest_json" "$PYTHON_BIN" - "$key" <<'PY'
import json
import os
import sys

key = sys.argv[1]
payload = json.loads(os.environ["JSON_INPUT"])
annotations = payload.get("annotations", {})
value = annotations.get(key)

if value is None:
    raise SystemExit(f"missing annotation {key}")

print(value)
PY
}

print_cosign_verification_material() {
  local layout_path="$1"
  local discovery_json="$2"
  local signature_referrer_digest
  local public_key_referrer_digest
  local signature_manifest_json
  local public_key_manifest_json
  local signature_layer_digest
  local public_key_layer_digest
  local signature
  local public_key_identity
  local public_key

  signature_referrer_digest="$(referrer_digest_by_type "$discovery_json" "$COSIGN_SIGNATURE_ARTIFACT_TYPE")"
  public_key_referrer_digest="$(referrer_digest_by_type "$discovery_json" "$COSIGN_PUBLIC_KEY_ARTIFACT_TYPE")"
  signature_manifest_json="$($ORAS_BIN manifest fetch --oci-layout "${layout_path}@${signature_referrer_digest}")"
  public_key_manifest_json="$($ORAS_BIN manifest fetch --oci-layout "${layout_path}@${public_key_referrer_digest}")"
  signature_layer_digest="$(manifest_layer_digest "$signature_manifest_json")"
  public_key_layer_digest="$(manifest_layer_digest "$public_key_manifest_json")"
  signature="$($ORAS_BIN blob fetch --oci-layout --output - "${layout_path}@${signature_layer_digest}")"
  public_key_identity="$(manifest_annotation "$public_key_manifest_json" "ai-catalog.identity")"
  public_key="$($ORAS_BIN blob fetch --oci-layout --output - "${layout_path}@${public_key_layer_digest}")"

  echo "signature artifact digest: $signature_referrer_digest"
  echo "signature: $signature"
  echo "public key artifact digest: $public_key_referrer_digest"
  echo "public key identity: $public_key_identity"
  echo "public key:"
  printf '%s\n' "$public_key"
}

workspace_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_root="$(mktemp -d -t ai-catalog-demo)"
catalog_json="$tmp_root/trusted-catalog.json"
layout_dir="$tmp_root/layout"
copied_layout_dir="$tmp_root/copied-layout"
roundtrip_json="$tmp_root/roundtrip.json"
cosign_key_prefix="$tmp_root/cosign"
cosign_key="$cosign_key_prefix.key"
cosign_pub="$cosign_key_prefix.pub"
target_ref="example.com/ai-catalog-demo:walkthrough"

cleanup() {
	rm -rf "$tmp_root"
}

trap cleanup EXIT

cat > "$catalog_json" <<'EOF'
{
  "specVersion": "1.0",
  "metadata": {
    "demo": "oci-layout-walkthrough"
  },
  "entries": [
    {
      "identifier": "urn:example:inline",
      "displayName": "Inline Entry",
      "mediaType": "application/json",
      "data": {
        "name": "inline",
        "version": 1
      },
      "trustManifest": {
        "identity": "urn:example:inline"
      }
    }
  ]
}
EOF

cd "$workspace_root"

step "Validate the demo catalog"
cargo run -q -p ai-catalog-cli -- validate "$catalog_json"

step "Generate a temporary Cosign key pair"
"$COSIGN_BIN" generate-key-pair --output-key-prefix "$cosign_key_prefix"
ls "$cosign_key" "$cosign_pub"

step "Export a standard OCI image layout with Cosign verification artifacts"
cargo run -q -p ai-catalog-cli -- oci export-layout --tag walkthrough --cosign-key "$cosign_key" --cosign-public-key "$cosign_pub" "$catalog_json" "$layout_dir"
find "$layout_dir" -maxdepth 2 -type f | sort

step "Fetch the root catalog artifact with ORAS"
"$ORAS_BIN" manifest fetch --oci-layout "${layout_dir}:walkthrough" --descriptor

entry_digest="$({
  "$ORAS_BIN" manifest fetch --oci-layout "${layout_dir}:walkthrough"
} | grep -Eo '"digest":"[^"]+"' | head -n 1 | cut -d '"' -f 4)"

step "Discover trust-manifest, Cosign signature, and public-key referrers for the entry"
echo "entry digest: $entry_digest"
discover_output="$($ORAS_BIN discover --oci-layout "${layout_dir}@${entry_digest}" --format json)"
printf '%s\n' "$discover_output"
assert_discovery_contains_verification_material "$discover_output"

step "Print the detached Cosign signature and public key identity"
print_cosign_verification_material "$layout_dir" "$discover_output"

step "Import the OCI layout back into AI Catalog JSON"
cargo run -q -p ai-catalog-cli -- oci unpack-layout --ref-name walkthrough "$layout_dir" > "$roundtrip_json"
cat "$roundtrip_json"
echo "note: Cosign verification artifacts remain in the OCI layout as referrers and are not projected into AI Catalog JSON"

step "Validate the imported catalog"
cargo run -q -p ai-catalog-cli -- validate "$roundtrip_json"

step "Push the catalog into a second OCI layout with ORAS mediation and Cosign artifacts"
cargo run -q -p ai-catalog-cli -- oci push --cosign-key "$cosign_key" --cosign-public-key "$cosign_pub" "$catalog_json" "$target_ref" --to-oci-layout-path "$copied_layout_dir"
"$ORAS_BIN" manifest fetch "$target_ref" --oci-layout-path "$copied_layout_dir" --descriptor

step "Verify the copied layout still exposes the trust and Cosign referrers"
copied_discover_output="$($ORAS_BIN discover --oci-layout "${copied_layout_dir}@${entry_digest}" --format json)"
printf '%s\n' "$copied_discover_output"
assert_discovery_contains_verification_material "$copied_discover_output"

step "Print the copied Cosign signature and public key identity"
print_cosign_verification_material "$copied_layout_dir" "$copied_discover_output"

step "Walkthrough complete"
echo "temporary demo files were created under $tmp_root during execution"