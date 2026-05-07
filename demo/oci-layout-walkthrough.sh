#!/usr/bin/env bash

# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

step() {
	echo
	echo "== $1 =="
}

if ! command -v oras >/dev/null 2>&1; then
	echo "oras is required for this walkthrough" >&2
	exit 1
fi

workspace_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_root="$(mktemp -d -t ai-catalog-demo)"
catalog_json="$tmp_root/trusted-catalog.json"
layout_dir="$tmp_root/layout"
copied_layout_dir="$tmp_root/copied-layout"
roundtrip_json="$tmp_root/roundtrip.json"
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

step "Export a standard OCI image layout"
cargo run -q -p ai-catalog-cli -- oci export-layout --tag walkthrough "$catalog_json" "$layout_dir"
find "$layout_dir" -maxdepth 2 -type f | sort

step "Fetch the root catalog artifact with ORAS"
oras manifest fetch --oci-layout "${layout_dir}:walkthrough" --descriptor

entry_digest="$({
	oras manifest fetch --oci-layout "${layout_dir}:walkthrough"
} | grep -Eo '"digest":"[^"]+"' | head -n 1 | cut -d '"' -f 4)"

step "Discover trust-manifest referrers for the entry"
echo "entry digest: $entry_digest"
oras discover --oci-layout "${layout_dir}@${entry_digest}" --format json

step "Import the OCI layout back into AI Catalog JSON"
cargo run -q -p ai-catalog-cli -- oci unpack-layout --ref-name walkthrough "$layout_dir" > "$roundtrip_json"
cat "$roundtrip_json"

step "Validate the imported catalog"
cargo run -q -p ai-catalog-cli -- validate "$roundtrip_json"

step "Push the catalog into a second OCI layout with ORAS mediation"
cargo run -q -p ai-catalog-cli -- oci push "$catalog_json" "$target_ref" --to-oci-layout-path "$copied_layout_dir"
oras manifest fetch "$target_ref" --oci-layout-path "$copied_layout_dir" --descriptor

step "Verify the copied layout still exposes the trust referrer"
oras discover --oci-layout "${copied_layout_dir}@${entry_digest}" --format json

step "Walkthrough complete"
echo "temporary demo files were created under $tmp_root during execution"