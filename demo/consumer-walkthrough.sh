#!/usr/bin/env bash

# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

# Consumer workflow walkthrough for ai-catalog.
#
# Covers the full CLI surface:
#   Author:   validate (text/json/stdin), format, trust inspect (text/json)
#   Consumer: catalog add/list/update/remove, search (text/json/regex/limit),
#             show (text/json/scoped), pull (inline-data/file-url)
#
# Runs entirely offline using file:// URLs.
# Uses AI_CATALOG_CACHE_DIR to keep all state in a temp directory so the
# walkthrough never touches the user's ~/.ai-catalog/ registry.

set -euo pipefail

step() {
    echo
    echo "== $* =="
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: $1 is required for this walkthrough" >&2
        exit 1
    fi
}

run_cli() {
    cargo run -q -p ai-catalog-cli -- "$@"
}

require_tool cargo

workspace_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_root="$(mktemp -d -t ai-catalog-consumer-demo)"
export AI_CATALOG_CACHE_DIR="$tmp_root/cache"

cleanup() {
    rm -rf "$tmp_root"
}
trap cleanup EXIT

cd "$workspace_root"

# ── Write fixture files ───────────────────────────────────────────────────────

eval_suite_path="$tmp_root/eval-suite-v3.jsonl"
nested_catalog_path="$tmp_root/datasets-catalog.json"
root_catalog_path="$tmp_root/demo-catalog.json"
pull_dir="$tmp_root/pulled"
mkdir -p "$pull_dir"

# A small pullable artifact (JSONL file) referenced by the nested catalog
cat > "$eval_suite_path" <<'EOF'
{"prompt": "What is 2+2?", "expected": "4"}
{"prompt": "Translate 'hello' to French", "expected": "bonjour"}
{"prompt": "Summarise the A2A protocol in one sentence", "expected": "A2A enables AI agents to communicate using JSON-RPC 2.0 over HTTP."}
EOF

# Nested catalog with two dataset entries
cat > "$nested_catalog_path" <<EOF
{
  "specVersion": "1.0",
  "host": {
    "displayName": "Demo Dataset Registry"
  },
  "entries": [
    {
      "identifier": "urn:demo:dataset:training-corpus-2025",
      "displayName": "Training Corpus 2025",
      "type": "application/parquet",
      "description": "Curated instruction-following dataset for 2025 model training",
      "tags": ["dataset", "training", "instruction-following", "nlp"],
      "url": "https://example.com/datasets/training-corpus-2025.parquet"
    },
    {
      "identifier": "urn:demo:dataset:eval-suite-v3",
      "displayName": "Evaluation Suite v3",
      "type": "application/jsonl",
      "description": "Benchmark prompt/answer pairs for language model evaluation",
      "tags": ["dataset", "evaluation", "benchmark", "nlp"],
      "url": "file://${eval_suite_path}"
    }
  ]
}
EOF

# Root catalog with three leaf entries (agent, model, inline-config) and a
# nested catalog reference that points at the datasets catalog above
cat > "$root_catalog_path" <<EOF
{
  "specVersion": "1.0",
  "host": {
    "displayName": "Demo AI Registry",
    "identifier": "did:example:demo-registry",
    "documentationUrl": "https://docs.example.com/ai-registry"
  },
  "entries": [
    {
      "identifier": "urn:demo:agent:conversational-v1",
      "displayName": "Conversational Agent v1",
      "type": "application/a2a-agent-card+json",
      "description": "A general-purpose conversational AI agent implementing the A2A protocol",
      "tags": ["agent", "chat", "nlp", "a2a"],
      "url": "https://example.com/agents/conversational-v1.json",
      "version": "1.0.0",
      "trustManifest": {
        "identity": "urn:demo:agent:conversational-v1",
        "identityType": "urn"
      }
    },
    {
      "identifier": "urn:demo:model:embeddings-v2",
      "displayName": "Embeddings Model v2",
      "type": "application/gguf",
      "description": "Lightweight 128-dimensional text embedding model",
      "tags": ["model", "embeddings", "nlp"],
      "url": "https://example.com/models/embeddings-v2.gguf",
      "version": "2.0.0"
    },
    {
      "identifier": "urn:demo:config:default-settings",
      "displayName": "Default Agent Settings",
      "type": "application/json",
      "description": "Shared default configuration for all demo agents",
      "tags": ["config", "settings"],
      "data": {
        "timeout_ms": 30000,
        "max_retries": 3,
        "log_level": "info",
        "supported_protocols": ["a2a", "rest"]
      }
    },
    {
      "identifier": "urn:demo:catalog:datasets",
      "displayName": "Demo Dataset Catalog",
      "type": "application/ai-catalog+json",
      "description": "Nested catalog of training and evaluation datasets",
      "url": "file://${nested_catalog_path}"
    }
  ]
}
EOF

# ── Author commands ───────────────────────────────────────────────────────────

step "1. Validate the catalog (text output)"
run_cli validate "$root_catalog_path"

step "2. Validate the catalog (JSON output)"
run_cli validate --json "$root_catalog_path"

step "3. Validate from stdin"
run_cli validate --json - < "$root_catalog_path"

step "4. Format / pretty-print the catalog"
run_cli format "$root_catalog_path"

step "5. Inspect trust manifests (text output)"
run_cli trust inspect "$root_catalog_path"

step "6. Inspect trust manifests (JSON output)"
run_cli trust inspect --json "$root_catalog_path"

# ── Consumer commands: catalog management ─────────────────────────────────────

step "7. Register the catalog (fetches and caches locally)"
run_cli catalog add demo-registry "file://$root_catalog_path"

step "8. List registered catalogs (text)"
run_cli catalog list

step "9. List registered catalogs (JSON)"
run_cli catalog list --json

# ── Consumer commands: search ─────────────────────────────────────────────────

step "10. Search by keyword: 'agent' (text table)"
run_cli search agent

step "11. Search by keyword: 'dataset' (JSON output)"
run_cli search --json dataset

step "12. Search with regex: A2A agents and datasets"
run_cli search --regex "urn:demo:(agent|dataset).*"

step "13. Search with result limit (-n 2)"
run_cli search -n 2 nlp

# ── Consumer commands: show ───────────────────────────────────────────────────

step "14. Show entry details (text table): conversational agent"
run_cli show urn:demo:agent:conversational-v1

step "15. Show entry details (JSON): conversational agent"
run_cli show --json urn:demo:agent:conversational-v1

step "16. Show entry scoped to a specific registered catalog"
run_cli show --scope demo-registry urn:demo:dataset:eval-suite-v3

# ── Consumer commands: pull ───────────────────────────────────────────────────

step "17. Pull inline-data entry (config) to disk"
run_cli pull --output "$pull_dir" urn:demo:config:default-settings
echo "pulled file:"
cat "$pull_dir/default-settings.json"

step "18. Pull file-URL entry (eval suite JSONL) to disk"
run_cli pull --output "$pull_dir" urn:demo:dataset:eval-suite-v3
echo "pulled file:"
cat "$pull_dir/eval-suite-v3.json"

# ── Consumer commands: update and remove ─────────────────────────────────────

step "19. Update the catalog (content unchanged — reports 'up to date')"
run_cli catalog update demo-registry

step "20. Remove the catalog from the local registry"
run_cli catalog remove demo-registry

step "21. List catalogs after removal"
run_cli catalog list

step "Consumer walkthrough complete"
echo "all temporary files were cleaned up from $tmp_root"
