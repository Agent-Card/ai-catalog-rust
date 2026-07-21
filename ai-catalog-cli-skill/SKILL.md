---
name: ai-catalog-cli
description: Use this skill whenever the user wants to discover, inspect, validate, or install AI resources — MCP servers, A2A agents, agent skills, or other AI artifacts — from an AI Catalog. Triggers include requests to find an MCP server, add an MCP server to Claude, install an agent skill, find or connect to an A2A agent, browse available AI tools, search a catalog, validate a catalog document, or work with OCI-packaged catalogs.
license: Apache-2.0
compatibility: Requires the `ai-catalog` binary on PATH. Install with `cargo install --git https://github.com/agntcy/ai-catalog-rust`.
metadata:
  author: ai-catalog-rust
  version: "0.1"
---

# AI Catalog CLI

`ai-catalog` is a command-line tool for discovering, validating, and pulling resources from AI Catalogs — typed JSON documents (`application/ai-catalog+json`) that index MCP servers, A2A agents, agent skills, and other AI artifacts.

## Core concepts

- **Catalog** — a remote JSON file (`application/ai-catalog+json`) that lists typed entries. Catalogs can nest other catalogs (fetched up to 4 levels deep).
- **Entry** — a single item in a catalog with an `identifier` (URN), a `type` (MIME type), and a `url` pointing to the artifact.
- **Registry** — the local list of catalogs registered via `catalog add` or `oci add`, stored at `~/.ai-catalog/`.

Common entry types:

| Type | Artifact |
|------|----------|
| `application/mcp-server-card+json` | MCP server card |
| `application/a2a-agent-card+json` | A2A agent card |
| `application/agent-skills+md` | Agent skill (markdown) |
| `application/ai-catalog+json` | Nested catalog |

## Workflow

### 1. Register a catalog

Before searching, register at least one catalog:

```bash
ai-catalog catalog add <name> <url>
```

Example:

```bash
ai-catalog catalog add ai-tools https://raw.githubusercontent.com/agntcy/ai-catalog-rust/main/fixtures/simple.json
```

Accepts HTTP/HTTPS URLs or `file://` paths. Nested catalogs are fetched and cached automatically.

### 2. Search for entries

```bash
ai-catalog search <keyword>             # full-text search across all registered catalogs
ai-catalog search <keyword> -n 100      # override result limit (default 50)
ai-catalog search <pattern> --regex     # treat keyword as a regular expression
ai-catalog search <keyword> --json      # machine-readable output
```

Searches `identifier`, `displayName`, `description`, and `tags`. Works fully offline after the catalog is cached.

### 3. Inspect an entry

```bash
ai-catalog show <identifier>                              # table view
ai-catalog show <identifier> --json                       # full entry JSON
ai-catalog show <identifier> --scope <catalog-name>       # scope to a registered catalog by name
ai-catalog show <identifier> --scope <url>                # scope to any catalog by URI (file:// or http/https)
ai-catalog show <identifier> --media-type <mime>          # filter/disambiguate by MIME type
```

`--scope` accepts either a registered catalog name or a URI directly. `file://` URIs are read from disk; `http://`/`https://` URIs are fetched and cached on the fly without registering.

`--media-type` on a catalog entry resolves its children and shows the single entry matching that type; `None` or `application/ai-catalog+json` shows the catalog entry itself.

### 4. Pull an artifact

```bash
ai-catalog pull <identifier>                                 # write to current directory
ai-catalog pull <identifier> -o <dir>                        # write to a specific directory
ai-catalog pull <identifier> -o -                            # stream artifact bytes to stdout
ai-catalog pull <identifier> --scope <catalog-name-or-url>   # narrow search to one catalog
ai-catalog pull <identifier> --media-type <mime>             # required when <id> is a catalog entry
```

**Important:** if `<identifier>` resolves to a catalog entry (type `application/ai-catalog+json`), `pull` **requires** `--media-type`:

| `--media-type` value | Result |
|---|---|
| `application/ai-catalog+json` | Write the catalog JSON document itself |
| `<other>` e.g. `application/json` | Pull the single child entry of that type (error if 0 or >1 match) |
| *(omitted)* | Error — suggests using `--media-type` |

`--scope` obeys the same URI rules as `show` (name or URI).

## Common workflows

### Install an MCP server into Claude

MCP server cards (`application/mcp-server-card+json`) contain a `remotes` array with endpoint URLs:

```bash
# Find the server
ai-catalog search <keyword>

# Stream the card through jq to get the remote URL
MCP_URL=$(ai-catalog pull <identifier> -o - | jq -r '.remotes[0].url')

# Register with Claude
claude mcp add --transport http <name> "$MCP_URL"
```

### Install an agent skill into Claude

Agent skills (`application/agent-skills+md`) are markdown files. Pull them into Claude's skills directory:

```bash
ai-catalog pull <identifier> -o ~/.claude/skills/
```

To install all skills matching a search:

```bash
ai-catalog search skill --json \
  | jq -r '.entries[].identifier' \
  | xargs -I{} ai-catalog pull {} -o ~/.claude/skills/
```

### Connect to an A2A agent

A2A agent cards (`application/a2a-agent-card+json`) contain `supportedInterfaces` with the endpoint and protocol binding:

```bash
# Pull the agent card
ai-catalog pull <identifier> -o ./

# Extract endpoint and binding
AGENT_URL=$(jq -r '.supportedInterfaces[0].url'             ./agent.json)
BINDING=$(jq -r   '.supportedInterfaces[0].protocolBinding' ./agent.json)

# Send a message
a2acli --base-url "$AGENT_URL" --binding "$BINDING" send "<message>"

# Retrieve the result
a2acli --base-url "$AGENT_URL" --binding "$BINDING" get-task <task-id>
```

## Catalog management

```bash
ai-catalog catalog list                  # list registered catalogs (--json supported)
ai-catalog catalog update <name>         # re-fetch from source, skip if unchanged
ai-catalog catalog remove <name-or-url>  # remove and garbage-collect cached objects
```

## Validation and formatting

```bash
ai-catalog validate <path|->             # validate catalog JSON against the spec
ai-catalog validate --json <path|->      # machine-readable validation result
ai-catalog format <path|->               # pretty-print a catalog document
```

Validation reports conformance level (`minimal`, `discoverable`, or `trusted`) and any errors or warnings. Exit code 0 = valid, 1 = invalid.

## OCI workflows

Use `oci` subcommands to work with OCI-packaged catalogs (e.g. from GHCR):

```bash
# Pack a catalog JSON into an OCI artifact envelope
ai-catalog oci pack <path|->

# Push a catalog to an OCI registry (requires `oras` on PATH)
ai-catalog oci push <path|-> <registry-target>
  # e.g. ai-catalog oci push catalog.json ghcr.io/example/ai-catalog:latest
  # --plain-http       use HTTP instead of HTTPS
  # --insecure         skip TLS verification
  # --cosign-key <key> sign trust manifests

# Export a catalog to an OCI image layout directory
ai-catalog oci export-layout <path|-> <layout-dir>
  # --tag <tag>  (default: latest)

# Import an OCI image layout into the local registry
ai-catalog oci add <name> <layout-dir>

# Search, inspect, and pull from OCI-sourced catalogs only
ai-catalog oci search <keyword>
ai-catalog oci show <identifier> [--media-type <mime>]
ai-catalog oci pull <identifier> -o <dir> [--media-type <mime>]
```

## Trust inspection

```bash
ai-catalog trust inspect <path|->        # show trust report (identity, signatures, attestations)
ai-catalog trust inspect --json <path|-> # machine-readable report
```

Exit code 0 = clean, 1 = errors found (identity mismatch, malformed signature, weak digest).

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AI_CATALOG_CACHE_DIR` | Override default cache directory | `~/.ai-catalog/` |
| `AI_CATALOG_COSIGN_BIN` | Path to `cosign` binary | `cosign` |
| `AI_CATALOG_ORAS_BIN` | Path to `oras` binary | `oras` |
| `COSIGN_PASSWORD` | Password for encrypted Cosign private key | (none) |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Validation/trust errors, parse failures, runtime errors |
| 2 | Usage errors (missing arguments, unknown options) |
