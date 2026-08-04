# ai-catalog-rust

Rust toolkit for the [AI Catalog specification](https://agent-card.github.io/ai-catalog/).

| Resource | Link |
|---|---|
| Specification | <https://agent-card.github.io/ai-catalog/> |
| Upstream repository | <https://github.com/Agent-Card/ai-catalog> |

## Workspace

| Crate | Description |
|---|---|
| [`crates/ai-catalog`](crates/ai-catalog/README.md) | Core types (`AiCatalog`, `CatalogEntry`, `HostInfo`, `Publisher`, `TrustManifest`), parse and serialize helpers |
| [`crates/ai-catalog-validate`](crates/ai-catalog-validate/README.md) | Semantic validation and conformance detection |
| [`crates/ai-catalog-trust`](crates/ai-catalog-trust/README.md) | Trust manifest analysis, digest verification, and canonicalization |
| [`crates/ai-catalog-oci`](crates/ai-catalog-oci/README.md) | OCI artifact-set pack/unpack and standard OCI image layout import/export |
| `crates/ai-catalog-cli` | `ai-catalog` command-line tool |

### Conformance levels

| Level | Requirements |
|---|---|
| **Minimal** | `specVersion` + at least one entry with `identifier` and `type` |
| **Discoverable** | Minimal + `url` or `data` on each entry + `tags` |
| **Trusted** | Discoverable + `trustManifest` with `identity` on each entry |

## Getting started

```sh
just build          # cargo build --workspace
just lint           # fmt --check + clippy -D warnings
just test           # cargo test --workspace
just coverage       # llvm-cov summary
```

Install the CLI:

```sh
cargo install --path crates/ai-catalog-cli
```

Or run directly during development (replace `ai-catalog` with
`cargo run -p ai-catalog-cli --`):

```sh
cargo run -p ai-catalog-cli -- help
cargo run -p ai-catalog-cli -- version
```

## CLI reference

```
ai-catalog validate [--json] <path|->
ai-catalog format <path|->
ai-catalog trust inspect [--json] <path|->
ai-catalog oci pack <path|->
ai-catalog oci unpack <path|->
ai-catalog oci export-layout [--tag <tag>] [--cosign-key <path>] [--cosign-public-key <path>] <path|-> <layout-dir>
ai-catalog oci unpack-layout [--ref-name <name>] <layout-dir>
ai-catalog oci push [--tag <tag>] [--plain-http] [--insecure] [--to-oci-layout-path <layout-dir>] [--cosign-key <path>] [--cosign-public-key <path>] <path|-> <target>
ai-catalog oci add <name> <layout-dir> [--ref-name <tag>]
ai-catalog oci search [--regex] [-n <limit>] [--json] <keyword>
ai-catalog oci show [--json] <identifier>
ai-catalog oci pull [--output <path>] <identifier>
ai-catalog catalog add <name> <url>
ai-catalog catalog list [--json]
ai-catalog catalog remove <name-or-url>
ai-catalog catalog update <name>
ai-catalog search [--regex] [-n <limit>] [--json] <keyword>
ai-catalog show [--scope <catalog-name>] [--json] <identifier>
ai-catalog pull [--output <path>] <identifier>
ai-catalog help
ai-catalog version
```

Use `-` as `<path>` to read from stdin.

---

### `validate`

Validates a catalog document against the AI Catalog specification and reports
the conformance level (Minimal / Discoverable / Trusted).

```sh
ai-catalog validate catalog.json          # text report
ai-catalog validate --json catalog.json   # JSON report
cat catalog.json | ai-catalog validate -  # from stdin
```

Exits with code `0` on success, `1` on validation errors.

---

### `format`

Pretty-prints a catalog document to stdout without modifying the source file.

```sh
ai-catalog format catalog.json
cat catalog.json | ai-catalog format -
```

---

### `trust inspect`

Reads and reports on trust manifests declared in a catalog (host and entries).
Shows identity, presence of a signature, and counts of attestations and
provenance records. Does not perform cryptographic signature verification.

```sh
ai-catalog trust inspect catalog.json
ai-catalog trust inspect --json catalog.json
```

Exits with code `0` when all findings are clean, `1` when errors are found
(e.g. identity mismatch, malformed signature, weak digest algorithm).

---

### `catalog add`

Fetches a catalog from a URL (or `file://` path), stores all catalog blobs in
the local content-addressed cache, and registers the catalog in the local
registry. Nested catalogs are fetched recursively (up to depth 4).

```sh
ai-catalog catalog add my-registry https://example.com/ai-catalog.json
ai-catalog catalog add local-demo  file:///path/to/catalog.json
```

Makes network requests. All other consumer commands operate on the local cache.

---

### `catalog list`

Lists all catalogs registered in the local registry.

```sh
ai-catalog catalog list
ai-catalog catalog list --json
```

---

### `catalog update`

Re-fetches a registered catalog from its source URL and refreshes the local
cache. Accepts a catalog name.

```sh
ai-catalog catalog update my-registry
```

---

### `catalog remove`

Removes a catalog from the local registry by name or source URL. Also removes
the cached object blob if no other registered catalog references it.

```sh
ai-catalog catalog remove my-registry
ai-catalog catalog remove https://example.com/ai-catalog.json
```

---

### `search`

Searches entries across all registered catalogs (all sources).

```sh
ai-catalog search "finance agent"                # substring match
ai-catalog search --regex "urn:example:(agent|data).*"
ai-catalog search --json dataset                 # JSON output
ai-catalog search -n 5 embeddings               # limit to 5 results
```

Matches against `identifier`, `displayName`, `description`, and `tags`.
Default limit is 20.

---

### `show`

Shows full details of a single catalog entry by identifier.

```sh
ai-catalog show urn:example:agent:v1
ai-catalog show --json urn:example:agent:v1
ai-catalog show --scope my-registry urn:example:agent:v1  # restrict to one catalog
```

---

### `pull`

Downloads an entry's content to disk. For nested-catalog entries the full
catalog JSON is written; for other types the raw bytes from `entry.url` are
fetched. Falls back to fetching by URL if the identifier is not in the local
registry.

```sh
ai-catalog pull urn:example:data:dataset-v1
ai-catalog pull --output ./downloads urn:example:data:dataset-v1
ai-catalog pull --output ./report.json urn:example:data:dataset-v1
```

If `--output` is a directory, a filename is derived from the identifier. If it
is a file path, that path is used directly. Omitting `--output` writes to the
current directory.

---

### `oci pack`

Packs a catalog into the internal JSON artifact-set envelope used by the Rust
library. Useful for debugging or pipeline integration when you need to inspect
how the CLI represents a catalog before pushing it to an OCI registry.

```sh
ai-catalog oci pack catalog.json
cat catalog.json | ai-catalog oci pack -
```

Output is JSON written to stdout.

---

### `oci unpack`

Unpacks an internal JSON artifact-set envelope back into AI Catalog JSON.

```sh
ai-catalog oci unpack artifacts.json
```

Output is JSON written to stdout.

---

### `oci export-layout`

Exports a catalog as a standard [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
directory. Each catalog entry is stored as a separate OCI manifest; the catalog
itself becomes an OCI image index tagged with `--tag`.

```sh
ai-catalog oci export-layout catalog.json /path/to/layout
ai-catalog oci export-layout --tag v1.0 catalog.json /path/to/layout
```

With Cosign signing (see [Trust manifest signing](#trust-manifest-signing)):

```sh
ai-catalog oci export-layout \
  --cosign-key cosign.key \
  --cosign-public-key cosign.pub \
  catalog.json /path/to/layout
```

| Flag | Description |
|---|---|
| `--tag <tag>` | OCI tag to apply (default: `latest`) |
| `--cosign-key <path>` | Path to Cosign private key; triggers signing of trust manifests |
| `--cosign-public-key <path>` | Path to PEM public key (derived from `--cosign-key` if omitted) |

Reads from stdin when `<path>` is `-`.

---

### `oci unpack-layout`

Imports a standard OCI image layout back into AI Catalog JSON. Prints the
reconstructed catalog to stdout.

```sh
ai-catalog oci unpack-layout /path/to/layout
ai-catalog oci unpack-layout --ref-name v1.0 /path/to/layout
```

| Flag | Description |
|---|---|
| `--ref-name <name>` | Tag to import (default: first entry in `index.json`) |

---

### `oci push`

Pushes a catalog to an OCI registry. Internally calls `oci export-layout` into
a temporary directory, then delegates distribution to `oras cp -r`.

```sh
ai-catalog oci push catalog.json ghcr.io/example/ai-catalog:latest
ai-catalog oci push --tag v1.0 catalog.json ghcr.io/example/ai-catalog:v1.0
```

With signing and registry options:

```sh
ai-catalog oci push \
  --cosign-key cosign.key \
  --cosign-public-key cosign.pub \
  catalog.json ghcr.io/example/ai-catalog:latest
```

| Flag | Description |
|---|---|
| `--tag <tag>` | OCI tag (default: `latest`) |
| `--plain-http` | Use plain HTTP instead of HTTPS |
| `--insecure` | Skip TLS certificate verification |
| `--to-oci-layout-path <dir>` | Also write the exported layout to this directory |
| `--cosign-key <path>` | Path to Cosign private key |
| `--cosign-public-key <path>` | Path to PEM public key |

Reads from stdin when `<path>` is `-`. Requires `oras` on `PATH`.

---

### `oci add`

Imports a local OCI image layout into the local registry. Unpacks all catalog
entries from the layout and registers the catalog with a `urn:ai-catalog:oci:`
identifier prefix.

```sh
ai-catalog oci add my-layout /path/to/layout
ai-catalog oci add my-layout /path/to/layout --ref-name v1.0
```

| Flag | Description |
|---|---|
| `--ref-name <tag>` | Tag to import from the layout (default: first entry) |

---

### `oci search`

Searches entries across OCI-sourced catalogs only (those added via `oci add`).
Accepts the same flags as `search`.

```sh
ai-catalog oci search embeddings
ai-catalog oci search --regex "^urn:ai-catalog:oci:"
ai-catalog oci search --json nlp
ai-catalog oci search -n 10 agent
```

---

### `oci show`

Shows full details of an entry from OCI-sourced catalogs only.

```sh
ai-catalog oci show urn:ai-catalog:oci:abc12345
ai-catalog oci show --json urn:ai-catalog:oci:abc12345
```

---

### `oci pull`

Pulls an entry from OCI-sourced catalogs to disk. Accepts the same `--output`
flag as `pull`.

```sh
ai-catalog oci pull urn:ai-catalog:oci:abc12345
ai-catalog oci pull --output ./artifact.json urn:ai-catalog:oci:abc12345
```

---

## Local storage

The local registry lives at `~/.ai-catalog/` by default. Override with the
`AI_CATALOG_CACHE_DIR` environment variable.

```
~/.ai-catalog/
├── catalog.json      # registry index (AiCatalog document)
├── refs.json         # source URL → SHA-256 hash map
└── objects/
    └── <sha256>.json # cached catalog blobs
```

Entries added via `catalog add` are stored under their source URL and use the
`urn:ai-catalog:local:` convention. Entries added via `oci add` use the
`urn:ai-catalog:oci:` prefix and are scoped separately. The plain `search`,
`show`, and `pull` commands span all sources; the `oci search / show / pull`
variants are restricted to OCI-sourced entries. See
[`docs/storage.md`](docs/storage.md) for a detailed comparison.

---

## Trust manifest signing

When `--cosign-key` is supplied to `oci export-layout` or `oci push`, the CLI:

1. Canonicalizes each entry trust manifest (key-sorted JSON, `signature` field stripped)
2. Signs the canonical blob with `cosign sign-blob`
3. Attaches three OCI referrer artifacts to each signed entry:
   - the canonical trust manifest (`application/vnd.ai-catalog.trust-manifest.v1+json`)
   - the detached Cosign signature (`application/vnd.ai-catalog.cosign.signature.v1`)
   - the public key (`application/vnd.ai-catalog.cosign.public-key.v1`)

Signatures live in the OCI layout as referrers, not embedded in the AI Catalog
JSON. Use `oras discover` to inspect the referrer tree and `cosign verify-blob`
to verify. See [`demo/trust-walkthrough.sh`](demo/trust-walkthrough.sh) for a
complete end-to-end example.

---

## Environment variables

| Variable | Description |
|---|---|
| `AI_CATALOG_CACHE_DIR` | Override the default cache directory (`~/.ai-catalog/`) |
| `AI_CATALOG_COSIGN_BIN` | Path to the `cosign` binary (default: `cosign`) |
| `AI_CATALOG_ORAS_BIN` | Path to the `oras` binary (default: `oras`) |
| `COSIGN_PASSWORD` | Password for an encrypted Cosign private key |

---

## Demo

All demos create a temporary workspace and clean up on exit.

| Demo | Command | Prerequisites |
|---|---|---|
| OCI image layout | `just demo-oci-layout` | `cargo`, `cosign`, `oras` |
| Consumer workflow | `just demo-consumer` | `cargo` |
| Trust sign & verify | `just demo-trust` | `cargo`, `cosign`, `oras` |

### OCI layout walkthrough (`just demo-oci-layout`)

Exercises the full OCI publish/verify flow: validate → generate Cosign key pair
→ `oci export-layout --cosign-key` → `oras discover` referrers → print
signature and public key → `oci unpack-layout` round-trip → `oci push` to a
second layout. Script: [`demo/oci-layout-walkthrough.sh`](demo/oci-layout-walkthrough.sh).

### Consumer workflow walkthrough (`just demo-consumer`)

Exercises every author and consumer command without external tools or network
calls: validate, format, trust inspect, catalog add/list/update/remove, search
(keyword, regex, JSON, limit), show (text, JSON, scoped), pull (inline-data
and file-URL entries), and the full OCI consumer path (oci add, oci search,
oci show, oci pull). Script: [`demo/consumer-walkthrough.sh`](demo/consumer-walkthrough.sh).

### Trust sign & verify walkthrough (`just demo-trust`)

Demonstrates the complete trust manifest lifecycle: validate → `trust inspect`
(unsigned) → generate Cosign key pair → sign via `oci export-layout
--cosign-key` → `oras discover` referrer tree → extract canonical trust
manifest and detached signature → `cosign verify-blob` → tamper detection →
`oci unpack-layout` round-trip. Script: [`demo/trust-walkthrough.sh`](demo/trust-walkthrough.sh).

---

## Governance

| File | Purpose |
|---|---|
| `LICENSE` | Apache License 2.0 |
| `CONTRIBUTING.md` | Contribution workflow and local checks |
| `CODE_OF_CONDUCT.md` | Collaboration expectations |
| `SECURITY.md` | Vulnerability reporting guidance |
| `GOVERNANCE.md` | Project decision-making and branch policy |
