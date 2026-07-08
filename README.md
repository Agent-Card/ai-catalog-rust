# ai-catalog-rust

Rust toolkit for the AI Catalog specification.

Upstream references:

- AI Catalog repository: <https://github.com/Agent-Card/ai-catalog>
- Published specification: <https://ai-catalog.io>

## Workspace

| Crate | Description |
|---|---|
| `crates/ai-catalog` | Core types (`AiCatalog`, `CatalogEntry` with `"type"` field, `HostInfo`, `Publisher`, `TrustManifest`), parse/serialize helpers |
| `crates/ai-catalog-validate` | Semantic validation; conformance levels: Minimal, Discoverable, Trusted |
| `crates/ai-catalog-trust` | Trust manifest analysis, digest verification, and canonicalization |
| `crates/ai-catalog-oci` | OCI artifact-set pack/unpack; standard OCI image layout import/export |
| `crates/ai-catalog-cli` | CLI binary `ai-catalog`; author and consumer commands |

### Conformance levels

- **Minimal** — `specVersion` + at least one entry with `identifier` and `type`
- **Discoverable** — Minimal + `url` or `data` on entries + `tags`
- **Trusted** — Discoverable + `trustManifest` with `identity` on entries

## Getting started

```sh
# Build all crates
just build
# Or with cargo
cargo build --workspace

# Install the CLI
cargo install --path crates/ai-catalog-cli
```

## CLI — Author commands

Author commands validate, format, and publish AI Catalog documents.

During development use `cargo run -p ai-catalog-cli -- <args>` in place of
`ai-catalog`.

```sh
# Validate a catalog (text or JSON output)
ai-catalog validate fixtures/spec-example.json
ai-catalog validate --json fixtures/spec-example.json

# Format / pretty-print a catalog
ai-catalog format fixtures/spec-example.json

# Inspect trust manifests
ai-catalog trust inspect fixtures/spec-example.json
ai-catalog trust inspect --json fixtures/spec-example.json

# Pack into OCI artifact set JSON
ai-catalog oci pack fixtures/spec-example.json

# Export / import standard OCI image layout
ai-catalog oci export-layout [--tag <tag>] fixtures/spec-example.json /tmp/layout
ai-catalog oci unpack-layout /tmp/layout

# Push to OCI registry (delegates to oras)
ai-catalog oci push fixtures/spec-example.json ghcr.io/example/ai-catalog:latest
ai-catalog oci push --cosign-key cosign.key fixtures/spec-example.json ghcr.io/example/ai-catalog:latest

# Read from stdin using '-'
cat fixtures/spec-example.json | ai-catalog validate --json -
cat fixtures/spec-example.json | ai-catalog oci pack -
```

## CLI — Consumer commands

Consumer commands discover and pull artifacts from registered catalogs. Catalogs
are stored locally in `~/.ai-catalog/` using content-addressed storage (SHA-256).
Only `catalog add` and `catalog update` make network requests; all other consumer
commands operate on the local cache.

`catalog add` fetches the target catalog and any nested catalogs recursively (up
to depth 4) and caches them locally.

```sh
# Register a remote catalog (fetches and caches locally in ~/.ai-catalog/)
ai-catalog catalog add my-registry https://example.com/ai-catalog.json

# List registered catalogs
ai-catalog catalog list
ai-catalog catalog list --json

# Refresh a registered catalog from source
ai-catalog catalog update my-registry

# Remove a registered catalog
ai-catalog catalog remove my-registry

# Search across all registered catalogs
ai-catalog search "finance agent"
ai-catalog search --regex "urn:example:(agent|data).*"
ai-catalog search --json "dataset"

# Show details of a specific entry
ai-catalog show urn:example:agent-finance-001
ai-catalog show --json urn:example:agent-finance-001
ai-catalog show --scope my-registry urn:example:agent-finance-001

# Pull an artifact to disk
ai-catalog pull urn:example:data:market-dataset-2026q1
ai-catalog pull --output ./downloads urn:example:data:market-dataset-2026q1
```

## OCI and cosign

`oci pack` / `oci unpack` operate on the internal JSON artifact-set envelope used
by the Rust library.

`oci export-layout` writes a standard OCI image layout directory;
`oci unpack-layout` imports that layout back into AI Catalog JSON.

`oci push` delegates distribution to `oras cp -r` from a temporary exported
layout so standard OCI tooling can validate or publish the result.

When `--cosign-key` is supplied to `oci export-layout` or `oci push`, the CLI
canonicalizes each entry trust manifest, signs the blob with `cosign sign-blob`,
derives or reads a PEM public key, and stores both the detached signature and
public key as OCI referrer artifacts in the exported layout. If the private key
is encrypted, supply the password through the `COSIGN_PASSWORD` environment
variable.

## Development

```sh
just build     # cargo build --workspace
just lint      # fmt check + clippy -D warnings
just test      # cargo test --workspace
just coverage  # llvm-cov summary
```

## Demo

Run the end-to-end OCI walkthrough with:

```sh
just demo-oci-layout
```

Requires `cargo`, `oras`, and `cosign` on `PATH`. See
`demo/oci-layout-walkthrough.md` for prerequisites and a step-by-step
description of the walkthrough.

## Governance

- `LICENSE` — Apache License 2.0
- `CONTRIBUTING.md` — contribution workflow and local checks
- `CODE_OF_CONDUCT.md` — collaboration expectations
- `SECURITY.md` — vulnerability reporting guidance
- `GOVERNANCE.md` — project decision-making and branch policy
