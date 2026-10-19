# ai-catalog-rust

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Agent-Card/ai-catalog-rust/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Agent-Card/ai-catalog-rust)

Rust libraries for the [AI Catalog specification](https://ai-catalog.io/).

| Resource | Link |
|---|---|
| Specification | <https://ai-catalog.io/> |
| Upstream repository | <https://github.com/Agent-Card/ai-catalog> |
| Command-line tool | <https://github.com/Agent-Card/ai-catalog-cli> |

## Workspace

| Crate | Description |
|---|---|
| [`crates/ai-catalog`](crates/ai-catalog/README.md) | Core types (`AiCatalog`, `CatalogEntry`, `HostInfo`, `Publisher`, `TrustManifest`), parse and serialize helpers |
| [`crates/ai-catalog-validate`](crates/ai-catalog-validate/README.md) | Semantic validation and conformance detection |
| [`crates/ai-catalog-trust`](crates/ai-catalog-trust/README.md) | Digest verification and canonicalization |
| [`crates/ai-catalog-oci`](crates/ai-catalog-oci/README.md) | OCI artifact-set pack/unpack and standard OCI image layout import/export |

`ai-catalog`, `ai-catalog-validate`, and `ai-catalog-trust` implement the
specification. `ai-catalog-oci` is a convenience for distributing catalogs over
existing registry infrastructure; OCI packaging is not part of the spec.

The `ai-catalog` command-line tool lives in
[`Agent-Card/ai-catalog-cli`](https://github.com/Agent-Card/ai-catalog-cli) and consumes
these crates from crates.io.

### Conformance levels

| Level | Requirements |
|---|---|
| **Minimal** | `specVersion`, and every entry carrying `identifier`, `type`, and exactly one of `url` or `data` |
| **Discoverable** | Minimal + a `host` object identifying the catalog operator |
| **Trusted** | Discoverable + every root entry `trustManifest` signed, bound to its entry, unexpired and conforming to the did:web Publisher Profile |

## Usage

```toml
[dependencies]
ai-catalog = "0.2"
ai-catalog-validate = "0.2"
ai-catalog-trust = "0.2"
```

Parse a catalog and look up entries. Unrecognized fields survive a round-trip:

```rust
let catalog = ai_catalog::parse_file("ai-catalog.json")?;

for entry in catalog.search("finance") {
    println!("{}", entry.identifier);
}

let entry = catalog.get_by_id("urn:air:example.com:agent:finance");
```

Validate a document and report its conformance level. Signatures are not
cryptographically verified:

```rust
let result = ai_catalog_validate::validate(&catalog);

for diagnostic in &result.errors {
    eprintln!("{} {}: {}", diagnostic.code, diagnostic.path, diagnostic.message);
}
```

Verify an attestation digest against its bytes:

```rust
let matches = ai_catalog_trust::verify_digest("sha256:9f86d081...", bytes)?;
```

Each crate's README covers its API in more detail.

## Development

```sh
just build          # cargo build --workspace
just lint           # fmt --check + clippy -D warnings
just test           # cargo test --workspace
just coverage       # llvm-cov summary
```

## Releases

Crates are published to crates.io by
[release-plz](https://release-plz.dev/) when a release pull request merges to
`main`. Version bumps and changelogs are derived from
[conventional commits](https://www.conventionalcommits.org/).

## Governance

| File | Purpose |
|---|---|
| `LICENSE` | Apache License 2.0 |
| `CONTRIBUTING.md` | Contribution workflow and local checks |
| `CODE_OF_CONDUCT.md` | Collaboration expectations |
| `SECURITY.md` | Vulnerability reporting guidance |
| `GOVERNANCE.md` | Project decision-making and branch policy |
