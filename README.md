# ai-catalog-rust

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
| [`crates/ai-catalog-trust`](crates/ai-catalog-trust/README.md) | Trust manifest analysis, digest verification, and canonicalization |
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
| **Trusted** | Discoverable + every `trustManifest` in the document signed, with a `subject` and `issuedAt` |

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

Validate a document and report its conformance level:

```rust
let result = ai_catalog_validate::validate(&catalog);

if !result.is_valid {
    for diagnostic in &result.errors {
        eprintln!("{}: {}", diagnostic.path, diagnostic.message);
    }
}
```

Inspect trust manifests. This reports findings such as malformed signatures,
weak digests, and identities whose domain does not align with the entry's
publisher domain. It does not perform cryptographic signature verification:

```rust
let report = ai_catalog_trust::analyze_catalog(&catalog);

for finding in &report.findings {
    println!("{:?} {}: {}", finding.severity, finding.path, finding.message);
}
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
