# ai-catalog-trust

Trust manifest analysis, digest verification, and canonicalization for
[AI Catalog](https://agent-card.github.io/ai-catalog/) documents.

Inspects the trust manifests attached to catalog entries and host objects, reporting
findings such as malformed signatures, weak or invalid digests, and trust-manifest
identities whose domain does not align with the entry's publisher domain.

## Usage

```rust
let catalog = ai_catalog::parse_file("ai-catalog.json")?;
let report = ai_catalog_trust::analyze_catalog(&catalog);

for finding in &report.findings {
    println!("{:?} {}: {}", finding.severity, finding.path, finding.message);
}
```

Digests are parsed and verified against the accepted algorithms (SHA-256, SHA-384,
SHA-512); weaker algorithms are rejected.

```rust
let matches = ai_catalog_trust::verify_digest("sha256:9f86d081...", bytes)?;
```

## License

Apache-2.0
