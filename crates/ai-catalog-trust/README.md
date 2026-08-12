# ai-catalog-trust

Trust manifest analysis, digest verification, and canonicalization for
[AI Catalog](https://ai-catalog.io/) documents.

Inspects the trust manifests attached to catalog entries and host objects, reporting
findings such as malformed signatures, signature algorithms that cannot establish
third-party trust, signatures that commit to no artifact, weak or invalid digests, and
trust-manifest identities whose domain does not align with the entry's publisher domain.
The document-level `signature` is held to the same algorithm constraints.

Analysis descends into catalogs embedded in an entry's `data`, up to the specification's
RECOMMENDED nesting depth of 4. A finding's `path` records where it was found, for example
`catalog.entries[0].data.entries[2].trustManifest`.

Canonicalization follows [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JCS), so the
payload a signature covers is byte-identical to the one produced by other conforming
implementations. `canonicalize_trust_manifest` and `canonicalize_catalog` produce the
payloads for manifest-level and document-level signatures respectively.

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
