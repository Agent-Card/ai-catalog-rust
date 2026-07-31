# ai-catalog

Core types and JSON parsing for the [AI Catalog specification](https://agent-card.github.io/ai-catalog/).

Provides `AiCatalog`, `CatalogEntry`, `HostInfo`, `Publisher`, `TrustManifest`, and the
surrounding model types, along with helpers to parse and serialize catalog documents.
Unrecognized fields are preserved on round-trip.

## Usage

```rust
let catalog = ai_catalog::parse_file("ai-catalog.json")?;

for entry in catalog.search("finance") {
    println!("{}", entry.identifier);
}

let entry = catalog.get_by_id("urn:air:example.com:agent:finance");
```

## Related crates

| Crate | Purpose |
|---|---|
| [`ai-catalog-validate`](https://crates.io/crates/ai-catalog-validate) | Semantic validation and conformance levels |
| [`ai-catalog-trust`](https://crates.io/crates/ai-catalog-trust) | Trust manifest analysis and digest verification |
| [`ai-catalog-oci`](https://crates.io/crates/ai-catalog-oci) | OCI artifact packaging |

## License

Apache-2.0
