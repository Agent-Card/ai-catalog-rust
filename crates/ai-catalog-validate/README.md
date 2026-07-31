# ai-catalog-validate

Semantic validation and conformance-level detection for
[AI Catalog](https://agent-card.github.io/ai-catalog/) documents.

Checks the rules a JSON schema cannot express — duplicate identifiers, timestamp formats,
nesting depth, and trust-manifest identity binding — and reports the conformance level a
document reaches.

## Conformance levels

| Level | Requirements |
|---|---|
| Minimal | `specVersion` plus at least one entry with `identifier` and `type` |
| Discoverable | Minimal, plus `url` or `data` and `tags` on each entry |
| Trusted | Discoverable, plus a `trustManifest` with `identity` on each entry |

## Usage

```rust
let catalog = ai_catalog::parse_file("ai-catalog.json")?;
let result = ai_catalog_validate::validate(&catalog);

if !result.is_valid {
    for diagnostic in &result.errors {
        eprintln!("{}: {}", diagnostic.path, diagnostic.message);
    }
}
```

## License

Apache-2.0
