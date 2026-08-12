# ai-catalog-validate

Semantic validation and conformance-level detection for
[AI Catalog](https://ai-catalog.io/) documents.

Checks the rules a JSON schema cannot express — duplicate identifiers, timestamp formats,
nesting depth, extension key namespacing, and trust-manifest identity and subject binding —
and reports the conformance level a document reaches.

## Conformance levels

| Level | Requirements |
|---|---|
| Minimal | `specVersion`, and every entry carrying `identifier`, `type`, and exactly one of `url` or `data` |
| Discoverable | Minimal, plus a `host` object identifying the catalog operator |
| Trusted | Discoverable, plus every `trustManifest` in the document signed, with a `subject` and `issuedAt` |

A single unsigned manifest downgrades the whole document below Trusted, because a consumer
cannot rely on trust it has no way to verify.

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
