# ai-catalog-validate

Semantic validation and conformance-level detection for
[AI Catalog](https://ai-catalog.io/) documents.

Checks the rules a JSON schema cannot express: duplicate identifiers, timestamp formats,
nesting depth, extension key namespacing, signature objects, trust manifest subject
binding, and the did:web signer and publisher profiles. Every diagnostic carries a stable `Code`, a
`path` and a message; match on the code rather than the message.

## Conformance levels

| Level | Requirements |
|---|---|
| Minimal | `specVersion`, and every entry carrying `identifier`, `type`, and exactly one of `url` or `data` |
| Discoverable | Minimal, plus a `host` object identifying the catalog operator |
| Trusted | Discoverable, plus every root entry that carries `trustManifests` has one signed by its publisher under the did:web Publisher Profile, bound to the entry (`subject` and `digest`) and current |

Profile violations and expired signatures are warnings: the document stays valid but is held
at Discoverable. Other contributors' manifests never hold it back; an assessor alone does not
make a catalog Trusted. Signatures are not cryptographically verified.

## Usage

```rust
let catalog = ai_catalog::parse_file("ai-catalog.json")?;
let result = ai_catalog_validate::validate(&catalog);

for diagnostic in &result.errors {
    eprintln!("{} {}: {}", diagnostic.code, diagnostic.path, diagnostic.message);
}
```

Fix the clock used for expiry, or the nesting limit (default 4):

```rust
use ai_catalog_validate::{Options, validate_with};

let options = Options::default()
    .with_clock(std::time::SystemTime::now())
    .with_max_nesting_depth(2);

let result = validate_with(&catalog, &options);
```

## License

Apache-2.0
