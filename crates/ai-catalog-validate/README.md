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
| Trusted | Discoverable, plus a verified publisher endorsement (see [Verification](#verification)) |

`validate` checks structure and reports at most Discoverable. It never verifies a signature:
Trusted is reported only by `verify`. Profile violations and expired signatures are warnings.

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

## Verification

`verify` also checks the signatures and artifacts of the root entries and of the catalog, as the
did:web Signer and Publisher Profiles require. It reads the document as served, since signatures
cover members this library does not model, and fetches DID documents and artifacts through a
`Fetch` you provide:

```rust
use ai_catalog_validate::{Options, verify};

let fetch = |url: &str| -> Result<Vec<u8>, String> { /* safe https fetch */ todo!() };
let options = Options::default()
    .with_base_url("https://example.com/.well-known/ai-catalog.json")
    .with_authorized_operators(["did:web:example.com"]);

let result = verify(&document_bytes, &options, &fetch)?;
println!("{}", result.conformance_level);
```

`Fetch` must follow the specification's safe-fetching rules: `https` only, no private, loopback
or link-local addresses (also after redirects), and a size limit and a timeout.

A catalog is Trusted when at least one entry has a verified publisher endorsement and no
manifest signed by a publisher fails. An endorsement is verified when the signer is
authenticated (the `did:web` DID document authorizes the `kid` under `assertionMethod`, and the
ES256 signature verifies), the signature is current, the signed subject is the entry release,
the signer is the publisher the `urn:air` identifier names, and the artifact matches
`entry.digest`. Other contributors' manifests are reported but never hold the publisher back.

Each check is an `Outcome`: `Verified`, `Failed` (the check ran and did not pass), or
`Unverifiable` (a document could not be fetched, or the profile is not supported). A catalog
signature is reported as authorized only for the signers in `with_authorized_operators`, since
the specification defines no mapping from a signer to catalog authority. Nested catalogs are not
opened.

## License

Apache-2.0
