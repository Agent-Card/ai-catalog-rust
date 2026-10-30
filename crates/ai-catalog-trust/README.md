# ai-catalog-trust

Digest verification and canonicalization for [AI Catalog](https://ai-catalog.io/)
documents. Rule checking lives in [`ai-catalog-validate`](https://crates.io/crates/ai-catalog-validate).

Digests are parsed and verified against the accepted algorithms (SHA-256, SHA-384,
SHA-512); weaker algorithms are rejected.

```rust
let matches = ai_catalog_trust::verify_digest("sha256:9f86d081...", bytes)?;
```

Canonicalization follows [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JCS), so the
payload a signature covers is byte-identical to the one produced by other conforming
implementations.

- `canonicalize_for_signature` returns the payload a catalog or manifest `signature` covers: the document without its
  own `signature.jws` and `additionalSignatures`.
  Pass the original JSON, not a re-serialized `AiCatalog`, which drops empty arrays and
  strings, `null`s and members the SDK does not model.
- `canonicalize_trust_manifest` returns the payload for a manifest-level signature, from
  the JSON the manifest was read from. A manifest built in code or changed after reading
  is canonicalized from its serialization.
- `canonicalize` returns the canonical form of any JSON document.
- `parse_json` parses JSON.

All of them reject duplicate member names.

## License

Apache-2.0
