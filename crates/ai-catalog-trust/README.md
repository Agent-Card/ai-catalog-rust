# ai-catalog-trust

Digest verification, ES256 signature verification and canonicalization for [AI Catalog](https://ai-catalog.io/)
documents. Rule checking lives in [`ai-catalog-validate`](https://crates.io/crates/ai-catalog-validate).

Digests are parsed and verified against the accepted algorithms (SHA-256, SHA-384,
SHA-512); weaker algorithms are rejected.

```rust
let matches = ai_catalog_trust::verify_digest("sha256:9f86d081...", bytes)?;
```

ES256 detached JWS signatures (RFC 7515) verify against P-256 keys read from JWKs:

```rust
let key = ai_catalog_trust::P256Key::from_jwk(&jwk)?;
ai_catalog_trust::verify_es256(jws, payload, &key)?;
```

The protected header must declare `alg` `ES256` and must not contain `b64` or `crit`; the other
header members are left to the caller. Resolving keys and authorizing signers is done by
[`ai-catalog-validate`](https://crates.io/crates/ai-catalog-validate).

Canonicalization follows [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JCS), so the
payload a signature covers is byte-identical to the one produced by other conforming
implementations.

- `canonicalize_for_signature` returns the payload a catalog or manifest `signature` covers: the document without its
  own `signature.jws` and `additionalSignatures`.
  Pass the original JSON, not a re-serialized `AiCatalog`, which drops empty arrays and
  strings, `null`s and members the SDK does not model.
- `canonicalize_value_for_signature` does the same for a document that is already parsed.
- `canonicalize_trust_manifest` returns the payload for a manifest-level signature, from
  the JSON the manifest was read from. A manifest built in code or changed after reading
  is canonicalized from its serialization.
- `canonicalize` returns the canonical form of any JSON document.
- `parse_json` parses JSON.

All of them reject duplicate member names.

## License

Apache-2.0
