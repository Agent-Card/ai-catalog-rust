# ai-catalog-oci

Pack and unpack [AI Catalog](https://ai-catalog.io/) documents as OCI
artifacts and standard OCI image layouts.

Turns a catalog and its referenced entries into a content-addressed artifact set that can
be pushed to any OCI registry, and reverses the process on the way back.

Note that OCI packaging is not part of the AI Catalog specification; this crate is a
convenience for distributing catalogs over existing registry infrastructure.

## Usage

```rust
let catalog = ai_catalog::parse_file("ai-catalog.json")?;
let artifacts = ai_catalog_oci::pack(&catalog)?;
let restored = ai_catalog_oci::unpack(&artifacts)?;
```

## License

Apache-2.0
