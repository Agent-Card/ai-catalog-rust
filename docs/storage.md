# Local Storage Approaches

`ai-catalog` supports two local storage backends for catalog data.
Both are content-addressed — blobs are stored by the SHA-256 digest of
their content — but they differ in format and interoperability.

## Custom CAS (`catalog add`)

Catalogs registered with `catalog add` are stored in a lightweight
proprietary layout under `~/.ai-catalog/`.

```
~/.ai-catalog/
├── catalog.json      # registry index (AiCatalog document listing registered catalogs)
├── refs.json         # source URL → SHA-256 hash map
└── objects/
    └── <sha256>.json # catalog blob, addressed by content hash
```

`catalog.json` is itself a valid AI Catalog document. Its entries point
at the locally cached blobs via `file://` URLs and carry source metadata
(original URL, hash, entry count, timestamp) in the `metadata` field.

**Properties**

- Simple — no dependency on OCI tooling
- Self-contained — a single directory, readable without additional tools
- Not interoperable — proprietary layout, not readable by `oras`, `skopeo`, or container runtimes
- Identifier prefix: `urn:ai-catalog:local:<hash-prefix>`

## OCI Image Layout (`oci add`)

Catalogs registered with `oci add` are unpacked from a standard
[OCI Image Layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
and stored in the same CAS blobs directory. The OCI layout itself — the
source of truth for the catalog — stays at the path given to `oci add`.

```
<layout-dir>/             # OCI image layout (source, created by oci export-layout)
├── oci-layout            # {"imageLayoutVersion": "1.0.0"}
├── index.json            # OCI image index — lists manifests by digest and tag
└── blobs/
    └── sha256/
        └── <digest>      # OCI manifest or blob (AI Catalog JSON, trust manifests, …)
```

`index.json` is the OCI index — it lists manifests by digest and
associates tags (e.g. `walkthrough`) via the
`org.opencontainers.image.ref.name` annotation. The AI Catalog JSON
document is stored as a blob inside `blobs/sha256/`; `index.json` itself
never contains catalog content directly.

**Properties**

- Standard — any OCI-conformant tool can read the layout
- Interoperable — `oras manifest fetch --oci-layout`, `skopeo`, crane, and
  container runtimes all understand it without modification
- Richer metadata — trust manifests and Cosign verification artifacts
  travel as OCI referrers alongside the catalog blob
- Identifier prefix: `urn:ai-catalog:oci:<hash-prefix>`

## Side-by-side comparison

| | Custom CAS | OCI Image Layout |
|---|---|---|
| Blob store | `objects/<sha256>.json` | `blobs/sha256/<digest>` |
| Index file | `catalog.json` (AiCatalog) | `index.json` (OCI image index) |
| URL→hash map | `refs.json` | index annotations |
| Tag | display name in registry entry | `org.opencontainers.image.ref.name` |
| Interoperable | No | Yes — any OCI tool |
| Trust / signing metadata | Not stored | OCI referrers (Cosign signature, public key) |
| CLI command | `catalog add <name> <url>` | `oci add <name> <layout-dir>` |
| Search / show / pull | `search`, `show`, `pull` | `oci search`, `oci show`, `oci pull` |

## Scoping

`search`, `show`, and `pull` span **all** registered catalogs regardless
of storage backend. `oci search`, `oci show`, and `oci pull` are scoped
exclusively to catalogs registered via `oci add` (identified by the
`urn:ai-catalog:oci:` prefix).

## Future direction

The custom CAS was designed for simplicity. The OCI layout provides the
same content-addressing guarantees with the added benefit of standard
interoperability. A future version may unify both backends by using an
OCI image layout as the single local store (`~/.ai-catalog/layout/`),
making the local registry directly inspectable with `oras` and
eliminating the custom index files entirely.
