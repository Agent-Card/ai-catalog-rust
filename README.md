# ai-catalog-rust

Rust toolkit for the AI Catalog specification.

The workspace is intended to land as `agntcy/ai-catalog-rust` and starts with
the first useful slice: parse, serialize, and validate static AI Catalog
documents against the current specification.
It may move to the AI Catalog project at some point.

## Workspace

- `crates/ai-catalog` — core models plus parse and serialize helpers
- `crates/ai-catalog-validate` — semantic validation and conformance detection
- `crates/ai-catalog-trust` — trust-manifest analysis, digest verification, and canonicalization helpers
- `crates/ai-catalog-oci` — AI Catalog OCI artifact-set pack/unpack plus standard OCI image layout import/export
- `crates/ai-catalog-cli` — CLI entry point for validating and formatting catalogs

## First milestone

The first milestone is a green `cargo test` that parses, serializes, and
validates the canonical spec example plus a small set of semantic rules such as
`url`/`data` exclusivity, duplicate identifiers, and trust identity binding.

## CLI

Build and test the workspace with:

```sh
just build
just lint
just test
just coverage
```

Use the CLI with:

```sh
cargo run -p ai-catalog-cli -- help
cargo run -p ai-catalog-cli -- validate fixtures/spec-example.json
cargo run -p ai-catalog-cli -- validate --json fixtures/spec-example.json
cargo run -p ai-catalog-cli -- format fixtures/spec-example.json
cargo run -p ai-catalog-cli -- trust inspect fixtures/spec-example.json
cargo run -p ai-catalog-cli -- trust inspect --json fixtures/spec-example.json
cargo run -p ai-catalog-cli -- oci pack fixtures/spec-example.json
cargo run -p ai-catalog-cli -- oci unpack artifacts.json
cargo run -p ai-catalog-cli -- oci export-layout fixtures/spec-example.json /tmp/ai-catalog-layout
cargo run -p ai-catalog-cli -- oci unpack-layout /tmp/ai-catalog-layout
cargo run -p ai-catalog-cli -- oci push fixtures/spec-example.json ghcr.io/example/ai-catalog:latest
cargo run -p ai-catalog-cli -- oci push fixtures/spec-example.json example.com:latest --to-oci-layout-path /tmp/ai-catalog-copy
cat fixtures/spec-example.json | cargo run -p ai-catalog-cli -- validate --json -
cat fixtures/spec-example.json | cargo run -p ai-catalog-cli -- format -
cat fixtures/spec-example.json | cargo run -p ai-catalog-cli -- oci pack -
```

`oci pack` and `oci unpack` operate on the internal JSON artifact-set envelope used by
the Rust library. `oci export-layout` writes a standard OCI image layout directory,
`oci unpack-layout` imports that standard layout back into AI Catalog JSON, and
`oci push` delegates distribution to `oras cp -r` from a temporary exported layout
so standard OCI tooling can validate or publish the result.

## Demo

Run the end-to-end OCI walkthrough with:

```sh
just demo-oci-layout
```

The walkthrough script lives at `demo/oci-layout-walkthrough.sh` and is described
in `demo/oci-layout-walkthrough.md`.

## Governance

- `LICENSE` — Apache License 2.0
- `CONTRIBUTING.md` — contribution workflow and local checks
- `CODE_OF_CONDUCT.md` — collaboration expectations
- `SECURITY.md` — vulnerability reporting guidance
- `GOVERNANCE.md` — project decision-making and branch policy
