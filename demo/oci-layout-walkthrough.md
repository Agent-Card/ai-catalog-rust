# OCI Layout Walkthrough

This walkthrough exercises the standard OCI path end to end with a small trusted
catalog that contains an inline entry and a trust manifest. It generates an
ephemeral Cosign keypair and stores a detached signature and public-key
verification artifacts alongside the trust manifest in the OCI layout.

## Prerequisites

The walkthrough requires:

- a Bash-compatible shell on macOS or Linux, or PowerShell on Windows
- Rust with `cargo` on `PATH`
- ORAS CLI on `PATH`
- Cosign CLI on `PATH`

`just` is optional, but it is the documented entry point for repository tasks.

### macOS

```sh
brew install rust oras cosign just
```

### Linux

- Rust: https://www.rust-lang.org/tools/install
- ORAS: https://oras.land/docs/installation
- Cosign: https://docs.sigstore.dev/cosign/system_config/installation/
- just: https://just.systems/man/en/packages.html

### Windows

```powershell
winget install --id Rustlang.Rustup --exact
winget install --id ORASProject.ORAS --exact
winget install --id Sigstore.Cosign --exact
winget install --id Casey.Just --exact
```

Open a new terminal after installation so `cargo`, `oras`, `cosign`, and `just`
are on `PATH`. ORAS and Cosign Windows releases are `amd64`; Windows ARM64 users
should prefer WSL or x64 emulation.

## Running the walkthrough

```sh
just demo-oci-layout
```

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo\oci-layout-walkthrough.ps1
```

## What the script does

The script uses the `ai-catalog` binary (built from `crates/ai-catalog-cli`) via
`cargo run -p ai-catalog-cli`. The demo catalog uses `"type"` for the entry type
field, matching the AI Catalog specification.

1. Writes a demo catalog with one inline entry (`"type": "application/json"`)
   and a trust manifest.
2. Validates the demo catalog with `ai-catalog validate`.
3. Generates an ephemeral Cosign keypair for the walkthrough.
4. Exports a standard OCI image layout with
   `ai-catalog oci export-layout --cosign-key --cosign-public-key`.
5. Uses `oras manifest fetch` to prove the layout is readable by standard OCI
   tooling.
6. Uses `oras discover` on the entry manifest digest to show the trust-manifest,
   Cosign signature, and Cosign public-key referrers.
7. Fetches and prints the detached Cosign signature and the public-key identity
   and PEM from those OCI referrers.
8. Imports the OCI layout back into AI Catalog JSON with
   `ai-catalog oci unpack-layout`.
9. Validates the imported catalog.
10. Uses `ai-catalog oci push --to-oci-layout-path --cosign-key
    --cosign-public-key` to copy the artifact set into a second OCI layout
    through ORAS.
11. Uses `oras discover` again to verify the copied layout still exposes the
    trust and Cosign referrers.
12. Fetches and prints the copied signature and public-key identity.

The demo uses temporary files and directories and cleans them up on exit. The AI
Catalog JSON round-trip contains catalog and trust-manifest data only; detached
Cosign signatures and public keys remain attached as OCI referrer artifacts in
the layout.
