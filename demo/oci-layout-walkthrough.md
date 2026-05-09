# OCI Layout Walkthrough

This walkthrough exercises the standard OCI path end to end with a small trusted
catalog that contains an inline entry and a trust manifest. It now also uses
Cosign to generate a temporary signing keypair and stores detached signature and
public-key verification artifacts alongside the trust manifest in the OCI layout.

## Prerequisites

The walkthrough requires:

- a Bash-compatible shell on macOS or Linux, or PowerShell on Windows
- Rust with `cargo` on `PATH`
- ORAS CLI on `PATH`
- Cosign CLI on `PATH`

`just` is optional, but it is the documented entry point for repository tasks.

### macOS

Install the dependencies before running the demo:

```sh
brew install rust oras cosign just
```

### Linux

Install Rust with Rustup, then install ORAS, Cosign, and optionally `just`
using your distro package manager or the upstream release binaries:

- Rust: https://www.rust-lang.org/tools/install
- ORAS: https://oras.land/docs/installation
- Cosign: https://docs.sigstore.dev/cosign/system_config/installation/
- just: https://just.systems/man/en/packages.html

### Windows

Install these dependencies before running the PowerShell walkthrough:

```powershell
winget install --id Rustlang.Rustup --exact
winget install --id ORASProject.ORAS --exact
winget install --id Sigstore.Cosign --exact
winget install --id Casey.Just --exact
```

Open a new terminal after installation so `cargo`, `oras`, `cosign`, and
`just` are available on `PATH`.

Current upstream ORAS and Cosign Windows release assets are `amd64`, so Windows
ARM64 users should prefer WSL or x64 emulation for this walkthrough.

Run it with:

```sh
just demo-oci-layout
```

On Windows PowerShell, use:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo\oci-layout-walkthrough.ps1
```

The script performs these steps:

1. Validates the demo catalog with `ai-catalog-cli validate`.
2. Generates an ephemeral Cosign keypair for the walkthrough.
3. Exports a standard OCI image layout with `ai-catalog-cli oci export-layout --cosign-key --cosign-public-key`.
4. Uses `oras manifest fetch` to prove the layout is readable by a standard OCI tool.
5. Uses `oras discover` on the entry manifest digest to show the trust-manifest, Cosign signature, and Cosign public-key referrers.
6. Fetches and prints the detached Cosign signature plus the public-key identity and PEM from those OCI referrers.
7. Imports the standard OCI layout back into AI Catalog JSON with `ai-catalog-cli oci unpack-layout`.
8. Validates the imported catalog again.
9. Uses `ai-catalog-cli oci push --to-oci-layout-path --cosign-key --cosign-public-key` to copy the artifact set into a second OCI layout through ORAS.
10. Uses `oras discover` again to verify the copied layout still exposes the trust and Cosign referrers.
11. Fetches and prints the copied signature and public-key identity again to show the verification material survived the copy.

The demo intentionally uses temporary files and directories so it can be rerun
without cleaning up repository state. The AI Catalog JSON round-trip still only
contains catalog and trust-manifest data; the detached Cosign signature and
public key remain attached as OCI referrer artifacts in the layout. The script
uses ORAS go-template output and bash helpers to select the correct referrer and
blob digests.