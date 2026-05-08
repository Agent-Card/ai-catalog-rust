# OCI Layout Walkthrough

This walkthrough exercises the standard OCI path end to end with a small trusted
catalog that contains an inline entry and a trust manifest. It now also uses
Cosign to generate a temporary signing keypair and stores detached signature and
public-key verification artifacts alongside the trust manifest in the OCI layout.

Run it with:

```sh
just demo-oci-layout
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
uses `python3` only to select the correct referrer and blob digests from the
JSON returned by ORAS.