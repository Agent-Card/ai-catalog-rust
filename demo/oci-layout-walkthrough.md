# OCI Layout Walkthrough

This walkthrough exercises the standard OCI path end to end with a small trusted
catalog that contains an inline entry and a trust manifest.

Run it with:

```sh
just demo-oci-layout
```

The script performs these steps:

1. Validates the demo catalog with `ai-catalog-cli validate`.
2. Exports a standard OCI image layout with `ai-catalog-cli oci export-layout`.
3. Uses `oras manifest fetch` to prove the layout is readable by a standard OCI tool.
4. Uses `oras discover` on the entry manifest digest to show the trust-manifest referrer.
5. Imports the standard OCI layout back into AI Catalog JSON with `ai-catalog-cli oci unpack-layout`.
6. Validates the imported catalog again.
7. Uses `ai-catalog-cli oci push --to-oci-layout-path` to copy the artifact set into a second OCI layout through ORAS.
8. Uses `oras discover` again to verify the copied layout still exposes the trust referrer.

The demo intentionally uses temporary files and directories so it can be rerun
without cleaning up repository state.