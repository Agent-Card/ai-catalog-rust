# Contributing

Contributions are accepted through pull requests.

## Workflow

1. Create a feature branch from `main`.
2. Make focused changes with tests and documentation updates when relevant.
3. Run the local checks before opening a pull request.
4. Open a pull request for review; do not push directly to `main`.

## Local Checks

Run the baseline checks before requesting review:

```sh
just build
just lint
just test
cargo fmt --check
```

If you touch OCI functionality, also run:

```sh
just demo-oci-layout
```

## Change Expectations

- Keep changes scoped to a single concern when possible.
- Add or update tests for behavior changes.
- Update `README.md`, ADRs, or demo material when the user-facing workflow changes.
- Preserve the repository license headers on source and script files.

## Review and Merge

- Pull requests should describe the motivation, implementation approach, and validation performed.
- Significant format or specification decisions should be captured in `adr/` when appropriate.
- Changes land through reviewed pull requests.