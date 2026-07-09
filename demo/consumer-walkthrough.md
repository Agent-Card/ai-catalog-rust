# Consumer Workflow Walkthrough

This walkthrough exercises the full `ai-catalog` CLI surface end to end using
only local files — no network calls, no external registry.  It uses
`AI_CATALOG_CACHE_DIR` to keep all state in a temporary directory so it never
touches your real `~/.ai-catalog/` registry.

The script creates two nested catalogs:

- **Root catalog** — agent, model, inline-config, and a reference to a nested catalog
- **Nested catalog** — two dataset entries (one remote URL, one pullable local file)

Both catalogs follow the AI Catalog spec with `"type"` for entry types and
`"specVersion": "1.0"`.

## Prerequisites

- Bash-compatible shell on macOS or Linux, or PowerShell on Windows
- Rust with `cargo` on `PATH`

`just` is optional but is the documented entry point for repository tasks.

### macOS

```sh
brew install rust just
```

### Linux

- Rust: https://www.rust-lang.org/tools/install
- just: https://just.systems/man/en/packages.html

### Windows

```powershell
winget install --id Rustlang.Rustup --exact
winget install --id Casey.Just --exact
```

Open a new terminal after installation so `cargo` and `just` are on `PATH`.

## Running the walkthrough

```sh
just demo-consumer
```

Or directly:

```sh
./demo/consumer-walkthrough.sh
```

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo\consumer-walkthrough.ps1
```

## CLI surfaces covered

The walkthrough exercises 21 steps covering the full CLI:

### Author commands

| Step | Command |
|------|---------|
| 1 | `ai-catalog validate <file>` — text output |
| 2 | `ai-catalog validate --json <file>` — JSON output |
| 3 | `ai-catalog validate --json -` — validate from stdin |
| 4 | `ai-catalog format <file>` — pretty-print |
| 5 | `ai-catalog trust inspect <file>` — text output |
| 6 | `ai-catalog trust inspect --json <file>` — JSON output |

### Consumer commands

| Step | Command |
|------|---------|
| 7  | `ai-catalog catalog add <name> <url>` — register a catalog |
| 8  | `ai-catalog catalog list` — text table |
| 9  | `ai-catalog catalog list --json` — JSON output |
| 10 | `ai-catalog search <keyword>` — text table |
| 11 | `ai-catalog search --json <keyword>` — JSON output |
| 12 | `ai-catalog search --regex <pattern>` — regex search across all cached catalogs |
| 13 | `ai-catalog search -n <N> <keyword>` — limit results |
| 14 | `ai-catalog show <identifier>` — entry detail, text table |
| 15 | `ai-catalog show --json <identifier>` — entry detail, JSON |
| 16 | `ai-catalog show --scope <name> <identifier>` — restrict search to one catalog |
| 17 | `ai-catalog pull --output <dir> <identifier>` — pull inline-data entry to disk |
| 18 | `ai-catalog pull --output <dir> <identifier>` — pull file-URL entry to disk |
| 19 | `ai-catalog catalog update <name>` — re-fetch and refresh a registered catalog |
| 20 | `ai-catalog catalog remove <name>` — unregister a catalog |
| 21 | `ai-catalog catalog list` — confirm empty registry after removal |

## What the script does

1. Creates a temporary directory and sets `AI_CATALOG_CACHE_DIR` to isolate the
   demo from your real registry.
2. Writes a three-entry JSONL eval file, a nested dataset catalog (two entries),
   and a root catalog (agent, model, inline config, nested-catalog reference) —
   all using `file://` URLs so no network is required.
3. Runs the author commands against the root catalog to demonstrate validation,
   formatting, and trust inspection.
4. Registers the root catalog with `catalog add`.  The CLI resolves the nested
   catalog reference and caches all entries via content-addressed storage under
   `AI_CATALOG_CACHE_DIR/objects/`.
5. Searches the cached entries by keyword, regex, and result limit.
6. Shows individual entry details by identifier in both text and JSON formats,
   and demonstrates `--scope` to restrict lookup to one named catalog.
7. Pulls two entries to disk:
   - `urn:demo:config:default-settings` — saved from the inline `data` field
     (no network required)
   - `urn:demo:dataset:eval-suite-v3` — fetched from the `file://` URL
8. Updates and removes the catalog, then confirms the registry is empty.
9. Cleans up the temporary directory on exit.

## Key concepts demonstrated

**Content-addressed storage** — catalogs are stored under
`AI_CATALOG_CACHE_DIR/objects/<sha256>.json` so identical content is never
duplicated.

**Nested catalog resolution** — `catalog add` follows `application/ai-catalog+json`
entries recursively (up to depth 10) and indexes all leaf entries so they are
searchable and showable by identifier.

**Inline-data pull** — entries with a `data` field are written offline without
any HTTP fetch.

**Scoped search** — `show --scope <name>` and `search` with `--scope` restrict
results to a single registered catalog by its local name.

**Isolation** — `AI_CATALOG_CACHE_DIR` lets the demo, tests, and CI all run
independently without touching the user's real `~/.ai-catalog/` registry.
