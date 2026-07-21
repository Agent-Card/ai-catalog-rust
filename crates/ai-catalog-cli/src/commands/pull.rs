// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use colored::Colorize;

use ai_catalog::{AiCatalog, CatalogEntry};

use crate::cache::CacheManager;
use crate::error::{Error, Result};
use crate::fetch::build_client;
use crate::resolver::{
    find_entry_by_id_in_registry, find_entry_by_id_in_url, resolve_and_cache,
    resolve_catalog_leaf_entries,
};

const CATALOG_MIME_TYPE: &str = "application/ai-catalog+json";

/// Pull a catalog entry by identifier and write its content to disk.
///
/// `scope` restricts the search to a specific catalog (by registered name or URI).
/// `media_type` disambiguates when the entry resolves to a catalog:
///   - None → error
///   - "application/ai-catalog+json" → write the catalog JSON itself
///   - other → find the single child entry of that type and write it
pub async fn execute(
    identifier: &str,
    output_path: Option<&str>,
    scope: Option<&str>,
    media_type: Option<&str>,
) -> Result<()> {
    let cache = CacheManager::new()?;
    let client = build_client()?;

    let entry = if let Some(scope_val) = scope {
        find_entry_in_scope(identifier, scope_val, &cache, &client).await?
    } else {
        // First search the local registry without hitting the network.
        let found = find_entry_by_id_in_registry(identifier, &cache)?;
        if found.is_none() {
            // The identifier might itself be a URL – try fetching it as a catalog.
            if identifier.starts_with("http://") || identifier.starts_with("https://") {
                return pull_from_url(identifier, output_path, &cache, &client).await;
            }
            return Err(Error::EntryNotFound(format!(
                "{identifier} — run `ai-catalog search {identifier}` or `ai-catalog catalog add <name> <url>` first"
            )));
        }
        found
    };

    let entry = entry.ok_or_else(|| Error::EntryNotFound(identifier.to_string()))?;

    dispatch_pull(&entry, output_path, media_type, &cache).await
}

/// Resolve an entry within a specific scope (registered name or URI).
async fn find_entry_in_scope(
    identifier: &str,
    scope: &str,
    cache: &CacheManager,
    client: &reqwest::Client,
) -> Result<Option<CatalogEntry>> {
    if scope.contains("://") {
        // Treat as a URI
        if scope.starts_with("file://") {
            find_entry_by_id_in_url(identifier, scope, cache)
        } else {
            // http/https — fetch and cache, then search
            cache.ensure_dirs()?;
            resolve_and_cache(scope, client, cache).await?;
            let url_to_hash = cache.read_refs()?;
            if let Some(hash) = url_to_hash.get(scope) {
                find_entry_by_id_in_url(identifier, &cache.object_file_url(hash), cache)
            } else {
                Ok(None)
            }
        }
    } else {
        // Treat as a registered catalog name
        let registry = cache.read_registry()?;
        let catalog_entry = registry.entries.iter().find(|e| {
            e.display_name
                .as_deref()
                .map(|n| n.eq_ignore_ascii_case(scope))
                .unwrap_or(false)
                || e.metadata
                    .as_ref()
                    .and_then(|m| m.get("sourceUrl"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.eq_ignore_ascii_case(scope))
                    .unwrap_or(false)
        });
        let catalog_entry = catalog_entry.ok_or_else(|| {
            Error::CatalogNotFound(format!(
                "no catalog matching \"{scope}\" found. Use `ai-catalog catalog list` to see registered catalogs."
            ))
        })?;
        let file_url = catalog_entry
            .url
            .as_deref()
            .ok_or_else(|| Error::Other(format!("catalog \"{scope}\" has no local file URL")))?;
        find_entry_by_id_in_url(identifier, file_url, cache)
    }
}

/// Core dispatch: handle media_type gating and catalog-vs-leaf branching.
///
/// Also used by `oci_pull` — the client is not needed here since all data
/// sources are either local cache or fetched inline by `write_data_entry`.
pub(crate) async fn dispatch_pull(
    entry: &CatalogEntry,
    output_path: Option<&str>,
    media_type: Option<&str>,
    cache: &CacheManager,
) -> Result<()> {
    if !entry.is_nested_catalog() {
        // Leaf entry — check media_type guard
        if let Some(mt) = media_type
            && entry.entry_type != mt
        {
            return Err(Error::Other(format!(
                "entry \"{}\" has type \"{}\" but --media-type \"{}\" was requested",
                entry.identifier, entry.entry_type, mt
            )));
        }
        return write_entry(entry, output_path, cache).await;
    }

    // Catalog entry — branch on --media-type
    match media_type {
        None => Err(Error::Other(format!(
            "\"{}\" refers to a catalog, not a pullable artifact.\n  \
             Use --media-type {CATALOG_MIME_TYPE} to fetch the catalog JSON itself, \
             or --media-type <type> to pull the single entry of that type within it.",
            entry.identifier
        ))),
        Some(mt) if mt == CATALOG_MIME_TYPE => write_entry(entry, output_path, cache).await,
        Some(mt) => {
            let leaves = catalog_leaf_entries_for_entry(entry, cache)?;
            let matches: Vec<&_> = leaves.iter().filter(|e| e.entry.entry_type == mt).collect();
            match matches.len() {
                0 => Err(Error::EntryNotFound(format!(
                    "no entries of type \"{mt}\" found in catalog \"{}\"",
                    entry.identifier
                ))),
                1 => write_entry(&matches[0].entry, output_path, cache).await,
                n => Err(Error::Other(format!(
                    "{n} entries of type \"{mt}\" found in catalog \"{}\"; \
                     use --scope to narrow the search",
                    entry.identifier
                ))),
            }
        }
    }
}

/// Get the leaf entries of a catalog entry using only the local cache.
fn catalog_leaf_entries_for_entry(
    entry: &CatalogEntry,
    cache: &CacheManager,
) -> Result<Vec<crate::resolver::ResolvedEntry>> {
    let file_url = entry.url.as_deref().ok_or_else(|| {
        Error::Other(format!("catalog entry \"{}\" has no URL", entry.identifier))
    })?;

    let path = file_url.strip_prefix("file://").unwrap_or(file_url);
    let bytes = std::fs::read(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("cannot read cached catalog at {file_url}: {e}"),
        ))
    })?;
    let catalog: AiCatalog = serde_json::from_slice(&bytes)?;
    resolve_catalog_leaf_entries(&catalog, file_url, cache)
}

async fn pull_from_url(
    url: &str,
    output_path: Option<&str>,
    cache: &CacheManager,
    client: &reqwest::Client,
) -> Result<()> {
    println!("Fetching catalog from {}...", url.cyan());
    cache.ensure_dirs()?;
    let entries = resolve_and_cache(url, client, cache).await?;
    println!(
        "{} fetched {} entries from {}",
        "✓".green(),
        entries.len(),
        url
    );
    let url_to_hash = cache.read_refs()?;
    if let Some(hash) = url_to_hash.get(url) {
        let file_url = cache.object_file_url(hash);
        let path = file_url.strip_prefix("file://").unwrap_or(&file_url);
        let bytes = std::fs::read(path)?;
        if output_path == Some("-") {
            use std::io::Write;
            std::io::stdout().write_all(&bytes)?;
        } else {
            let dest = resolve_output_path(output_path, url, "json");
            std::fs::write(&dest, &bytes)?;
            println!("{} written to {}", "✓".green(), dest.display());
        }
    }
    Ok(())
}

pub(crate) async fn write_entry(
    entry: &CatalogEntry,
    output_path: Option<&str>,
    cache: &CacheManager,
) -> Result<()> {
    if entry.is_nested_catalog() {
        write_catalog_entry(entry, output_path, cache).await
    } else {
        write_data_entry(entry, output_path).await
    }
}

async fn write_catalog_entry(
    entry: &CatalogEntry,
    output_path: Option<&str>,
    _cache: &CacheManager,
) -> Result<()> {
    let file_url = entry
        .url
        .as_deref()
        .ok_or_else(|| Error::Other(format!("entry \"{}\" has no URL", entry.identifier)))?;

    let path = file_url.strip_prefix("file://").unwrap_or(file_url);
    let bytes = std::fs::read(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("cannot read cached catalog at {file_url}: {e}"),
        ))
    })?;

    if output_path == Some("-") {
        use std::io::Write;
        std::io::stdout().write_all(&bytes)?;
        return Ok(());
    }

    let dest = resolve_output_path(output_path, &entry.identifier, "json");
    std::fs::write(&dest, &bytes)?;
    println!(
        "{} \"{}\" written to {}",
        "✓".green(),
        entry.identifier.bold(),
        dest.display()
    );
    Ok(())
}

async fn write_data_entry(entry: &CatalogEntry, output_path: Option<&str>) -> Result<()> {
    let bytes = if let Some(data) = &entry.data {
        serde_json::to_vec_pretty(data)?
    } else if let Some(url) = &entry.url {
        let client = build_client()?;
        crate::fetch::fetch_bytes(url, &client).await?
    } else {
        return Err(Error::Other(format!(
            "entry \"{}\" has neither inline data nor a URL to fetch",
            entry.identifier
        )));
    };

    if output_path == Some("-") {
        use std::io::Write;
        std::io::stdout().write_all(&bytes)?;
        return Ok(());
    }

    let ext = extension_for_type(&entry.entry_type);
    let dest = resolve_output_path(output_path, &entry.identifier, ext);
    std::fs::write(&dest, &bytes)?;
    println!(
        "{} \"{}\" written to {}",
        "✓".green(),
        entry.identifier.bold(),
        dest.display()
    );
    Ok(())
}

fn resolve_output_path(output_path: Option<&str>, stem: &str, ext: &str) -> PathBuf {
    let filename = safe_filename(stem, ext);
    match output_path {
        None => PathBuf::from(&filename),
        Some(p) => {
            let path = Path::new(p);
            if path.is_dir() {
                path.join(filename)
            } else {
                path.to_path_buf()
            }
        }
    }
}

fn safe_filename(stem: &str, ext: &str) -> String {
    let base = stem
        .rsplit(':')
        .next()
        .or_else(|| stem.rsplit('/').next())
        .unwrap_or(stem);
    let sanitised: String = base
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{sanitised}.{ext}")
}

fn extension_for_type(mime: &str) -> &'static str {
    match mime {
        "application/json" | "application/ai-catalog+json" => "json",
        "application/yaml" | "text/yaml" => "yaml",
        "text/plain" => "txt",
        "application/octet-stream" => "bin",
        _ => "json",
    }
}
