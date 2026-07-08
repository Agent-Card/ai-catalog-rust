// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use colored::Colorize;

use ai_catalog::CatalogEntry;

use crate::cache::CacheManager;
use crate::error::{Error, Result};
use crate::fetch::build_client;
use crate::resolver::{find_entry_by_id_in_registry, resolve_and_cache};

/// Pull a catalog entry by identifier and write its content to disk.
///
/// If `output_path` is a directory (or omitted), a filename is derived from
/// the identifier. If it ends with a filename, that path is used directly.
///
/// For nested-catalog entries the full catalog JSON is written; for all other
/// types the raw bytes fetched from `entry.url` are written (if present).
pub async fn execute(identifier: &str, output_path: Option<&str>) -> Result<()> {
    let cache = CacheManager::new()?;

    // First search the local registry without hitting the network.
    let entry = find_entry_by_id_in_registry(identifier, &cache)?;

    if let Some(entry) = entry {
        write_entry(&entry, output_path, &cache).await?;
    } else {
        // The identifier might itself be a URL – try fetching it as a catalog.
        if identifier.starts_with("http://") || identifier.starts_with("https://") {
            pull_from_url(identifier, output_path, &cache).await?;
        } else {
            return Err(Error::EntryNotFound(format!(
                "{identifier} — run `ai-catalog search {identifier}` or `ai-catalog catalog add <name> <url>` first"
            )));
        }
    }

    Ok(())
}

async fn pull_from_url(url: &str, output_path: Option<&str>, cache: &CacheManager) -> Result<()> {
    println!("Fetching catalog from {}...", url.cyan());
    let client = build_client()?;
    cache.ensure_dirs()?;
    let entries = resolve_and_cache(url, &client, cache).await?;
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
        let dest = resolve_output_path(output_path, url, "json");
        std::fs::write(&dest, &bytes)?;
        println!("{} written to {}", "✓".green(), dest.display());
    }
    Ok(())
}

async fn write_entry(
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
    // For a nested catalog entry, read the locally cached file.
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
    // Prefer inline data, fall back to fetching the URL.
    if let Some(data) = &entry.data {
        let bytes = serde_json::to_vec_pretty(data)?;
        let ext = extension_for_type(&entry.entry_type);
        let dest = resolve_output_path(output_path, &entry.identifier, ext);
        std::fs::write(&dest, &bytes)?;
        println!(
            "{} \"{}\" written to {}",
            "✓".green(),
            entry.identifier.bold(),
            dest.display()
        );
        return Ok(());
    }

    if let Some(url) = &entry.url {
        let client = build_client()?;
        let bytes = crate::fetch::fetch_bytes(url, &client).await?;
        let ext = extension_for_type(&entry.entry_type);
        let dest = resolve_output_path(output_path, &entry.identifier, ext);
        std::fs::write(&dest, &bytes)?;
        println!(
            "{} \"{}\" written to {}",
            "✓".green(),
            entry.identifier.bold(),
            dest.display()
        );
        return Ok(());
    }

    Err(Error::Other(format!(
        "entry \"{}\" has neither inline data nor a URL to fetch",
        entry.identifier
    )))
}

/// Derive a destination path from an optional user-supplied path, a stem
/// derived from the identifier/URL, and a file extension.
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

/// Turn an identifier or URL into a safe filename stem + the given extension.
fn safe_filename(stem: &str, ext: &str) -> String {
    // Use only the last component of a URN / URL path.
    let base = stem
        .rsplit(':')
        .next()
        .or_else(|| stem.rsplit('/').next())
        .unwrap_or(stem);
    let sanitised: String = base
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    format!("{sanitised}.{ext}")
}

/// Pick a reasonable file extension given a MIME type string.
fn extension_for_type(mime: &str) -> &'static str {
    match mime {
        "application/json" | "application/ai-catalog+json" => "json",
        "application/yaml" | "text/yaml" => "yaml",
        "text/plain" => "txt",
        "application/octet-stream" => "bin",
        _ => "json",
    }
}
