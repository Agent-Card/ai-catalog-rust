// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use colored::Colorize;

use ai_catalog::{AiCatalog, CatalogEntry};

use crate::cache::CacheManager;
use crate::error::{Error, Result};
use crate::fetch::build_client;
use crate::resolver::{
    find_entry_by_id_in_registry, find_entry_by_id_in_url, resolve_and_cache,
    resolve_catalog_leaf_entries,
};

use super::OutputFormat;

const CATALOG_MIME_TYPE: &str = "application/ai-catalog+json";

/// Show full details of a catalog entry by identifier.
///
/// `scope` restricts the search to a specific catalog (by registered name or URI).
/// `media_type` disambiguates when the entry resolves to a catalog:
///   - None or "application/ai-catalog+json" → show the catalog entry itself
///   - other → find the single child entry of that type and show it
pub async fn execute(
    identifier: &str,
    output: OutputFormat,
    scope: Option<&str>,
    media_type: Option<&str>,
) -> Result<()> {
    let cache = CacheManager::new()?;
    let client = build_client()?;

    let entry = if let Some(scope_val) = scope {
        find_entry_in_scope(identifier, scope_val, &cache, &client).await?
    } else {
        find_entry_by_id_in_registry(identifier, &cache)?
    };

    let entry = entry.ok_or_else(|| Error::EntryNotFound(identifier.to_string()))?;

    dispatch_show_entry(&entry, output, media_type, &cache).await
}

/// Core dispatch: handle media_type gating and catalog-vs-leaf branching.
/// Also used by `oci_show`.
pub(crate) async fn dispatch_show_entry(
    entry: &CatalogEntry,
    output: OutputFormat,
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
        return print_entry(entry, &output, cache);
    }

    // Catalog entry — branch on --media-type
    match media_type {
        None | Some(CATALOG_MIME_TYPE) => print_entry(entry, &output, cache),
        Some(mt) => {
            let leaves = catalog_leaf_entries_for_entry(entry, cache)?;
            let matches: Vec<&_> = leaves.iter().filter(|e| e.entry.entry_type == mt).collect();
            match matches.len() {
                0 => Err(Error::EntryNotFound(format!(
                    "no entries of type \"{mt}\" found in catalog \"{}\"",
                    entry.identifier
                ))),
                1 => print_entry(&matches[0].entry, &output, cache),
                n => Err(Error::Other(format!(
                    "{n} entries of type \"{mt}\" found in catalog \"{}\"; \
                     use --scope to narrow the search",
                    entry.identifier
                ))),
            }
        }
    }
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
        // Treat as a registered catalog name or sourceUrl metadata
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

fn print_entry(entry: &CatalogEntry, output: &OutputFormat, cache: &CacheManager) -> Result<()> {
    if let OutputFormat::Json = output {
        println!("{}", serde_json::to_string_pretty(entry)?);
        return Ok(());
    }
    print_entry_table(entry, cache);
    Ok(())
}

pub(crate) fn print_entry_table(entry: &CatalogEntry, cache: &CacheManager) {
    println!("{}", "─".repeat(60));
    println!("  {}  {}", "Identifier:".bold(), entry.identifier);
    if let Some(name) = &entry.display_name {
        println!("  {}  {}", "Name:".bold(), name);
    }
    println!("  {}  {}", "Type:".bold(), entry.entry_type);
    if let Some(desc) = &entry.description {
        println!("  {}  {}", "Description:".bold(), desc);
    }
    if let Some(ver) = &entry.version {
        println!("  {}  {}", "Version:".bold(), ver);
    }
    if let Some(updated) = &entry.updated_at {
        println!("  {}  {}", "Updated at:".bold(), updated);
    }
    if !entry.tags.is_empty() {
        println!("  {}  {}", "Tags:".bold(), entry.tags.join(", "));
    }
    if let Some(url) = &entry.url {
        println!("  {}  {}", "URL:".bold(), url);
    }
    if let Some(publisher) = &entry.publisher {
        println!(
            "  {}  {} ({})",
            "Publisher:".bold(),
            publisher.display_name,
            publisher.identifier
        );
    }
    if let Some(trust) = &entry.trust_manifest {
        println!("  {}  {}", "Trust identity:".bold(), trust.identity);
        if trust.signature.is_some() {
            println!("  {}  present", "Signature:".bold());
        }
        if !trust.attestations.is_empty() {
            println!(
                "  {}  {} attestation(s)",
                "Attestations:".bold(),
                trust.attestations.len()
            );
        }
    }
    if let Some(meta) = &entry.metadata
        && !meta.is_empty()
    {
        println!("  {}:", "Metadata".bold());
        for (k, v) in meta {
            println!("    {}: {}", k, v);
        }
    }

    // If this is a nested catalog entry, show its leaf entries
    if entry.is_nested_catalog() {
        print_nested_catalog_entries(entry, cache);
    }

    println!("{}", "─".repeat(60));
}

fn print_nested_catalog_entries(entry: &CatalogEntry, cache: &CacheManager) {
    let file_url = match &entry.url {
        Some(u) if u.starts_with("file://") => u.clone(),
        _ => return,
    };

    let path = file_url.strip_prefix("file://").unwrap_or(&file_url);
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return,
    };
    let catalog: AiCatalog = match serde_json::from_slice(&bytes) {
        Ok(c) => c,
        Err(_) => return,
    };
    let leaf_entries = match resolve_catalog_leaf_entries(&catalog, &file_url, cache) {
        Ok(e) => e,
        Err(_) => return,
    };

    if leaf_entries.is_empty() {
        return;
    }

    println!(
        "  {}  {} entries",
        "Nested entries:".bold(),
        leaf_entries.len()
    );
    for resolved in leaf_entries.iter().take(10) {
        let e = &resolved.entry;
        let name = e.display_name.as_deref().unwrap_or("-");
        println!("    • {} ({})", e.identifier.cyan(), name);
    }
    if leaf_entries.len() > 10 {
        println!("    … and {} more", leaf_entries.len() - 10);
    }
}
