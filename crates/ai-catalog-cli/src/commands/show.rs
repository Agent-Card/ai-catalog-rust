// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use colored::Colorize;

use ai_catalog::{AiCatalog, CatalogEntry};

use crate::cache::CacheManager;
use crate::error::{Error, Result};
use crate::resolver::{
    find_entry_by_id_in_registry, find_entry_by_id_in_url, resolve_catalog_leaf_entries,
};

use super::OutputFormat;

/// Show full details of a catalog entry by identifier.
///
/// `scope` optionally restricts the search to a specific registered catalog
/// (by name or source URL). If omitted, the entire local registry is searched.
pub async fn execute(
    identifier: &str,
    output: OutputFormat,
    scope: Option<&str>,
) -> Result<()> {
    let cache = CacheManager::new()?;

    let entry = if let Some(scope_name) = scope {
        find_entry_in_scope(identifier, scope_name, &cache)?
    } else {
        find_entry_by_id_in_registry(identifier, &cache)?
    };

    let entry = entry.ok_or_else(|| Error::EntryNotFound(identifier.to_string()))?;

    if let OutputFormat::Json = output {
        println!("{}", serde_json::to_string_pretty(&entry)?);
        return Ok(());
    }

    print_entry_table(&entry, &cache);
    Ok(())
}

fn find_entry_in_scope(
    identifier: &str,
    scope_name: &str,
    cache: &CacheManager,
) -> Result<Option<CatalogEntry>> {
    let registry = cache.read_registry()?;
    // Find the registry entry matching the scope name or source URL
    let catalog_entry = registry.entries.iter().find(|e| {
        e.display_name
            .as_deref()
            .map(|n| n.eq_ignore_ascii_case(scope_name))
            .unwrap_or(false)
            || e.metadata
                .as_ref()
                .and_then(|m| m.get("sourceUrl"))
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case(scope_name))
                .unwrap_or(false)
    });
    let catalog_entry = catalog_entry.ok_or_else(|| {
        Error::CatalogNotFound(format!(
            "no catalog matching \"{scope_name}\" found. Use `ai-catalog catalog list` to see registered catalogs."
        ))
    })?;
    let file_url = catalog_entry
        .url
        .as_deref()
        .ok_or_else(|| Error::Other(format!("catalog \"{scope_name}\" has no local file URL")))?;
    find_entry_by_id_in_url(identifier, file_url, cache)
}

fn print_entry_table(entry: &CatalogEntry, cache: &CacheManager) {
    println!("{}", "─".repeat(60));
    println!(
        "  {}  {}",
        "Identifier:".bold(),
        entry.identifier
    );
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
    if let Some(meta) = &entry.metadata {
        if !meta.is_empty() {
            println!("  {}:", "Metadata".bold());
            for (k, v) in meta {
                println!("    {}: {}", k, v);
            }
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

    println!("  {}  {} entries", "Nested entries:".bold(), leaf_entries.len());
    for resolved in leaf_entries.iter().take(10) {
        let e = &resolved.entry;
        let name = e.display_name.as_deref().unwrap_or("-");
        println!("    • {} ({})", e.identifier.cyan(), name);
    }
    if leaf_entries.len() > 10 {
        println!(
            "    … and {} more",
            leaf_entries.len() - 10
        );
    }
}
