// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use colored::Colorize;

use crate::cache::CacheManager;
use crate::error::{Error, Result};
use crate::fetch::build_client;
use crate::resolver::{make_entry_metadata, resolve_and_cache};

pub async fn execute(name: &str) -> Result<()> {
    let cache = CacheManager::new()?;
    cache.ensure_dirs()?;
    let client = build_client()?;
    let mut registry = cache.read_registry()?;
    let idx = registry
        .entries
        .iter()
        .position(|e| {
            e.display_name
                .as_deref()
                .map(|n| n.eq_ignore_ascii_case(name))
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            Error::CatalogNotFound(format!(
                "no catalog named \"{name}\". Use `ai-catalog catalog list` to see registered catalogs."
            ))
        })?;
    let source_url = registry.entries[idx]
        .metadata
        .as_ref()
        .and_then(|m| m.get("sourceUrl"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::Other(format!(
                "catalog \"{name}\" has no sourceUrl in metadata"
            ))
        })?
        .to_string();
    let old_hash = registry.entries[idx]
        .metadata
        .as_ref()
        .and_then(|m| m.get("contentHash"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    print!("Updating \"{}\"... ", name.bold());
    let new_entries = resolve_and_cache(&source_url, &client, &cache).await?;
    let url_to_hash = cache.read_refs()?;
    let new_hash = url_to_hash
        .get(&source_url)
        .ok_or_else(|| Error::Other("root catalog hash not found after fetch".to_string()))?
        .clone();
    if old_hash.as_deref() == Some(&new_hash) {
        println!("{}", "(up to date)".dimmed());
        return Ok(());
    }
    let entry_count = new_entries.len();
    let file_url = cache.object_file_url(&new_hash);
    let meta_val = make_entry_metadata(&source_url, &new_hash, entry_count);
    registry.entries[idx].url = Some(file_url);
    registry.entries[idx].identifier =
        format!("urn:ai-catalog:local:{}", &new_hash[..8]);
    registry.entries[idx].updated_at = Some(chrono::Utc::now().to_rfc3339());
    registry.entries[idx].metadata =
        Some(serde_json::from_value(meta_val).unwrap_or_default());
    cache.write_registry(&registry)?;
    println!(
        "{} ({entry_count} entries, hash {})",
        "updated".green(),
        &new_hash[..8]
    );
    Ok(())
}
