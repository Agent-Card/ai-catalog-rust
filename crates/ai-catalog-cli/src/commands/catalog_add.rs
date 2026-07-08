// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use colored::Colorize;

use ai_catalog::CatalogEntry;

use crate::cache::CacheManager;
use crate::error::{Error, Result};
use crate::fetch::build_client;
use crate::resolver::{make_entry_metadata, resolve_and_cache};

pub async fn execute(name: &str, url: &str) -> Result<()> {
    let cache = CacheManager::new()?;
    cache.ensure_dirs()?;
    let client = build_client()?;
    {
        let registry = cache.read_registry()?;
        for entry in &registry.entries {
            if entry
                .display_name
                .as_deref()
                .map(|n| n.eq_ignore_ascii_case(name))
                .unwrap_or(false)
            {
                return Err(Error::Other(format!(
                    "a catalog named \"{name}\" is already registered. Use `ai-catalog catalog update {name}` to refresh it."
                )));
            }
            if let Some(source_url) = entry
                .metadata
                .as_ref()
                .and_then(|m| m.get("sourceUrl"))
                .and_then(|v| v.as_str())
            {
                if source_url.eq_ignore_ascii_case(url) {
                    return Err(Error::Other(format!(
                        "URL is already registered as \"{}\". Use `ai-catalog catalog update {}` to refresh it.",
                        entry.display_name.as_deref().unwrap_or("?"),
                        entry.display_name.as_deref().unwrap_or("?")
                    )));
                }
            }
        }
    }
    println!("Fetching catalog from {}...", url.cyan());
    let entries = resolve_and_cache(url, &client, &cache).await?;
    let url_to_hash = cache.read_refs()?;
    let root_hash = url_to_hash
        .get(url)
        .ok_or_else(|| Error::Other(format!("root catalog hash not found after fetch: {url}")))?
        .clone();
    let entry_count = entries.len();
    let file_url = cache.object_file_url(&root_hash);
    let identifier = format!("urn:ai-catalog:local:{}", &root_hash[..8]);
    let meta_val = make_entry_metadata(url, &root_hash, entry_count);
    let new_entry = CatalogEntry {
        identifier,
        entry_type: "application/ai-catalog+json".to_string(),
        display_name: Some(name.to_string()),
        description: None,
        tags: Vec::new(),
        url: Some(file_url),
        data: None,
        version: None,
        updated_at: Some(chrono::Utc::now().to_rfc3339()),
        metadata: Some(serde_json::from_value(meta_val).unwrap_or_default()),
        publisher: None,
        trust_manifest: None,
        extra_fields: Default::default(),
    };
    let mut registry = cache.read_registry()?;
    registry.entries.push(new_entry);
    cache.write_registry(&registry)?;
    println!(
        "{} \"{}\" added ({} entries)",
        "✓".green(),
        name.bold(),
        entry_count
    );
    Ok(())
}
