// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use colored::Colorize;

use crate::cache::CacheManager;
use crate::error::{Error, Result};

pub async fn execute(name_or_url: &str) -> Result<()> {
    let cache = CacheManager::new()?;
    let mut registry = cache.read_registry()?;
    let pos = registry.entries.iter().position(|e| {
        e.display_name
            .as_deref()
            .map(|n| n.eq_ignore_ascii_case(name_or_url))
            .unwrap_or(false)
            || e.metadata
                .as_ref()
                .and_then(|m| m.get("sourceUrl"))
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case(name_or_url))
                .unwrap_or(false)
    });
    let pos = pos.ok_or_else(|| {
        Error::CatalogNotFound(format!(
            "no catalog matching \"{name_or_url}\" found. Use `ai-catalog catalog list` to see registered catalogs."
        ))
    })?;
    let removed = registry.entries.remove(pos);
    let display_name = removed.display_name.as_deref().unwrap_or("<unnamed>");
    let referenced_hashes: std::collections::HashSet<String> = registry
        .entries
        .iter()
        .filter_map(|e| {
            e.metadata
                .as_ref()
                .and_then(|m| m.get("contentHash"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    if let Some(hash) = removed
        .metadata
        .as_ref()
        .and_then(|m| m.get("contentHash"))
        .and_then(|v| v.as_str())
    {
        if !referenced_hashes.contains(hash) {
            let obj_path = cache.object_path(hash);
            if obj_path.exists() {
                std::fs::remove_file(&obj_path)?;
            }
            let mut refs = cache.read_refs()?;
            refs.retain(|_, v| v != hash);
            cache.write_refs(&refs)?;
        }
    }
    cache.write_registry(&registry)?;
    println!("{} \"{}\" removed.", "✓".green(), display_name.bold());
    Ok(())
}
