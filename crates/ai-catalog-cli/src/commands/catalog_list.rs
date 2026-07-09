// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use colored::Colorize;

use crate::cache::CacheManager;
use crate::error::Result;

use super::OutputFormat;

pub async fn execute(output: OutputFormat) -> Result<()> {
    let cache = CacheManager::new()?;
    let registry = cache.read_registry()?;

    if let OutputFormat::Json = output {
        println!("{}", serde_json::to_string_pretty(&registry)?);
        return Ok(());
    }

    if registry.entries.is_empty() {
        println!(
            "No catalogs registered. Use {} to add one.",
            "`ai-catalog catalog add <name> <url>`".cyan()
        );
        return Ok(());
    }

    // Column widths
    let name_w = registry
        .entries
        .iter()
        .map(|e| e.display_name.as_deref().unwrap_or("<unnamed>").len())
        .max()
        .unwrap_or(4)
        .max(4);
    let url_w = registry
        .entries
        .iter()
        .map(|e| {
            e.metadata
                .as_ref()
                .and_then(|m| m.get("sourceUrl"))
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .len()
        })
        .max()
        .unwrap_or(3)
        .clamp(3, 60);

    println!(
        "{:<name_w$}  {:<url_w$}  {:>7}  {:<20}  {}",
        "NAME".bold(),
        "URL".bold(),
        "ENTRIES".bold(),
        "LAST UPDATED".bold(),
        "HASH".bold(),
        name_w = name_w,
        url_w = url_w
    );
    println!("{}", "-".repeat(name_w + url_w + 45));

    for entry in &registry.entries {
        let name = entry.display_name.as_deref().unwrap_or("<unnamed>");
        let meta = entry.metadata.as_ref();
        let source_url = meta
            .and_then(|m| m.get("sourceUrl"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let entry_count = meta
            .and_then(|m| m.get("entryCount"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let last_updated = meta
            .and_then(|m| m.get("lastUpdated"))
            .and_then(|v| v.as_str())
            .map(|s| &s[..s.len().min(19)])
            .unwrap_or("-");
        let hash_short = meta
            .and_then(|m| m.get("contentHash"))
            .and_then(|v| v.as_str())
            .map(|h| &h[..h.len().min(8)])
            .unwrap_or("-");
        let source_url_display = if source_url.len() > url_w {
            format!("{}…", &source_url[..url_w - 1])
        } else {
            source_url.to_string()
        };
        println!(
            "{name:<name_w$}  {source_url_display:<url_w$}  {entry_count:>7}  {last_updated:<20}  {hash_short}"
        );
    }
    Ok(())
}
