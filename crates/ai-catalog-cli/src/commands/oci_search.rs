// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use colored::Colorize;
use regex::Regex;

use ai_catalog::AiCatalog;

use crate::cache::CacheManager;
use crate::error::Result;
use crate::resolver::resolve_local_oci;

use super::{OutputFormat, search::truncate};

/// Search entries from OCI-sourced catalogs only (those added via `oci add`).
pub async fn execute(
    keyword: &str,
    use_regex: bool,
    limit: usize,
    output: OutputFormat,
) -> Result<()> {
    let cache = CacheManager::new()?;
    let entries = resolve_local_oci(&cache).await?;

    let matches: Vec<_> = if use_regex {
        let re = Regex::new(keyword)?;
        entries
            .iter()
            .filter(|resolved| {
                let e = &resolved.entry;
                re.is_match(&e.identifier)
                    || e.display_name
                        .as_deref()
                        .map(|s| re.is_match(s))
                        .unwrap_or(false)
                    || e.description
                        .as_deref()
                        .map(|s| re.is_match(s))
                        .unwrap_or(false)
                    || e.tags.iter().any(|t| re.is_match(t))
            })
            .take(limit)
            .collect()
    } else {
        let kw = keyword.to_lowercase();
        entries
            .iter()
            .filter(|resolved| {
                let e = &resolved.entry;
                e.identifier.to_lowercase().contains(&kw)
                    || e.display_name
                        .as_deref()
                        .map(|s| s.to_lowercase().contains(&kw))
                        .unwrap_or(false)
                    || e.description
                        .as_deref()
                        .map(|s| s.to_lowercase().contains(&kw))
                        .unwrap_or(false)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&kw))
            })
            .take(limit)
            .collect()
    };

    if let OutputFormat::Json = output {
        let catalog = AiCatalog {
            spec_version: "1.0".to_string(),
            host: None,
            entries: matches.iter().map(|re| re.entry.clone()).collect(),
            metadata: None,
            extra_fields: Default::default(),
        };
        println!("{}", serde_json::to_string_pretty(&catalog)?);
        return Ok(());
    }

    if matches.is_empty() {
        println!("No OCI entries found matching \"{}\".", keyword.yellow());
        return Ok(());
    }

    let id_w = matches
        .iter()
        .map(|re| re.entry.identifier.len())
        .max()
        .unwrap_or(10)
        .clamp(10, 50);
    let name_w = matches
        .iter()
        .map(|re| re.entry.display_name.as_deref().unwrap_or("-").len())
        .max()
        .unwrap_or(4)
        .clamp(4, 30);
    let type_w = matches
        .iter()
        .map(|re| re.entry.entry_type.len())
        .max()
        .unwrap_or(4)
        .clamp(4, 40);

    println!(
        "{:<id_w$}  {:<name_w$}  {:<60}  {:<type_w$}  {}",
        "IDENTIFIER".bold(),
        "NAME".bold(),
        "DESCRIPTION".bold(),
        "TYPE".bold(),
        "CATALOG".bold()
    );
    println!("{}", "-".repeat(id_w + name_w + 60 + type_w + 30));
    for re in &matches {
        let e = &re.entry;
        let identifier = truncate(&e.identifier, id_w);
        let name = truncate(e.display_name.as_deref().unwrap_or("-"), name_w);
        let description = truncate(e.description.as_deref().unwrap_or("-"), 60);
        let entry_type = truncate(&e.entry_type, type_w);
        let catalog = truncate(&re.source_catalog_url, 30);
        println!(
            "{identifier:<id_w$}  {name:<name_w$}  {description:<60}  {entry_type:<type_w$}  {catalog}"
        );
    }
    if matches.len() == limit {
        println!(
            "\n(showing first {limit} results — use {} to see more)",
            format!("-n {}", limit * 2).cyan()
        );
    }
    Ok(())
}
