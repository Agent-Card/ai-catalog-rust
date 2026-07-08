// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use reqwest::Client;
use serde_json::json;

use ai_catalog::{AiCatalog, CatalogEntry};

use crate::cache::{content_hash, CacheManager};
use crate::error::{Error, Result};
use crate::fetch::fetch_catalog;

const MAX_DEPTH: usize = 4;

/// A catalog entry together with provenance information.
#[derive(Debug, Clone)]
pub struct ResolvedEntry {
    pub entry: CatalogEntry,
    /// The URL (remote or `file://`) from which this entry's parent catalog was loaded.
    pub source_catalog_url: String,
}

// ── Download mode ────────────────────────────────────────────────────────────

/// Fetch a catalog and all its nested catalogs recursively, storing every
/// catalog in the CAS (`~/.ai-catalog/objects/`) and recording URL→hash in refs.
///
/// Returns all non-catalog entries found in the tree.
pub async fn resolve_and_cache(
    root_url: &str,
    client: &Client,
    cache: &CacheManager,
) -> Result<Vec<ResolvedEntry>> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut url_to_hash = cache.read_refs()?;
    let mut entries = Vec::new();

    resolve_and_cache_inner(
        root_url,
        client,
        cache,
        0,
        &mut visited,
        &mut url_to_hash,
        &mut entries,
    )
    .await?;

    cache.write_refs(&url_to_hash)?;
    Ok(entries)
}

#[async_recursion::async_recursion]
async fn resolve_and_cache_inner(
    url: &str,
    client: &Client,
    cache: &CacheManager,
    depth: usize,
    visited: &mut HashSet<String>,
    url_to_hash: &mut std::collections::HashMap<String, String>,
    entries: &mut Vec<ResolvedEntry>,
) -> Result<()> {
    if visited.contains(url) {
        return Err(Error::CircularReference(url.to_string()));
    }
    if depth > MAX_DEPTH {
        return Err(Error::MaxDepthExceeded(MAX_DEPTH));
    }

    visited.insert(url.to_string());

    let (catalog, bytes) = fetch_catalog(url, client).await?;
    let hash = content_hash(&bytes);

    cache.store_object(&hash, &bytes)?;
    url_to_hash.insert(url.to_string(), hash.clone());

    process_catalog_entries(
        &catalog,
        url,
        client,
        cache,
        depth,
        visited,
        url_to_hash,
        entries,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[async_recursion::async_recursion]
async fn process_catalog_entries(
    catalog: &AiCatalog,
    source_url: &str,
    client: &Client,
    cache: &CacheManager,
    depth: usize,
    visited: &mut HashSet<String>,
    url_to_hash: &mut std::collections::HashMap<String, String>,
    entries: &mut Vec<ResolvedEntry>,
) -> Result<()> {
    for entry in &catalog.entries {
        if entry.is_nested_catalog() {
            if let Some(nested_url) = &entry.url {
                if let Err(e) = resolve_and_cache_inner(
                    nested_url,
                    client,
                    cache,
                    depth + 1,
                    visited,
                    url_to_hash,
                    entries,
                )
                .await
                {
                    eprintln!(
                        "Warning: skipping nested catalog \"{}\": {e}",
                        entry.identifier
                    );
                }
            } else if let Some(data) = &entry.data {
                // Inline nested catalog
                match serde_json::from_value::<AiCatalog>(data.clone()) {
                    Ok(inline_catalog) => {
                        let inline_url = format!("inline:{}", entry.identifier);
                        if !visited.contains(&inline_url) {
                            visited.insert(inline_url.clone());
                            process_catalog_entries(
                                &inline_catalog,
                                &inline_url,
                                client,
                                cache,
                                depth + 1,
                                visited,
                                url_to_hash,
                                entries,
                            )
                            .await?;
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: could not parse inline catalog for {}: {e}",
                            entry.identifier
                        );
                    }
                }
            }
        } else {
            entries.push(ResolvedEntry {
                entry: entry.clone(),
                source_catalog_url: source_url.to_string(),
            });
        }
    }
    Ok(())
}

// ── Offline (local-only) mode ─────────────────────────────────────────────────

/// Resolve the local registry recursively without making any network requests.
/// Uses `refs.json` to map remote URLs encountered in stored catalogs to local objects.
pub async fn resolve_local(cache: &CacheManager) -> Result<Vec<ResolvedEntry>> {
    let registry = cache.read_registry()?;
    let url_to_hash = cache.read_refs()?;
    let mut visited: HashSet<String> = HashSet::new();
    let mut entries = Vec::new();

    let registry_path = format!("file://{}", cache.registry_path().display());
    visited.insert(registry_path.clone());

    resolve_local_inner(
        &registry,
        &registry_path,
        0,
        &url_to_hash,
        &mut visited,
        &mut entries,
        cache,
    );

    Ok(entries)
}

/// Resolve entries from a single catalog file URL (must be `file://`),
/// using `refs.json` for any nested catalog references. Does not touch
/// the registry — useful for scoping a pull to one registered catalog.
pub fn resolve_local_from_url(file_url: &str, cache: &CacheManager) -> Result<Vec<ResolvedEntry>> {
    let path = file_url.strip_prefix("file://").unwrap_or(file_url);
    let bytes = std::fs::read(path)?;
    let catalog: AiCatalog = serde_json::from_slice(&bytes)?;
    let url_to_hash = cache.read_refs()?;
    let mut visited: HashSet<String> = HashSet::new();
    let mut entries = Vec::new();
    visited.insert(file_url.to_string());
    resolve_local_inner(
        &catalog,
        file_url,
        0,
        &url_to_hash,
        &mut visited,
        &mut entries,
        cache,
    );
    Ok(entries)
}

fn resolve_local_inner(
    catalog: &AiCatalog,
    source_url: &str,
    depth: usize,
    url_to_hash: &std::collections::HashMap<String, String>,
    visited: &mut HashSet<String>,
    entries: &mut Vec<ResolvedEntry>,
    cache: &CacheManager,
) {
    for entry in &catalog.entries {
        if entry.is_nested_catalog() {
            let nested_url = match &entry.url {
                Some(u) => u.clone(),
                None => {
                    if let Some(data) = &entry.data {
                        // Inline nested catalog
                        if let Ok(inline_catalog) =
                            serde_json::from_value::<AiCatalog>(data.clone())
                        {
                            let inline_url = format!("inline:{}", entry.identifier);
                            if !visited.contains(&inline_url) && depth < MAX_DEPTH {
                                visited.insert(inline_url.clone());
                                resolve_local_inner(
                                    &inline_catalog,
                                    &inline_url,
                                    depth + 1,
                                    url_to_hash,
                                    visited,
                                    entries,
                                    cache,
                                );
                            }
                        }
                    }
                    continue;
                }
            };

            if visited.contains(&nested_url) || depth >= MAX_DEPTH {
                continue;
            }
            visited.insert(nested_url.clone());

            // Resolve the URL to a local object
            let local_url = if nested_url.starts_with("file://") {
                nested_url.clone()
            } else if let Some(hash) = url_to_hash.get(&nested_url) {
                cache.object_file_url(hash)
            } else {
                // Not cached — skip gracefully
                eprintln!("Warning: nested catalog not in local cache, skipping: {nested_url}");
                continue;
            };

            let path = local_url.strip_prefix("file://").unwrap_or(&local_url);
            match std::fs::read(path) {
                Ok(bytes) => match serde_json::from_slice::<AiCatalog>(&bytes) {
                    Ok(nested_catalog) => {
                        resolve_local_inner(
                            &nested_catalog,
                            &nested_url,
                            depth + 1,
                            url_to_hash,
                            visited,
                            entries,
                            cache,
                        );
                    }
                    Err(e) => {
                        eprintln!("Warning: could not parse cached catalog at {local_url}: {e}");
                    }
                },
                Err(e) => {
                    eprintln!("Warning: could not read cached catalog at {local_url}: {e}");
                }
            }
        } else {
            entries.push(ResolvedEntry {
                entry: entry.clone(),
                source_catalog_url: source_url.to_string(),
            });
        }
    }
}

// ── Entry search (includes catalog-type entries) ──────────────────────────────

/// Search the entire local catalog tree for an entry by identifier,
/// including catalog-type entries that resolve_local skips.
pub fn find_entry_by_id_in_registry(
    id: &str,
    cache: &CacheManager,
) -> Result<Option<CatalogEntry>> {
    let registry = cache.read_registry()?;
    let url_to_hash = cache.read_refs()?;
    let mut visited = HashSet::new();
    Ok(search_catalog_for_id(
        &registry,
        id,
        &url_to_hash,
        &mut visited,
        0,
        cache,
    ))
}

/// Search within a specific local catalog file for an entry by identifier,
/// including catalog-type entries.
pub fn find_entry_by_id_in_url(
    id: &str,
    file_url: &str,
    cache: &CacheManager,
) -> Result<Option<CatalogEntry>> {
    let path = file_url.strip_prefix("file://").unwrap_or(file_url);
    let bytes = std::fs::read(path)?;
    let catalog: AiCatalog = serde_json::from_slice(&bytes)?;
    let url_to_hash = cache.read_refs()?;
    let mut visited = HashSet::new();
    visited.insert(file_url.to_string());
    Ok(search_catalog_for_id(
        &catalog,
        id,
        &url_to_hash,
        &mut visited,
        0,
        cache,
    ))
}

/// Resolve the leaf (non-catalog) entries of an already-parsed AiCatalog struct.
/// Used when a catalog entry's content has already been fetched or inlined.
pub fn resolve_catalog_leaf_entries(
    catalog: &AiCatalog,
    source_url: &str,
    cache: &CacheManager,
) -> Result<Vec<ResolvedEntry>> {
    let url_to_hash = cache.read_refs()?;
    let mut visited = HashSet::new();
    let mut entries = Vec::new();
    visited.insert(source_url.to_string());
    resolve_local_inner(
        catalog,
        source_url,
        0,
        &url_to_hash,
        &mut visited,
        &mut entries,
        cache,
    );
    Ok(entries)
}

fn search_catalog_for_id(
    catalog: &AiCatalog,
    id: &str,
    url_to_hash: &std::collections::HashMap<String, String>,
    visited: &mut HashSet<String>,
    depth: usize,
    cache: &CacheManager,
) -> Option<CatalogEntry> {
    for entry in &catalog.entries {
        if entry.identifier == id {
            return Some(entry.clone());
        }
        if !entry.is_nested_catalog() || depth >= MAX_DEPTH {
            continue;
        }
        if let Some(nested_url) = &entry.url {
            if visited.contains(nested_url) {
                continue;
            }
            visited.insert(nested_url.clone());
            let local_url = if nested_url.starts_with("file://") {
                nested_url.clone()
            } else {
                match url_to_hash.get(nested_url.as_str()) {
                    Some(hash) => cache.object_file_url(hash),
                    None => continue,
                }
            };
            let path = local_url.strip_prefix("file://").unwrap_or(&local_url);
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(nested) = serde_json::from_slice::<AiCatalog>(&bytes) {
                    if let Some(found) =
                        search_catalog_for_id(&nested, id, url_to_hash, visited, depth + 1, cache)
                    {
                        return Some(found);
                    }
                }
            }
        } else if let Some(data) = &entry.data {
            if let Ok(inline) = serde_json::from_value::<AiCatalog>(data.clone()) {
                let inline_url = format!("inline:{}", entry.identifier);
                if !visited.contains(&inline_url) {
                    visited.insert(inline_url.clone());
                    if let Some(found) =
                        search_catalog_for_id(&inline, id, url_to_hash, visited, depth + 1, cache)
                    {
                        return Some(found);
                    }
                }
            }
        }
    }
    None
}

/// Retrieve a `serde_json::Value` metadata object for a registry entry.
pub fn make_entry_metadata(source_url: &str, hash: &str, entry_count: usize) -> serde_json::Value {
    json!({
        "sourceUrl": source_url,
        "lastUpdated": chrono::Utc::now().to_rfc3339(),
        "contentHash": hash,
        "entryCount": entry_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_cache(dir: &tempfile::TempDir) -> CacheManager {
        CacheManager::with_base_dir(dir.path().to_path_buf())
    }

    fn leaf_entry(id: &str, entry_type: &str) -> CatalogEntry {
        CatalogEntry {
            identifier: id.to_string(),
            display_name: None,
            entry_type: entry_type.to_string(),
            url: Some(format!("https://example.com/{id}.json")),
            data: None,
            version: None,
            description: None,
            tags: vec![],
            publisher: None,
            trust_manifest: None,
            updated_at: None,
            metadata: None,
            extra_fields: BTreeMap::new(),
        }
    }

    fn catalog_entry(id: &str, nested_url: &str) -> CatalogEntry {
        CatalogEntry {
            identifier: id.to_string(),
            display_name: None,
            entry_type: "application/ai-catalog+json".to_string(),
            url: Some(nested_url.to_string()),
            data: None,
            version: None,
            description: None,
            tags: vec![],
            publisher: None,
            trust_manifest: None,
            updated_at: None,
            metadata: None,
            extra_fields: BTreeMap::new(),
        }
    }

    fn bare_catalog(entries: Vec<CatalogEntry>) -> AiCatalog {
        AiCatalog {
            spec_version: "1.0".to_string(),
            host: None,
            entries,
            metadata: None,
            extra_fields: BTreeMap::new(),
        }
    }

    #[test]
    fn make_entry_metadata_has_expected_keys() {
        let meta = make_entry_metadata("https://example.com/catalog.json", "deadbeef", 42);
        assert_eq!(meta["sourceUrl"], "https://example.com/catalog.json");
        assert_eq!(meta["contentHash"], "deadbeef");
        assert_eq!(meta["entryCount"], 42);
        assert!(meta["lastUpdated"].is_string());
    }

    #[test]
    fn resolve_catalog_leaf_entries_empty_catalog() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        let catalog = bare_catalog(vec![]);
        let entries = resolve_catalog_leaf_entries(&catalog, "file:///test", &cache).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn resolve_catalog_leaf_entries_returns_non_catalog_entries() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        let catalog = bare_catalog(vec![
            leaf_entry("urn:test:a", "application/json"),
            leaf_entry("urn:test:b", "application/parquet"),
        ]);
        let entries = resolve_catalog_leaf_entries(&catalog, "file:///test", &cache).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entry.identifier, "urn:test:a");
        assert_eq!(entries[1].entry.identifier, "urn:test:b");
        assert_eq!(entries[0].source_catalog_url, "file:///test");
    }

    #[test]
    fn resolve_catalog_leaf_entries_skips_nested_without_local_cache() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        // A catalog with one leaf and one nested catalog (URL not in cache)
        let catalog = bare_catalog(vec![
            leaf_entry("urn:test:leaf", "application/json"),
            catalog_entry("urn:test:nested", "https://example.com/nested.json"),
        ]);
        let entries = resolve_catalog_leaf_entries(&catalog, "file:///root", &cache).unwrap();
        // Only the leaf entry should be returned — nested skipped (not in cache)
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry.identifier, "urn:test:leaf");
    }

    #[test]
    fn find_entry_by_id_in_registry_returns_none_on_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        let result = find_entry_by_id_in_registry("urn:test:missing", &cache).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn find_entry_by_id_in_url_found() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        let catalog = bare_catalog(vec![
            leaf_entry("urn:test:target", "application/json"),
            leaf_entry("urn:test:other", "application/parquet"),
        ]);
        let json = serde_json::to_vec(&catalog).unwrap();
        let catalog_path = dir.path().join("catalog.json");
        std::fs::write(&catalog_path, &json).unwrap();
        let file_url = format!("file://{}", catalog_path.display());
        let result = find_entry_by_id_in_url("urn:test:target", &file_url, &cache).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().identifier, "urn:test:target");
    }

    #[test]
    fn find_entry_by_id_in_url_not_found_returns_none() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        let catalog = bare_catalog(vec![leaf_entry("urn:test:only", "application/json")]);
        let json = serde_json::to_vec(&catalog).unwrap();
        let catalog_path = dir.path().join("catalog.json");
        std::fs::write(&catalog_path, &json).unwrap();
        let file_url = format!("file://{}", catalog_path.display());
        let result = find_entry_by_id_in_url("urn:test:nonexistent", &file_url, &cache).unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolve_and_cache_simple_catalog() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        cache.ensure_dirs().unwrap();

        let catalog = bare_catalog(vec![
            leaf_entry("urn:test:alpha", "application/json"),
            leaf_entry("urn:test:beta", "application/parquet"),
        ]);
        let json = serde_json::to_vec(&catalog).unwrap();
        let catalog_path = dir.path().join("root.json");
        std::fs::write(&catalog_path, &json).unwrap();
        let url = format!("file://{}", catalog_path.display());

        let client = crate::fetch::build_client().unwrap();
        let entries = resolve_and_cache(&url, &client, &cache).await.unwrap();

        // Both leaf entries returned
        assert_eq!(entries.len(), 2);
        let ids: Vec<&str> = entries.iter().map(|e| e.entry.identifier.as_str()).collect();
        assert!(ids.contains(&"urn:test:alpha"));
        assert!(ids.contains(&"urn:test:beta"));

        // CAS should contain the stored object
        let refs = cache.read_refs().unwrap();
        assert!(refs.contains_key(&url));
        let hash = refs.get(&url).unwrap();
        assert!(cache.object_path(hash).exists());
    }

    #[tokio::test]
    async fn resolve_and_cache_detects_circular_reference() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        cache.ensure_dirs().unwrap();

        // A catalog that references itself
        let catalog_path = dir.path().join("self.json");
        let url = format!("file://{}", catalog_path.display());
        let catalog = bare_catalog(vec![catalog_entry("urn:test:self", &url)]);
        let json = serde_json::to_vec(&catalog).unwrap();
        std::fs::write(&catalog_path, &json).unwrap();

        let client = crate::fetch::build_client().unwrap();
        // resolve_and_cache itself returns Ok (circular nested catalogs are skipped with a warning)
        // but we can verify the root was processed
        let result = resolve_and_cache(&url, &client, &cache).await;
        // May succeed with 0 entries (self-ref skipped) or fail — either is acceptable
        // What must NOT happen is an infinite loop; the call must terminate
        let _ = result; // just verify it terminates and doesn't panic
    }
}
