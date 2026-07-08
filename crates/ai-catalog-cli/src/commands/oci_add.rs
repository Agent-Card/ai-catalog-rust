// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use colored::Colorize;

use ai_catalog::CatalogEntry;
use ai_catalog_oci::{import_layout, unpack_catalog};

use crate::cache::{content_hash, CacheManager};
use crate::error::{Error, Result};
use crate::resolver::make_entry_metadata;

/// Register a catalog sourced from an OCI image layout.
///
/// The layout is imported with `import_layout`, the catalog is unpacked,
/// serialized, stored in the CAS, and registered with an `urn:ai-catalog:oci:`
/// prefix so the `oci search/show/pull` commands can scope to it.
pub async fn execute(name: &str, layout_path: &str, ref_name: Option<&str>) -> Result<()> {
    let tag = ref_name.unwrap_or("latest");

    let artifacts = import_layout(layout_path, ref_name)
        .map_err(|e| Error::Other(format!("failed to import OCI layout from '{layout_path}': {e}")))?;

    let catalog = unpack_catalog(&artifacts)
        .map_err(|e| Error::Other(format!("failed to unpack catalog from OCI layout: {e}")))?;

    let bytes = serde_json::to_vec_pretty(&catalog)?;
    let hash = content_hash(&bytes);

    let cache = CacheManager::new()?;
    cache.ensure_dirs()?;

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
        }
    }

    cache.store_object(&hash, &bytes)?;

    let source_ref = format!("oci+layout:{layout_path}:{tag}");
    let mut refs = cache.read_refs()?;
    refs.insert(source_ref.clone(), hash.clone());
    cache.write_refs(&refs)?;

    let entry_count = catalog.entries.iter().filter(|e| !e.is_nested_catalog()).count();
    let file_url = cache.object_file_url(&hash);
    let identifier = format!("urn:ai-catalog:oci:{}", &hash[..8]);

    let mut meta_val = make_entry_metadata(&source_ref, &hash, entry_count);
    if let Some(obj) = meta_val.as_object_mut() {
        obj.insert("sourceType".to_string(), serde_json::json!("oci"));
        obj.insert("ociLayoutPath".to_string(), serde_json::json!(layout_path));
        obj.insert("ociRefName".to_string(), serde_json::json!(tag));
    }

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
        "{} \"{}\" added ({} entries, from OCI layout {}:{})",
        "✓".green(),
        name.bold(),
        entry_count,
        layout_path,
        tag
    );
    Ok(())
}
