// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use crate::cache::CacheManager;
use crate::error::{Error, Result};
use crate::resolver::find_entry_by_id_oci;

use super::pull::write_entry;

/// Pull an OCI-sourced catalog entry by identifier and write its content to disk.
///
/// Only searches catalogs added via `oci add`. If `output_path` is a directory
/// (or omitted), a filename is derived from the identifier.
pub async fn execute(identifier: &str, output_path: Option<&str>) -> Result<()> {
    let cache = CacheManager::new()?;

    let entry = find_entry_by_id_oci(identifier, &cache)?
        .ok_or_else(|| {
            Error::EntryNotFound(format!(
                "{identifier} — run `ai-catalog oci search {identifier}` or `ai-catalog oci add <name> <layout-dir>` first"
            ))
        })?;

    write_entry(&entry, output_path, &cache).await
}
