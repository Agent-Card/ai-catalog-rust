// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use crate::cache::CacheManager;
use crate::error::{Error, Result};
use crate::resolver::find_entry_by_id_oci;

use super::{OutputFormat, show::dispatch_show_entry};

/// Show full details of an OCI-sourced catalog entry by identifier.
///
/// Only searches catalogs added via `oci add`.
pub async fn execute(
    identifier: &str,
    output: OutputFormat,
    media_type: Option<&str>,
) -> Result<()> {
    let cache = CacheManager::new()?;

    let entry = find_entry_by_id_oci(identifier, &cache)?
        .ok_or_else(|| {
            Error::EntryNotFound(format!(
                "{identifier} — run `ai-catalog oci search {identifier}` or `ai-catalog oci add <name> <layout-dir>` first"
            ))
        })?;

    dispatch_show_entry(&entry, output, media_type, &cache).await
}
