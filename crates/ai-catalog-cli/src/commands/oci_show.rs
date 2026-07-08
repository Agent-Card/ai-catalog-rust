// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use crate::cache::CacheManager;
use crate::error::{Error, Result};
use crate::resolver::find_entry_by_id_oci;

use super::{OutputFormat, show::print_entry_table};

/// Show full details of an OCI-sourced catalog entry by identifier.
///
/// Only searches catalogs added via `oci add`.
pub async fn execute(identifier: &str, output: OutputFormat) -> Result<()> {
    let cache = CacheManager::new()?;

    let entry = find_entry_by_id_oci(identifier, &cache)?
        .ok_or_else(|| {
            Error::EntryNotFound(format!(
                "{identifier} — run `ai-catalog oci search {identifier}` or `ai-catalog oci add <name> <layout-dir>` first"
            ))
        })?;

    if let OutputFormat::Json = output {
        println!("{}", serde_json::to_string_pretty(&entry)?);
        return Ok(());
    }

    print_entry_table(&entry, &cache);
    Ok(())
}
