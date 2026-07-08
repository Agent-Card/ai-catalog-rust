// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::Path;

use crate::error::Result;

pub fn read_refs(path: &Path) -> Result<HashMap<String, String>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn write_refs(path: &Path, refs: &HashMap<String, String>) -> Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(refs)?)?;
    Ok(())
}
