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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn read_refs_returns_empty_when_file_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("refs.json");
        let refs = read_refs(&path).unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn write_and_read_refs_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("refs.json");
        let mut refs = HashMap::new();
        refs.insert(
            "https://example.com/a.json".to_string(),
            "hash1".to_string(),
        );
        refs.insert(
            "https://example.com/b.json".to_string(),
            "hash2".to_string(),
        );
        write_refs(&path, &refs).unwrap();
        let read_back = read_refs(&path).unwrap();
        assert_eq!(read_back.len(), 2);
        assert_eq!(
            read_back
                .get("https://example.com/a.json")
                .map(|s| s.as_str()),
            Some("hash1")
        );
        assert_eq!(
            read_back
                .get("https://example.com/b.json")
                .map(|s| s.as_str()),
            Some("hash2")
        );
    }

    #[test]
    fn write_refs_overwrites_existing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("refs.json");
        let mut refs = HashMap::new();
        refs.insert("url1".to_string(), "hashA".to_string());
        write_refs(&path, &refs).unwrap();
        let mut refs2 = HashMap::new();
        refs2.insert("url2".to_string(), "hashB".to_string());
        write_refs(&path, &refs2).unwrap();
        let read_back = read_refs(&path).unwrap();
        assert_eq!(read_back.len(), 1);
        assert!(read_back.contains_key("url2"));
        assert!(!read_back.contains_key("url1"));
    }
}
