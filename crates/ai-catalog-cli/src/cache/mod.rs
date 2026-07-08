// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

pub mod refs;

use std::collections::HashMap;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use ai_catalog::{AiCatalog, HostInfo};

use crate::error::{Error, Result};

pub struct CacheManager {
    pub base_dir: PathBuf,
}

impl CacheManager {
    /// Create a new CacheManager rooted at `~/.ai-catalog/`.
    pub fn new() -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::CacheDir("cannot determine home directory".to_string()))?;
        Ok(CacheManager {
            base_dir: home.join(".ai-catalog"),
        })
    }

    /// Create a CacheManager rooted at an arbitrary directory (useful in tests).
    pub fn with_base_dir(base_dir: PathBuf) -> Self {
        CacheManager { base_dir }
    }

    /// Ensure `~/.ai-catalog/` and `~/.ai-catalog/objects/` exist.
    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(self.objects_dir())?;
        Ok(())
    }

    pub fn registry_path(&self) -> PathBuf {
        self.base_dir.join("catalog.json")
    }

    pub fn refs_path(&self) -> PathBuf {
        self.base_dir.join("refs.json")
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.base_dir.join("objects")
    }

    pub fn object_path(&self, hash: &str) -> PathBuf {
        self.objects_dir().join(format!("{hash}.json"))
    }

    // ── Registry ──────────────────────────────────────────────────────────

    /// Read `~/.ai-catalog/catalog.json`. Returns a bare catalog if missing.
    pub fn read_registry(&self) -> Result<AiCatalog> {
        let path = self.registry_path();
        if !path.exists() {
            return Ok(AiCatalog {
                spec_version: "1.0".to_string(),
                host: Some(HostInfo {
                    display_name: Some("ai-catalog local registry".to_string()),
                    identifier: None,
                    documentation_url: None,
                    logo_url: None,
                    trust_manifest: None,
                    extra_fields: Default::default(),
                }),
                entries: vec![],
                metadata: None,
                extra_fields: Default::default(),
            });
        }
        let bytes = std::fs::read(&path)?;
        let catalog: AiCatalog = serde_json::from_slice(&bytes)?;
        Ok(catalog)
    }

    pub fn write_registry(&self, catalog: &AiCatalog) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(catalog)?;
        std::fs::write(self.registry_path(), bytes)?;
        Ok(())
    }

    // ── Refs ──────────────────────────────────────────────────────────────

    pub fn read_refs(&self) -> Result<HashMap<String, String>> {
        refs::read_refs(&self.refs_path())
    }

    pub fn write_refs(&self, refs: &HashMap<String, String>) -> Result<()> {
        refs::write_refs(&self.refs_path(), refs)
    }

    // ── Objects ───────────────────────────────────────────────────────────

    /// Store raw bytes under their SHA-256 hash.
    /// Returns `true` if newly written, `false` if the object already existed.
    pub fn store_object(&self, hash: &str, bytes: &[u8]) -> Result<bool> {
        let path = self.object_path(hash);
        if path.exists() {
            return Ok(false);
        }
        std::fs::write(&path, bytes)?;
        Ok(true)
    }

    /// Compute the `file://` URL for an object given its hash.
    pub fn object_file_url(&self, hash: &str) -> String {
        format!("file://{}", self.object_path(hash).display())
    }
}

/// Compute the SHA-256 hex digest of a byte slice.
pub fn content_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_cache(dir: &tempfile::TempDir) -> CacheManager {
        CacheManager::with_base_dir(dir.path().to_path_buf())
    }

    #[test]
    fn content_hash_known_value() {
        // SHA-256 of b"hello" is a fixed value
        let hash = content_hash(b"hello");
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn content_hash_empty_input() {
        let hash = content_hash(b"");
        // SHA-256 of empty string
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn with_base_dir_uses_given_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = CacheManager::with_base_dir(dir.path().to_path_buf());
        assert_eq!(cache.base_dir, dir.path());
    }

    #[test]
    fn path_helpers_relative_to_base() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        assert_eq!(cache.registry_path(), dir.path().join("catalog.json"));
        assert_eq!(cache.refs_path(), dir.path().join("refs.json"));
        assert_eq!(cache.objects_dir(), dir.path().join("objects"));
        assert_eq!(cache.object_path("abc123"), dir.path().join("objects").join("abc123.json"));
    }

    #[test]
    fn ensure_dirs_creates_objects_subdir() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        cache.ensure_dirs().unwrap();
        assert!(dir.path().join("objects").is_dir());
    }

    #[test]
    fn read_registry_returns_default_when_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        let registry = cache.read_registry().unwrap();
        assert_eq!(registry.spec_version, "1.0");
        assert!(registry.entries.is_empty());
        let host = registry.host.unwrap();
        assert_eq!(host.display_name.as_deref(), Some("ai-catalog local registry"));
    }

    #[test]
    fn write_and_read_registry_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        let mut catalog = cache.read_registry().unwrap();
        catalog.spec_version = "1.0".to_string();
        cache.write_registry(&catalog).unwrap();
        let read_back = cache.read_registry().unwrap();
        assert_eq!(read_back.spec_version, "1.0");
    }

    #[test]
    fn write_and_read_refs_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        let mut refs = HashMap::new();
        refs.insert("https://example.com/catalog.json".to_string(), "deadbeef".to_string());
        cache.write_refs(&refs).unwrap();
        let read_back = cache.read_refs().unwrap();
        assert_eq!(read_back.get("https://example.com/catalog.json").map(|s| s.as_str()), Some("deadbeef"));
    }

    #[test]
    fn read_refs_returns_empty_when_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        let refs = cache.read_refs().unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn store_object_writes_bytes_and_returns_true() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        cache.ensure_dirs().unwrap();
        let data = b"test object content";
        let hash = content_hash(data);
        let is_new = cache.store_object(&hash, data).unwrap();
        assert!(is_new);
        let stored = std::fs::read(cache.object_path(&hash)).unwrap();
        assert_eq!(stored, data);
    }

    #[test]
    fn store_object_returns_false_when_already_exists() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        cache.ensure_dirs().unwrap();
        let data = b"test object content";
        let hash = content_hash(data);
        cache.store_object(&hash, data).unwrap();
        let is_new = cache.store_object(&hash, data).unwrap();
        assert!(!is_new);
    }

    #[test]
    fn object_file_url_has_file_scheme() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = make_cache(&dir);
        let url = cache.object_file_url("abc123");
        assert!(url.starts_with("file://"));
        assert!(url.ends_with("abc123.json"));
    }
}
