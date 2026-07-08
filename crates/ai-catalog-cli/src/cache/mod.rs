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
