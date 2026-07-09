// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use reqwest::Client;
use std::path::Path;

use ai_catalog::AiCatalog;

use crate::error::{Error, Result};

pub fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent(format!("ai-catalog/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(Error::Http)
}

pub async fn fetch_bytes(url: &str, client: &Client) -> Result<Vec<u8>> {
    if let Some(path) = url.strip_prefix("file://") {
        return Ok(tokio::fs::read(Path::new(path)).await?);
    }
    let bytes = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    Ok(bytes.to_vec())
}

pub async fn fetch_catalog(url: &str, client: &Client) -> Result<(AiCatalog, Vec<u8>)> {
    let bytes = fetch_bytes(url, client).await?;
    let catalog: AiCatalog = serde_json::from_slice(&bytes)?;
    Ok((catalog, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_client_succeeds() {
        build_client().unwrap();
    }

    #[tokio::test]
    async fn fetch_bytes_reads_local_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, b"hello world").unwrap();
        let url = format!("file://{}", path.display());
        let client = build_client().unwrap();
        let bytes = fetch_bytes(&url, &client).await.unwrap();
        assert_eq!(bytes, b"hello world");
    }

    #[tokio::test]
    async fn fetch_catalog_parses_valid_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("catalog.json");
        let catalog_json = r#"{
            "specVersion": "1.0",
            "entries": [
                {"identifier": "urn:test:entry-1", "type": "application/json", "url": "https://example.com/a.json"}
            ]
        }"#;
        std::fs::write(&path, catalog_json).unwrap();
        let url = format!("file://{}", path.display());
        let client = build_client().unwrap();
        let (catalog, bytes) = fetch_catalog(&url, &client).await.unwrap();
        assert_eq!(catalog.spec_version, "1.0");
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.entries[0].identifier, "urn:test:entry-1");
        assert!(!bytes.is_empty());
    }

    #[tokio::test]
    async fn fetch_catalog_fails_on_invalid_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"not valid json{{{").unwrap();
        let url = format!("file://{}", path.display());
        let client = build_client().unwrap();
        let result = fetch_catalog(&url, &client).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fetch_bytes_fails_for_missing_file() {
        let client = build_client().unwrap();
        let result =
            fetch_bytes("file:///nonexistent/path/that/does/not/exist.json", &client).await;
        assert!(result.is_err());
    }
}
