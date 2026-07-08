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
    let bytes = client.get(url).send().await?.error_for_status()?.bytes().await?;
    Ok(bytes.to_vec())
}

pub async fn fetch_catalog(url: &str, client: &Client) -> Result<(AiCatalog, Vec<u8>)> {
    let bytes = fetch_bytes(url, client).await?;
    let catalog: AiCatalog = serde_json::from_slice(&bytes)?;
    Ok((catalog, bytes))
}
