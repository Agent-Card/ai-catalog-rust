// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Http(#[from] reqwest::Error),

    #[error("{0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("catalog not found: {0}")]
    CatalogNotFound(String),

    #[error("entry not found: {0}")]
    EntryNotFound(String),

    #[error("cache directory error: {0}")]
    CacheDir(String),

    #[error("maximum nesting depth ({0}) exceeded")]
    MaxDepthExceeded(usize),

    #[error("circular reference detected: {0}")]
    CircularReference(String),

    #[error("{0}")]
    InvalidRegex(#[from] regex::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
