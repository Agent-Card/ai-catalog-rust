// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

pub(crate) const ALLOWED_ALGORITHMS: [&str; 6] =
    ["ES256", "ES384", "EdDSA", "PS256", "PS384", "RS256"];

const COMPACT_PARTS: usize = 3;

pub(crate) struct Header {
    pub(crate) algorithm: String,
    pub(crate) key_id: String,
    members: Map<String, Value>,
}

impl Header {
    pub(crate) fn has(&self, name: &str) -> bool {
        self.members.contains_key(name)
    }
}

pub(crate) fn parse(signature: &str) -> Result<Header, String> {
    let encoded = signature.split('.').next().unwrap_or_default();
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| format!("header is not base64url: {error}"))?;
    let text = String::from_utf8(raw).map_err(|_| "header is not UTF-8".to_owned())?;

    let Value::Object(members) = ai_catalog_trust::parse_json(&text)
        .map_err(|error| format!("header is not valid JSON: {error}"))?
    else {
        return Err("header is not a JSON object".to_owned());
    };

    let algorithm = string_member(&members, "alg")?;

    if algorithm.is_empty() {
        return Err("header declares no alg".to_owned());
    }

    let key_id = string_member(&members, "kid")?;

    Ok(Header {
        algorithm,
        key_id,
        members,
    })
}

fn string_member(members: &Map<String, Value>, name: &str) -> Result<String, String> {
    match members.get(name) {
        None => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(format!("header member {name:?} is not a string")),
    }
}

pub(crate) fn is_detached(signature: &str) -> bool {
    let parts: Vec<&str> = signature.split('.').collect();

    parts.len() == COMPACT_PARTS
        && !parts[0].is_empty()
        && parts[1].is_empty()
        && !parts[2].is_empty()
}

pub(crate) fn is_forbidden(algorithm: &str) -> bool {
    let normalized = algorithm.to_ascii_uppercase();

    normalized == "NONE" || normalized.starts_with("HS")
}
