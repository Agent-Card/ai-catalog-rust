// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;

const URN_AIR_PREFIX: &str = "urn:air:";
const DID_WEB_PREFIX: &str = "did:web:";
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

static DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
        .expect("domain pattern is valid")
});

pub(crate) fn publisher(identifier: &str) -> Option<&str> {
    let rest = identifier.strip_prefix(URN_AIR_PREFIX)?;
    let publisher = rest.split(':').next()?;

    (!publisher.is_empty()).then_some(publisher)
}

pub(crate) fn is_valid_publisher(publisher: &str) -> bool {
    publisher.len() <= MAX_NAME_LEN
        && DOMAIN.is_match(publisher)
        && publisher
            .split('.')
            .all(|label| label.len() <= MAX_LABEL_LEN)
        && publisher.parse::<IpAddr>().is_err()
}

pub(crate) fn did(publisher: &str) -> String {
    format!("{DID_WEB_PREFIX}{publisher}")
}

/// Whether the value is a root `did:web` DID: a lowercase ASCII domain with no port, path or IP.
pub(crate) fn is_root_did_web(value: &str) -> bool {
    value
        .strip_prefix(DID_WEB_PREFIX)
        .is_some_and(is_valid_publisher)
}
