// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

mod error;
mod media;
mod model;

pub use error::{Error, Result};
pub use media::{
    MEDIA_TYPE_A2A_AGENT_CARD, MEDIA_TYPE_AGENT_CARD, MEDIA_TYPE_AGENT_PLUGINS_GZIP,
    MEDIA_TYPE_AGENT_PLUGINS_ZIP, MEDIA_TYPE_AGENT_SKILLS_GZIP, MEDIA_TYPE_AGENT_SKILLS_JSON,
    MEDIA_TYPE_AGENT_SKILLS_MARKDOWN, MEDIA_TYPE_AGENT_SKILLS_ZIP, MEDIA_TYPE_CATALOG,
    MEDIA_TYPE_MCP_SERVER_CARD,
};
pub use model::{
    AiCatalog, Attestation, CatalogEntry, HostInfo, ProvenanceLink, Publisher, Subject,
    TrustManifest, TrustSchema,
};

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

pub fn parse_str(input: &str) -> Result<AiCatalog> {
    serde_json::from_str(input).map_err(Error::from)
}

pub fn parse_slice(input: &[u8]) -> Result<AiCatalog> {
    serde_json::from_slice(input).map_err(Error::from)
}

pub fn parse_reader(reader: impl Read) -> Result<AiCatalog> {
    serde_json::from_reader(reader).map_err(Error::from)
}

pub fn parse_file(path: impl AsRef<Path>) -> Result<AiCatalog> {
    let text = fs::read_to_string(path).map_err(Error::from)?;
    parse_str(&text)
}

pub fn to_string(catalog: &AiCatalog) -> Result<String> {
    serde_json::to_string(catalog).map_err(Error::from)
}

pub fn to_string_pretty(catalog: &AiCatalog) -> Result<String> {
    serde_json::to_string_pretty(catalog).map_err(Error::from)
}

pub fn write_writer(writer: impl Write, catalog: &AiCatalog) -> Result<()> {
    serde_json::to_writer_pretty(writer, catalog).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::{Error, parse_file, parse_str, to_string};

    const FUTURE_MEMBER: &str = include_str!("../../../fixtures/future_member.json");

    fn sample() -> super::AiCatalog {
        parse_str(
            r#"{
                "specVersion": "1.0",
                "entries": [
                    {
                        "identifier": "urn:example:agent:finance-v1",
                        "displayName": "Finance Agent",
                        "type": "application/a2a-agent-card+json",
                        "description": "Handles financial queries",
                        "tags": ["finance", "banking"],
                        "url": "https://example.com/finance.json"
                    },
                    {
                        "identifier": "urn:example:model:embedding-v2",
                        "type": "application/gguf",
                        "url": "https://example.com/embed.gguf"
                    }
                ]
            }"#,
        )
        .expect("sample should parse")
    }

    #[test]
    fn parses_the_spec_example() {
        let catalog = parse_file(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/spec-example.json"
        ))
        .expect("fixture should parse");

        assert_eq!(catalog.spec_version, "1.0");
        assert!(!catalog.entries.is_empty());
    }

    #[test]
    fn unrecognized_members_survive_a_round_trip() {
        let catalog = parse_str(FUTURE_MEMBER).expect("document should parse");
        let written: serde_json::Value =
            serde_json::from_str(&to_string(&catalog).expect("serializes")).expect("json");

        assert_eq!(written["futureMember"], serde_json::json!({"a": 1}));
    }

    #[test]
    fn looks_up_entries() {
        let catalog = sample();

        assert!(catalog.get_by_id("urn:example:agent:finance-v1").is_some());
        assert!(catalog.get_by_id("finance").is_none());

        for query in ["FINANCE", "Finance Agent", "financial queries", "banking"] {
            assert_eq!(catalog.search(query).len(), 1, "{query}");
        }

        assert!(catalog.search("no-such-entry").is_empty());
    }

    #[test]
    fn searches_by_regex() {
        let catalog = sample();

        assert_eq!(
            catalog
                .search_by_regex(r"^urn:example:model:")
                .expect("valid pattern")
                .len(),
            1
        );
        assert!(matches!(
            catalog.search_by_regex("[invalid("),
            Err(Error::Regex(_))
        ));
    }
}
