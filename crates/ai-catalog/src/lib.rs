// Copyright AI-Catalog Contributors (https://github.com/Agent-Card)
// SPDX-License-Identifier: Apache-2.0

mod error;
mod identity;
mod model;

pub use error::{Error, Result};
pub use identity::{identity_binds_to_entry, identity_domain, publisher_domain};
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
    use std::fs;
    use std::io::Cursor;

    use super::{
        AiCatalog, Error, parse_file, parse_reader, parse_slice, parse_str, to_string,
        to_string_pretty, write_writer,
    };

    fn canonical_fixture() -> String {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let fixture = format!("{manifest_dir}/../../fixtures/spec-example.json");

        fs::read_to_string(fixture).expect("fixture should be readable")
    }

    #[test]
    fn parses_and_serializes_canonical_fixture() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let fixture = format!("{manifest_dir}/../../fixtures/spec-example.json");

        let catalog = parse_file(&fixture).expect("fixture should parse");

        assert_eq!(catalog.spec_version, "1.0");
        assert_eq!(catalog.entries.len(), 2);
        assert_eq!(
            catalog.host.as_ref().map(|host| host.display_name.as_str()),
            Some("Acme Services Inc."),
        );

        let compact = to_string(&catalog).expect("catalog should serialize");
        let pretty = to_string_pretty(&catalog).expect("catalog should pretty serialize");

        assert!(compact.contains("\"specVersion\":\"1.0\""));
        assert!(pretty.contains("\"entries\": ["));
    }

    #[test]
    fn parses_from_slice_and_reader() {
        let fixture = canonical_fixture();

        let from_slice = parse_slice(fixture.as_bytes()).expect("slice should parse");
        let from_reader =
            parse_reader(Cursor::new(fixture.as_bytes())).expect("reader should parse");

        assert_eq!(from_slice, from_reader);
        assert_eq!(from_slice.spec_version, "1.0");
    }

    #[test]
    fn writes_pretty_json_to_writer() {
        let fixture = canonical_fixture();
        let catalog = parse_str(&fixture).expect("fixture should parse");
        let mut output = Vec::new();

        write_writer(&mut output, &catalog).expect("writer should serialize");

        let written = String::from_utf8(output).expect("output should be utf-8");
        let reparsed = parse_str(&written).expect("written JSON should parse");

        assert!(written.contains("\"entries\": ["));
        assert_eq!(reparsed.entries.len(), catalog.entries.len());
    }

    #[test]
    fn parse_helpers_report_json_and_io_errors() {
        assert!(matches!(parse_str("not json"), Err(Error::Json(_))));
        assert!(matches!(
            parse_file("/definitely/missing/catalog.json"),
            Err(Error::Io(_))
        ));
    }

    fn sample_catalog() -> AiCatalog {
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
                        "identifier": "urn:example:data:nlp-corpus",
                        "displayName": "NLP Corpus",
                        "type": "application/octet-stream",
                        "description": "Large language model training data",
                        "tags": ["nlp", "dataset"],
                        "url": "https://example.com/nlp.bin"
                    },
                    {
                        "identifier": "urn:example:model:embedding-v2",
                        "type": "application/gguf",
                        "url": "https://example.com/embed.gguf"
                    }
                ]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn get_by_id_returns_matching_entry() {
        let catalog = sample_catalog();
        let entry = catalog.get_by_id("urn:example:agent:finance-v1").unwrap();
        assert_eq!(entry.identifier, "urn:example:agent:finance-v1");
        assert_eq!(entry.display_name.as_deref(), Some("Finance Agent"));
    }

    #[test]
    fn get_by_id_returns_none_for_unknown_id() {
        let catalog = sample_catalog();
        assert!(catalog.get_by_id("urn:does:not:exist").is_none());
    }

    #[test]
    fn get_by_id_is_exact_match_only() {
        let catalog = sample_catalog();
        assert!(catalog.get_by_id("finance").is_none());
        assert!(catalog.get_by_id("urn:example:agent:finance").is_none());
    }

    #[test]
    fn search_matches_identifier_substring() {
        let catalog = sample_catalog();
        let results = catalog.search("nlp-corpus");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].identifier, "urn:example:data:nlp-corpus");
    }

    #[test]
    fn search_is_case_insensitive() {
        let catalog = sample_catalog();
        let results = catalog.search("FINANCE");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].identifier, "urn:example:agent:finance-v1");
    }

    #[test]
    fn search_matches_display_name() {
        let catalog = sample_catalog();
        let results = catalog.search("NLP Corpus");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].identifier, "urn:example:data:nlp-corpus");
    }

    #[test]
    fn search_matches_description() {
        let catalog = sample_catalog();
        let results = catalog.search("financial queries");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].identifier, "urn:example:agent:finance-v1");
    }

    #[test]
    fn search_matches_tags() {
        let catalog = sample_catalog();
        let results = catalog.search("dataset");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].identifier, "urn:example:data:nlp-corpus");
    }

    #[test]
    fn search_returns_multiple_matches() {
        let catalog = sample_catalog();
        let results = catalog.search("urn:example");
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn search_returns_empty_for_no_match() {
        let catalog = sample_catalog();
        assert!(catalog.search("xyzzy-not-found").is_empty());
    }

    #[test]
    fn search_by_regex_matches_pattern() {
        let catalog = sample_catalog();
        let results = catalog
            .search_by_regex(r"urn:example:(agent|data):.*")
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_by_regex_anchored_identifier() {
        let catalog = sample_catalog();
        let results = catalog.search_by_regex(r"^urn:example:model:").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].identifier, "urn:example:model:embedding-v2");
    }

    #[test]
    fn search_by_regex_returns_error_on_invalid_pattern() {
        let catalog = sample_catalog();
        assert!(matches!(
            catalog.search_by_regex("[invalid("),
            Err(Error::Regex(_))
        ));
    }
}
