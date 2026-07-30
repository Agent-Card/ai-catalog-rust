// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};

use ai_catalog::{
    AiCatalog, CatalogEntry, identity_binds_to_entry, identity_domain, publisher_domain,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceLevel {
    Minimal,
    Discoverable,
    Trusted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub conformance_level: ConformanceLevel,
    pub errors: Vec<Diagnostic>,
    pub warnings: Vec<Diagnostic>,
}

const MAX_NESTING_DEPTH: usize = 4;

pub fn validate(catalog: &AiCatalog) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    validate_catalog(catalog, "catalog", 1, &mut errors, &mut warnings);

    let conformance_level = detect_level(catalog, &errors);

    ValidationResult {
        is_valid: errors.is_empty(),
        conformance_level,
        errors,
        warnings,
    }
}

fn detect_level(catalog: &AiCatalog, errors: &[Diagnostic]) -> ConformanceLevel {
    if !errors.is_empty() {
        return ConformanceLevel::Minimal;
    }

    if catalog.host.is_none() {
        return ConformanceLevel::Minimal;
    }

    if catalog
        .host
        .as_ref()
        .and_then(|host| host.trust_manifest.as_ref())
        .is_some()
        || catalog
            .entries
            .iter()
            .any(|entry| entry.trust_manifest.is_some())
    {
        ConformanceLevel::Trusted
    } else {
        ConformanceLevel::Discoverable
    }
}

fn validate_catalog(
    catalog: &AiCatalog,
    path: &str,
    depth: usize,
    errors: &mut Vec<Diagnostic>,
    warnings: &mut Vec<Diagnostic>,
) {
    validate_spec_version(
        &catalog.spec_version,
        &format!("{path}.specVersion"),
        errors,
    );
    validate_metadata_keys(
        catalog.metadata.as_ref(),
        &format!("{path}.metadata"),
        errors,
    );

    let mut seen_versioned: HashMap<(&str, &str), usize> = HashMap::new();
    let mut seen_unversioned: HashMap<&str, usize> = HashMap::new();

    for (index, entry) in catalog.entries.iter().enumerate() {
        validate_entry(
            entry,
            &format!("{path}.entries[{index}]"),
            depth,
            errors,
            warnings,
        );

        match entry.version.as_deref() {
            Some(version) => {
                if seen_unversioned.contains_key(entry.identifier.as_str()) {
                    push_error(
                        errors,
                        format!("{path}.entries[{index}].identifier"),
                        format!(
                            "identifier '{}' cannot appear with and without version",
                            entry.identifier
                        ),
                    );
                }

                if seen_versioned
                    .insert((entry.identifier.as_str(), version), index)
                    .is_some()
                {
                    push_error(
                        errors,
                        format!("{path}.entries[{index}]"),
                        format!(
                            "duplicate (identifier, version) pair: ('{}', '{}')",
                            entry.identifier, version
                        ),
                    );
                }
            }
            None => {
                if seen_unversioned
                    .insert(entry.identifier.as_str(), index)
                    .is_some()
                    || seen_versioned
                        .keys()
                        .any(|(identifier, _)| *identifier == entry.identifier.as_str())
                {
                    push_error(
                        errors,
                        format!("{path}.entries[{index}]"),
                        format!(
                            "duplicate identifier '{}' without version differentiation",
                            entry.identifier
                        ),
                    );
                }
            }
        }
    }
}

fn validate_entry(
    entry: &CatalogEntry,
    path: &str,
    depth: usize,
    errors: &mut Vec<Diagnostic>,
    warnings: &mut Vec<Diagnostic>,
) {
    let has_url = entry.url.is_some();
    let has_data = entry.data.is_some();

    match (has_url, has_data) {
        (true, true) => push_error(
            errors,
            path.to_owned(),
            "entry must have exactly one of 'url' or 'data', found both".to_owned(),
        ),
        (false, false) => push_error(
            errors,
            path.to_owned(),
            "entry must have exactly one of 'url' or 'data'".to_owned(),
        ),
        _ => {}
    }

    if let Some(updated_at) = &entry.updated_at
        && OffsetDateTime::parse(updated_at, &Rfc3339).is_err()
    {
        push_error(
            errors,
            format!("{path}.updatedAt"),
            format!("updatedAt is not a valid RFC 3339 datetime: '{updated_at}'"),
        );
    }

    validate_metadata_keys(entry.metadata.as_ref(), &format!("{path}.metadata"), errors);

    if let Some(trust_manifest) = &entry.trust_manifest {
        validate_metadata_keys(
            trust_manifest.metadata.as_ref(),
            &format!("{path}.trustManifest.metadata"),
            errors,
        );

        if identity_binds_to_entry(&entry.identifier, &trust_manifest.identity) == Some(false) {
            push_error(
                errors,
                format!("{path}.trustManifest.identity"),
                format!(
                    "trustManifest.identity domain '{}' does not align with the entry identifier publisher domain '{}'",
                    identity_domain(&trust_manifest.identity).unwrap_or_default(),
                    publisher_domain(&entry.identifier).unwrap_or_default()
                ),
            );
        }
    }

    if entry.entry_type == "application/ai-catalog+json" {
        if depth >= MAX_NESTING_DEPTH {
            push_error(
                errors,
                path.to_owned(),
                format!("nested catalog depth exceeds recommended limit of {MAX_NESTING_DEPTH}"),
            );
        } else if let Some(data) = &entry.data {
            match serde_json::from_value::<AiCatalog>(data.clone()) {
                Ok(nested) => validate_catalog(
                    &nested,
                    &format!("{path}.data"),
                    depth + 1,
                    errors,
                    warnings,
                ),
                Err(error) => push_error(
                    errors,
                    format!("{path}.data"),
                    format!("nested catalog data is not a valid AI Catalog: {error}"),
                ),
            }
        }
    }

    if entry.identifier.find(':').is_none() {
        warnings.push(Diagnostic {
            path: format!("{path}.identifier"),
            message: "identifier SHOULD be a URN or URI".to_owned(),
        });
    }
}

fn validate_metadata_keys(
    metadata: Option<&BTreeMap<String, serde_json::Value>>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if let Some(metadata) = metadata {
        for key in metadata.keys() {
            if key.is_empty() {
                push_error(
                    errors,
                    path.to_owned(),
                    "metadata keys must be non-empty strings".to_owned(),
                );
            }
        }
    }
}

fn validate_spec_version(spec_version: &str, path: &str, errors: &mut Vec<Diagnostic>) {
    if spec_version.is_empty() {
        push_error(
            errors,
            path.to_owned(),
            "specVersion must not be empty".to_owned(),
        );
        return;
    }

    let mut parts = spec_version.split('.');
    let major = parts.next();
    let minor = parts.next();

    if major.is_none() || minor.is_none() || parts.next().is_some() {
        push_error(
            errors,
            path.to_owned(),
            format!(
                "specVersion must be in Major.Minor format (e.g., '1.0'), found '{spec_version}'"
            ),
        );
        return;
    }

    let (major, minor) = (major.unwrap(), minor.unwrap());
    let major_number = major.parse::<u64>();
    let minor_number = minor.parse::<u64>();

    if major_number.is_err() || minor_number.is_err() {
        push_error(
            errors,
            path.to_owned(),
            format!(
                "specVersion major and minor components must be non-negative integers, found '{spec_version}'"
            ),
        );
        return;
    }

    if major_number.expect("checked above") > 1 {
        push_error(
            errors,
            path.to_owned(),
            format!(
                "unsupported specVersion major version: {} (this implementation supports major version 1)",
                major
            ),
        );
    }
}

fn push_error(errors: &mut Vec<Diagnostic>, path: String, message: String) {
    errors.push(Diagnostic { path, message });
}

#[cfg(test)]
mod tests {
    use ai_catalog::{parse_file, parse_str};
    use serde_json::json;

    use super::{ConformanceLevel, ValidationResult, validate};

    #[test]
    fn validates_canonical_fixture_as_discoverable() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let fixture = format!("{manifest_dir}/../../fixtures/spec-example.json");
        let catalog = parse_file(&fixture).expect("fixture should parse");

        let result = validate(&catalog);

        assert!(
            result.is_valid,
            "expected no validation errors: {:?}",
            result.errors
        );
        assert_eq!(result.conformance_level, ConformanceLevel::Discoverable);
    }

    #[test]
    fn rejects_entry_with_both_url_and_data() {
        let catalog = parse_str(
            r#"{
              "specVersion": "1.0",
              "entries": [
                {
                  "identifier": "urn:example:test",
                  "displayName": "Test",
                  "type": "application/json",
                  "url": "https://example.com/test.json",
                  "data": {"key": "value"}
                }
              ]
            }"#,
        )
        .expect("document should parse");

        let result = validate(&catalog);

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("exactly one of 'url' or 'data'")
        }));
    }

    #[test]
    fn rejects_duplicate_identifier_without_version() {
        let catalog = parse_str(
            r#"{
              "specVersion": "1.0",
              "entries": [
                {
                  "identifier": "urn:example:test",
                  "displayName": "First",
                  "type": "application/json",
                  "url": "https://example.com/one.json"
                },
                {
                  "identifier": "urn:example:test",
                  "displayName": "Second",
                  "type": "application/json",
                  "url": "https://example.com/two.json"
                }
              ]
            }"#,
        )
        .expect("document should parse");

        let result = validate(&catalog);

        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("duplicate identifier"))
        );
    }

    #[test]
    fn rejects_misaligned_trust_identity_domain() {
        let catalog = parse_str(
            r#"{
              "specVersion": "1.0",
              "entries": [
                {
                  "identifier": "urn:air:acme.com:agent:test",
                  "displayName": "Test",
                  "type": "application/json",
                  "url": "https://acme.com/test.json",
                  "trustManifest": {
                    "identity": "did:web:evil.example"
                  }
                }
              ]
            }"#,
        )
        .expect("document should parse");

        let result = validate(&catalog);

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("does not align with the entry identifier publisher domain")
        }));
    }

    #[test]
    fn accepts_trust_identity_aligned_by_domain() {
        let catalog = parse_str(
            r#"{
              "specVersion": "1.0",
              "entries": [
                {
                  "identifier": "urn:air:acme.com:agent:test",
                  "displayName": "Test",
                  "type": "application/json",
                  "url": "https://acme.com/test.json",
                  "trustManifest": {
                    "identity": "did:web:acme.com"
                  }
                }
              ]
            }"#,
        )
        .expect("document should parse");

        let result = validate(&catalog);

        assert!(result.is_valid);
    }

    #[test]
    fn classifies_valid_hostless_catalog_as_minimal() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:minimal",
                    "displayName": "Minimal",
                    "type": "application/json",
                    "url": "https://example.com/minimal.json"
                }
            ]
        }));

        assert!(result.is_valid);
        assert_eq!(result.conformance_level, ConformanceLevel::Minimal);
    }

    #[test]
    fn classifies_valid_catalog_with_entry_trust_manifest_as_trusted() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "host": {
                "displayName": "Example Host"
            },
            "entries": [
                {
                    "identifier": "urn:example:trusted",
                    "displayName": "Trusted",
                    "type": "application/json",
                    "url": "https://example.com/trusted.json",
                    "trustManifest": {
                        "identity": "urn:example:trusted"
                    }
                }
            ]
        }));

        assert!(result.is_valid, "unexpected errors: {:?}", result.errors);
        assert_eq!(result.conformance_level, ConformanceLevel::Trusted);
    }

    #[test]
    fn rejects_duplicate_identifier_with_same_version() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:versioned",
                    "displayName": "First",
                    "type": "application/json",
                    "url": "https://example.com/one.json",
                    "version": "1.0.0"
                },
                {
                    "identifier": "urn:example:versioned",
                    "displayName": "Second",
                    "type": "application/json",
                    "url": "https://example.com/two.json",
                    "version": "1.0.0"
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("duplicate (identifier, version) pair")
        }));
    }

    #[test]
    fn rejects_mixing_versioned_and_unversioned_identifiers() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:mixed",
                    "displayName": "Unversioned",
                    "type": "application/json",
                    "url": "https://example.com/unversioned.json"
                },
                {
                    "identifier": "urn:example:mixed",
                    "displayName": "Versioned",
                    "type": "application/json",
                    "url": "https://example.com/versioned.json",
                    "version": "1.0.0"
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("cannot appear with and without version")
        }));
    }

    #[test]
    fn rejects_entry_without_url_or_data() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:missing-payload",
                    "displayName": "Missing Payload",
                    "type": "application/json"
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("entry must have exactly one of 'url' or 'data'")
        }));
    }

    #[test]
    fn rejects_invalid_updated_at_and_warns_on_non_uri_identifier() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "plain-identifier",
                    "displayName": "Plain Identifier",
                    "type": "application/json",
                    "url": "https://example.com/plain.json",
                    "updatedAt": "yesterday"
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("updatedAt is not a valid RFC 3339 datetime")
        }));
        assert!(result.warnings.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("identifier SHOULD be a URN or URI")
        }));
    }

    #[test]
    fn rejects_empty_metadata_keys() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "metadata": {
                "": true
            },
            "entries": [
                {
                    "identifier": "urn:example:metadata",
                    "displayName": "Metadata",
                    "type": "application/json",
                    "url": "https://example.com/metadata.json",
                    "metadata": {
                        "": 1
                    },
                    "trustManifest": {
                        "identity": "urn:example:metadata",
                        "metadata": {
                            "": "bad"
                        }
                    }
                }
            ]
        }));

        assert!(!result.is_valid);
        assert_eq!(
            result
                .errors
                .iter()
                .filter(|diagnostic| diagnostic
                    .message
                    .contains("metadata keys must be non-empty strings"))
                .count(),
            3
        );
    }

    #[test]
    fn rejects_invalid_spec_versions() {
        let empty_result = validate_value(json!({
            "specVersion": "",
            "entries": []
        }));
        let malformed_result = validate_value(json!({
            "specVersion": "1",
            "entries": []
        }));
        let non_numeric_result = validate_value(json!({
            "specVersion": "one.zero",
            "entries": []
        }));
        let unsupported_result = validate_value(json!({
            "specVersion": "2.0",
            "entries": []
        }));

        assert!(
            empty_result
                .errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("must not be empty"))
        );
        assert!(
            malformed_result
                .errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("Major.Minor format"))
        );
        assert!(
            non_numeric_result
                .errors
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("must be non-negative integers") })
        );
        assert!(unsupported_result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("unsupported specVersion major version")
        }));
    }

    #[test]
    fn validates_nested_catalog_data() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:nested-root",
                    "displayName": "Nested Root",
                    "type": "application/ai-catalog+json",
                    "data": {
                        "specVersion": "1.0",
                        "entries": [
                            {
                                "identifier": "urn:example:nested-child",
                                "displayName": "Nested Child",
                                "type": "application/json",
                                "url": "https://example.com/nested-child.json"
                            }
                        ]
                    }
                }
            ]
        }));

        assert!(result.is_valid, "unexpected errors: {:?}", result.errors);
    }

    #[test]
    fn rejects_invalid_nested_catalog_data() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:bad-nested",
                    "displayName": "Bad Nested",
                    "type": "application/ai-catalog+json",
                    "data": {
                        "unexpected": true
                    }
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("nested catalog data is not a valid AI Catalog")
        }));
    }

    #[test]
    fn rejects_nested_catalogs_beyond_depth_limit() {
        let result = validate_value(nested_catalog_value(4));

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("nested catalog depth exceeds recommended limit")
        }));
    }

    fn validate_value(value: serde_json::Value) -> ValidationResult {
        let catalog = parse_str(&value.to_string()).expect("document should parse");

        validate(&catalog)
    }

    fn nested_catalog_value(levels: usize) -> serde_json::Value {
        if levels == 0 {
            json!({
                "specVersion": "1.0",
                "entries": [
                    {
                        "identifier": "urn:example:leaf",
                        "displayName": "Leaf",
                        "type": "application/json",
                        "url": "https://example.com/leaf.json"
                    }
                ]
            })
        } else {
            json!({
                "specVersion": "1.0",
                "entries": [
                    {
                        "identifier": format!("urn:example:nested:{levels}"),
                        "displayName": format!("Nested {levels}"),
                        "type": "application/ai-catalog+json",
                        "data": nested_catalog_value(levels - 1)
                    }
                ]
            })
        }
    }
}
