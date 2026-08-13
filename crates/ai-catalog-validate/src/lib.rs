// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use ai_catalog::{
    AiCatalog, Attestation, CatalogEntry, HostInfo, ProvenanceLink, Publisher, Subject,
    TrustManifest, TrustSchema, identity_binds_to_entry, identity_domain, publisher_domain,
};
use regex::Regex;
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

    if is_trusted(catalog) {
        ConformanceLevel::Trusted
    } else {
        ConformanceLevel::Discoverable
    }
}

fn is_trusted(catalog: &AiCatalog) -> bool {
    let manifests = catalog
        .host
        .as_ref()
        .and_then(|host| host.trust_manifest.as_ref())
        .into_iter()
        .chain(
            catalog
                .entries
                .iter()
                .filter_map(|entry| entry.trust_manifest.as_ref()),
        )
        .collect::<Vec<_>>();

    if manifests.is_empty() {
        return false;
    }

    manifests.iter().all(|manifest| {
        manifest.signature.is_some() && manifest.subject.is_some() && manifest.issued_at.is_some()
    })
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
    if let Some(host) = &catalog.host {
        validate_host(host, &format!("{path}.host"), errors, warnings);
    }

    validate_extension_keys(
        catalog.extensions.as_ref(),
        &format!("{path}.extensions"),
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
    require_member(
        &entry.identifier,
        &format!("{path}.identifier"),
        "identifier",
        errors,
    );
    require_member(&entry.entry_type, &format!("{path}.type"), "type", errors);

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

    validate_extension_keys(
        entry.extensions.as_ref(),
        &format!("{path}.extensions"),
        errors,
    );

    if let Some(publisher) = &entry.publisher {
        validate_publisher(publisher, &format!("{path}.publisher"), errors);
    }

    if let Some(trust_manifest) = &entry.trust_manifest {
        let manifest_path = format!("{path}.trustManifest");

        validate_trust_manifest(trust_manifest, &manifest_path, errors, warnings);
        validate_subject_binding(entry, trust_manifest, &manifest_path, errors);

        if identity_binds_to_entry(&entry.identifier, &trust_manifest.identity) == Some(false) {
            let publisher = publisher_domain(&entry.identifier).unwrap_or_default();
            let message = match identity_domain(&trust_manifest.identity) {
                Some(domain) => format!(
                    "trustManifest.identity domain '{domain}' does not align with the entry identifier publisher domain '{publisher}'"
                ),
                None => format!(
                    "trustManifest.identity '{}' has no trust domain to align with the entry identifier publisher domain '{publisher}'",
                    trust_manifest.identity
                ),
            };

            push_error(errors, format!("{path}.trustManifest.identity"), message);
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

static REVERSE_DNS_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$",
    )
    .expect("reverse-DNS pattern is valid")
});

static URL_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/?#\s]+").expect("URL pattern is valid")
});

fn is_extension_key(key: &str) -> bool {
    URL_KEY.is_match(key) || REVERSE_DNS_KEY.is_match(key)
}

fn validate_extension_keys(
    extensions: Option<&BTreeMap<String, serde_json::Value>>,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(extensions) = extensions else {
        return;
    };

    for key in extensions.keys() {
        if !is_extension_key(key) {
            push_error(
                errors,
                path.to_owned(),
                format!("extension key '{key}' must be a valid URL or a reverse-DNS string"),
            );
        }
    }
}

fn require_member(value: &str, path: &str, member: &str, errors: &mut Vec<Diagnostic>) {
    if value.is_empty() {
        push_error(
            errors,
            path.to_owned(),
            format!("{member} is required and must not be empty"),
        );
    }
}

fn validate_publisher(publisher: &Publisher, path: &str, errors: &mut Vec<Diagnostic>) {
    require_member(
        &publisher.identifier,
        &format!("{path}.identifier"),
        "publisher.identifier",
        errors,
    );
    require_member(
        &publisher.display_name,
        &format!("{path}.displayName"),
        "publisher.displayName",
        errors,
    );
}

fn validate_trust_schema(schema: &TrustSchema, path: &str, errors: &mut Vec<Diagnostic>) {
    require_member(
        &schema.identifier,
        &format!("{path}.identifier"),
        "trustSchema.identifier",
        errors,
    );
    require_member(
        &schema.version,
        &format!("{path}.version"),
        "trustSchema.version",
        errors,
    );
}

fn validate_attestation(attestation: &Attestation, path: &str, errors: &mut Vec<Diagnostic>) {
    require_member(
        &attestation.r#type,
        &format!("{path}.type"),
        "attestation.type",
        errors,
    );
    require_member(
        &attestation.uri,
        &format!("{path}.uri"),
        "attestation.uri",
        errors,
    );
}

fn validate_provenance_link(link: &ProvenanceLink, path: &str, errors: &mut Vec<Diagnostic>) {
    require_member(
        &link.relation,
        &format!("{path}.relation"),
        "provenance.relation",
        errors,
    );
    require_member(
        &link.source_id,
        &format!("{path}.sourceId"),
        "provenance.sourceId",
        errors,
    );
}

fn validate_host(
    host: &HostInfo,
    path: &str,
    errors: &mut Vec<Diagnostic>,
    warnings: &mut Vec<Diagnostic>,
) {
    require_member(
        &host.display_name,
        &format!("{path}.displayName"),
        "host.displayName",
        errors,
    );

    if let Some(manifest) = &host.trust_manifest {
        validate_trust_manifest(manifest, &format!("{path}.trustManifest"), errors, warnings);
    }
}

fn validate_trust_manifest(
    manifest: &TrustManifest,
    path: &str,
    errors: &mut Vec<Diagnostic>,
    warnings: &mut Vec<Diagnostic>,
) {
    validate_extension_keys(
        manifest.extensions.as_ref(),
        &format!("{path}.extensions"),
        errors,
    );

    require_member(
        &manifest.identity,
        &format!("{path}.identity"),
        "trustManifest.identity",
        errors,
    );

    if let Some(schema) = &manifest.trust_schema {
        validate_trust_schema(schema, &format!("{path}.trustSchema"), errors);
    }

    for (index, attestation) in manifest.attestations.iter().enumerate() {
        validate_attestation(
            attestation,
            &format!("{path}.attestations[{index}]"),
            errors,
        );
    }

    for (index, link) in manifest.provenance.iter().enumerate() {
        validate_provenance_link(link, &format!("{path}.provenance[{index}]"), errors);
    }

    if !is_substantive(manifest) {
        push_error(
            errors,
            path.to_owned(),
            "trustManifest must carry at least one substantive member (a signature with its \
             subject and issuedAt, a non-empty attestations or provenance array, or a \
             trustSchema) and must otherwise be omitted entirely"
                .to_owned(),
        );
    }

    validate_signed_manifest_members(manifest, path, errors);
    validate_manifest_timestamps(manifest, path, errors, warnings);
    validate_subject(
        manifest.subject.as_ref(),
        &format!("{path}.subject"),
        errors,
    );
}

fn is_substantive(manifest: &TrustManifest) -> bool {
    let signed =
        manifest.signature.is_some() && manifest.subject.is_some() && manifest.issued_at.is_some();

    signed
        || !manifest.attestations.is_empty()
        || !manifest.provenance.is_empty()
        || manifest.trust_schema.is_some()
}

fn validate_signed_manifest_members(
    manifest: &TrustManifest,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if manifest.signature.is_none() {
        return;
    }

    if manifest.subject.is_none() {
        push_error(
            errors,
            format!("{path}.subject"),
            "a trustManifest carrying a signature must include a subject".to_owned(),
        );
    }

    if manifest.issued_at.is_none() {
        push_error(
            errors,
            format!("{path}.issuedAt"),
            "a trustManifest carrying a signature must include issuedAt".to_owned(),
        );
    }
}

fn validate_manifest_timestamps(
    manifest: &TrustManifest,
    path: &str,
    errors: &mut Vec<Diagnostic>,
    warnings: &mut Vec<Diagnostic>,
) {
    if let Some(issued_at) = &manifest.issued_at
        && OffsetDateTime::parse(issued_at, &Rfc3339).is_err()
    {
        push_error(
            errors,
            format!("{path}.issuedAt"),
            format!("issuedAt is not a valid RFC 3339 datetime: '{issued_at}'"),
        );
    }

    let Some(expires_at) = &manifest.expires_at else {
        return;
    };

    match OffsetDateTime::parse(expires_at, &Rfc3339) {
        Ok(parsed) => {
            if parsed < OffsetDateTime::now_utc() {
                warnings.push(Diagnostic {
                    path: format!("{path}.expiresAt"),
                    message: format!(
                        "trustManifest expired at '{expires_at}' and SHOULD be rejected"
                    ),
                });
            }
        }
        Err(_) => push_error(
            errors,
            format!("{path}.expiresAt"),
            format!("expiresAt is not a valid RFC 3339 datetime: '{expires_at}'"),
        ),
    }
}

fn validate_subject(subject: Option<&Subject>, path: &str, errors: &mut Vec<Diagnostic>) {
    let Some(subject) = subject else {
        return;
    };

    if subject.r#type.is_empty() {
        push_error(
            errors,
            format!("{path}.type"),
            "subject.type is required and must not be empty".to_owned(),
        );
    }

    if subject.digest.is_empty() {
        push_error(
            errors,
            format!("{path}.digest"),
            "subject.digest is required and must not be empty".to_owned(),
        );
    }
}

fn validate_subject_binding(
    entry: &CatalogEntry,
    manifest: &TrustManifest,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    let Some(subject) = &manifest.subject else {
        return;
    };

    if !subject.r#type.is_empty()
        && !entry.entry_type.is_empty()
        && subject.r#type != entry.entry_type
    {
        push_error(
            errors,
            format!("{path}.subject.type"),
            format!(
                "subject.type '{}' must equal the entry type '{}'",
                subject.r#type, entry.entry_type
            ),
        );
    }

    if let Some(subject_url) = &subject.url
        && Some(subject_url) != entry.url.as_ref()
    {
        push_error(
            errors,
            format!("{path}.subject.url"),
            format!(
                "subject.url '{subject_url}' must equal the entry url '{}'",
                entry.url.as_deref().unwrap_or_default()
            ),
        );
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
    fn rejects_trust_identity_without_a_trust_domain() {
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
                    "identity": "urn:acme:agent:test"
                  }
                }
              ]
            }"#,
        )
        .expect("document should parse");

        let result = validate(&catalog);

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic.message
                == "trustManifest.identity 'urn:acme:agent:test' has no trust domain to align with the entry identifier publisher domain 'acme.com'"
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
                    "identity": "did:web:acme.com",
                    "trustSchema": {
                      "identifier": "urn:example:schema",
                      "version": "1.0"
                    }
                  }
                }
              ]
            }"#,
        )
        .expect("document should parse");

        let result = validate(&catalog);

        assert!(result.is_valid, "unexpected errors: {:?}", result.errors);
    }

    #[test]
    fn rejects_trust_manifest_without_substantive_members() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:bare",
                    "displayName": "Bare",
                    "type": "application/json",
                    "url": "https://example.com/bare.json",
                    "trustManifest": {
                        "identity": "urn:example:bare"
                    }
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("must carry at least one substantive member")
        }));
    }

    #[test]
    fn requires_subject_and_issued_at_alongside_a_signature() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:signed",
                    "displayName": "Signed",
                    "type": "application/json",
                    "url": "https://example.com/signed.json",
                    "trustManifest": {
                        "identity": "urn:example:signed",
                        "signature": "eyJhbGciOiJFUzI1NiJ9..c2ln"
                    }
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("must include a subject") })
        );
        assert!(
            result
                .errors
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("must include issuedAt") })
        );
    }

    #[test]
    fn rejects_subject_that_does_not_restate_the_entry() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:bound",
                    "displayName": "Bound",
                    "type": "application/json",
                    "url": "https://example.com/bound.json",
                    "trustManifest": {
                        "identity": "urn:example:bound",
                        "issuedAt": "2026-01-01T00:00:00Z",
                        "signature": "eyJhbGciOiJFUzI1NiJ9..c2ln",
                        "subject": {
                            "type": "application/gguf",
                            "digest": "sha256:abc",
                            "url": "https://example.com/other.json"
                        }
                    }
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("must equal the entry type") })
        );
        assert!(
            result
                .errors
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("must equal the entry url") })
        );
    }

    #[test]
    fn diagnoses_every_missing_required_member() {
        let cases: [(serde_json::Value, &str); 6] = [
            (json!({"entries": []}), "specVersion must not be empty"),
            (
                json!({"specVersion": "1.0", "entries": [{"type": "application/json", "url": "https://e.com/a"}]}),
                "identifier is required",
            ),
            (
                json!({"specVersion": "1.0", "entries": [{"identifier": "urn:air:e.com:a:b", "url": "https://e.com/a"}]}),
                "type is required",
            ),
            (
                json!({"specVersion": "1.0", "entries": [{"identifier": "urn:air:e.com:a:b", "type": "application/json", "url": "https://e.com/a", "publisher": {"identifier": "did:web:e.com"}}]}),
                "publisher.displayName is required",
            ),
            (
                json!({"specVersion": "1.0", "entries": [{"identifier": "urn:air:e.com:a:b", "type": "application/json", "url": "https://e.com/a", "trustManifest": {"attestations": [{"type": "soc2"}]}}]}),
                "attestation.uri is required",
            ),
            (
                json!({"specVersion": "1.0", "entries": [{"identifier": "urn:air:e.com:a:b", "type": "application/json", "url": "https://e.com/a", "trustManifest": {"identity": "did:web:e.com", "provenance": [{"relation": "derivedFrom"}]}}]}),
                "provenance.sourceId is required",
            ),
        ];

        for (document, expected) in cases {
            let result = validate_value(document.clone());

            assert!(
                result
                    .errors
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains(expected)),
                "expected '{expected}' for {document}, got {:?}",
                result.errors
            );
        }
    }

    #[test]
    fn requires_trust_schema_identifier_and_version() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:air:e.com:a:b",
                    "type": "application/json",
                    "url": "https://e.com/a",
                    "trustManifest": {
                        "identity": "did:web:e.com",
                        "trustSchema": {}
                    }
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("trustSchema.identifier is required")
        }));
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("trustSchema.version is required")
        }));
    }

    #[test]
    fn requires_publisher_identifier_and_display_name() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:pub",
                    "displayName": "Pub",
                    "type": "application/json",
                    "url": "https://example.com/pub.json",
                    "publisher": {"identifier": "", "displayName": ""}
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("publisher.identifier is required")
        }));
        assert!(result.errors.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("publisher.displayName is required")
        }));
    }

    #[test]
    fn requires_host_display_name() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "host": {
                "identifier": "did:web:example.com"
            },
            "entries": []
        }));

        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("host.displayName is required") })
        );
    }

    #[test]
    fn warns_on_expired_trust_manifest() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:expired",
                    "displayName": "Expired",
                    "type": "application/json",
                    "url": "https://example.com/expired.json",
                    "trustManifest": {
                        "identity": "urn:example:expired",
                        "issuedAt": "2020-01-01T00:00:00Z",
                        "expiresAt": "2020-06-01T00:00:00Z",
                        "signature": "eyJhbGciOiJFUzI1NiJ9..c2ln",
                        "subject": {
                            "type": "application/json",
                            "digest": "sha256:abc",
                            "url": "https://example.com/expired.json"
                        }
                    }
                }
            ]
        }));

        assert!(result.is_valid, "unexpected errors: {:?}", result.errors);
        assert!(
            result
                .warnings
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("expired at") })
        );
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
    fn classifies_valid_catalog_with_signed_entry_manifest_as_trusted() {
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
                        "identity": "urn:example:trusted",
                        "issuedAt": "2026-01-01T00:00:00Z",
                        "signature": "eyJhbGciOiJFUzI1NiJ9..c2ln",
                        "subject": {
                            "type": "application/json",
                            "digest": "sha256:abc",
                            "url": "https://example.com/trusted.json"
                        }
                    }
                }
            ]
        }));

        assert!(result.is_valid, "unexpected errors: {:?}", result.errors);
        assert_eq!(result.conformance_level, ConformanceLevel::Trusted);
    }

    #[test]
    fn an_unsigned_manifest_downgrades_the_catalog_below_trusted() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "host": {
                "displayName": "Example Host"
            },
            "entries": [
                {
                    "identifier": "urn:example:unsigned",
                    "displayName": "Unsigned",
                    "type": "application/json",
                    "url": "https://example.com/unsigned.json",
                    "trustManifest": {
                        "identity": "urn:example:unsigned",
                        "trustSchema": {
                            "identifier": "urn:example:schema",
                            "version": "1.0"
                        }
                    }
                }
            ]
        }));

        assert!(result.is_valid, "unexpected errors: {:?}", result.errors);
        assert_eq!(result.conformance_level, ConformanceLevel::Discoverable);
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
    fn rejects_unnamespaced_extension_keys() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "extensions": {
                "": true,
                "scope": "demo"
            },
            "entries": [
                {
                    "identifier": "urn:example:extensions",
                    "displayName": "Extensions",
                    "type": "application/json",
                    "url": "https://example.com/extensions.json",
                    "extensions": {
                        "notNamespaced": 1
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
                    .contains("must be a valid URL or a reverse-DNS string"))
                .count(),
            3
        );
    }

    #[test]
    fn accepts_url_and_reverse_dns_extension_keys() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "extensions": {
                "com.example.confidenceScore": 0.9,
                "https://example.com/ext": true
            },
            "entries": [
                {
                    "identifier": "urn:example:extensions",
                    "displayName": "Extensions",
                    "type": "application/json",
                    "url": "https://example.com/extensions.json"
                }
            ]
        }));

        assert!(result.is_valid, "unexpected errors: {:?}", result.errors);
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
    fn reports_the_violated_member_inside_nested_catalog_data() {
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
        assert!(
            result.errors.iter().any(|diagnostic| {
                diagnostic.path == "catalog.entries[0].data.specVersion"
                    && diagnostic.message.contains("specVersion must not be empty")
            }),
            "unexpected errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn rejects_structurally_invalid_nested_catalog_data() {
        let result = validate_value(json!({
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:example:bad-nested",
                    "displayName": "Bad Nested",
                    "type": "application/ai-catalog+json",
                    "data": {
                        "specVersion": "1.0",
                        "entries": "not-an-array"
                    }
                }
            ]
        }));

        assert!(!result.is_valid);
        assert!(
            result.errors.iter().any(|diagnostic| {
                diagnostic
                    .message
                    .contains("nested catalog data is not a valid AI Catalog")
            }),
            "unexpected errors: {:?}",
            result.errors
        );
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
