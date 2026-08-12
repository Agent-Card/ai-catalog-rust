// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use ai_catalog::{
    AiCatalog, CatalogEntry, HostInfo, Subject, TrustManifest, identity_binds_to_entry,
    identity_domain, publisher_domain,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Error)]
pub enum Error {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("digest must use the format 'algorithm:hex-value', found '{0}'")]
    InvalidDigestFormat(String),
    #[error("unsupported digest algorithm '{0}'")]
    UnsupportedDigestAlgorithm(String),
    #[error("digest algorithm '{0}' is weaker than SHA-256")]
    WeakDigestAlgorithm(String),
    #[error("digest hex value contains non-hex characters")]
    InvalidDigestHex,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestReport {
    pub path: String,
    pub identity: String,
    pub has_signature: bool,
    pub attestation_count: usize,
    pub provenance_count: usize,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogTrustReport {
    pub findings: Vec<Finding>,
    pub host: Option<ManifestReport>,
    pub entries: Vec<ManifestReport>,
    pub has_signature: bool,
}

const SHA256_HEX_LEN: usize = 64;
const SHA384_HEX_LEN: usize = 96;
const SHA512_HEX_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDigest {
    algorithm: String,
    hex_value: String,
}

impl ParsedDigest {
    pub fn parse(value: &str) -> Result<Self> {
        let (algorithm, hex_value) = value
            .split_once(':')
            .ok_or_else(|| Error::InvalidDigestFormat(value.to_owned()))?;

        if algorithm.is_empty() || hex_value.is_empty() || value.matches(':').count() != 1 {
            return Err(Error::InvalidDigestFormat(value.to_owned()));
        }

        let normalized_algorithm = algorithm.to_ascii_lowercase();

        let expected_len = match normalized_algorithm.as_str() {
            "sha256" => SHA256_HEX_LEN,
            "sha384" => SHA384_HEX_LEN,
            "sha512" => SHA512_HEX_LEN,
            "md5" | "sha1" | "sha224" => {
                return Err(Error::WeakDigestAlgorithm(normalized_algorithm));
            }
            _ => return Err(Error::UnsupportedDigestAlgorithm(normalized_algorithm)),
        };

        if hex_value.len() != expected_len
            || !hex_value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::InvalidDigestHex);
        }

        Ok(Self {
            algorithm: normalized_algorithm,
            hex_value: hex_value.to_ascii_lowercase(),
        })
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn hex_value(&self) -> &str {
        &self.hex_value
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> bool {
        match self.algorithm.as_str() {
            "sha256" => self.hex_value == digest_hex(Sha256::digest(bytes).as_slice()),
            "sha384" => self.hex_value == digest_hex(Sha384::digest(bytes).as_slice()),
            "sha512" => self.hex_value == digest_hex(Sha512::digest(bytes).as_slice()),
            _ => false,
        }
    }
}

pub fn canonicalize_trust_manifest(manifest: &TrustManifest) -> Result<String> {
    let mut value = serde_json::to_value(manifest)?;

    if let Value::Object(object) = &mut value {
        object.remove("signature");
    }

    serde_jcs::to_string(&value).map_err(Error::from)
}

pub fn canonicalize_catalog(catalog: &AiCatalog) -> Result<String> {
    let mut value = serde_json::to_value(catalog)?;

    if let Value::Object(object) = &mut value {
        object.remove("signature");
    }

    serde_jcs::to_string(&value).map_err(Error::from)
}

pub fn verify_digest(expected_digest: &str, bytes: &[u8]) -> Result<bool> {
    Ok(ParsedDigest::parse(expected_digest)?.verify_bytes(bytes))
}

pub fn analyze_catalog(catalog: &AiCatalog) -> CatalogTrustReport {
    let mut host = None;
    let mut entries = Vec::new();

    analyze_catalog_at(catalog, "catalog", 1, &mut host, &mut entries);

    let mut findings = Vec::new();

    if let Some(signature) = &catalog.signature {
        analyze_signature_algorithm("catalog.signature", signature, &mut findings);
    }

    findings.extend(
        host.iter()
            .flat_map(|report: &ManifestReport| report.findings.iter().cloned())
            .chain(
                entries
                    .iter()
                    .flat_map(|report: &ManifestReport| report.findings.iter().cloned()),
            ),
    );

    CatalogTrustReport {
        findings,
        host,
        entries,
        has_signature: catalog.signature.is_some(),
    }
}

const MAX_NESTING_DEPTH: usize = 4;

fn analyze_catalog_at(
    catalog: &AiCatalog,
    path: &str,
    depth: usize,
    root_host: &mut Option<ManifestReport>,
    entries: &mut Vec<ManifestReport>,
) {
    if let Some(host) = &catalog.host
        && let Some(report) = analyze_host_manifest(host, &format!("{path}.host.trustManifest"))
    {
        if depth == 1 {
            *root_host = Some(report);
        } else {
            entries.push(report);
        }
    }

    for (index, entry) in catalog.entries.iter().enumerate() {
        let entry_path = format!("{path}.entries[{index}]");

        if let Some(report) = analyze_entry_manifest(entry, &entry_path) {
            entries.push(report);
        }

        if depth >= MAX_NESTING_DEPTH || !entry.is_nested_catalog() {
            continue;
        }

        let Some(data) = &entry.data else {
            continue;
        };

        if let Ok(nested) = serde_json::from_value::<AiCatalog>(data.clone()) {
            analyze_catalog_at(
                &nested,
                &format!("{entry_path}.data"),
                depth + 1,
                root_host,
                entries,
            );
        }
    }
}

fn analyze_host_manifest(host: &HostInfo, path: &str) -> Option<ManifestReport> {
    let manifest = host.trust_manifest.as_ref()?;
    let mut findings = Vec::new();
    let path = path.to_owned();

    if manifest.identity.find(':').is_none() {
        findings.push(Finding {
            severity: Severity::Warning,
            path: format!("{path}.identity"),
            message: "trust manifest identity SHOULD be a URI-like identifier".to_owned(),
        });
    }

    if let Some(identifier) = &host.identifier
        && manifest.identity != *identifier
    {
        findings.push(Finding {
            severity: Severity::Warning,
            path: format!("{path}.identity"),
            message: format!(
                "host trustManifest.identity '{}' SHOULD match host.identifier '{}'",
                manifest.identity, identifier
            ),
        });
    }

    analyze_manifest_contents(&path, manifest, &mut findings);

    Some(ManifestReport {
        path,
        identity: manifest.identity.clone(),
        has_signature: manifest.signature.is_some(),
        attestation_count: manifest.attestations.len(),
        provenance_count: manifest.provenance.len(),
        findings,
    })
}

fn analyze_entry_manifest(entry: &CatalogEntry, entry_path: &str) -> Option<ManifestReport> {
    let manifest = entry.trust_manifest.as_ref()?;
    let path = format!("{entry_path}.trustManifest");
    let mut findings = Vec::new();

    if identity_binds_to_entry(&entry.identifier, &manifest.identity) == Some(false) {
        let publisher = publisher_domain(&entry.identifier).unwrap_or_default();
        let message = match identity_domain(&manifest.identity) {
            Some(domain) => format!(
                "trustManifest.identity domain '{domain}' MUST align with entry identifier publisher domain '{publisher}'"
            ),
            None => format!(
                "trustManifest.identity '{}' MUST carry a trust domain aligned with entry identifier publisher domain '{publisher}'",
                manifest.identity
            ),
        };

        findings.push(Finding {
            severity: Severity::Error,
            path: format!("{path}.identity"),
            message,
        });
    }

    if manifest.identity.find(':').is_none() {
        findings.push(Finding {
            severity: Severity::Warning,
            path: format!("{path}.identity"),
            message: "trust manifest identity SHOULD be a URI-like identifier".to_owned(),
        });
    }

    analyze_manifest_contents(&path, manifest, &mut findings);

    Some(ManifestReport {
        path,
        identity: manifest.identity.clone(),
        has_signature: manifest.signature.is_some(),
        attestation_count: manifest.attestations.len(),
        provenance_count: manifest.provenance.len(),
        findings,
    })
}

fn analyze_manifest_contents(path: &str, manifest: &TrustManifest, findings: &mut Vec<Finding>) {
    analyze_signature(path, manifest, findings);
    analyze_subject(path, manifest.subject.as_ref(), findings);
    analyze_validity_window(path, manifest, findings);

    if let Some(trust_schema) = &manifest.trust_schema {
        if trust_schema.identifier.is_empty() {
            findings.push(Finding {
                severity: Severity::Error,
                path: format!("{path}.trustSchema.identifier"),
                message: "trustSchema.identifier must not be empty".to_owned(),
            });
        }

        if trust_schema.version.is_empty() {
            findings.push(Finding {
                severity: Severity::Error,
                path: format!("{path}.trustSchema.version"),
                message: "trustSchema.version must not be empty".to_owned(),
            });
        }
    }

    for (index, attestation) in manifest.attestations.iter().enumerate() {
        if attestation.r#type.is_empty() {
            findings.push(Finding {
                severity: Severity::Error,
                path: format!("{path}.attestations[{index}].type"),
                message: "attestation type must not be empty".to_owned(),
            });
        }

        if attestation.uri.is_empty() {
            findings.push(Finding {
                severity: Severity::Error,
                path: format!("{path}.attestations[{index}].uri"),
                message: "attestation uri must not be empty".to_owned(),
            });
        }

        if let Some(digest) = &attestation.digest {
            analyze_digest_field(
                digest,
                &format!("{path}.attestations[{index}].digest"),
                findings,
            );
        }
    }

    for (index, provenance) in manifest.provenance.iter().enumerate() {
        if provenance.relation.is_empty() {
            findings.push(Finding {
                severity: Severity::Error,
                path: format!("{path}.provenance[{index}].relation"),
                message: "provenance relation must not be empty".to_owned(),
            });
        }

        if provenance.source_id.is_empty() {
            findings.push(Finding {
                severity: Severity::Error,
                path: format!("{path}.provenance[{index}].sourceId"),
                message: "provenance sourceId must not be empty".to_owned(),
            });
        }

        if let Some(digest) = &provenance.source_digest {
            analyze_digest_field(
                digest,
                &format!("{path}.provenance[{index}].sourceDigest"),
                findings,
            );
        }
    }
}

const ALLOWED_JWS_ALGORITHMS: [&str; 6] = ["ES256", "ES384", "EdDSA", "PS256", "PS384", "RS256"];

fn analyze_signature(path: &str, manifest: &TrustManifest, findings: &mut Vec<Finding>) {
    let Some(signature) = &manifest.signature else {
        return;
    };

    if !looks_like_detached_jws(signature) {
        findings.push(Finding {
            severity: Severity::Error,
            path: format!("{path}.signature"),
            message: "signature must use detached JWS compact serialization".to_owned(),
        });

        return;
    }

    if manifest.subject.is_none() {
        findings.push(Finding {
            severity: Severity::Error,
            path: format!("{path}.subject"),
            message: "a signed trust manifest must carry a subject binding it to the artifact"
                .to_owned(),
        });
    }

    if manifest.issued_at.is_none() {
        findings.push(Finding {
            severity: Severity::Error,
            path: format!("{path}.issuedAt"),
            message: "a signed trust manifest must carry an issuedAt timestamp".to_owned(),
        });
    }

    analyze_signature_algorithm(&format!("{path}.signature"), signature, findings);
}

fn analyze_signature_algorithm(path: &str, signature: &str, findings: &mut Vec<Finding>) {
    let Some(algorithm) = jws_algorithm(signature) else {
        findings.push(Finding {
            severity: Severity::Error,
            path: path.to_owned(),
            message: "signature JWS header must be base64url-encoded JSON declaring an 'alg'"
                .to_owned(),
        });

        return;
    };

    if is_forbidden_jws_algorithm(&algorithm) {
        findings.push(Finding {
            severity: Severity::Error,
            path: path.to_owned(),
            message: format!(
                "signature algorithm '{algorithm}' must be rejected; a trust manifest requires an \
                 asymmetric signature"
            ),
        });
    } else if !ALLOWED_JWS_ALGORITHMS.contains(&algorithm.as_str()) {
        findings.push(Finding {
            severity: Severity::Warning,
            path: path.to_owned(),
            message: format!(
                "signature algorithm '{algorithm}' is outside the specification allowlist ({})",
                ALLOWED_JWS_ALGORITHMS.join(", ")
            ),
        });
    }
}

fn is_forbidden_jws_algorithm(algorithm: &str) -> bool {
    let normalized = algorithm.to_ascii_uppercase();

    normalized == "NONE" || normalized.starts_with("HS")
}

fn jws_algorithm(signature: &str) -> Option<String> {
    let encoded = signature.split('.').next()?;
    let header = BASE64_URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let parsed: Value = serde_json::from_slice(&header).ok()?;

    match parsed.get("alg")?.as_str()? {
        "" => None,
        algorithm => Some(algorithm.to_owned()),
    }
}

fn analyze_subject(path: &str, subject: Option<&Subject>, findings: &mut Vec<Finding>) {
    let Some(subject) = subject else {
        return;
    };

    if subject.r#type.is_empty() {
        findings.push(Finding {
            severity: Severity::Error,
            path: format!("{path}.subject.type"),
            message: "subject type must not be empty".to_owned(),
        });
    }

    if subject.digest.is_empty() {
        findings.push(Finding {
            severity: Severity::Error,
            path: format!("{path}.subject.digest"),
            message: "subject digest must not be empty".to_owned(),
        });

        return;
    }

    analyze_digest_field(&subject.digest, &format!("{path}.subject.digest"), findings);
}

fn analyze_validity_window(path: &str, manifest: &TrustManifest, findings: &mut Vec<Finding>) {
    if let Some(issued_at) = &manifest.issued_at
        && OffsetDateTime::parse(issued_at, &Rfc3339).is_err()
    {
        findings.push(invalid_timestamp(&format!("{path}.issuedAt"), issued_at));
    }

    let Some(expires_at) = &manifest.expires_at else {
        return;
    };

    match OffsetDateTime::parse(expires_at, &Rfc3339) {
        Ok(parsed) => {
            if parsed < OffsetDateTime::now_utc() {
                findings.push(Finding {
                    severity: Severity::Warning,
                    path: format!("{path}.expiresAt"),
                    message: format!(
                        "trust manifest expired at {expires_at} and SHOULD be rejected"
                    ),
                });
            }
        }
        Err(_) => findings.push(invalid_timestamp(&format!("{path}.expiresAt"), expires_at)),
    }
}

fn invalid_timestamp(path: &str, value: &str) -> Finding {
    Finding {
        severity: Severity::Error,
        path: path.to_owned(),
        message: format!("'{value}' is not a valid RFC 3339 datetime"),
    }
}

fn analyze_digest_field(value: &str, path: &str, findings: &mut Vec<Finding>) {
    if let Err(error) = ParsedDigest::parse(value) {
        findings.push(Finding {
            severity: Severity::Error,
            path: path.to_owned(),
            message: error.to_string(),
        });
    }
}

fn looks_like_detached_jws(signature: &str) -> bool {
    let mut parts = signature.split('.');

    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(payload), Some(signature), None) => {
            !header.is_empty() && payload.is_empty() && !signature.is_empty()
        }
        _ => false,
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        use std::fmt::Write as _;

        let _ = write!(&mut hex, "{byte:02x}");
    }

    hex
}

#[cfg(test)]
mod tests {
    use ai_catalog::parse_str;

    use super::{
        CatalogTrustReport, Error, ParsedDigest, Severity, analyze_catalog, canonicalize_catalog,
        canonicalize_trust_manifest, verify_digest,
    };

    #[test]
    fn canonicalization_sorts_keys_by_utf16_code_unit() {
        let manifest = parse_str(&format!(
            r#"{{
              "specVersion": "1.0",
              "entries": [
                {{
                  "identifier": "urn:example:keys",
                  "type": "application/json",
                  "url": "https://example.com/a.json",
                  "trustManifest": {{
                    "identity": "urn:example:keys",
                    "extensions": {{ "{bmp}": 1, "{non_bmp}": 2 }}
                  }}
                }}
              ]
            }}"#,
            bmp = '\u{e000}',
            non_bmp = '\u{10000}'
        ))
        .expect("document should parse");

        let canonical = canonicalize_trust_manifest(
            manifest.entries[0]
                .trust_manifest
                .as_ref()
                .expect("manifest should exist"),
        )
        .expect("manifest should canonicalize");

        let non_bmp = canonical.find('\u{10000}').expect("non-BMP key is present");
        let bmp = canonical.find('\u{e000}').expect("BMP key is present");

        assert!(
            non_bmp < bmp,
            "non-BMP key must sort first, got: {canonical}"
        );
    }

    #[test]
    fn canonicalization_uses_ecmascript_number_formatting() {
        let manifest = parse_str(
            r#"{
              "specVersion": "1.0",
              "entries": [
                {
                  "identifier": "urn:example:numbers",
                  "type": "application/json",
                  "url": "https://example.com/a.json",
                  "trustManifest": {
                    "identity": "urn:example:numbers",
                    "extensions": { "com.example.big": 1e21 }
                  }
                }
              ]
            }"#,
        )
        .expect("document should parse");

        let canonical = canonicalize_trust_manifest(
            manifest.entries[0]
                .trust_manifest
                .as_ref()
                .expect("manifest should exist"),
        )
        .expect("manifest should canonicalize");

        assert!(
            canonical.contains("1e+21"),
            "expected ECMAScript number form, got: {canonical}"
        );
    }

    #[test]
    fn rejects_signatures_that_cannot_establish_third_party_trust() {
        for (algorithm, signature) in [
            ("none", "eyJhbGciOiJub25lIn0..c2ln"),
            ("HS256", "eyJhbGciOiJIUzI1NiJ9..c2ln"),
        ] {
            let report = analyze(&format!(
                r#"{{
                  "specVersion": "1.0",
                  "entries": [
                    {{
                      "identifier": "urn:example:weak",
                      "type": "application/json",
                      "url": "https://example.com/a.json",
                      "trustManifest": {{
                        "identity": "urn:example:weak",
                        "issuedAt": "2026-01-01T00:00:00Z",
                        "signature": "{signature}",
                        "subject": {{
                          "type": "application/json",
                          "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                        }}
                      }}
                    }}
                  ]
                }}"#
            ));

            assert!(
                report.findings.iter().any(|finding| {
                    finding.severity == Severity::Error
                        && finding.message.contains("must be rejected")
                }),
                "expected {algorithm} to be rejected"
            );
        }
    }

    #[test]
    fn analyzes_manifests_inside_nested_catalogs() {
        let manifest = r#"{
            "identity": "did:web:acme.com",
            "signature": "eyJhbGciOiJub25lIn0..c2ln",
            "issuedAt": "2026-01-01T00:00:00Z",
            "subject": {"type": "application/parquet", "digest": "md5:abc", "url": "https://acme.com/d.parquet"}
        }"#;
        let report = analyze(&format!(
            r#"{{"specVersion":"1.0","entries":[
                {{"identifier":"urn:air:acme.com:catalog:c","type":"application/ai-catalog+json","data":{{
                    "specVersion":"1.0","entries":[
                        {{"identifier":"urn:air:acme.com:data:d","type":"application/parquet","url":"https://acme.com/d.parquet","trustManifest":{manifest}}}
                    ]}}}}
            ]}}"#
        ));

        assert!(
            report.findings.iter().any(|finding| {
                finding.severity == Severity::Error && finding.message.contains("'none'")
            }),
            "nested forbidden algorithm went unreported: {:?}",
            report.findings
        );
        assert!(
            report.findings.iter().any(|finding| {
                finding.severity == Severity::Error
                    && finding.message.contains("weaker than SHA-256")
            }),
            "nested weak digest went unreported: {:?}",
            report.findings
        );
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.path == "catalog.entries[0].data.entries[0].trustManifest"),
            "nested manifest missing from the report: {:?}",
            report.entries.iter().map(|e| &e.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn stops_descending_at_the_recommended_depth_limit() {
        let mut document = r#"{"specVersion":"1.0","entries":[{"identifier":"urn:air:acme.com:data:d","type":"application/parquet","url":"https://acme.com/d.parquet","trustManifest":{"identity":"did:web:acme.com","signature":"eyJhbGciOiJub25lIn0..c2ln","issuedAt":"2026-01-01T00:00:00Z","subject":{"type":"application/parquet","digest":"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","url":"https://acme.com/d.parquet"}}}]}"#.to_owned();

        for _ in 0..5 {
            document = format!(
                r#"{{"specVersion":"1.0","entries":[{{"identifier":"urn:air:acme.com:catalog:c","type":"application/ai-catalog+json","data":{document}}}]}}"#
            );
        }

        let report = analyze(&document);

        assert!(
            report.findings.is_empty(),
            "recursion passed the depth limit: {:?}",
            report.findings
        );
    }

    #[test]
    fn analyzes_the_catalog_level_signature() {
        let report = analyze(
            r#"{
              "specVersion": "1.0",
              "entries": [],
              "signature": "eyJhbGciOiJIUzI1NiJ9..c2ln"
            }"#,
        );

        assert!(report.has_signature);
        assert!(
            report.findings.iter().any(|finding| {
                finding.severity == Severity::Error && finding.path == "catalog.signature"
            }),
            "catalog signature not analyzed: {:?}",
            report.findings
        );
    }

    #[test]
    fn canonicalizes_catalog_without_signature() {
        let catalog = parse_str(
            r#"{"specVersion":"1.0","entries":[],"signature":"eyJhbGciOiJFUzI1NiJ9..c2ln"}"#,
        )
        .expect("document should parse");

        let canonical = canonicalize_catalog(&catalog).expect("canonicalizes");

        assert!(!canonical.contains("signature"));
        assert_eq!(canonical, r#"{"entries":[],"specVersion":"1.0"}"#);
    }

    #[test]
    fn reports_malformed_and_expired_manifest_timestamps() {
        let report = analyze(
            r#"{
              "specVersion": "1.0",
              "entries": [
                {
                  "identifier": "urn:example:bad-issued",
                  "type": "application/json",
                  "url": "https://example.com/a.json",
                  "trustManifest": {
                    "identity": "urn:example:bad-issued",
                    "issuedAt": "not-a-date",
                    "expiresAt": "2020-01-01T00:00:00Z"
                  }
                }
              ]
            }"#,
        );

        assert!(report.findings.iter().any(|finding| {
            finding.severity == Severity::Error
                && finding.message.contains("not a valid RFC 3339 datetime")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.severity == Severity::Warning && finding.message.contains("expired at")
        }));
    }

    #[test]
    fn compares_timestamps_as_instants_not_strings() {
        let report = analyze(
            r#"{
              "specVersion": "1.0",
              "entries": [
                {
                  "identifier": "urn:example:offset",
                  "type": "application/json",
                  "url": "https://example.com/a.json",
                  "trustManifest": {
                    "identity": "urn:example:offset",
                    "issuedAt": "2030-01-01T12:00:00Z",
                    "expiresAt": "2030-01-01T02:00:00-11:00"
                  }
                }
              ]
            }"#,
        );

        assert!(
            report.findings.is_empty(),
            "unexpected findings: {:?}",
            report.findings
        );
    }

    #[test]
    fn warns_on_algorithms_outside_the_allowlist() {
        let report = analyze(
            r#"{
              "specVersion": "1.0",
              "entries": [
                {
                  "identifier": "urn:example:odd",
                  "type": "application/json",
                  "url": "https://example.com/a.json",
                  "trustManifest": {
                    "identity": "urn:example:odd",
                    "issuedAt": "2026-01-01T00:00:00Z",
                    "signature": "eyJhbGciOiJSUzUxMiJ9..c2ln",
                    "subject": {
                      "type": "application/json",
                      "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                    }
                  }
                }
              ]
            }"#,
        );

        assert!(report.findings.iter().any(|finding| {
            finding.severity == Severity::Warning
                && finding
                    .message
                    .contains("outside the specification allowlist")
        }));
    }

    #[test]
    fn flags_a_signed_manifest_missing_its_subject_and_issued_at() {
        let report = analyze(
            r#"{
              "specVersion": "1.0",
              "entries": [
                {
                  "identifier": "urn:example:bare",
                  "type": "application/json",
                  "url": "https://example.com/a.json",
                  "trustManifest": {
                    "identity": "urn:example:bare",
                    "signature": "eyJhbGciOiJFUzI1NiJ9..c2ln"
                  }
                }
              ]
            }"#,
        );

        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.message.contains("must carry a subject") })
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.message.contains("must carry an issuedAt") })
        );
    }

    #[test]
    fn parses_and_verifies_supported_digests() {
        let digest = ParsedDigest::parse(
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        )
        .expect("digest should parse");

        assert_eq!(digest.algorithm(), "sha256");
        assert!(digest.verify_bytes(b"test"));
        assert!(
            verify_digest(
                &digest.hex_value().prepend_with_algorithm("sha256"),
                b"test"
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_weak_and_malformed_digests() {
        assert!(matches!(
            ParsedDigest::parse("md5:abcd"),
            Err(Error::WeakDigestAlgorithm(_))
        ));
        assert!(matches!(
            ParsedDigest::parse("sha256:not-hex"),
            Err(Error::InvalidDigestHex)
        ));
        assert!(matches!(
            ParsedDigest::parse("missing-colon"),
            Err(Error::InvalidDigestFormat(_))
        ));
    }

    #[test]
    fn rejects_hex_values_of_the_wrong_length() {
        assert!(matches!(
            ParsedDigest::parse("sha256:abc"),
            Err(Error::InvalidDigestHex)
        ));
        assert!(matches!(
            ParsedDigest::parse(
                "sha512:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            ),
            Err(Error::InvalidDigestHex)
        ));
        assert!(matches!(
            ParsedDigest::parse(&"z".repeat(64).prepend_with_algorithm("sha256")),
            Err(Error::InvalidDigestHex)
        ));
    }

    #[test]
    fn canonicalizes_manifest_without_signature() {
        let catalog = parse_catalog(
            r#"{
			  "specVersion": "1.0",
			  "entries": [
				{
				  "identifier": "urn:example:agent",
				  "displayName": "Example Agent",
				  "type": "application/json",
				  "url": "https://example.com/agent.json",
				  "trustManifest": {
					"identity": "urn:example:agent",
					"signature": "eyJhbGciOiJFUzI1NiJ9..c2ln",
					"extensions": {
					  "com.example.zeta": true,
					  "com.example.alpha": 1
					}
				  }
				}
			  ]
			}"#,
        );

        let manifest = catalog.entries[0]
            .trust_manifest
            .as_ref()
            .expect("entry trust manifest should exist");
        let canonical =
            canonicalize_trust_manifest(manifest).expect("canonicalization should work");

        assert!(!canonical.contains("signature"));
        assert!(canonical.contains("\"com.example.alpha\":1"));
        assert!(canonical.find("alpha").expect("alpha") < canonical.find("zeta").expect("zeta"));
    }

    #[test]
    fn analyzes_catalog_trust_findings() {
        let report = analyze_catalog(&parse_catalog(
            r#"{
			  "specVersion": "1.0",
			  "host": {
				"displayName": "Example Host",
				"identifier": "did:web:example.com",
				"trustManifest": {
				  "identity": "did:web:other.example.com",
				  "signature": "not-a-detached-jws"
				}
			  },
			  "entries": [
				{
				  "identifier": "urn:air:acme.com:agent:artifact",
				  "displayName": "Artifact",
				  "type": "application/json",
				  "url": "https://example.com/artifact.json",
				  "trustManifest": {
					"identity": "did:web:evil.example",
					"signature": "header.payload.signature",
					"trustSchema": {
					  "identifier": "",
					  "version": ""
					},
					"attestations": [
					  {
						"type": "",
						"uri": "",
						"digest": "md5:abcd"
					  }
					],
					"provenance": [
					  {
						"relation": "",
						"sourceId": "",
						"sourceDigest": "sha256:not-hex"
					  }
					]
				  }
				}
			  ]
			}"#,
        ));

        assert_eq!(report.entries.len(), 1);
        assert_eq!(
            report.host.as_ref().map(|host| host.findings.len()),
            Some(2)
        );
        assert!(contains_finding(
            &report,
            Severity::Warning,
            "host trustManifest.identity 'did:web:other.example.com' SHOULD match host.identifier 'did:web:example.com'"
        ));
        assert!(contains_finding(
            &report,
            Severity::Error,
            "signature must use detached JWS compact serialization"
        ));
        assert!(contains_finding(
            &report,
            Severity::Error,
            "trustManifest.identity domain 'evil.example' MUST align with entry identifier publisher domain 'acme.com'"
        ));
        assert!(contains_finding(
            &report,
            Severity::Error,
            "digest algorithm 'md5' is weaker than SHA-256"
        ));
        assert!(contains_finding(
            &report,
            Severity::Error,
            "digest hex value contains non-hex characters"
        ));
    }

    #[test]
    fn non_uri_identity_warns_without_binding_error() {
        let report = analyze_catalog(&parse_catalog(
            r#"{
			  "specVersion": "1.0",
			  "entries": [
				{
				  "identifier": "urn:example:artifact",
				  "displayName": "Artifact",
				  "type": "application/json",
				  "url": "https://example.com/artifact.json",
				  "trustManifest": {
					"identity": "plain-identifier"
				  }
				}
			  ]
			}"#,
        ));

        assert!(contains_finding(
            &report,
            Severity::Warning,
            "trust manifest identity SHOULD be a URI-like identifier"
        ));
        assert!(!contains_finding(
            &report,
            Severity::Error,
            "MUST align with entry identifier publisher domain"
        ));
    }

    #[test]
    fn identity_without_trust_domain_fails_binding() {
        let report = analyze_catalog(&parse_catalog(
            r#"{
			  "specVersion": "1.0",
			  "entries": [
				{
				  "identifier": "urn:air:acme.com:agent:artifact",
				  "displayName": "Artifact",
				  "type": "application/json",
				  "url": "https://acme.com/artifact.json",
				  "trustManifest": {
					"identity": "urn:acme:agent:artifact"
				  }
				}
			  ]
			}"#,
        ));

        assert!(contains_finding(
            &report,
            Severity::Error,
            "MUST carry a trust domain aligned with entry identifier publisher domain 'acme.com'"
        ));
    }

    #[test]
    fn identity_binding_accepts_aligned_domains() {
        let report = analyze_catalog(&parse_catalog(
            r#"{
			  "specVersion": "1.0",
			  "entries": [
				{
				  "identifier": "urn:air:acme.com:agent:artifact",
				  "displayName": "Artifact",
				  "type": "application/json",
				  "url": "https://acme.com/artifact.json",
				  "trustManifest": {
					"identity": "did:web:acme.com"
				  }
				}
			  ]
			}"#,
        ));

        assert!(report.findings.is_empty());
    }

    #[test]
    fn clean_catalog_produces_no_findings() {
        let report = analyze_catalog(&parse_catalog(
            r#"{
			  "specVersion": "1.0",
			  "host": {
				"displayName": "Example Host",
				"identifier": "did:web:example.com",
				"trustManifest": {
				  "identity": "did:web:example.com",
				  "issuedAt": "2026-01-01T00:00:00Z",
				  "signature": "eyJhbGciOiJFUzI1NiJ9..c2ln",
				  "subject": {
					"type": "application/ai-catalog+json",
					"digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
				  }
				}
			  },
			  "entries": [
				{
				  "identifier": "urn:example:artifact",
				  "displayName": "Artifact",
				  "type": "application/json",
				  "url": "https://example.com/artifact.json",
				  "trustManifest": {
					"identity": "urn:example:artifact",
					"issuedAt": "2026-01-01T00:00:00Z",
					"signature": "eyJhbGciOiJFUzI1NiJ9..c2ln",
					"subject": {
					  "type": "application/json",
					  "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
					  "url": "https://example.com/artifact.json"
					},
					"trustSchema": {
					  "identifier": "urn:trust:example",
					  "version": "1.0"
					},
					"attestations": [
					  {
						"type": "publisher-identity",
						"uri": "https://example.com/publisher.jwt",
						"digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
					  }
					],
					"provenance": [
					  {
						"relation": "publishedFrom",
						"sourceId": "https://github.com/example/repo",
						"sourceDigest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
					  }
					]
				  }
				}
			  ]
			}"#,
        ));

        assert!(report.findings.is_empty());
        assert_eq!(
            report.host.as_ref().map(|host| host.has_signature),
            Some(true)
        );
        assert_eq!(report.entries[0].attestation_count, 1);
    }

    fn parse_catalog(document: &str) -> ai_catalog::AiCatalog {
        parse_str(document).expect("catalog should parse")
    }

    fn analyze(document: &str) -> CatalogTrustReport {
        analyze_catalog(&parse_catalog(document))
    }

    fn contains_finding(report: &CatalogTrustReport, severity: Severity, message: &str) -> bool {
        report
            .findings
            .iter()
            .any(|finding| finding.severity == severity && finding.message.contains(message))
    }

    trait DigestStringExt {
        fn prepend_with_algorithm(&self, algorithm: &str) -> String;
    }

    impl DigestStringExt for str {
        fn prepend_with_algorithm(&self, algorithm: &str) -> String {
            format!("{algorithm}:{}", self)
        }
    }
}
