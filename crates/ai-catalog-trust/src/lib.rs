// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use ai_catalog::{
    AiCatalog, CatalogEntry, HostInfo, TrustManifest, identity_binds_to_entry, identity_domain,
    publisher_domain,
};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use thiserror::Error;

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

    serde_json::to_string(&sort_value(value)).map_err(Error::from)
}

pub fn verify_digest(expected_digest: &str, bytes: &[u8]) -> Result<bool> {
    Ok(ParsedDigest::parse(expected_digest)?.verify_bytes(bytes))
}

pub fn analyze_catalog(catalog: &AiCatalog) -> CatalogTrustReport {
    let host = catalog.host.as_ref().and_then(analyze_host_manifest);
    let entries = catalog
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| analyze_entry_manifest(entry, index))
        .collect::<Vec<_>>();

    let findings = host
        .iter()
        .flat_map(|report| report.findings.iter().cloned())
        .chain(
            entries
                .iter()
                .flat_map(|report| report.findings.iter().cloned()),
        )
        .collect();

    CatalogTrustReport {
        findings,
        host,
        entries,
    }
}

fn analyze_host_manifest(host: &HostInfo) -> Option<ManifestReport> {
    let manifest = host.trust_manifest.as_ref()?;
    let mut findings = Vec::new();
    let path = "catalog.host.trustManifest".to_owned();

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

fn analyze_entry_manifest(entry: &CatalogEntry, index: usize) -> Option<ManifestReport> {
    let manifest = entry.trust_manifest.as_ref()?;
    let path = format!("catalog.entries[{index}].trustManifest");
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
    if let Some(signature) = &manifest.signature
        && !looks_like_detached_jws(signature)
    {
        findings.push(Finding {
            severity: Severity::Error,
            path: format!("{path}.signature"),
            message: "signature must use detached JWS compact serialization".to_owned(),
        });
    }

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

fn sort_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_value).collect()),
        Value::Object(object) => {
            let mut sorted = object.into_iter().collect::<Vec<_>>();
            sorted.sort_by(|left, right| left.0.cmp(&right.0));

            let mut map = Map::new();
            for (key, value) in sorted {
                map.insert(key, sort_value(value));
            }

            Value::Object(map)
        }
        other => other,
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
        CatalogTrustReport, Error, ParsedDigest, Severity, analyze_catalog,
        canonicalize_trust_manifest, verify_digest,
    };

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
					"signature": "header..signature",
					"metadata": {
					  "zeta": true,
					  "alpha": 1
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
        assert!(canonical.contains("\"alpha\":1"));
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
				  "signature": "header..signature"
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
					"signature": "header..signature",
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
