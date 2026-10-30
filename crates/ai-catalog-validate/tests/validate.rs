// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, SystemTime};

use ai_catalog::{AiCatalog, parse_str};
use ai_catalog_validate::{
    Code, ConformanceLevel, Diagnostic, Options, ValidationResult, validate, validate_with,
};

fn parse(name: &str) -> AiCatalog {
    let path = format!("{}/../../fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let json = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));

    parse_str(&json).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn entry(index: usize, member: &str) -> String {
    format!("catalog.entries[{index}]{member}")
}

fn manifest(index: usize, member: &str) -> String {
    entry(index, &format!(".trustManifests[0]{member}"))
}

fn compare(kind: &str, got: &[Diagnostic], want: &[(Code, String)]) {
    for diagnostic in got {
        assert!(
            !diagnostic.message.is_empty(),
            "{kind} {} at {} has no message",
            diagnostic.code,
            diagnostic.path
        );
    }

    let mut found: Vec<_> = got.iter().map(|d| (d.code, d.path.clone())).collect();
    let mut want = want.to_vec();

    found.sort();
    want.sort();

    assert_eq!(found, want, "{kind}s");
}

fn at(code: Code, path: impl Into<String>) -> (Code, String) {
    (code, path.into())
}

fn at_time(unix_seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(unix_seconds)
}

#[test]
fn detects_conformance_levels() {
    let cases = [
        ("minimal.json", true, ConformanceLevel::Minimal),
        ("discoverable.json", true, ConformanceLevel::Discoverable),
        ("unsigned_trust.json", true, ConformanceLevel::Discoverable),
        ("trust_clean.json", true, ConformanceLevel::Trusted),
        ("catalog.json", true, ConformanceLevel::Trusted),
        ("weak_signature.json", false, ConformanceLevel::Minimal),
    ];

    for (fixture, valid, level) in cases {
        let result = validate(&parse(fixture));

        assert_eq!(
            (result.is_valid, result.conformance_level),
            (valid, level),
            "{fixture}: {:?}",
            result.errors
        );
    }
}

#[test]
fn reports_rule_violations() {
    let result = validate(&parse("invalid.json"));

    let errors = [
        at(Code::HostMember, "catalog.host.displayName"),
        at(Code::SignatureForm, "catalog.signature.jws"),
        at(Code::ExtensionKey, "catalog.extensions"),
        at(Code::EntryArtifact, entry(0, "")),
        at(Code::EntryArtifact, entry(1, "")),
        at(Code::EntryDuplicate, entry(3, "")),
        at(Code::EntryDuplicate, entry(5, "")),
        at(Code::EntryVersion, entry(7, ".identifier")),
        at(Code::ManifestEmpty, manifest(8, "")),
        at(Code::EntryMember, entry(9, ".identifier")),
        at(Code::EntryMember, entry(9, ".type")),
        at(Code::PublisherMember, entry(9, ".publisher.identifier")),
        at(Code::PublisherMember, entry(9, ".publisher.displayName")),
        at(Code::ManifestContributor, manifest(9, ".contributor")),
        at(Code::ManifestEmpty, manifest(9, "")),
        at(Code::Timestamp, entry(10, ".updatedAt")),
        at(Code::ExtensionKey, entry(11, ".extensions")),
        at(Code::ExtensionKey, manifest(11, ".extensions")),
        at(Code::ManifestEmpty, manifest(12, "")),
        at(Code::ManifestSignedMember, manifest(13, ".subject")),
        at(Code::SignatureMember, manifest(13, ".signature.issuedAt")),
        at(Code::EntryDigest, entry(13, ".digest")),
        at(Code::Timestamp, manifest(14, ".signature.issuedAt")),
        at(Code::SubjectMismatch, manifest(15, ".subject.identifier")),
        at(Code::SubjectMismatch, manifest(15, ".subject.version")),
        at(Code::SubjectMismatch, manifest(15, ".subject.type")),
        at(Code::SubjectMismatch, manifest(15, ".subject.digest")),
        at(Code::NestedInvalid, entry(16, ".data")),
        at(Code::ManifestSigner, manifest(17, ".signature.signer")),
        at(Code::SignatureType, manifest(18, ".signature.jws")),
        at(Code::SignatureType, manifest(19, ".signature.jws")),
        at(Code::SignatureSigner, manifest(20, ".signature.signer")),
        at(Code::ManifestSigner, manifest(20, ".signature.signer")),
        at(Code::ManifestContributorUri, manifest(21, ".contributor")),
        at(Code::SignatureMember, manifest(22, ".signature.profile")),
        at(Code::SignatureMember, manifest(22, ".signature.jws")),
    ];

    let warnings = [
        at(Code::IdentifierNotUri, entry(10, ".identifier")),
        at(Code::ProfileSigner, manifest(13, ".signature.signer")),
        at(Code::ProfileKeyId, manifest(13, ".signature.jws")),
        at(Code::SignatureExpired, manifest(14, ".signature.expiresAt")),
        at(Code::ProfileSigner, manifest(15, ".signature.signer")),
        at(Code::ProfileKeyId, manifest(15, ".signature.jws")),
        at(Code::ProfileSigner, manifest(20, ".signature.signer")),
    ];

    compare("error", &result.errors, &errors);
    compare("warning", &result.warnings, &warnings);
}

#[test]
fn rejects_none_signatures_and_weak_digests() {
    let result = validate(&parse("weak_signature.json"));

    let errors = [
        at(Code::DigestInvalid, entry(1, ".digest")),
        at(Code::SignatureAlgorithm, manifest(1, ".signature.jws")),
        at(Code::DigestInvalid, manifest(1, ".subject.digest")),
        at(Code::SignatureAlgorithm, manifest(2, ".signature.jws")),
        at(Code::SignatureMalformed, manifest(3, ".signature.jws")),
        at(Code::DigestInvalid, manifest(4, ".attestations[0].digest")),
        at(
            Code::DigestInvalid,
            manifest(4, ".provenance[0].sourceDigest"),
        ),
    ];

    compare("error", &result.errors, &errors);
}

#[test]
fn applies_the_did_web_signer_profile() {
    let result = validate(&parse("profile.json"));

    let warnings = [
        at(Code::ProfileSigner, manifest(3, ".signature.signer")),
        at(Code::ProfileAlgorithm, manifest(5, ".signature.jws")),
        at(Code::ProfileKeyId, manifest(6, ".signature.jws")),
        at(Code::ProfileKeyId, manifest(7, ".signature.jws")),
        at(Code::ProfileKeyId, manifest(8, ".signature.jws")),
        at(Code::ProfileHeader, manifest(9, ".signature.jws")),
        at(Code::ProfileSigner, manifest(10, ".signature.signer")),
        at(Code::ProfileSigner, manifest(15, ".signature.signer")),
    ];

    let errors = [
        at(Code::SignatureB64, manifest(11, ".signature.jws")),
        at(Code::SignatureMalformed, manifest(12, ".signature.jws")),
        at(Code::SignatureForm, manifest(13, ".signature.jws")),
    ];

    compare("warning", &result.warnings, &warnings);
    compare("error", &result.errors, &errors);
}

#[test]
fn only_the_publisher_makes_a_catalog_trusted() {
    let catalog = parse("profile.json");

    for index in 0..catalog.entries.len() {
        let alone = AiCatalog {
            entries: vec![catalog.entries[index].clone()],
            ..catalog.clone()
        };
        let trusted = validate(&alone).conformance_level == ConformanceLevel::Trusted;

        assert_eq!(trusted, index == 0, "entry {index}");
    }
}

#[test]
fn an_assessor_alone_does_not_make_a_catalog_trusted() {
    let mut catalog = parse("trust_clean.json");
    let trust = &mut catalog.entries[0].trust_manifests[0];

    trust.contributor = "did:web:assessor.example".to_owned();
    trust.signature.as_mut().expect("fixture is signed").signer =
        "did:web:assessor.example".to_owned();

    let result = validate(&catalog);

    assert!(result.is_valid, "{:?}", result.errors);
    assert_eq!(result.conformance_level, ConformanceLevel::Discoverable);
}

#[test]
fn another_contributor_does_not_hold_back_the_publisher() {
    let mut catalog = parse("trust_clean.json");
    let mut assessor = catalog.entries[0].trust_manifests[0].clone();

    assessor.contributor = "did:web:assessor.example".to_owned();
    assessor.signature = None;
    catalog.entries[0].trust_manifests.push(assessor);

    let result = validate(&catalog);

    assert!(result.is_valid, "{:?}", result.errors);
    assert_eq!(result.conformance_level, ConformanceLevel::Trusted);
}

#[test]
fn expiry_follows_the_clock() {
    let mut catalog = parse("trust_clean.json");
    let signature = catalog.entries[0].trust_manifests[0]
        .signature
        .as_mut()
        .expect("fixture is signed");

    signature.expires_at = Some("2026-06-01T00:00:00Z".to_owned());

    let judge = |now: SystemTime| -> ValidationResult {
        validate_with(&catalog, &Options::default().with_clock(now))
    };

    let before = judge(at_time(1_780_185_600));

    assert_eq!(before.conformance_level, ConformanceLevel::Trusted);
    assert!(before.warnings.is_empty(), "{:?}", before.warnings);

    let after = judge(at_time(1_780_358_400));

    assert!(after.is_valid);
    assert_eq!(after.conformance_level, ConformanceLevel::Discoverable);
    compare(
        "warning",
        &after.warnings,
        &[at(
            Code::SignatureExpired,
            manifest(0, ".signature.expiresAt"),
        )],
    );
}

#[test]
fn limits_nesting_depth() {
    let cases = [
        ("nested_max.json", Options::default(), true),
        ("nested_deep.json", Options::default(), false),
        (
            "nested_max.json",
            Options::default().with_max_nesting_depth(1),
            false,
        ),
    ];

    for (fixture, options, valid) in cases {
        let result = validate_with(&parse(fixture), &options);

        assert_eq!(result.is_valid, valid, "{fixture}: {:?}", result.errors);
        assert_eq!(
            result.errors.iter().any(|d| d.code == Code::NestedDepth),
            !valid,
            "{fixture}"
        );
    }
}

#[test]
fn checks_the_spec_version() {
    let cases = [
        ("1.0", true),
        ("1.7", true),
        ("", false),
        ("1", false),
        ("one.zero", false),
        ("-1.0", false),
        ("2.0", false),
    ];

    for (version, valid) in cases {
        let catalog = AiCatalog {
            spec_version: version.to_owned(),
            ..parse("minimal.json")
        };

        assert_eq!(
            validate(&catalog).is_valid,
            valid,
            "specVersion {version:?}"
        );
    }
}
