// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::time::SystemTime;

use ai_catalog_trust::canonicalize_value_for_signature;
use ai_catalog_validate::{ConformanceLevel, Options, Outcome, Verification, verify};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const ID: &str = "urn:air:acme.com:agent:billing";
const TYPE: &str = "application/a2a-agent-card+json";
const ARTIFACT: &[u8] = br#"{"name":"billing"}"#;
const NOW: &str = "2026-10-01T00:00:00Z";

fn clock(time: &str) -> SystemTime {
    OffsetDateTime::parse(time, &Rfc3339).unwrap().into()
}

fn digest(bytes: &[u8]) -> String {
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    format!("sha256:{hex}")
}

struct Party {
    did: String,
    key: SigningKey,
}

impl Party {
    fn new(domain: &str, seed: u8) -> Self {
        Self {
            did: format!("did:web:{domain}"),
            key: SigningKey::from_slice(&[seed; 32]).unwrap(),
        }
    }

    fn kid(&self) -> String {
        format!("{}#key-1", self.did)
    }

    fn did_document(&self) -> Value {
        let point = self.key.verifying_key().to_sec1_point(false);

        json!({
            "id": self.did,
            "verificationMethod": [{
                "id": self.kid(),
                "controller": self.did,
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                }
            }],
            "assertionMethod": [self.kid()],
        })
    }

    fn sign(&self, mut object: Value, typ: &str) -> Value {
        object["signature"] = json!({
            "signer": self.did,
            "profile": "did-web-v1",
            "issuedAt": "2026-09-12T10:00:00Z",
            "expiresAt": "2026-12-01T00:00:00Z",
        });

        let payload = canonicalize_value_for_signature(&object).unwrap();
        let header = URL_SAFE_NO_PAD
            .encode(json!({"alg": "ES256", "kid": self.kid(), "typ": typ}).to_string());
        let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(payload));
        let signature: Signature = self.key.sign(input.as_bytes());

        object["signature"]["jws"] = json!(format!(
            "{header}..{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ));
        object
    }

    fn endorse(&self) -> Value {
        self.sign(
            json!({
                "contributor": self.did,
                "subject": {"identifier": ID, "type": TYPE, "digest": digest(ARTIFACT)},
            }),
            "ai-catalog-trust-manifest+jws",
        )
    }
}

struct Site(HashMap<String, Vec<u8>>);

impl Site {
    fn new(parties: &[&Party]) -> Self {
        let mut documents = HashMap::from([(
            "https://acme.com/billing.json".to_owned(),
            ARTIFACT.to_vec(),
        )]);

        for party in parties {
            documents.insert(
                format!(
                    "https://{}/.well-known/did.json",
                    party.did.trim_start_matches("did:web:")
                ),
                party.did_document().to_string().into_bytes(),
            );
        }

        Self(documents)
    }
}

fn catalog(manifests: Vec<Value>) -> Value {
    json!({
        "specVersion": "1.0",
        "host": {"displayName": "Acme"},
        "entries": [{
            "identifier": ID,
            "type": TYPE,
            "url": "https://acme.com/billing.json",
            "digest": digest(ARTIFACT),
            "trustManifests": manifests,
        }],
    })
}

fn run(catalog: &Value, site: &Site, options: &Options) -> Verification {
    verify(catalog.to_string().as_bytes(), options, &|url: &str| {
        site.0
            .get(url)
            .cloned()
            .ok_or_else(|| "not found".to_owned())
    })
    .unwrap()
}

fn options() -> Options {
    Options::default().with_clock(clock(NOW))
}

#[test]
fn a_verified_publisher_endorsement_makes_the_catalog_trusted() {
    let acme = Party::new("acme.com", 1);
    let result = run(
        &catalog(vec![acme.endorse()]),
        &Site::new(&[&acme]),
        &options(),
    );

    let entry = &result.entries[0];

    assert_eq!(entry.manifests[0].signature, Some(Outcome::Verified));
    assert_eq!(entry.manifests[0].release, Some(Outcome::Verified));
    assert_eq!(entry.artifact, Some(Outcome::Verified));
    assert!(entry.publisher_endorsed);
    assert_eq!(result.conformance_level, ConformanceLevel::Trusted);
}

#[test]
fn anything_unverified_keeps_the_catalog_from_being_trusted() {
    type Change = fn(&mut Value, &mut Site, &mut Options);

    let cases: [(&str, Change, bool); 5] = [
        (
            "manifest changed after signing",
            |catalog, _, _| {
                catalog["entries"][0]["trustManifests"][0]["trustSchema"] =
                    json!({"identifier": "https://example.com/schema", "version": "1"});
            },
            true,
        ),
        (
            "artifact changed",
            |_, site, _| {
                site.0
                    .insert("https://acme.com/billing.json".to_owned(), b"{}".to_vec());
            },
            true,
        ),
        (
            "another key in the DID document",
            |_, site, _| {
                let other = Party::new("acme.com", 2);
                site.0.insert(
                    "https://acme.com/.well-known/did.json".to_owned(),
                    other.did_document().to_string().into_bytes(),
                );
            },
            true,
        ),
        (
            "signature expired",
            |_, _, options| *options = Options::default().with_clock(clock("2027-01-01T00:00:00Z")),
            true,
        ),
        (
            "DID document unreachable",
            |_, site, _| {
                site.0.remove("https://acme.com/.well-known/did.json");
            },
            false,
        ),
    ];

    for (name, change, publisher_failed) in cases {
        let acme = Party::new("acme.com", 1);
        let mut document = catalog(vec![acme.endorse()]);
        let mut site = Site::new(&[&acme]);
        let mut options = options();

        change(&mut document, &mut site, &mut options);

        let result = run(&document, &site, &options);
        let entry = &result.entries[0];

        assert_eq!(
            result.conformance_level,
            ConformanceLevel::Discoverable,
            "{name}"
        );
        assert!(!entry.publisher_endorsed, "{name}");
        assert_eq!(entry.publisher_failed, publisher_failed, "{name}");
    }
}

#[test]
fn an_assessor_endorses_the_release_without_being_the_publisher() {
    let assessor = Party::new("assessor.example", 3);
    let site = Site::new(&[&assessor]);
    let result = run(&catalog(vec![assessor.endorse()]), &site, &options());

    let entry = &result.entries[0];

    assert!(entry.manifests[0].signature.as_ref().unwrap().is_verified());
    assert_eq!(entry.artifact, Some(Outcome::Verified));
    assert!(!entry.publisher_endorsed);
    assert_eq!(result.conformance_level, ConformanceLevel::Discoverable);
}

#[test]
fn the_catalog_signature_covers_the_whole_document() {
    let acme = Party::new("acme.com", 1);
    let site = Site::new(&[&acme]);
    let signed = acme.sign(catalog(vec![acme.endorse()]), "ai-catalog+jws");

    let result = run(&signed, &site, &options());
    assert_eq!(result.catalog_signature, Some(Outcome::Verified));
    assert!(!result.catalog_authorized);

    let operators = options().with_authorized_operators(["did:web:acme.com"]);
    assert!(run(&signed, &site, &operators).catalog_authorized);

    let mut changed = signed;
    changed["host"]["displayName"] = json!("Evil");
    let result = run(&changed, &site, &operators);
    assert!(result.catalog_signature.as_ref().unwrap().is_failed());
    assert!(!result.catalog_authorized);
}
