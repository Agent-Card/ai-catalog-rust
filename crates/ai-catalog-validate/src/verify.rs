// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// SPDX-License-Identifier: Apache-2.0

//! Signature and artifact verification under the did:web profiles.

use ai_catalog::{CatalogEntry, Signature, TrustManifest};
use ai_catalog_trust::{P256Key, canonicalize_value_for_signature, verify_digest, verify_es256};
use serde_json::Value;
use time::OffsetDateTime;
use url::Url;

use crate::manifest::subject_mismatches;
use crate::profile::DID_WEB_PROFILE;
use crate::signature::{Kind, instant};
use crate::{ConformanceLevel, Options, ValidationResult, did, identity, jws, validate_with};

const PROFILE_ALGORITHM: &str = "ES256";
const KEY_SOURCE_MEMBERS: [&str; 4] = ["jku", "jwk", "x5u", "x5c"];

/// Fetches DID documents and artifacts. Implementations must follow the specification's safe
/// fetching rules: https only, no private addresses, size and time limits.
pub trait Fetch {
    fn get(&self, url: &str) -> Result<Vec<u8>, String>;
}

impl<F: Fn(&str) -> Result<Vec<u8>, String>> Fetch for F {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        self(url)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a valid JSON document: {0}")]
    Json(#[from] ai_catalog_trust::Error),
    #[error("not an AI Catalog document: {0}")]
    Catalog(#[from] ai_catalog::Error),
}

/// The result of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Verified,
    Failed(String),
    /// The check could not run: a fetch failed or the profile is unsupported.
    Unverifiable(String),
}

impl Outcome {
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }

    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestTrust {
    pub index: usize,
    pub contributor: String,
    pub signer: Option<String>,
    /// `None` when the manifest is unsigned.
    pub signature: Option<Outcome>,
    pub release: Option<Outcome>,
    pub publisher: bool,
}

impl ManifestTrust {
    fn is_accepted(&self) -> bool {
        self.signature.as_ref().is_some_and(Outcome::is_verified)
            && self.release.as_ref().is_some_and(Outcome::is_verified)
    }

    fn has_failed(&self) -> bool {
        self.signature.as_ref().is_some_and(Outcome::is_failed)
            || self.release.as_ref().is_some_and(Outcome::is_failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryTrust {
    pub index: usize,
    pub identifier: String,
    pub manifests: Vec<ManifestTrust>,
    /// Checked only when a manifest is accepted for the entry.
    pub artifact: Option<Outcome>,
    pub publisher_endorsed: bool,
    pub publisher_failed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub validation: ValidationResult,
    /// Trusted when an entry has a verified publisher endorsement and none fails.
    pub conformance_level: ConformanceLevel,
    pub catalog_signature: Option<Outcome>,
    pub catalog_authorized: bool,
    pub entries: Vec<EntryTrust>,
}

/// Validates the document and verifies the signatures and artifacts of its root entries. It is
/// read as served, since signatures cover members the SDK does not model.
pub fn verify(
    document: &[u8],
    options: &Options,
    fetch: &dyn Fetch,
) -> Result<Verification, Error> {
    let raw = ai_catalog_trust::parse_json(document)?;
    let catalog = ai_catalog::parse_slice(document)?;
    let validation = validate_with(&catalog, options);

    let verifier = Verifier {
        now: options
            .now
            .map_or_else(OffsetDateTime::now_utc, OffsetDateTime::from),
        fetch,
        base: options
            .base_url
            .as_deref()
            .and_then(|url| Url::parse(url).ok()),
    };

    let catalog_signature = catalog
        .signature
        .as_ref()
        .map(|signature| verifier.signature(signature, Kind::Catalog, &raw));
    let catalog_authorized = catalog_signature.as_ref().is_some_and(Outcome::is_verified)
        && catalog
            .signature
            .as_ref()
            .is_some_and(|signature| options.authorized_operators.contains(&signature.signer));

    let entries: Vec<EntryTrust> = catalog
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| verifier.entry(index, entry, &raw["entries"][index]))
        .collect();

    let trusted = entries.iter().any(|entry| entry.publisher_endorsed)
        && !entries.iter().any(|entry| entry.publisher_failed);
    let conformance_level =
        if trusted && validation.conformance_level >= ConformanceLevel::Discoverable {
            ConformanceLevel::Trusted
        } else {
            validation.conformance_level
        };

    Ok(Verification {
        validation,
        conformance_level,
        catalog_signature,
        catalog_authorized,
        entries,
    })
}

enum Failure {
    Failed(String),
    Unverifiable(String),
}

fn failed(reason: impl Into<String>) -> Failure {
    Failure::Failed(reason.into())
}

struct Verifier<'a> {
    now: OffsetDateTime,
    fetch: &'a dyn Fetch,
    base: Option<Url>,
}

impl Verifier<'_> {
    fn entry(&self, index: usize, entry: &CatalogEntry, raw: &Value) -> EntryTrust {
        let manifests: Vec<ManifestTrust> = entry
            .trust_manifests
            .iter()
            .enumerate()
            .map(|(position, manifest)| {
                self.manifest(entry, manifest, position, &raw["trustManifests"][position])
            })
            .collect();

        let artifact = manifests
            .iter()
            .any(ManifestTrust::is_accepted)
            .then(|| self.artifact(entry, raw));
        let artifact_verified = artifact.as_ref().is_some_and(Outcome::is_verified);
        let artifact_failed = artifact.as_ref().is_some_and(Outcome::is_failed);

        let publisher_accepted = manifests
            .iter()
            .any(|manifest| manifest.publisher && manifest.is_accepted());

        EntryTrust {
            index,
            identifier: entry.identifier.clone(),
            publisher_endorsed: publisher_accepted && artifact_verified,
            publisher_failed: manifests
                .iter()
                .any(|manifest| manifest.publisher && manifest.has_failed())
                || (publisher_accepted && artifact_failed),
            manifests,
            artifact,
        }
    }

    fn manifest(
        &self,
        entry: &CatalogEntry,
        manifest: &TrustManifest,
        index: usize,
        raw: &Value,
    ) -> ManifestTrust {
        let signature = manifest.signature.as_ref();

        ManifestTrust {
            index,
            contributor: manifest.contributor.clone(),
            signer: signature.map(|signature| signature.signer.clone()),
            signature: signature.map(|signature| self.signature(signature, Kind::Manifest, raw)),
            release: signature.map(|signature| release(entry, manifest, signature)),
            publisher: signature.is_some_and(|signature| {
                identity::is_publisher_of(&entry.identifier, &signature.signer)
            }),
        }
    }

    fn signature(&self, signature: &Signature, kind: Kind, payload: &Value) -> Outcome {
        match self.check_signature(signature, kind, payload) {
            Ok(()) => Outcome::Verified,
            Err(Failure::Failed(reason)) => Outcome::Failed(reason),
            Err(Failure::Unverifiable(reason)) => Outcome::Unverifiable(reason),
        }
    }

    fn check_signature(
        &self,
        signature: &Signature,
        kind: Kind,
        payload: &Value,
    ) -> Result<(), Failure> {
        if signature.profile != DID_WEB_PROFILE {
            return Err(Failure::Unverifiable(format!(
                "the signer profile {:?} is not supported",
                signature.profile
            )));
        }

        let header = self.check_header(signature, kind)?;
        self.check_time(signature)?;

        let url = did::document_url(&signature.signer)
            .ok_or_else(|| failed("the signer is not a root did:web DID"))?;
        let body = self.fetch.get(&url).map_err(|error| {
            Failure::Unverifiable(format!("cannot fetch the DID document: {error}"))
        })?;
        let document = ai_catalog_trust::parse_json(body)
            .map_err(|error| failed(format!("the DID document is not valid JSON: {error}")))?;

        let jwk = did::select_key(&document, &signature.signer, &header.key_id).map_err(failed)?;
        let key = P256Key::from_jwk(&jwk).map_err(|error| failed(error.to_string()))?;
        let signed =
            canonicalize_value_for_signature(payload).map_err(|error| failed(error.to_string()))?;

        verify_es256(&signature.jws, signed.as_bytes(), &key)
            .map_err(|error| failed(error.to_string()))
    }

    fn check_header(&self, signature: &Signature, kind: Kind) -> Result<jws::Header, Failure> {
        if !jws::is_detached(&signature.jws) {
            return Err(failed("the jws is not a detached compact serialization"));
        }

        let header = jws::parse(&signature.jws)
            .map_err(|reason| failed(format!("the jws header is invalid: {reason}")))?;

        if header.algorithm != PROFILE_ALGORITHM {
            return Err(failed(format!(
                "the jws algorithm {:?} is not {PROFILE_ALGORITHM}",
                header.algorithm
            )));
        }

        if header.typ != kind.typ() {
            return Err(failed(format!(
                "the jws typ {:?} is not {:?}",
                header.typ,
                kind.typ()
            )));
        }

        if let Some(member) = KEY_SOURCE_MEMBERS.iter().find(|member| header.has(member)) {
            return Err(failed(format!(
                "the jws header must not contain {member:?}"
            )));
        }

        if !identity::is_root_did_web(&signature.signer) {
            return Err(failed("the signer is not a root did:web DID"));
        }

        let has_fragment = header
            .key_id
            .strip_prefix(&format!("{}#", signature.signer))
            .is_some_and(|fragment| !fragment.is_empty() && !fragment.contains(['/', '?', '#']));

        if !has_fragment {
            return Err(failed(format!(
                "the jws kid {:?} is not the signer followed by a fragment",
                header.key_id
            )));
        }

        Ok(header)
    }

    fn check_time(&self, signature: &Signature) -> Result<(), Failure> {
        let issued = instant(&signature.issued_at)
            .ok_or_else(|| failed("issuedAt is not an RFC 3339 timestamp"))?;

        if issued > self.now {
            return Err(failed(format!(
                "issued in the future, at {}",
                signature.issued_at
            )));
        }

        if let Some(expires_at) = &signature.expires_at {
            let expires = instant(expires_at)
                .ok_or_else(|| failed("expiresAt is not an RFC 3339 timestamp"))?;

            if expires <= self.now {
                return Err(failed(format!("expired at {expires_at}")));
            }
        }

        Ok(())
    }

    fn artifact(&self, entry: &CatalogEntry, raw: &Value) -> Outcome {
        match self.check_artifact(entry, raw) {
            Ok(()) => Outcome::Verified,
            Err(Failure::Failed(reason)) => Outcome::Failed(reason),
            Err(Failure::Unverifiable(reason)) => Outcome::Unverifiable(reason),
        }
    }

    fn check_artifact(&self, entry: &CatalogEntry, raw: &Value) -> Result<(), Failure> {
        let digest = entry.digest.as_deref().unwrap_or_default();

        let content = if let Some(data) = raw.get("data") {
            ai_catalog_trust::canonicalize(data.to_string())
                .map_err(|error| failed(error.to_string()))?
                .into_bytes()
        } else {
            let reference = entry.url.as_deref().unwrap_or_default();
            let url = match &self.base {
                Some(base) => base.join(reference),
                None => Url::parse(reference),
            }
            .map_err(|error| failed(format!("the entry url is not a URL: {error}")))?;

            if url.scheme() != "https" {
                return Err(Failure::Unverifiable(
                    "only https artifacts are fetched".to_owned(),
                ));
            }

            self.fetch.get(url.as_str()).map_err(|error| {
                Failure::Unverifiable(format!("cannot fetch the artifact: {error}"))
            })?
        };

        match verify_digest(digest, &content) {
            Ok(true) => Ok(()),
            Ok(false) => Err(failed("the content does not match the entry digest")),
            Err(error) => Err(failed(error.to_string())),
        }
    }
}

/// Entry Release Coverage.
fn release(entry: &CatalogEntry, manifest: &TrustManifest, signature: &Signature) -> Outcome {
    let reason = if signature.signer != manifest.contributor {
        "the signer is not the contributor".to_owned()
    } else if entry.digest.as_deref().unwrap_or_default().is_empty() {
        "the entry has no digest".to_owned()
    } else if let Some(subject) = &manifest.subject {
        if subject.identifier.is_empty() || subject.r#type.is_empty() || subject.digest.is_empty() {
            "the subject is incomplete".to_owned()
        } else if let Some((_, message)) = subject_mismatches(entry, subject).into_iter().next() {
            message
        } else {
            return Outcome::Verified;
        }
    } else {
        "the manifest has no subject".to_owned()
    };

    Outcome::Failed(reason)
}
