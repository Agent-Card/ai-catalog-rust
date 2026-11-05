// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use ai_catalog::{Attestation, CatalogEntry, ProvenanceLink, Subject, TrustManifest, TrustSchema};
use ai_catalog_trust::ParsedDigest;

use crate::profile::DID_WEB_PROFILE;
use crate::signature::Kind;
use crate::{Code, Validator, is_absolute_uri};

impl Validator {
    pub(crate) fn validate_entry_trust(&mut self, entry: &CatalogEntry, path: &str) {
        self.validate_digest(
            entry.digest.as_deref().unwrap_or_default(),
            &format!("{path}.digest"),
        );

        let mut has_signed = false;

        for (index, manifest) in entry.trust_manifests.iter().enumerate() {
            let manifest_path = format!("{path}.trustManifests[{index}]");

            self.validate_trust_manifest(manifest, &manifest_path);
            has_signed |= manifest.signature.is_some();

            self.validate_subject_binding(entry, manifest, &manifest_path);
            self.check_manifest_profile(manifest, &manifest_path);
        }

        if has_signed && entry.digest.as_deref().unwrap_or_default().is_empty() {
            self.error(
                Code::EntryDigest,
                format!("{path}.digest"),
                "an entry carrying a signed trust manifest must include digest",
            );
        }
    }

    fn validate_trust_manifest(&mut self, manifest: &TrustManifest, path: &str) {
        self.validate_extension_keys(manifest.extensions.as_ref(), &format!("{path}.extensions"));
        self.validate_contributor(&manifest.contributor, &format!("{path}.contributor"));

        if !is_substantive(manifest) {
            self.error(
                Code::ManifestEmpty,
                path,
                "trust manifest must contain at least one of a signature, a trustSchema, \
                 non-empty attestations or provenance, or non-empty extensions, and must \
                 otherwise be omitted entirely",
            );
        }

        if let Some(signature) = &manifest.signature {
            let signature_path = format!("{path}.signature");

            if manifest.subject.is_none() {
                self.error(
                    Code::ManifestSignedMember,
                    format!("{path}.subject"),
                    "a trust manifest carrying a signature must include a subject",
                );
            }

            self.validate_signature(signature, Kind::Manifest, &signature_path);

            if !signature.signer.is_empty() && signature.signer != manifest.contributor {
                self.error(
                    Code::ManifestSigner,
                    format!("{signature_path}.signer"),
                    format!(
                        "signature.signer {:?} must exactly equal the contributor {:?}",
                        signature.signer, manifest.contributor
                    ),
                );
            }
        }

        if let Some(subject) = &manifest.subject {
            self.validate_subject(subject, &format!("{path}.subject"));
        }

        if let Some(schema) = &manifest.trust_schema {
            self.validate_trust_schema(schema, &format!("{path}.trustSchema"));
        }

        for (index, attestation) in manifest.attestations.iter().enumerate() {
            self.validate_attestation(attestation, &format!("{path}.attestations[{index}]"));
        }

        for (index, link) in manifest.provenance.iter().enumerate() {
            self.validate_provenance(link, &format!("{path}.provenance[{index}]"));
        }
    }

    fn validate_contributor(&mut self, contributor: &str, path: &str) {
        if contributor.is_empty() {
            self.error(
                Code::ManifestContributor,
                path,
                "trust manifest contributor is required and must not be empty",
            );
        } else if !is_absolute_uri(contributor) {
            self.error(
                Code::ManifestContributorUri,
                path,
                "trust manifest contributor must be an absolute URI",
            );
        }
    }

    /// Warns about did:web profile violations and a signature outside its validity window.
    fn check_manifest_profile(&mut self, manifest: &TrustManifest, path: &str) {
        let Some(signature) = &manifest.signature else {
            return;
        };

        let signature_path = format!("{path}.signature");

        // Re-parse quietly: the structure was already reported while validating the manifest.
        let Ok(header) = crate::jws::parse(&signature.jws) else {
            return;
        };

        if signature.profile != DID_WEB_PROFILE || !crate::jws::is_detached(&signature.jws) {
            return;
        }

        self.check_signer_profile(signature, &header, &signature_path);
        self.signature_current(signature, &signature_path);
    }

    fn validate_subject(&mut self, subject: &Subject, path: &str) {
        for (member, value) in [
            ("identifier", &subject.identifier),
            ("type", &subject.r#type),
            ("digest", &subject.digest),
        ] {
            if value.is_empty() {
                self.error(
                    Code::SubjectMember,
                    format!("{path}.{member}"),
                    format!("subject.{member} is required and must not be empty"),
                );
            }
        }

        self.validate_digest(&subject.digest, &format!("{path}.digest"));
    }

    fn validate_subject_binding(
        &mut self,
        entry: &CatalogEntry,
        manifest: &TrustManifest,
        path: &str,
    ) {
        let Some(subject) = &manifest.subject else {
            return;
        };

        for (member, message) in subject_mismatches(entry, subject) {
            self.error(
                Code::SubjectMismatch,
                format!("{path}.subject.{member}"),
                message,
            );
        }
    }

    fn validate_trust_schema(&mut self, schema: &TrustSchema, path: &str) {
        if schema.identifier.is_empty() {
            self.error(
                Code::TrustSchemaMember,
                format!("{path}.identifier"),
                "trustSchema.identifier must not be empty",
            );
        }

        if schema.version.is_empty() {
            self.error(
                Code::TrustSchemaMember,
                format!("{path}.version"),
                "trustSchema.version must not be empty",
            );
        }
    }

    fn validate_attestation(&mut self, attestation: &Attestation, path: &str) {
        if attestation.r#type.is_empty() {
            self.error(
                Code::AttestationMember,
                format!("{path}.type"),
                "attestation type must not be empty",
            );
        }

        if attestation.uri.is_empty() {
            self.error(
                Code::AttestationMember,
                format!("{path}.uri"),
                "attestation uri must not be empty",
            );
        }

        self.validate_digest(
            attestation.digest.as_deref().unwrap_or_default(),
            &format!("{path}.digest"),
        );
    }

    fn validate_provenance(&mut self, link: &ProvenanceLink, path: &str) {
        if link.relation.is_empty() {
            self.error(
                Code::ProvenanceMember,
                format!("{path}.relation"),
                "provenance relation must not be empty",
            );
        }

        if link.source_id.is_empty() {
            self.error(
                Code::ProvenanceMember,
                format!("{path}.sourceId"),
                "provenance sourceId must not be empty",
            );
        }

        self.validate_digest(
            link.source_digest.as_deref().unwrap_or_default(),
            &format!("{path}.sourceDigest"),
        );
    }

    pub(crate) fn validate_digest(&mut self, value: &str, path: &str) {
        if value.is_empty() {
            return;
        }

        if let Err(error) = ParsedDigest::parse(value) {
            self.error(Code::DigestInvalid, path, error.to_string());
        }
    }
}

fn is_substantive(manifest: &TrustManifest) -> bool {
    manifest.signature.is_some()
        || manifest.trust_schema.is_some()
        || !manifest.attestations.is_empty()
        || !manifest.provenance.is_empty()
        || manifest
            .extensions
            .as_ref()
            .is_some_and(|extensions| !extensions.is_empty())
}

/// The members of the subject that do not match the entry release, with what is wrong. Members
/// that are empty are reported as missing elsewhere.
pub(crate) fn subject_mismatches(
    entry: &CatalogEntry,
    subject: &Subject,
) -> Vec<(&'static str, String)> {
    let mut mismatches = Vec::new();

    if !subject.identifier.is_empty() && subject.identifier != entry.identifier {
        mismatches.push((
            "identifier",
            format!(
                "subject.identifier {:?} must equal the entry identifier {:?}",
                subject.identifier, entry.identifier
            ),
        ));
    }

    if !subject.r#type.is_empty()
        && !entry.entry_type.is_empty()
        && subject.r#type != entry.entry_type
    {
        mismatches.push((
            "type",
            format!(
                "subject.type {:?} must equal the entry type {:?}",
                subject.r#type, entry.entry_type
            ),
        ));
    }

    let entry_digest = entry.digest.as_deref().unwrap_or_default();

    if !subject.digest.is_empty() && !entry_digest.is_empty() && subject.digest != entry_digest {
        mismatches.push((
            "digest",
            format!(
                "subject.digest {:?} must equal the entry digest {entry_digest:?}",
                subject.digest
            ),
        ));
    }

    if subject.version != entry.version {
        mismatches.push((
            "version",
            format!(
                "subject.version {:?} must be present exactly when the entry version is and equal it ({:?})",
                subject.version, entry.version
            ),
        ));
    }

    mismatches
}
