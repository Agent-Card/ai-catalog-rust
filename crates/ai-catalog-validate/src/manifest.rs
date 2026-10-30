// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use ai_catalog::{Attestation, CatalogEntry, ProvenanceLink, Subject, TrustManifest, TrustSchema};
use ai_catalog_trust::ParsedDigest;

use crate::profile::DID_WEB_PROFILE;
use crate::signature::Kind;
use crate::{Code, Validator, is_absolute_uri};

impl Validator {
    pub(crate) fn validate_entry_trust(&mut self, entry: &CatalogEntry, path: &str, depth: usize) {
        self.validate_digest(
            entry.digest.as_deref().unwrap_or_default(),
            &format!("{path}.digest"),
        );

        let mut has_signed = false;
        let mut has_publisher = false;

        for (index, manifest) in entry.trust_manifests.iter().enumerate() {
            let manifest_path = format!("{path}.trustManifests[{index}]");

            self.validate_trust_manifest(manifest, &manifest_path);
            has_signed |= manifest.signature.is_some();

            let bound = self.validate_subject_binding(entry, manifest, &manifest_path);
            let endorsed = self.is_publisher_endorsement(entry, manifest, &manifest_path);

            has_publisher |= bound && endorsed;
        }

        if has_signed && entry.digest.as_deref().unwrap_or_default().is_empty() {
            self.error(
                Code::EntryDigest,
                format!("{path}.digest"),
                "an entry carrying a signed trust manifest must include digest",
            );
            has_publisher = false;
        }

        if depth == 0 && !entry.trust_manifests.is_empty() {
            self.entries_with_manifests += 1;
            self.held_back |= !has_publisher;
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

    /// Whether the manifest is a signed, current did:web endorsement of the entry by the
    /// publisher its `urn:air` identifier names, free of profile violations.
    fn is_publisher_endorsement(
        &mut self,
        entry: &CatalogEntry,
        manifest: &TrustManifest,
        path: &str,
    ) -> bool {
        let Some(signature) = &manifest.signature else {
            return false;
        };

        let signature_path = format!("{path}.signature");

        // Re-parse quietly: the structure was already reported while validating the manifest.
        let Ok(header) = crate::jws::parse(&signature.jws) else {
            return false;
        };

        if signature.profile != DID_WEB_PROFILE || !crate::jws::is_detached(&signature.jws) {
            return false;
        }

        let profile_ok = self.check_signer_profile(signature, &header, &signature_path);
        let current = self.signature_current(signature, &signature_path);

        profile_ok
            && current
            && signature.signer == manifest.contributor
            && header.typ == "ai-catalog-trust-manifest+jws"
            && Self::is_publisher(entry, &signature.signer)
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

    /// Checks the subject against the entry release and reports whether it matches.
    fn validate_subject_binding(
        &mut self,
        entry: &CatalogEntry,
        manifest: &TrustManifest,
        path: &str,
    ) -> bool {
        let Some(subject) = &manifest.subject else {
            return false;
        };

        let before = self.errors.len();

        if !subject.identifier.is_empty() && subject.identifier != entry.identifier {
            self.error(
                Code::SubjectMismatch,
                format!("{path}.subject.identifier"),
                format!(
                    "subject.identifier {:?} must equal the entry identifier {:?}",
                    subject.identifier, entry.identifier
                ),
            );
        }

        if !subject.r#type.is_empty()
            && !entry.entry_type.is_empty()
            && subject.r#type != entry.entry_type
        {
            self.error(
                Code::SubjectMismatch,
                format!("{path}.subject.type"),
                format!(
                    "subject.type {:?} must equal the entry type {:?}",
                    subject.r#type, entry.entry_type
                ),
            );
        }

        let entry_digest = entry.digest.as_deref().unwrap_or_default();

        if !subject.digest.is_empty() && !entry_digest.is_empty() && subject.digest != entry_digest
        {
            self.error(
                Code::SubjectMismatch,
                format!("{path}.subject.digest"),
                format!(
                    "subject.digest {:?} must equal the entry digest {entry_digest:?}",
                    subject.digest
                ),
            );
        }

        if subject.version != entry.version {
            self.error(
                Code::SubjectMismatch,
                format!("{path}.subject.version"),
                format!(
                    "subject.version {:?} must be present exactly when the entry version is and equal it ({:?})",
                    subject.version, entry.version
                ),
            );
        }

        self.errors.len() == before
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
