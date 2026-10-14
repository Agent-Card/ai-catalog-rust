// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use ai_catalog::{Attestation, CatalogEntry, ProvenanceLink, Subject, TrustManifest, TrustSchema};
use ai_catalog_trust::ParsedDigest;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Code, Validator, text};

impl Validator {
    pub(crate) fn validate_entry_trust(&mut self, entry: &CatalogEntry, path: &str, depth: usize) {
        let Some(manifest) = &entry.trust_manifest else {
            return;
        };

        let path = format!("{path}.trustManifest");

        self.validate_trust_manifest(manifest, &path);
        self.validate_subject_binding(entry, manifest, &path);

        let ready = is_signed(manifest)
            && self.check_profile(entry, manifest, &path)
            && !self.expired(manifest);

        if depth == 0 {
            self.manifests += 1;
            self.held_back |= !ready;
        }
    }

    fn validate_trust_manifest(&mut self, manifest: &TrustManifest, path: &str) {
        self.validate_extension_keys(manifest.extensions.as_ref(), &format!("{path}.extensions"));
        self.validate_identity(&manifest.identity, &format!("{path}.identity"));

        if !is_substantive(manifest) {
            self.error(
                Code::ManifestEmpty,
                path,
                "trustManifest must carry at least one substantive member (a signature with its \
                 subject and issuedAt, a non-empty attestations or provenance array, or a \
                 trustSchema) and must otherwise be omitted entirely",
            );
        }

        self.validate_signed_members(manifest, path);
        self.validate_signature(text(&manifest.signature), &format!("{path}.signature"));
        self.validate_timestamp(text(&manifest.issued_at), &format!("{path}.issuedAt"));
        self.validate_expiry(manifest, path);

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

    fn validate_identity(&mut self, identity: &str, path: &str) {
        if identity.is_empty() {
            self.error(
                Code::ManifestIdentity,
                path,
                "trustManifest.identity is required and must not be empty",
            );
        } else if !identity.contains(':') {
            self.warning(
                Code::ManifestIdentityUri,
                path,
                "trustManifest.identity SHOULD be a URI",
            );
        }
    }

    fn validate_signed_members(&mut self, manifest: &TrustManifest, path: &str) {
        if text(&manifest.signature).is_empty() {
            return;
        }

        if manifest.subject.is_none() {
            self.error(
                Code::ManifestSignedMember,
                format!("{path}.subject"),
                "a trustManifest carrying a signature must include a subject",
            );
        }

        if text(&manifest.issued_at).is_empty() {
            self.error(
                Code::ManifestSignedMember,
                format!("{path}.issuedAt"),
                "a trustManifest carrying a signature must include issuedAt",
            );
        }
    }

    pub(crate) fn expired(&self, manifest: &TrustManifest) -> bool {
        OffsetDateTime::parse(text(&manifest.expires_at), &Rfc3339)
            .is_ok_and(|expires_at| expires_at < self.now)
    }

    fn validate_expiry(&mut self, manifest: &TrustManifest, path: &str) {
        let expires_at = text(&manifest.expires_at);

        self.validate_timestamp(expires_at, &format!("{path}.expiresAt"));

        if self.expired(manifest) {
            self.warning(
                Code::ManifestExpired,
                format!("{path}.expiresAt"),
                format!("trustManifest expired at {expires_at:?} and SHOULD be rejected"),
            );
        }
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

        let (subject_version, entry_version) = (text(&subject.version), text(&entry.version));

        if subject_version != entry_version {
            self.error(
                Code::SubjectMismatch,
                format!("{path}.subject.version"),
                format!(
                    "subject.version {subject_version:?} must equal the entry version {entry_version:?} (both absent or both present)"
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

        let (subject_url, entry_url) = (text(&subject.url), text(&entry.url));

        if !subject_url.is_empty() && subject_url != entry_url {
            self.error(
                Code::SubjectMismatch,
                format!("{path}.subject.url"),
                format!("subject.url {subject_url:?} must equal the entry url {entry_url:?}"),
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

        self.validate_digest(text(&attestation.digest), &format!("{path}.digest"));
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

        self.validate_digest(text(&link.source_digest), &format!("{path}.sourceDigest"));
    }

    fn validate_digest(&mut self, value: &str, path: &str) {
        if value.is_empty() {
            return;
        }

        if let Err(error) = ParsedDigest::parse(value) {
            self.error(Code::DigestInvalid, path, error.to_string());
        }
    }
}

fn is_signed(manifest: &TrustManifest) -> bool {
    !text(&manifest.signature).is_empty()
        && manifest.subject.is_some()
        && !text(&manifest.issued_at).is_empty()
}

fn is_substantive(manifest: &TrustManifest) -> bool {
    is_signed(manifest)
        || !manifest.attestations.is_empty()
        || !manifest.provenance.is_empty()
        || manifest.trust_schema.is_some()
}
