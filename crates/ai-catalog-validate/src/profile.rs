// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use ai_catalog::{CatalogEntry, TrustManifest};

use crate::{Code, Validator, identity, jws, text};

const PROFILE_ALGORITHM: &str = "ES256";

const KEY_SOURCE_MEMBERS: [&str; 4] = ["jku", "jwk", "x5u", "x5c"];

impl Validator {
    /// Applies the did:web Publisher Profile to a signed entry trust manifest, warns for each
    /// violation, and reports whether there were none. A manifest without a usable signature is
    /// reported elsewhere and fails the check.
    pub(crate) fn check_profile(
        &mut self,
        entry: &CatalogEntry,
        manifest: &TrustManifest,
        path: &str,
    ) -> bool {
        let signature = text(&manifest.signature);

        let Ok(header) = jws::parse(signature) else {
            return false;
        };

        if !jws::is_detached(signature) {
            return false;
        }

        let before = self.warnings.len();

        self.check_namespace(entry, manifest, path);
        self.check_header(manifest, &header, &format!("{path}.signature"));

        self.warnings.len() == before
    }

    fn check_namespace(&mut self, entry: &CatalogEntry, manifest: &TrustManifest, path: &str) {
        match identity::publisher(&entry.identifier).filter(|p| identity::is_valid_publisher(p)) {
            None => self.warning(
                Code::ProfileIdentifier,
                path,
                format!(
                    "entry identifier {:?} must start with the lowercase prefix \"urn:air:\" followed by a lowercase DNS publisher",
                    entry.identifier
                ),
            ),
            Some(publisher) => {
                let want = identity::did(publisher);

                if manifest.identity != want {
                    self.warning(
                        Code::ProfileIdentity,
                        format!("{path}.identity"),
                        format!(
                            "trustManifest.identity {:?} must be exactly {want:?}",
                            manifest.identity
                        ),
                    );
                }
            }
        }

        let identity_type = text(&manifest.identity_type);

        if !identity_type.is_empty() && identity_type != "did" {
            self.warning(
                Code::ProfileType,
                format!("{path}.identityType"),
                format!("trustManifest.identityType {identity_type:?} must be \"did\""),
            );
        }
    }

    fn check_header(&mut self, manifest: &TrustManifest, header: &jws::Header, path: &str) {
        if header.algorithm != PROFILE_ALGORITHM && !jws::is_forbidden(&header.algorithm) {
            self.warning(
                Code::ProfileAlgorithm,
                path,
                format!(
                    "signature algorithm {:?} must be {PROFILE_ALGORITHM}",
                    header.algorithm
                ),
            );
        }

        let has_fragment = header
            .key_id
            .strip_prefix(&format!("{}#", manifest.identity))
            .is_some_and(|fragment| !fragment.is_empty());

        if !has_fragment {
            self.warning(
                Code::ProfileKeyId,
                path,
                format!(
                    "signature kid {:?} must be the identity {:?} followed by a fragment",
                    header.key_id, manifest.identity
                ),
            );
        }

        for member in KEY_SOURCE_MEMBERS {
            if header.has(member) {
                self.warning(
                    Code::ProfileHeader,
                    path,
                    format!("signature header must not contain '{member}'"),
                );
            }
        }
    }
}
