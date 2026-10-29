// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use ai_catalog::{CatalogEntry, Signature};

use crate::{Code, Validator, identity, jws};

/// The reserved profile name of the did:web Signer Profile.
pub(crate) const DID_WEB_PROFILE: &str = "did-web-v1";

const PROFILE_ALGORITHM: &str = "ES256";

const KEY_SOURCE_MEMBERS: [&str; 4] = ["jku", "jwk", "x5u", "x5c"];

impl Validator {
    /// Applies the did:web Signer Profile to a signature that selects it, warns for each
    /// violation, and reports whether there were none.
    pub(crate) fn check_signer_profile(
        &mut self,
        signature: &Signature,
        header: &jws::Header,
        path: &str,
    ) -> bool {
        let before = self.warnings.len();

        if !identity::is_root_did_web(&signature.signer) {
            self.warning(
                Code::ProfileSigner,
                format!("{path}.signer"),
                format!(
                    "signer {:?} must be a root did:web DID with a lowercase ASCII domain and no port, path or IP",
                    signature.signer
                ),
            );
        }

        if header.algorithm != PROFILE_ALGORITHM && !jws::is_forbidden(&header.algorithm) {
            self.warning(
                Code::ProfileAlgorithm,
                format!("{path}.jws"),
                format!(
                    "jws algorithm {:?} must be {PROFILE_ALGORITHM}",
                    header.algorithm
                ),
            );
        }

        let has_fragment = header
            .key_id
            .strip_prefix(&format!("{}#", signature.signer))
            .is_some_and(|fragment| !fragment.is_empty() && !fragment.contains(['/', '?', '#']));

        if !has_fragment {
            self.warning(
                Code::ProfileKeyId,
                format!("{path}.jws"),
                format!(
                    "jws kid {:?} must be the signer {:?} followed by a fragment",
                    header.key_id, signature.signer
                ),
            );
        }

        for member in KEY_SOURCE_MEMBERS {
            if header.has(member) {
                self.warning(
                    Code::ProfileHeader,
                    format!("{path}.jws"),
                    format!("jws header must not contain '{member}'"),
                );
            }
        }

        self.warnings.len() == before
    }

    /// Whether the signer is the publisher the entry's `urn:air` identifier names.
    pub(crate) fn is_publisher(entry: &CatalogEntry, signer: &str) -> bool {
        identity::publisher(&entry.identifier)
            .filter(|publisher| identity::is_valid_publisher(publisher))
            .is_some_and(|publisher| signer == identity::did(publisher))
    }
}
