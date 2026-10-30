// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use ai_catalog::Signature;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Code, Validator, jws};

/// The kind of object a signature is attached to, which fixes the protected `typ` header.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Catalog,
    Manifest,
}

impl Kind {
    fn typ(self) -> &'static str {
        match self {
            Self::Catalog => "ai-catalog+jws",
            Self::Manifest => "ai-catalog-trust-manifest+jws",
        }
    }
}

fn instant(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

impl Validator {
    /// Checks the Signature object's structure and returns its protected header when the JWS
    /// is a well-formed detached compact serialization. Signatures are not verified.
    pub(crate) fn validate_signature(
        &mut self,
        signature: &Signature,
        kind: Kind,
        path: &str,
    ) -> Option<jws::Header> {
        for (member, value) in [
            ("signer", &signature.signer),
            ("profile", &signature.profile),
            ("issuedAt", &signature.issued_at),
            ("jws", &signature.jws),
        ] {
            if value.is_empty() {
                self.error(
                    Code::SignatureMember,
                    format!("{path}.{member}"),
                    format!("signature.{member} is required and must not be empty"),
                );
            }
        }

        if !signature.signer.is_empty() && !crate::is_absolute_uri(&signature.signer) {
            self.error(
                Code::SignatureSigner,
                format!("{path}.signer"),
                "signature.signer must be an absolute URI",
            );
        }

        self.validate_timestamp(&signature.issued_at, &format!("{path}.issuedAt"));
        self.validate_validity_window(signature, path);

        self.validate_jws(&signature.jws, kind, &format!("{path}.jws"))
    }

    fn validate_validity_window(&mut self, signature: &Signature, path: &str) {
        let Some(expires_at) = signature.expires_at.as_deref() else {
            return;
        };

        self.validate_timestamp(expires_at, &format!("{path}.expiresAt"));

        if let (Some(issued), Some(expires)) = (instant(&signature.issued_at), instant(expires_at))
            && expires <= issued
        {
            self.error(
                Code::SignatureExpiry,
                format!("{path}.expiresAt"),
                "signature.expiresAt must be later than issuedAt",
            );
        }
    }

    fn validate_jws(&mut self, jws: &str, kind: Kind, path: &str) -> Option<jws::Header> {
        if jws.is_empty() {
            return None;
        }

        if !jws::is_detached(jws) {
            self.error(
                Code::SignatureForm,
                path,
                "jws must use detached compact serialization",
            );
            return None;
        }

        let header = match jws::parse(jws) {
            Ok(header) => header,
            Err(reason) => {
                self.error(
                    Code::SignatureMalformed,
                    path,
                    format!(
                        "jws header must be base64url-encoded JSON declaring an 'alg': {reason}"
                    ),
                );
                return None;
            }
        };

        if jws::is_forbidden(&header.algorithm) {
            self.error(
                Code::SignatureAlgorithm,
                path,
                format!("jws algorithm '{}' must be rejected", header.algorithm),
            );
        }

        if header.has("b64") {
            self.error(
                Code::SignatureB64,
                path,
                "jws header must not contain 'b64'",
            );
        }

        if header.typ != kind.typ() {
            self.error(
                Code::SignatureType,
                path,
                format!(
                    "jws header typ must be {:?}, found {:?}",
                    kind.typ(),
                    header.typ
                ),
            );
        }

        Some(header)
    }

    /// Whether the signature may be accepted at the clock time: issued, and not expired. A
    /// signature outside that window is warned about.
    pub(crate) fn signature_current(&mut self, signature: &Signature, path: &str) -> bool {
        let issued = instant(&signature.issued_at);
        let expires = signature.expires_at.as_deref().and_then(instant);
        let mut current = true;

        if issued.is_some_and(|issued| issued > self.now) {
            current = false;
            self.warning(
                Code::SignatureNotYetValid,
                format!("{path}.issuedAt"),
                format!(
                    "signature issuedAt {:?} is in the future and MUST NOT be accepted yet",
                    signature.issued_at
                ),
            );
        }

        if expires.is_some_and(|expires| expires <= self.now) {
            current = false;
            self.warning(
                Code::SignatureExpired,
                format!("{path}.expiresAt"),
                format!(
                    "signature expired at {:?} and MUST NOT be accepted",
                    signature.expires_at.as_deref().unwrap_or_default()
                ),
            );
        }

        current
    }
}
