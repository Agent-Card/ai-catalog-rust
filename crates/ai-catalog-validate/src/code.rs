// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

macro_rules! codes {
    ($($variant:ident => $text:literal,)*) => {
        /// A stable identifier for a kind of diagnostic. Match on it rather than on the message.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum Code {
            $($variant,)*
        }

        impl Code {
            /// Returns the kebab-case name of the code.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)*
                }
            }
        }
    };
}

codes! {
    SpecVersion => "spec-version",
    HostMember => "host-member-missing",
    EntryMember => "entry-member-missing",
    EntryArtifact => "entry-artifact-source",
    EntryDuplicate => "entry-duplicate",
    EntryVersion => "entry-version-conflict",
    IdentifierNotUri => "identifier-not-uri",
    Timestamp => "timestamp-invalid",
    PublisherMember => "publisher-member-missing",
    ExtensionKey => "extension-key-invalid",
    NestedDepth => "nested-depth-exceeded",
    NestedInvalid => "nested-catalog-invalid",
    DigestInvalid => "digest-invalid",
    SignatureForm => "signature-form",
    SignatureMalformed => "signature-malformed",
    SignatureAlgorithm => "signature-algorithm-forbidden",
    SignatureB64 => "signature-b64",
    SignatureUnlisted => "signature-algorithm-unlisted",
    ManifestIdentity => "manifest-identity-missing",
    ManifestIdentityUri => "manifest-identity-not-uri",
    ManifestEmpty => "manifest-not-substantive",
    ManifestSignedMember => "manifest-member-missing",
    ManifestExpired => "manifest-expired",
    SubjectMember => "subject-member-missing",
    SubjectMismatch => "subject-mismatch",
    TrustSchemaMember => "trust-schema-member-missing",
    AttestationMember => "attestation-member-missing",
    ProvenanceMember => "provenance-member-missing",
    ProfileIdentifier => "profile-identifier",
    ProfileIdentity => "profile-identity",
    ProfileType => "profile-identity-type",
    ProfileAlgorithm => "profile-algorithm",
    ProfileKeyId => "profile-key-id",
    ProfileHeader => "profile-header-member",
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
