// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use ai_catalog::TrustManifest;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("digest must use the format 'algorithm:hex-value', found '{0}'")]
    InvalidDigestFormat(String),
    #[error("unsupported digest algorithm '{0}'")]
    UnsupportedDigestAlgorithm(String),
    #[error("digest algorithm '{0}' is weaker than SHA-256")]
    WeakDigestAlgorithm(String),
    #[error("digest hex value contains non-hex characters")]
    InvalidDigestHex,
}

pub type Result<T> = std::result::Result<T, Error>;

const SHA256_HEX_LEN: usize = 64;
const SHA384_HEX_LEN: usize = 96;
const SHA512_HEX_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDigest {
    algorithm: String,
    hex_value: String,
}

impl ParsedDigest {
    pub fn parse(value: &str) -> Result<Self> {
        let (algorithm, hex_value) = value
            .split_once(':')
            .ok_or_else(|| Error::InvalidDigestFormat(value.to_owned()))?;

        if algorithm.is_empty() || hex_value.is_empty() || value.matches(':').count() != 1 {
            return Err(Error::InvalidDigestFormat(value.to_owned()));
        }

        let normalized_algorithm = algorithm.to_ascii_lowercase();

        let expected_len = match normalized_algorithm.as_str() {
            "sha256" => SHA256_HEX_LEN,
            "sha384" => SHA384_HEX_LEN,
            "sha512" => SHA512_HEX_LEN,
            "md5" | "sha1" | "sha224" => {
                return Err(Error::WeakDigestAlgorithm(normalized_algorithm));
            }
            _ => return Err(Error::UnsupportedDigestAlgorithm(normalized_algorithm)),
        };

        if hex_value.len() != expected_len
            || !hex_value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::InvalidDigestHex);
        }

        Ok(Self {
            algorithm: normalized_algorithm,
            hex_value: hex_value.to_ascii_lowercase(),
        })
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn hex_value(&self) -> &str {
        &self.hex_value
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> bool {
        match self.algorithm.as_str() {
            "sha256" => self.hex_value == digest_hex(Sha256::digest(bytes).as_slice()),
            "sha384" => self.hex_value == digest_hex(Sha384::digest(bytes).as_slice()),
            "sha512" => self.hex_value == digest_hex(Sha512::digest(bytes).as_slice()),
            _ => false,
        }
    }
}

pub fn verify_digest(expected_digest: &str, bytes: &[u8]) -> Result<bool> {
    Ok(ParsedDigest::parse(expected_digest)?.verify_bytes(bytes))
}

/// Parses a JSON document, rejecting duplicate member names.
pub fn parse_json(json: impl AsRef<[u8]>) -> Result<Value> {
    let StrictValue(value) = serde_json::from_slice(json.as_ref())?;

    Ok(value)
}

/// Returns the JCS (RFC 8785) form of a JSON document, rejecting duplicate member names.
pub fn canonicalize(json: impl AsRef<[u8]>) -> Result<String> {
    serde_jcs::to_string(&parse_json(json)?).map_err(Error::from)
}

/// Returns the JCS form of a manifest or catalog without its own `signature.jws` and
/// `additionalSignatures`, the payload a detached JWS covers.
pub fn canonicalize_for_signature(json: impl AsRef<[u8]>) -> Result<String> {
    let mut value = parse_json(json)?;

    strip_signature(&mut value);

    serde_jcs::to_string(&value).map_err(Error::from)
}

/// Returns the signing payload for a manifest, from the JSON it was decoded from or, if it was
/// built in code or changed since, from its serialization.
pub fn canonicalize_trust_manifest(manifest: &TrustManifest) -> Result<String> {
    let mut value = match manifest.decoded_json() {
        Some(json) => json.clone(),
        None => serde_json::to_value(manifest)?,
    };

    strip_signature(&mut value);

    serde_jcs::to_string(&value).map_err(Error::from)
}

// The omissions are not recursive: nested `jws` and `additionalSignatures` members stay in.
fn strip_signature(value: &mut Value) {
    let Value::Object(object) = value else {
        return;
    };

    object.remove(ADDITIONAL_SIGNATURES_MEMBER);

    if let Some(Value::Object(signature)) = object.get_mut(SIGNATURE_MEMBER) {
        signature.remove(JWS_MEMBER);
    }
}

const SIGNATURE_MEMBER: &str = "signature";
const JWS_MEMBER: &str = "jws";
const ADDITIONAL_SIGNATURES_MEMBER: &str = "additionalSignatures";

// Rejects duplicate member names, which `serde_json::Value` resolves silently.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<StrictValue, E> {
        Ok(StrictValue(Value::Bool(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<StrictValue, E> {
        Ok(StrictValue(v.into()))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<StrictValue, E> {
        Ok(StrictValue(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<StrictValue, E> {
        Number::from_f64(v)
            .map(|number| StrictValue(Value::Number(number)))
            .ok_or_else(|| E::custom("number is not finite"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<StrictValue, E> {
        Ok(StrictValue(Value::String(v.to_owned())))
    }

    fn visit_unit<E: de::Error>(self) -> std::result::Result<StrictValue, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<StrictValue, A::Error> {
        let mut items = Vec::new();

        while let Some(StrictValue(item)) = seq.next_element()? {
            items.push(item);
        }

        Ok(StrictValue(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<StrictValue, A::Error> {
        let mut object = Map::new();

        while let Some((name, StrictValue(value))) = map.next_entry::<String, StrictValue>()? {
            if object.insert(name.clone(), value).is_some() {
                return Err(de::Error::custom(format!("duplicate member name '{name}'")));
            }
        }

        Ok(StrictValue(Value::Object(object)))
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        use std::fmt::Write as _;

        let _ = write!(&mut hex, "{byte:02x}");
    }

    hex
}

#[cfg(test)]
mod tests {
    use ai_catalog::TrustManifest;
    use serde_json::Value;

    use super::{
        Error, ParsedDigest, canonicalize, canonicalize_for_signature, canonicalize_trust_manifest,
        verify_digest,
    };

    const SHAPES: &str = include_str!("../../../fixtures/manifest_shapes.json");

    const SHA256: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const SHA384: &str = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9";
    const SHA512: &str = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff";

    fn shapes() -> serde_json::Map<String, Value> {
        match serde_json::from_str(SHAPES).expect("shapes decode") {
            Value::Object(shapes) => shapes,
            other => panic!("shapes must be an object, got {other}"),
        }
    }

    #[test]
    fn verifies_digests() {
        for digest in [
            format!("sha256:{SHA256}"),
            format!("sha384:{SHA384}"),
            format!("sha512:{SHA512}"),
        ] {
            assert!(verify_digest(&digest, b"test").expect("valid digest"));
            assert!(!verify_digest(&digest, b"tampered").expect("valid digest"));
        }
    }

    #[test]
    fn rejects_weak_and_malformed_digests() {
        let rejected = [
            ("md5:abcd".to_owned(), "weak"),
            ("sha1:abcd".to_owned(), "weak"),
            ("crc32:abcd".to_owned(), "unsupported"),
            ("sha256:not-hex!".to_owned(), "hex"),
            ("sha256:abc".to_owned(), "hex"),
            (format!("sha256:{SHA256}ab"), "hex"),
            ("missing-colon".to_owned(), "format"),
            ("sha256:".to_owned(), "format"),
        ];

        for (value, kind) in rejected {
            let error = ParsedDigest::parse(&value).expect_err(&value);

            assert!(
                matches!(
                    (kind, &error),
                    ("weak", Error::WeakDigestAlgorithm(_))
                        | ("unsupported", Error::UnsupportedDigestAlgorithm(_))
                        | ("hex", Error::InvalidDigestHex)
                        | ("format", Error::InvalidDigestFormat(_))
                ),
                "{value}: {error}"
            );
        }
    }

    #[test]
    fn decoded_manifest_matches_the_published_bytes() {
        for (name, published) in shapes() {
            let json = published.to_string();
            let manifest: TrustManifest = serde_json::from_str(&json).expect("manifest decodes");

            assert_eq!(
                canonicalize_trust_manifest(&manifest).expect("canonicalizes"),
                canonicalize_for_signature(&json).expect("canonicalizes"),
                "{name}"
            );
        }
    }

    #[test]
    fn changed_manifest_follows_its_fields() {
        let published = shapes()["empty attestations"].to_string();
        let mut manifest: TrustManifest = serde_json::from_str(&published).expect("decodes");

        manifest.contributor = "did:web:b.example".to_owned();

        assert_eq!(
            canonicalize_trust_manifest(&manifest).expect("canonicalizes"),
            r#"{"contributor":"did:web:b.example"}"#
        );
    }

    #[test]
    fn signature_payload_omits_only_the_jws_and_additional_signatures() {
        let published = shapes()["signed with unmodelled member"].to_string();

        assert_eq!(
            canonicalize_for_signature(&published).expect("canonicalizes"),
            r#"{"contributor":"did:web:a.example","futureMember":42,"signature":{"futureMember":7,"issuedAt":"2026-03-15T10:00:00Z","profile":"did-web-v1","signer":"did:web:a.example"}}"#
        );
    }

    #[test]
    fn rejects_duplicate_member_names() {
        for json in [r#"{"a":1,"a":2}"#, r#"{"entries":[{"a":1,"b":2,"a":3}]}"#] {
            assert!(matches!(canonicalize(json), Err(Error::Json(_))), "{json}");
            assert!(
                matches!(canonicalize_for_signature(json), Err(Error::Json(_))),
                "{json}"
            );
        }
    }
}
