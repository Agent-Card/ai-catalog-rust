// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// SPDX-License-Identifier: Apache-2.0

//! ES256 verification of detached JWS signatures against P-256 JWKs.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value;

use crate::{Error, Result, parse_json};

const ALGORITHM: &str = "ES256";
const COORDINATE_LEN: usize = 32;
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// A P-256 verification key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P256Key(VerifyingKey);

impl P256Key {
    /// Reads a P-256 public key from a JWK, rejecting private key material.
    pub fn from_jwk(jwk: &Value) -> Result<Self> {
        let Value::Object(members) = jwk else {
            return Err(Error::Jwk("the key is not a JSON object".to_owned()));
        };

        let text = |name: &str| members.get(name).and_then(Value::as_str);

        if text("kty") != Some("EC") {
            return Err(Error::Jwk("kty must be \"EC\"".to_owned()));
        }

        if text("crv") != Some("P-256") {
            return Err(Error::Jwk("crv must be \"P-256\"".to_owned()));
        }

        if members.contains_key("d") {
            return Err(Error::Jwk(
                "the key contains private key material".to_owned(),
            ));
        }

        if members.get("alg").is_some_and(|alg| alg != ALGORITHM) {
            return Err(Error::Jwk(format!("alg must be \"{ALGORITHM}\"")));
        }

        if members.get("use").is_some_and(|usage| usage != "sig") {
            return Err(Error::Jwk("use must be \"sig\"".to_owned()));
        }

        if let Some(operations) = members.get("key_ops")
            && !operations
                .as_array()
                .is_some_and(|ops| ops.iter().any(|op| op == "verify"))
        {
            return Err(Error::Jwk("key_ops must permit \"verify\"".to_owned()));
        }

        let mut point = vec![SEC1_UNCOMPRESSED];

        for name in ["x", "y"] {
            let coordinate = text(name)
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
                .filter(|bytes| bytes.len() == COORDINATE_LEN)
                .ok_or_else(|| Error::Jwk(format!("{name} must be a 32-byte base64url value")))?;

            point.extend(coordinate);
        }

        VerifyingKey::from_sec1_bytes(&point)
            .map(Self)
            .map_err(|_| Error::Jwk("x and y are not a point on the P-256 curve".to_owned()))
    }
}

/// Verifies an ES256 detached JWS over `payload`. Header members other than `alg`, `b64` and
/// `crit` are the caller's to check.
pub fn verify_es256(jws: &str, payload: &[u8], key: &P256Key) -> Result<()> {
    let parts: Vec<&str> = jws.split('.').collect();

    let [header, "", signature] = parts[..] else {
        return Err(Error::Jws(
            "not a detached compact serialization".to_owned(),
        ));
    };

    check_header(header)?;

    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or_else(|| Error::Jws("the signature is not a 64-byte base64url value".to_owned()))?;

    let signing_input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(payload));

    key.0
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| Error::SignatureMismatch)
}

fn check_header(encoded: &str) -> Result<()> {
    let header = URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| parse_json(bytes).ok())
        .and_then(|value| match value {
            Value::Object(members) => Some(members),
            _ => None,
        })
        .ok_or_else(|| Error::Jws("the protected header is not a JSON object".to_owned()))?;

    if header.get("alg").and_then(Value::as_str) != Some(ALGORITHM) {
        return Err(Error::Jws(format!("alg must be \"{ALGORITHM}\"")));
    }

    for member in ["b64", "crit"] {
        if header.contains_key(member) {
            return Err(Error::Jws(format!(
                "the header must not contain \"{member}\""
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use serde_json::json;

    use super::*;

    // RFC 7515, Appendix A.3.
    const RFC_KEY: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
    const RFC_HEADER: &str = "eyJhbGciOiJFUzI1NiJ9";
    const RFC_PAYLOAD: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    const RFC_SIGNATURE: &str =
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

    fn rfc_key() -> P256Key {
        P256Key::from_jwk(&serde_json::from_str(RFC_KEY).unwrap()).unwrap()
    }

    fn sign(secret: u8, header: &Value, payload: &[u8]) -> (String, P256Key) {
        let signing_key = SigningKey::from_slice(&[secret; 32]).unwrap();
        let point = signing_key.verifying_key().to_sec1_point(false);
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        });
        let header = URL_SAFE_NO_PAD.encode(header.to_string());
        let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(payload));
        let signature: Signature = signing_key.sign(input.as_bytes());

        (
            format!("{header}..{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())),
            P256Key::from_jwk(&jwk).unwrap(),
        )
    }

    #[test]
    fn verifies_the_rfc_7515_example() {
        let payload = URL_SAFE_NO_PAD.decode(RFC_PAYLOAD).unwrap();

        verify_es256(
            &format!("{RFC_HEADER}..{RFC_SIGNATURE}"),
            &payload,
            &rfc_key(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_a_changed_payload_and_another_key() {
        let (jws, key) = sign(7, &json!({"alg": "ES256"}), b"payload");
        let (_, other) = sign(9, &json!({"alg": "ES256"}), b"payload");

        verify_es256(&jws, b"payload", &key).unwrap();
        assert!(matches!(
            verify_es256(&jws, b"changed", &key),
            Err(Error::SignatureMismatch)
        ));
        assert!(matches!(
            verify_es256(&jws, b"payload", &other),
            Err(Error::SignatureMismatch)
        ));
    }

    #[test]
    fn rejects_headers_that_are_not_plain_es256() {
        for header in [
            json!({"alg": "none"}),
            json!({"alg": "HS256"}),
            json!({"typ": "x"}),
            json!({"alg": "ES256", "b64": false}),
            json!({"alg": "ES256", "crit": ["exp"]}),
        ] {
            let (jws, key) = sign(7, &header, b"payload");

            assert!(
                matches!(verify_es256(&jws, b"payload", &key), Err(Error::Jws(_))),
                "{header}"
            );
        }
    }

    #[test]
    fn rejects_jwks_that_are_not_p256_verification_keys() {
        let valid: Value = serde_json::from_str(RFC_KEY).unwrap();

        for (name, value) in [
            ("kty", json!("RSA")),
            ("crv", json!("P-384")),
            ("d", json!("AA")),
            ("alg", json!("ES384")),
            ("use", json!("enc")),
            ("key_ops", json!(["sign"])),
            ("x", json!("AA")),
        ] {
            let mut jwk = valid.clone();
            jwk[name] = value;

            assert!(
                matches!(P256Key::from_jwk(&jwk), Err(Error::Jwk(_))),
                "{name}"
            );
        }

        let mut off_curve = valid.clone();
        off_curve["y"] = valid["x"].clone();
        assert!(P256Key::from_jwk(&off_curve).is_err());

        let mut allowed = valid;
        allowed["key_ops"] = json!(["verify"]);
        allowed["alg"] = json!("ES256");
        allowed["use"] = json!("sig");
        P256Key::from_jwk(&allowed).unwrap();
    }
}
