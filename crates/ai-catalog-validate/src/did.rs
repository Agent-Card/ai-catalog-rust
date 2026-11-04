// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// SPDX-License-Identifier: Apache-2.0

//! DID document resolution for the did:web Signer Profile.

use serde_json::{Map, Value};

use crate::identity;

const DID_WEB_PREFIX: &str = "did:web:";

/// The DID document URL of a root did:web DID.
pub(crate) fn document_url(did: &str) -> Option<String> {
    let domain = did.strip_prefix(DID_WEB_PREFIX)?;

    identity::is_root_did_web(did).then(|| format!("https://{domain}/.well-known/did.json"))
}

/// Selects the JWK of `kid`: a single method, authorized by `assertionMethod`, controlled by `signer`.
pub(crate) fn select_key(document: &Value, signer: &str, kid: &str) -> Result<Value, String> {
    if document.get("id").and_then(Value::as_str) != Some(signer) {
        return Err(format!("the DID document id is not {signer:?}"));
    }

    let resolve = |reference: &str| {
        if reference.starts_with('#') {
            format!("{signer}{reference}")
        } else {
            reference.to_owned()
        }
    };
    let is_kid = |method: &Map<String, Value>| {
        method
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| resolve(id) == kid)
    };
    let members = |name: &str| {
        document
            .get(name)
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
    };

    let mut methods: Vec<&Map<String, Value>> = members("verificationMethod")
        .iter()
        .filter_map(Value::as_object)
        .filter(|method| is_kid(method))
        .collect();
    let mut authorized = false;

    for entry in members("assertionMethod") {
        match entry {
            Value::String(reference) => authorized |= resolve(reference) == kid,
            Value::Object(method) if is_kid(method) => {
                authorized = true;
                methods.push(method);
            }
            _ => {}
        }
    }

    if !authorized {
        return Err(format!("assertionMethod does not authorize {kid:?}"));
    }

    let [method] = methods[..] else {
        return Err(format!(
            "{kid:?} selects {} verification methods, not one",
            methods.len()
        ));
    };

    if method.get("controller").and_then(Value::as_str) != Some(signer) {
        return Err(format!("the controller of {kid:?} is not {signer:?}"));
    }

    method
        .get("publicKeyJwk")
        .cloned()
        .ok_or_else(|| format!("{kid:?} has no publicKeyJwk"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SIGNER: &str = "did:web:acme.com";
    const KID: &str = "did:web:acme.com#key-1";

    fn document() -> Value {
        json!({
            "id": SIGNER,
            "verificationMethod": [{
                "id": "#key-1",
                "controller": SIGNER,
                "publicKeyJwk": {"kty": "EC"}
            }],
            "assertionMethod": ["#key-1"]
        })
    }

    #[test]
    fn builds_the_document_url_of_root_dids_only() {
        assert_eq!(
            document_url("did:web:acme.com").as_deref(),
            Some("https://acme.com/.well-known/did.json")
        );

        for did in [
            "did:web:acme.com:agents",
            "did:web:acme.com%3A8443",
            "did:web:127.0.0.1",
            "did:web:Acme.com",
            "did:key:z6Mk",
        ] {
            assert!(document_url(did).is_none(), "{did}");
        }
    }

    #[test]
    fn selects_only_a_key_the_document_authorizes() {
        assert_eq!(
            select_key(&document(), SIGNER, KID).unwrap(),
            json!({"kty": "EC"})
        );

        let mut other_id = document();
        other_id["id"] = json!("did:web:evil.com");

        let mut authentication_only = document();
        authentication_only["authentication"] = json!(["#key-1"]);
        authentication_only["assertionMethod"] = json!([]);

        let mut foreign_controller = document();
        foreign_controller["verificationMethod"][0]["controller"] = json!("did:web:evil.com");

        let mut no_key = document();
        no_key["verificationMethod"][0]["publicKeyJwk"] = Value::Null;
        no_key["verificationMethod"][0]
            .as_object_mut()
            .unwrap()
            .remove("publicKeyJwk");

        let mut twice = document();
        let method = twice["verificationMethod"][0].clone();
        twice["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(method);

        for (name, document) in [
            ("id", other_id),
            ("assertionMethod", authentication_only),
            ("controller", foreign_controller),
            ("publicKeyJwk", no_key),
            ("ambiguous", twice),
        ] {
            assert!(select_key(&document, SIGNER, KID).is_err(), "{name}");
        }

        assert!(select_key(&document(), SIGNER, "did:web:acme.com#other").is_err());
    }
}
