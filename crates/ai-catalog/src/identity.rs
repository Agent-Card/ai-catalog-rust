// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

const URN_AIR_PREFIX: &str = "urn:air:";
const DID_WEB_PREFIX: &str = "did:web:";

/// Returns the lowercased publisher segment of a
/// `urn:air:{publisher}:{namespace}:{name}` identifier, or `None` for
/// non-`urn:air` identifiers.
pub fn publisher_domain(identifier: &str) -> Option<String> {
    let rest = strip_prefix_ignore_case(identifier, URN_AIR_PREFIX)?;
    let publisher = rest.split(':').next().unwrap_or_default();

    if publisher.is_empty() {
        return None;
    }

    Some(publisher.to_ascii_lowercase())
}

/// Returns the lowercased domain of a trust-manifest identity, handling
/// `urn:air`, `did:web`, and authority-based schemes (`spiffe://`, `https://`,
/// ...), or `None` when no domain can be determined.
pub fn identity_domain(identity: &str) -> Option<String> {
    let id = identity.trim();

    if strip_prefix_ignore_case(id, URN_AIR_PREFIX).is_some() {
        publisher_domain(id)
    } else if let Some(rest) = strip_prefix_ignore_case(id, DID_WEB_PREFIX) {
        did_web_domain(rest)
    } else {
        authority_domain(id)
    }
}

/// Reports whether a trust-manifest identity's domain aligns with an entry
/// identifier's publisher domain. Returns `None` when either side carries no
/// domain, in which case callers must not report a violation.
pub fn identity_binds_to_entry(identifier: &str, identity: &str) -> Option<bool> {
    let publisher = publisher_domain(identifier)?;
    let domain = identity_domain(identity)?;

    Some(publisher == domain)
}

fn strip_prefix_ignore_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    if value.get(..prefix.len())?.eq_ignore_ascii_case(prefix) {
        value.get(prefix.len()..)
    } else {
        None
    }
}

fn did_web_domain(rest: &str) -> Option<String> {
    let mut segment = rest.split(':').next().unwrap_or_default();

    if let Some(index) = segment.to_ascii_lowercase().find("%3a") {
        segment = &segment[..index];
    }

    if segment.is_empty() {
        return None;
    }

    Some(segment.to_ascii_lowercase())
}

fn authority_domain(id: &str) -> Option<String> {
    let (_, authority) = id.split_once("://")?;
    let authority = authority.split('/').next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let authority = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);

    if authority.is_empty() {
        return None;
    }

    Some(authority.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{identity_binds_to_entry, identity_domain, publisher_domain};

    #[test]
    fn publisher_domain_reads_urn_air_publisher() {
        assert_eq!(
            publisher_domain("urn:air:Acme.com:agent:finance").as_deref(),
            Some("acme.com")
        );
        assert_eq!(publisher_domain("urn:example:agent"), None);
        assert_eq!(publisher_domain("urn:air:"), None);
    }

    #[test]
    fn identity_domain_handles_supported_schemes() {
        assert_eq!(
            identity_domain("did:web:acme.com").as_deref(),
            Some("acme.com")
        );
        assert_eq!(
            identity_domain("did:web:acme.com%3A8443:user").as_deref(),
            Some("acme.com")
        );
        assert_eq!(
            identity_domain("urn:air:acme.com:agent:finance").as_deref(),
            Some("acme.com")
        );
        assert_eq!(
            identity_domain("spiffe://acme.com/workload").as_deref(),
            Some("acme.com")
        );
        assert_eq!(
            identity_domain("https://user@acme.com:8443/path").as_deref(),
            Some("acme.com")
        );
        assert_eq!(identity_domain("plain-identifier"), None);
    }

    #[test]
    fn identity_binds_by_domain_not_exact_match() {
        assert_eq!(
            identity_binds_to_entry("urn:air:acme.com:agent:finance", "did:web:acme.com"),
            Some(true)
        );
        assert_eq!(
            identity_binds_to_entry("urn:air:acme.com:agent:finance", "did:web:evil.example"),
            Some(false)
        );
        assert_eq!(
            identity_binds_to_entry("urn:example:agent", "did:web:acme.com"),
            None
        );
        assert_eq!(
            identity_binds_to_entry("urn:air:acme.com:agent:finance", "plain-identifier"),
            None
        );
    }
}
