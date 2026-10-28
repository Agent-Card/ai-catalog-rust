// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// SPDX-License-Identifier: Apache-2.0

//! Find the AI Catalog of a website or domain, following the discovery procedure of the
//! specification (<https://ai-catalog.io/spec/#discovery>).
//!
//! Given a URL or a bare domain, [`discover`] looks, in order, for
//!
//! 1. a catalog document at the URL itself,
//! 2. a `Link` header with `rel="ai-catalog"`,
//! 3. a `<link rel="ai-catalog">` element in an HTML document, and
//! 4. a catalog at the well-known URI `/.well-known/ai-catalog.json`,
//!
//! and returns the first valid catalog it finds.
//!
//! ```no_run
//! let found = ai_catalog_discover::discover("example.com")?;
//! println!("{} via {}", found.url, found.method);
//! for entry in &found.catalog.entries {
//!     println!("{}", entry.identifier);
//! }
//! # Ok::<(), ai_catalog_discover::Error>(())
//! ```

mod html;
mod http;
mod link;

use std::collections::HashSet;
use std::fmt;

use ai_catalog::AiCatalog;
use url::Url;

pub use http::{Fetcher, HttpFetcher, MAX_BODY_BYTES, Response};

/// The well-known URI path of an AI Catalog (RFC 8615).
pub const WELL_KNOWN_PATH: &str = "/.well-known/ai-catalog.json";

/// The link relation type that points to an AI Catalog (RFC 8288).
pub const LINK_RELATION: &str = "ai-catalog";

/// How a catalog was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// The URL that was given is itself a catalog document.
    Direct,
    /// An `ai-catalog` relation in an HTTP `Link` header.
    LinkHeader,
    /// An `ai-catalog` `<link>` element in an HTML document.
    HtmlLink,
    /// The well-known URI.
    WellKnown,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::LinkHeader => "link-header",
            Self::HtmlLink => "html-link",
            Self::WellKnown => "well-known",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A catalog that was found.
#[derive(Debug, Clone)]
pub struct Discovery {
    /// Where the catalog was served from, after redirects. Relative references in the
    /// catalog resolve against it.
    pub url: String,
    pub method: Method,
    pub catalog: AiCatalog,
    /// The document as served. Signatures are verified against these bytes, and a
    /// re-serialized `catalog` drops what the SDK does not model.
    pub bytes: Vec<u8>,
}

/// A URL that was tried and did not lead to a catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub url: String,
    pub method: Method,
    pub reason: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot discover a catalog from \"{input}\": {reason}")]
    InvalidInput { input: String, reason: String },
    #[error("cannot create the HTTP client: {0}")]
    Client(String),
    #[error("{}", not_found(.input, .attempts))]
    NotFound {
        input: String,
        attempts: Vec<Attempt>,
    },
}

fn not_found(input: &str, attempts: &[Attempt]) -> String {
    let mut message = format!("no AI Catalog found for \"{input}\"");
    for attempt in attempts {
        message.push_str(&format!(
            "\n  {} ({}): {}",
            attempt.url, attempt.method, attempt.reason
        ));
    }
    message
}

pub type Result<T> = std::result::Result<T, Error>;

/// Discover the catalog of `input`, a URL or a bare domain (`https` is assumed).
pub fn discover(input: &str) -> Result<Discovery> {
    let fetcher = HttpFetcher::new().map_err(|e| Error::Client(e.to_string()))?;
    discover_with(&fetcher, input)
}

/// Like [`discover`], with the requests made by `fetcher`.
///
/// Only `https` URLs are requested. A link that points somewhere else, or at another
/// host, is followed when it is `https`: a site may keep its catalog elsewhere.
pub fn discover_with(fetcher: &dyn Fetcher, input: &str) -> Result<Discovery> {
    let start = parse_input(input)?;
    let mut attempts = Vec::new();
    let mut requested = HashSet::new();
    let mut candidates: Vec<(Url, Method)> = Vec::new();
    let mut well_known_bases = vec![start.clone()];

    requested.insert(request_key(&start));
    match fetcher.get(&start) {
        Err(reason) => attempts.push(attempt(&start, Method::Direct, reason)),
        Ok(response) => {
            // After a redirect, `www.example.com` is the host that was reached.
            if response.url.origin() != start.origin() {
                well_known_bases.insert(0, response.url.clone());
            }
            match as_catalog(&response) {
                Ok(catalog) => return Ok(found(response, Method::Direct, catalog)),
                Err(reason) => attempts.push(attempt(&response.url, Method::Direct, reason)),
            }
            if response.is_success() {
                candidates.extend(
                    link_header_targets(&response)
                        .into_iter()
                        .map(|t| (t, Method::LinkHeader)),
                );
                if response.is_html() {
                    candidates.extend(
                        html_link_targets(&response)
                            .into_iter()
                            .map(|t| (t, Method::HtmlLink)),
                    );
                }
            }
        }
    }
    let mut unresolved = std::mem::take(&mut attempts);
    // Keep what went wrong reading the links themselves.
    candidates.retain(|(url, method)| {
        if url.scheme() == "https" {
            return true;
        }
        unresolved.push(attempt(url, *method, "not an https URL".to_string()));
        false
    });
    for base in well_known_bases {
        if let Ok(url) = base.join(WELL_KNOWN_PATH) {
            candidates.push((url, Method::WellKnown));
        }
    }

    attempts = unresolved;
    for (url, method) in candidates {
        if !requested.insert(request_key(&url)) {
            continue;
        }
        match fetcher.get(&url) {
            Err(reason) => attempts.push(attempt(&url, method, reason)),
            Ok(response) => match as_catalog(&response) {
                Ok(catalog) => return Ok(found(response, method, catalog)),
                Err(reason) => attempts.push(attempt(&response.url, method, reason)),
            },
        }
    }
    Err(Error::NotFound {
        input: input.trim().to_string(),
        attempts,
    })
}

fn parse_input(input: &str) -> Result<Url> {
    let invalid = |reason: String| Error::InvalidInput {
        input: input.to_string(),
        reason,
    };
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid("the input is empty".into()));
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let url = Url::parse(&with_scheme).map_err(|e| invalid(e.to_string()))?;
    if url.scheme() != "https" {
        return Err(invalid(format!(
            "only https URLs are supported, not {}",
            url.scheme()
        )));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid("the URL has no host".into()));
    }
    Ok(url)
}

/// A URL without its fragment, which is never sent to the server.
fn request_key(url: &Url) -> String {
    let mut url = url.clone();
    url.set_fragment(None);
    url.into()
}

fn attempt(url: &Url, method: Method, reason: String) -> Attempt {
    Attempt {
        url: url.to_string(),
        method,
        reason,
    }
}

fn found(response: Response, method: Method, catalog: AiCatalog) -> Discovery {
    Discovery {
        url: response.url.to_string(),
        method,
        catalog,
        bytes: response.body,
    }
}

/// A response is a catalog when it succeeded and holds a JSON document with a
/// `specVersion`. The media type is not checked, as the specification accepts any JSON type.
fn as_catalog(response: &Response) -> std::result::Result<AiCatalog, String> {
    if !response.is_success() {
        return Err(format!("HTTP {}", response.status));
    }
    let catalog = ai_catalog::parse_slice(&response.body).map_err(|e| {
        if response.is_html() {
            "an HTML page, not an AI Catalog".to_string()
        } else {
            format!("not an AI Catalog document: {e}")
        }
    })?;
    if catalog.spec_version.trim().is_empty() {
        return Err("not an AI Catalog document: no specVersion".to_string());
    }
    Ok(catalog)
}

fn link_header_targets(response: &Response) -> Vec<Url> {
    let targets = link::targets_with_rel(
        response.link_headers.iter().map(String::as_str),
        LINK_RELATION,
    );
    resolve(&response.url, targets)
}

fn html_link_targets(response: &Response) -> Vec<Url> {
    let html = String::from_utf8_lossy(&response.body);
    let links = html::find_links(&html, LINK_RELATION);
    // A `<base href>` changes what the other references resolve against.
    let base = links
        .base
        .and_then(|base| response.url.join(&base).ok())
        .unwrap_or_else(|| response.url.clone());
    resolve(&base, links.hrefs)
}

/// Resolve references against `base`, dropping the ones that are not URLs.
fn resolve(base: &Url, references: Vec<String>) -> Vec<Url> {
    references
        .iter()
        .filter_map(|reference| base.join(reference).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;

    const CATALOG: &str = r#"{"specVersion": "1.0", "entries": []}"#;

    /// Serves canned responses, and records the requests.
    #[derive(Default)]
    struct Mock {
        responses: HashMap<String, std::result::Result<Response, String>>,
        requests: RefCell<Vec<String>>,
    }

    impl Mock {
        fn serve(
            mut self,
            url: &str,
            status: u16,
            content_type: &str,
            links: &[&str],
            body: &str,
        ) -> Self {
            let response = Response {
                url: Url::parse(url).unwrap(),
                status,
                content_type: Some(content_type.to_string()),
                link_headers: links.iter().map(|l| l.to_string()).collect(),
                body: body.as_bytes().to_vec(),
            };
            self.responses.insert(url.to_string(), Ok(response));
            self
        }

        fn catalog(self, url: &str) -> Self {
            self.serve(url, 200, "application/ai-catalog+json", &[], CATALOG)
        }

        fn html(self, url: &str, links: &[&str], body: &str) -> Self {
            self.serve(url, 200, "text/html; charset=utf-8", links, body)
        }

        fn redirect(mut self, from: &str, to: &str) -> Self {
            let mut response = self.responses[to].clone().unwrap();
            response.url = Url::parse(to).unwrap();
            self.responses.insert(from.to_string(), Ok(response));
            self
        }

        fn fail(mut self, url: &str, reason: &str) -> Self {
            self.responses.insert(url.to_string(), Err(reason.into()));
            self
        }

        fn requested(&self) -> Vec<String> {
            self.requests.borrow().clone()
        }
    }

    impl Fetcher for Mock {
        fn get(&self, url: &Url) -> std::result::Result<Response, String> {
            self.requests.borrow_mut().push(url.to_string());
            self.responses
                .get(url.as_str())
                .cloned()
                .unwrap_or_else(|| {
                    Ok(Response {
                        url: url.clone(),
                        status: 404,
                        content_type: None,
                        link_headers: vec![],
                        body: vec![],
                    })
                })
        }
    }

    #[test]
    fn a_url_that_is_a_catalog_is_used_as_is() {
        let mock = Mock::default().catalog("https://example.com/ai.json");

        let found = discover_with(&mock, "https://example.com/ai.json").unwrap();

        assert_eq!(found.method, Method::Direct);
        assert_eq!(found.url, "https://example.com/ai.json");
        assert_eq!(found.bytes, CATALOG.as_bytes());
        assert_eq!(mock.requested(), ["https://example.com/ai.json"]);
    }

    #[test]
    fn a_catalog_served_as_plain_text_is_accepted() {
        let mock = Mock::default().serve(
            "https://example.com/ai.json",
            200,
            "text/plain",
            &[],
            CATALOG,
        );

        let found = discover_with(&mock, "https://example.com/ai.json").unwrap();

        assert_eq!(found.method, Method::Direct);
    }

    #[test]
    fn a_bare_domain_gets_https() {
        let mock = Mock::default().catalog("https://example.com/");

        let found = discover_with(&mock, "  example.com ").unwrap();

        assert_eq!(found.url, "https://example.com/");
    }

    #[test]
    fn follows_a_link_header() {
        let mock = Mock::default()
            .html(
                "https://example.com/",
                &[r#"</catalog/ai.json>; rel="ai-catalog""#],
                "<html></html>",
            )
            .catalog("https://example.com/catalog/ai.json");

        let found = discover_with(&mock, "example.com").unwrap();

        assert_eq!(found.method, Method::LinkHeader);
        assert_eq!(found.url, "https://example.com/catalog/ai.json");
    }

    #[test]
    fn follows_an_html_link_element() {
        let mock = Mock::default()
            .html(
                "https://example.com/docs/",
                &[],
                r#"<head><link rel="ai-catalog" href="../ai.json"
                    type="application/ai-catalog+json"></head>"#,
            )
            .catalog("https://example.com/ai.json");

        let found = discover_with(&mock, "https://example.com/docs/").unwrap();

        assert_eq!(found.method, Method::HtmlLink);
        assert_eq!(found.url, "https://example.com/ai.json");
    }

    #[test]
    fn falls_back_to_the_well_known_uri() {
        let mock = Mock::default()
            .html("https://example.com/", &[], "<html><head></head></html>")
            .catalog("https://example.com/.well-known/ai-catalog.json");

        let found = discover_with(&mock, "example.com").unwrap();

        assert_eq!(found.method, Method::WellKnown);
    }

    #[test]
    fn the_well_known_uri_is_tried_when_the_page_cannot_be_fetched() {
        let mock = Mock::default()
            .fail("https://example.com/", "connection reset")
            .catalog("https://example.com/.well-known/ai-catalog.json");

        assert_eq!(
            discover_with(&mock, "example.com").unwrap().method,
            Method::WellKnown
        );
    }

    #[test]
    fn the_well_known_uri_of_the_host_after_a_redirect_is_tried_first() {
        let mock = Mock::default()
            .html("https://www.example.com/", &[], "<html></html>")
            .redirect("https://example.com/", "https://www.example.com/")
            .catalog("https://www.example.com/.well-known/ai-catalog.json");

        let found = discover_with(&mock, "example.com").unwrap();

        assert_eq!(
            found.url,
            "https://www.example.com/.well-known/ai-catalog.json"
        );
        assert_eq!(
            mock.requested().last().unwrap(),
            "https://www.example.com/.well-known/ai-catalog.json"
        );
    }

    #[test]
    fn a_link_header_wins_over_an_html_link_and_the_well_known_uri() {
        let mock = Mock::default()
            .html(
                "https://example.com/",
                &["</from-header.json>; rel=ai-catalog"],
                r#"<link rel="ai-catalog" href="/from-html.json">"#,
            )
            .catalog("https://example.com/from-header.json")
            .catalog("https://example.com/from-html.json")
            .catalog("https://example.com/.well-known/ai-catalog.json");

        let found = discover_with(&mock, "example.com").unwrap();

        assert_eq!(found.method, Method::LinkHeader);
        assert_eq!(mock.requested().len(), 2);
    }

    #[test]
    fn a_broken_link_does_not_stop_discovery() {
        let mock = Mock::default()
            .html(
                "https://example.com/",
                &["</gone.json>; rel=ai-catalog"],
                r#"<link rel="ai-catalog" href="/not-a-catalog.json">"#,
            )
            .serve(
                "https://example.com/not-a-catalog.json",
                200,
                "application/json",
                &[],
                r#"{"hello": 1}"#,
            )
            .catalog("https://example.com/.well-known/ai-catalog.json");

        let found = discover_with(&mock, "example.com").unwrap();

        assert_eq!(found.method, Method::WellKnown);
    }

    #[test]
    fn a_url_is_requested_once() {
        let mock = Mock::default().html(
            "https://example.com/",
            &["</.well-known/ai-catalog.json>; rel=ai-catalog"],
            r#"<link rel="ai-catalog" href="/.well-known/ai-catalog.json">"#,
        );

        assert!(discover_with(&mock, "example.com").is_err());
        assert_eq!(
            mock.requested(),
            [
                "https://example.com/",
                "https://example.com/.well-known/ai-catalog.json"
            ]
        );
    }

    #[test]
    fn links_to_other_schemes_are_not_followed() {
        let mock = Mock::default().html(
            "https://example.com/",
            &[
                "<http://example.com/ai.json>; rel=ai-catalog",
                "<file:///etc/passwd>; rel=ai-catalog",
            ],
            "",
        );

        let error = discover_with(&mock, "example.com").unwrap_err();

        assert!(
            mock.requested()
                .iter()
                .all(|url| url.starts_with("https://"))
        );
        assert!(error.to_string().contains("not an https URL"), "{error}");
    }

    #[test]
    fn a_document_without_a_spec_version_is_not_a_catalog() {
        for body in [
            "{}",
            r#"{"entries": []}"#,
            r#"{"specVersion": " "}"#,
            "[]",
            "null",
        ] {
            let mock = Mock::default().serve(
                "https://example.com/ai.json",
                200,
                "application/json",
                &[],
                body,
            );
            assert!(
                discover_with(&mock, "https://example.com/ai.json").is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn an_error_names_everything_that_was_tried() {
        let mock = Mock::default().html("https://example.com/", &[], "<html></html>");

        let error = discover_with(&mock, "example.com").unwrap_err();

        let Error::NotFound { attempts, .. } = &error else {
            panic!("{error}")
        };
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].method, Method::Direct);
        assert!(
            attempts[0].reason.contains("HTML"),
            "{}",
            attempts[0].reason
        );
        assert_eq!(attempts[1].method, Method::WellKnown);
        assert_eq!(attempts[1].reason, "HTTP 404");
        assert!(error.to_string().contains("/.well-known/ai-catalog.json"));
    }

    #[test]
    fn rejects_inputs_that_are_not_https_urls() {
        let mock = Mock::default();
        for input in [
            "",
            "   ",
            "http://example.com",
            "ftp://example.com",
            "file:///tmp/a.json",
            "https://",
            "exa mple.com",
        ] {
            assert!(
                matches!(discover_with(&mock, input), Err(Error::InvalidInput { .. })),
                "{input:?}"
            );
        }
        assert!(mock.requested().is_empty());
    }
}
