// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{CONTENT_TYPE, LINK};
use reqwest::redirect::Policy;
use url::Url;

/// Largest response body that is read.
pub const MAX_BODY_BYTES: u64 = 10 * 1024 * 1024;

const MAX_REDIRECTS: usize = 10;

/// An HTTP response, reduced to what discovery looks at.
#[derive(Debug, Clone)]
pub struct Response {
    /// The URL the body was served from, after redirects.
    pub url: Url,
    pub status: u16,
    pub content_type: Option<String>,
    /// The value of every `Link` header field.
    pub link_headers: Vec<String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub(crate) fn is_html(&self) -> bool {
        self.content_type.as_deref().is_some_and(|value| {
            let media_type = value.split(';').next().unwrap_or("").trim();
            media_type.eq_ignore_ascii_case("text/html")
                || media_type.eq_ignore_ascii_case("application/xhtml+xml")
        })
    }
}

/// Performs the GET requests of discovery. Implement it to use another HTTP client,
/// to add authentication or caching, or to restrict where requests may go.
///
/// A response with an error status is a `Response`, not an error; the error is for a
/// request that got no response at all.
pub trait Fetcher {
    fn get(&self, url: &Url) -> Result<Response, String>;
}

/// The default [`Fetcher`], backed by a blocking `reqwest` client.
///
/// It follows redirects only to `https` URLs, gives up after 30 seconds and refuses
/// bodies over 10 MiB. It does not guard against requests to private addresses; a
/// service that runs discovery on behalf of untrusted callers must supply a
/// [`Fetcher`] that does.
pub struct HttpFetcher {
    client: Client,
}

impl HttpFetcher {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .user_agent(concat!("ai-catalog-discover/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .redirect(Policy::custom(|attempt| {
                if attempt.url().scheme() != "https" {
                    attempt.error("refusing to follow a redirect to a non-https URL")
                } else if attempt.previous().len() >= MAX_REDIRECTS {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            }))
            .build()?;
        Ok(Self { client })
    }

    /// Use a client of your own. Its redirect policy is yours to set.
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

impl Fetcher for HttpFetcher {
    fn get(&self, url: &Url) -> Result<Response, String> {
        let response = self.client.get(url.clone()).send().map_err(describe)?;
        let header = |name| {
            response
                .headers()
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok().map(str::to_string))
                .collect::<Vec<_>>()
        };
        let link_headers = header(LINK);
        let content_type = header(CONTENT_TYPE).into_iter().next();
        let (status, url) = (response.status().as_u16(), response.url().clone());

        let mut body = Vec::new();
        response
            .take(MAX_BODY_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("reading the response failed: {e}"))?;
        if body.len() as u64 > MAX_BODY_BYTES {
            return Err(format!(
                "the response is larger than {} MiB",
                MAX_BODY_BYTES / 1024 / 1024
            ));
        }
        Ok(Response {
            url,
            status,
            content_type,
            link_headers,
            body,
        })
    }
}

/// The message of an error, with its causes: `reqwest` keeps the useful part
/// (a refused connection, a certificate problem) in the source.
fn describe(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut message = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// Answer one request with `raw` and return the base URL of the server.
    fn serve_once(raw: &'static str) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!("http://{}/page", listener.local_addr().unwrap())).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 1024];
            let _ = stream.read(&mut buf);
            stream.write_all(raw.as_bytes()).unwrap();
        });
        url
    }

    #[test]
    fn reads_status_headers_and_body() {
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
             Link: </a>; rel=ai-catalog\r\nLink: </b>; rel=next\r\n\
             Content-Length: 2\r\nConnection: close\r\n\r\nhi",
        );
        let response = HttpFetcher::new().unwrap().get(&url).unwrap();

        assert_eq!(response.status, 200);
        assert!(response.is_html());
        assert_eq!(
            response.link_headers,
            ["</a>; rel=ai-catalog", "</b>; rel=next"]
        );
        assert_eq!(response.body, b"hi");
        assert_eq!(response.url, url);
    }

    #[test]
    fn an_error_status_is_a_response() {
        let url =
            serve_once("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let response = HttpFetcher::new().unwrap().get(&url).unwrap();

        assert_eq!(response.status, 404);
        assert!(!response.is_success());
    }

    #[test]
    fn a_refused_connection_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        drop(listener);

        assert!(HttpFetcher::new().unwrap().get(&url).is_err());
    }
}
