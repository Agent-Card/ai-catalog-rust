# ai-catalog-discover

Find the [AI Catalog](https://ai-catalog.io/) of a website or domain, following the
[discovery procedure](https://ai-catalog.io/spec/#discovery) of the specification.

Given a URL or a bare domain, `discover` looks, in order, for

1. a catalog document at the URL itself,
2. a `Link` header with `rel="ai-catalog"`,
3. a `<link rel="ai-catalog">` element in an HTML document, and
4. a catalog at the well-known URI `/.well-known/ai-catalog.json`,

and returns the first valid catalog. A link that leads nowhere does not stop the search.

```rust
let found = ai_catalog_discover::discover("example.com")?;

println!("{} via {}", found.url, found.method); // Method::{Direct, LinkHeader, HtmlLink, WellKnown}
for entry in &found.catalog.entries {
    println!("{}", entry.identifier);
}
```

`Discovery` carries the catalog, the URL it was served from (resolve its relative
references against it) and the bytes as served, which is what a signature covers. When
nothing is found, `Error::NotFound` lists every URL that was tried and why it failed.

```sh
cargo run -p ai-catalog-discover --example discover -- example.com
```

## What counts as a catalog

A response that succeeded and holds a JSON document with a `specVersion`. The media type
is not checked: the specification prefers `application/ai-catalog+json` but accepts any
JSON type.

## Network behavior

- Only `https` is requested. Input with another scheme is rejected, and so are links to
  one. Redirects to `http` are refused.
- Requests time out after 30 seconds and bodies are limited to 10 MiB.
- The well-known URI is requested on the host that was reached after redirects, and on
  the one that was asked for if it differs.
- Discovery does not guard against requests to private addresses. A service that runs it
  for callers it does not trust must pass its own `Fetcher` to `discover_with`, one that
  checks where it connects.

```rust
use ai_catalog_discover::{discover_with, Fetcher, Response};

struct MyFetcher;
impl Fetcher for MyFetcher {
    fn get(&self, url: &url::Url) -> Result<Response, String> { todo!() }
}
let found = discover_with(&MyFetcher, "example.com")?;
```

Nested catalogs are not followed; discovery returns the catalog it finds.

## License

Apache-2.0
