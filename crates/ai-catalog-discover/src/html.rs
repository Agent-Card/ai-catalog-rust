// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// SPDX-License-Identifier: Apache-2.0

//! Finding `<link rel="ai-catalog">` elements in the head of an HTML document.

use std::sync::LazyLock;

use scraper::{Html, Selector};

/// The first `<base href>` and every matching `<link href>` in the head, in document order.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Links {
    pub base: Option<String>,
    pub hrefs: Vec<String>,
}

static HEAD_ELEMENTS: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("head > base, head > link").expect("a valid selector"));

/// Only elements the HTML parser places in the head are seen, so links in comments, scripts
/// or the body are ignored.
pub(crate) fn find_links(html: &str, rel: &str) -> Links {
    let document = Html::parse_document(html);
    let mut links = Links::default();
    for element in document.select(&HEAD_ELEMENTS) {
        let value = element.value();
        let Some(href) = value.attr("href") else {
            continue;
        };
        match value.name() {
            "base" if links.base.is_none() => links.base = Some(href.to_string()),
            "link" if has_relation(value.attr("rel"), rel) && !href.trim().is_empty() => {
                links.hrefs.push(href.trim().to_string());
            }
            _ => {}
        }
    }
    links
}

fn has_relation(value: Option<&str>, rel: &str) -> bool {
    value.is_some_and(|value| {
        value
            .split_ascii_whitespace()
            .any(|token| token.eq_ignore_ascii_case(rel))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hrefs(html: &str) -> Vec<String> {
        find_links(html, "ai-catalog").hrefs
    }

    #[test]
    fn finds_the_specification_example() {
        let html = r#"<!doctype html><html><head>
            <link rel="ai-catalog" href="/catalog/ai.json"
                  type="application/ai-catalog+json">
            </head><body></body></html>"#;
        assert_eq!(hrefs(html), ["/catalog/ai.json"]);
    }

    #[test]
    fn matches_the_relation_token_case_insensitively() {
        for html in [
            "<LINK REL=AI-CATALOG HREF=/c.json>",
            r#"<link rel="alternate ai-catalog" href="/c.json">"#,
        ] {
            assert_eq!(hrefs(html), ["/c.json"], "{html}");
        }
    }

    #[test]
    fn ignores_other_relations_and_links_without_href() {
        let html = r#"<link rel="stylesheet" href="/a.css">
            <link rel="ai-catalogue" href="/x">
            <link rel="ai-catalog">
            <link rel="ai-catalog" href="">"#;
        assert!(hrefs(html).is_empty());
    }

    #[test]
    fn ignores_links_outside_the_head() {
        let html = r#"<!-- <link rel="ai-catalog" href="/commented"> -->
            <head><link rel="ai-catalog" href="/head"></head>
            <body><link rel="ai-catalog" href="/body"></body>"#;
        assert_eq!(hrefs(html), ["/head"]);
    }

    #[test]
    fn reports_the_base_element() {
        let links = find_links(
            r#"<base href="https://cdn.example/x/"><link rel="ai-catalog" href="c.json">"#,
            "ai-catalog",
        );
        assert_eq!(links.base.as_deref(), Some("https://cdn.example/x/"));
        assert_eq!(links.hrefs, ["c.json"]);
    }
}
