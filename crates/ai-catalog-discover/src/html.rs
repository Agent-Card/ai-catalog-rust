// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// SPDX-License-Identifier: Apache-2.0

//! Finding `<link rel="ai-catalog">` elements in the head of an HTML document.

use std::sync::LazyLock;

use scraper::{Html, Selector};

/// What discovery reads from the head of a document: the `href` of the first `<base>`
/// element, and the `href` of every `<link>` element with the wanted relation type, in
/// document order.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Links {
    pub base: Option<String>,
    pub hrefs: Vec<String>,
}

static HEAD_ELEMENTS: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("head > base, head > link").expect("a valid selector"));

/// Parse `html` as a browser would and read the `<base>` and `<link>` elements of its head.
///
/// Elements that the HTML parser puts in the body, or that only appear in comments or in
/// raw-text elements such as `<script>`, are not seen.
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
    fn reads_attributes_in_any_style() {
        for html in [
            "<LINK REL=AI-CATALOG HREF=/c.json>",
            "<link href='/c.json' rel='ai-catalog' />",
            "<link\n  rel = \"ai-catalog\"\n  href = \"/c.json\"\n>",
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
    fn keeps_document_order_and_decodes_entities() {
        let html = r#"<link rel="ai-catalog" href="/a?x=1&amp;y=2">
            <link rel="ai-catalog" href="/b?x=1&#38;y=&#x32;&unknown;">"#;
        assert_eq!(hrefs(html), ["/a?x=1&y=2", "/b?x=1&y=2&unknown;"]);
    }

    #[test]
    fn markup_inside_comments_and_raw_text_is_not_a_link() {
        let html = r#"<!-- <link rel="ai-catalog" href="/commented"> -->
            <script>document.write('<link rel="ai-catalog" href="/script">')</script>
            <style>/* <link rel="ai-catalog" href="/style"> */</style>
            <title><link rel="ai-catalog" href="/title"></title>
            <link rel="ai-catalog" href="/real">"#;
        assert_eq!(hrefs(html), ["/real"]);
    }

    #[test]
    fn a_greater_than_sign_inside_a_value_does_not_end_the_tag() {
        let html = r#"<meta content="a > b"><link rel="ai-catalog" href="/c.json">"#;
        assert_eq!(hrefs(html), ["/c.json"]);
    }

    #[test]
    fn stops_at_the_end_of_the_head() {
        let html = r#"<head><link rel="ai-catalog" href="/head"></head>
            <body><link rel="ai-catalog" href="/body"></body>"#;
        assert_eq!(hrefs(html), ["/head"]);
        assert_eq!(
            hrefs(r#"<body><link rel="ai-catalog" href="/body">"#),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_link_the_parser_puts_in_the_body_is_not_in_the_head() {
        let html = r#"<p>text</p><link rel="ai-catalog" href="/body">"#;
        assert!(hrefs(html).is_empty());
        let html = r#"<html><link rel="ai-catalog" href="/implicit-head"><p>text</p>"#;
        assert_eq!(hrefs(html), ["/implicit-head"]);
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

    #[test]
    fn survives_garbage() {
        for html in [
            "",
            "<",
            "<<<>>>",
            "<link",
            "<link rel=",
            "<!--",
            "<link rel=\"ai-catalog",
            "ünï<cödé>",
        ] {
            let _ = hrefs(html);
        }
    }
}
