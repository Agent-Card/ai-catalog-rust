// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// SPDX-License-Identifier: Apache-2.0

//! Parsing of the HTTP `Link` header (RFC 8288).

/// One link of a `Link` header that carries a `rel` parameter.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Link {
    pub target: String,
    /// The space-separated relation types of `rel`, lowercased.
    pub rel: Vec<String>,
}

/// The targets of the links in `headers` that have the relation type `rel`, in order.
///
/// Links with an `anchor` parameter describe another resource than the one that
/// was requested and are skipped.
pub(crate) fn targets_with_rel<'a>(
    headers: impl IntoIterator<Item = &'a str>,
    rel: &str,
) -> Vec<String> {
    headers
        .into_iter()
        .flat_map(parse)
        .filter(|link| link.rel.iter().any(|r| r == rel))
        .map(|link| link.target)
        .collect()
}

/// Parse one `Link` header field value. Malformed links are skipped, not reported.
pub(crate) fn parse(value: &str) -> Vec<Link> {
    let mut links = Vec::new();
    let mut rest = value;
    loop {
        rest = rest.trim_start_matches([' ', '\t', ',']);
        let Some(after_open) = rest.strip_prefix('<') else {
            // Junk between links: resume at the next comma, if any.
            match rest.find(',') {
                Some(i) => {
                    rest = &rest[i..];
                    continue;
                }
                None => break,
            }
        };
        let Some(close) = after_open.find('>') else {
            break;
        };
        let target = after_open[..close].trim().to_string();
        let (params, remainder) = parse_params(&after_open[close + 1..]);
        rest = remainder;

        let mut rel = None;
        let mut anchored = false;
        for (name, value) in params {
            match name.as_str() {
                // Only the first `rel` counts.
                "rel" if rel.is_none() => rel = value,
                "anchor" => anchored = true,
                _ => {}
            }
        }
        if let (Some(rel), false) = (rel, anchored) {
            links.push(Link {
                target,
                rel: rel
                    .split_ascii_whitespace()
                    .map(str::to_ascii_lowercase)
                    .collect(),
            });
        }
    }
    links
}

/// Parse `; name=value` parameters up to the next link-separating comma.
/// Returns the parameters and the unparsed rest, starting at that comma.
fn parse_params(mut rest: &str) -> (Vec<(String, Option<String>)>, &str) {
    let mut params = Vec::new();
    loop {
        rest = rest.trim_start_matches([' ', '\t']);
        let Some(after) = rest.strip_prefix(';') else {
            // Anything but a comma here is junk; skip to the next link.
            return (params, rest.find(',').map_or("", |i| &rest[i..]));
        };
        rest = after.trim_start_matches([' ', '\t']);
        let name_end = rest
            .find(|c: char| matches!(c, '=' | ';' | ',') || c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let name = rest[..name_end].to_ascii_lowercase();
        rest = rest[name_end..].trim_start_matches([' ', '\t']);
        let value = if let Some(after_eq) = rest.strip_prefix('=') {
            let (value, remainder) = parse_value(after_eq.trim_start_matches([' ', '\t']));
            rest = remainder;
            Some(value)
        } else {
            None
        };
        if !name.is_empty() {
            params.push((name, value));
        }
    }
}

/// A token or a quoted string; returns the value and the unparsed rest.
fn parse_value(input: &str) -> (String, &str) {
    let Some(quoted) = input.strip_prefix('"') else {
        let end = input
            .find(|c: char| matches!(c, ';' | ',') || c.is_ascii_whitespace())
            .unwrap_or(input.len());
        return (input[..end].to_string(), &input[end..]);
    };
    let mut value = String::new();
    let mut chars = quoted.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return (value, &quoted[i + 1..]),
            '\\' => {
                if let Some((_, escaped)) = chars.next() {
                    value.push(escaped);
                }
            }
            _ => value.push(c),
        }
    }
    (value, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(value: &str) -> Vec<String> {
        targets_with_rel([value], "ai-catalog")
    }

    #[test]
    fn parses_the_specification_example() {
        assert_eq!(
            targets(r#"<https://example.com/catalog/ai.json>; rel="ai-catalog""#),
            ["https://example.com/catalog/ai.json"]
        );
    }

    #[test]
    fn picks_the_matching_link_out_of_several() {
        let value = r#"</style.css>; rel=preload; as=style, <https://a.example/ai.json>; rel="ai-catalog"; type="application/ai-catalog+json", </next>; rel=next"#;
        assert_eq!(targets(value), ["https://a.example/ai.json"]);
    }

    #[test]
    fn matches_the_relation_token() {
        assert_eq!(targets("</c.json>; REL=ai-catalog"), ["/c.json"]);
        assert_eq!(
            targets(r#"</c.json>; rel="alternate ai-catalog""#),
            ["/c.json"]
        );
        assert!(targets(r#"</c.json>; rel="ai-catalogs""#).is_empty());
    }

    #[test]
    fn commas_and_semicolons_inside_quotes_do_not_split() {
        let value = r#"</a?x=1,2>; title="a, b; c"; rel="ai-catalog""#;
        assert_eq!(targets(value), ["/a?x=1,2"]);
    }

    #[test]
    fn only_the_first_rel_counts() {
        assert!(targets(r#"</a>; rel=next; rel="ai-catalog""#).is_empty());
    }

    #[test]
    fn links_about_another_resource_are_skipped() {
        assert!(targets(r##"</a>; rel="ai-catalog"; anchor="#frag""##).is_empty());
    }

    #[test]
    fn malformed_values_yield_nothing() {
        for value in [
            "",
            "garbage",
            "<unterminated; rel=ai-catalog",
            "</a>",
            "</a>; rel",
        ] {
            assert!(targets(value).is_empty(), "{value:?}");
        }
        assert_eq!(targets("junk, </b>; rel=ai-catalog"), ["/b"]);
        assert_eq!(targets("</a> junk, </b>; rel=ai-catalog"), ["/b"]);
    }
}
