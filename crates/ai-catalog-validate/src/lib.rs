// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Validates AI Catalog documents against the specification and detects their
//! conformance level.

mod code;
mod identity;
mod jws;
mod manifest;
mod profile;
mod signature;

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::LazyLock;
use std::time::SystemTime;

use ai_catalog::{AiCatalog, CatalogEntry, HostInfo, Publisher};
use regex::Regex;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub use code::Code;

const DEFAULT_MAX_NESTING_DEPTH: usize = 4;
const MAX_SUPPORTED_MAJOR: u64 = 1;

/// The conformance level a document satisfies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConformanceLevel {
    /// A document with errors, or without a host.
    Minimal,
    /// A valid document with a host.
    Discoverable,
    /// A discoverable document in which every root entry that carries trust manifests has one
    /// signed by its publisher under the did:web Publisher Profile, bound to the entry and
    /// current. Signatures are not verified.
    Trusted,
}

impl fmt::Display for ConformanceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Minimal => "minimal",
            Self::Discoverable => "discoverable",
            Self::Trusted => "trusted",
        })
    }
}

/// A single validation error or warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: Code,
    pub path: String,
    pub message: String,
}

/// The outcome of validating an AI Catalog document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub conformance_level: ConformanceLevel,
    pub errors: Vec<Diagnostic>,
    /// Advisory problems, including did:web profile violations.
    pub warnings: Vec<Diagnostic>,
}

/// Customizes [`validate_with`].
#[derive(Debug, Clone)]
pub struct Options {
    now: Option<SystemTime>,
    max_nesting_depth: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            now: None,
            max_nesting_depth: DEFAULT_MAX_NESTING_DEPTH,
        }
    }
}

impl Options {
    /// Sets the time against which signature validity is judged. Defaults to the current time.
    #[must_use]
    pub fn with_clock(mut self, now: SystemTime) -> Self {
        self.now = Some(now);
        self
    }

    /// Sets how deeply catalogs may nest. The default is 4.
    #[must_use]
    pub fn with_max_nesting_depth(mut self, depth: usize) -> Self {
        self.max_nesting_depth = depth;
        self
    }
}

/// Validates the catalog with the default [`Options`].
#[must_use]
pub fn validate(catalog: &AiCatalog) -> ValidationResult {
    validate_with(catalog, &Options::default())
}

/// Validates the catalog against the AI Catalog specification.
#[must_use]
pub fn validate_with(catalog: &AiCatalog, options: &Options) -> ValidationResult {
    let mut validator = Validator {
        now: options
            .now
            .map_or_else(OffsetDateTime::now_utc, OffsetDateTime::from),
        max_depth: options.max_nesting_depth,
        errors: Vec::new(),
        warnings: Vec::new(),
        entries_with_manifests: 0,
        held_back: false,
    };

    validator.validate_catalog(catalog, "catalog", 0);

    ValidationResult {
        is_valid: validator.errors.is_empty(),
        conformance_level: validator.level(catalog),
        errors: validator.errors,
        warnings: validator.warnings,
    }
}

struct Validator {
    now: OffsetDateTime,
    max_depth: usize,
    errors: Vec<Diagnostic>,
    warnings: Vec<Diagnostic>,
    /// Counts the root entries carrying trust manifests; `held_back` is set when one of them has
    /// no manifest ready to be trusted.
    entries_with_manifests: usize,
    held_back: bool,
}

impl Validator {
    fn error(&mut self, code: Code, path: impl Into<String>, message: impl Into<String>) {
        self.errors.push(Diagnostic {
            code,
            path: path.into(),
            message: message.into(),
        });
    }

    fn warning(&mut self, code: Code, path: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(Diagnostic {
            code,
            path: path.into(),
            message: message.into(),
        });
    }

    fn level(&self, catalog: &AiCatalog) -> ConformanceLevel {
        if !self.errors.is_empty() || catalog.host.is_none() {
            ConformanceLevel::Minimal
        } else if self.entries_with_manifests > 0 && !self.held_back {
            ConformanceLevel::Trusted
        } else {
            ConformanceLevel::Discoverable
        }
    }

    fn validate_catalog(&mut self, catalog: &AiCatalog, path: &str, depth: usize) {
        self.validate_spec_version(&catalog.spec_version, &format!("{path}.specVersion"));
        self.validate_host(catalog.host.as_ref(), &format!("{path}.host"));

        if let Some(signature) = &catalog.signature {
            self.validate_signature(
                signature,
                signature::Kind::Catalog,
                &format!("{path}.signature"),
            );
        }

        self.validate_extension_keys(catalog.extensions.as_ref(), &format!("{path}.extensions"));
        self.validate_entry_uniqueness(&catalog.entries, path);

        for (index, entry) in catalog.entries.iter().enumerate() {
            self.validate_entry(entry, &format!("{path}.entries[{index}]"), depth);
        }
    }

    fn validate_host(&mut self, host: Option<&HostInfo>, path: &str) {
        if host.is_some_and(|host| host.display_name.is_empty()) {
            self.error(
                Code::HostMember,
                format!("{path}.displayName"),
                "host.displayName is required and must not be empty",
            );
        }
    }

    fn validate_entry_uniqueness(&mut self, entries: &[CatalogEntry], path: &str) {
        let mut seen_versioned: HashSet<(&str, &str)> = HashSet::new();
        let mut seen_unversioned: HashSet<&str> = HashSet::new();
        let mut versioned_ids: HashSet<&str> = HashSet::new();

        for (index, entry) in entries.iter().enumerate() {
            let entry_path = format!("{path}.entries[{index}]");
            let identifier = entry.identifier.as_str();
            let version = text(&entry.version);

            if version.is_empty() {
                if seen_unversioned.contains(identifier) || versioned_ids.contains(identifier) {
                    self.error(
                        Code::EntryDuplicate,
                        entry_path,
                        format!(
                            "duplicate identifier {identifier:?} without version differentiation"
                        ),
                    );
                }

                seen_unversioned.insert(identifier);
                continue;
            }

            if seen_unversioned.contains(identifier) {
                self.error(
                    Code::EntryVersion,
                    format!("{entry_path}.identifier"),
                    format!("identifier {identifier:?} cannot appear with and without version"),
                );
            }

            if !seen_versioned.insert((identifier, version)) {
                self.error(
                    Code::EntryDuplicate,
                    entry_path,
                    format!("duplicate (identifier, version) pair: ({identifier:?}, {version:?})"),
                );
            }

            versioned_ids.insert(identifier);
        }
    }

    fn validate_entry(&mut self, entry: &CatalogEntry, path: &str, depth: usize) {
        if entry.identifier.is_empty() {
            self.error(
                Code::EntryMember,
                format!("{path}.identifier"),
                "identifier is required and must not be empty",
            );
        }

        if entry.entry_type.is_empty() {
            self.error(
                Code::EntryMember,
                format!("{path}.type"),
                "type is required and must not be empty",
            );
        }

        match (!text(&entry.url).is_empty(), entry.data.is_some()) {
            (true, true) => self.error(
                Code::EntryArtifact,
                path,
                "entry must have exactly one of 'url' or 'data', found both",
            ),
            (false, false) => self.error(
                Code::EntryArtifact,
                path,
                "entry must have exactly one of 'url' or 'data'",
            ),
            _ => {}
        }

        self.validate_timestamp(text(&entry.updated_at), &format!("{path}.updatedAt"));
        self.validate_extension_keys(entry.extensions.as_ref(), &format!("{path}.extensions"));
        self.validate_policy_urls(entry.extensions.as_ref(), &format!("{path}.extensions"));
        self.validate_publisher(entry.publisher.as_ref(), &format!("{path}.publisher"));
        self.validate_entry_trust(entry, path, depth);
        self.validate_nested_catalog(entry, path, depth);

        if !entry.identifier.is_empty() && !entry.identifier.contains(':') {
            self.warning(
                Code::IdentifierNotUri,
                format!("{path}.identifier"),
                "identifier SHOULD be a URN or URI",
            );
        }
    }

    fn validate_publisher(&mut self, publisher: Option<&Publisher>, path: &str) {
        let Some(publisher) = publisher else {
            return;
        };

        if publisher.identifier.is_empty() {
            self.error(
                Code::PublisherMember,
                format!("{path}.identifier"),
                "publisher.identifier is required and must not be empty",
            );
        }

        if publisher.display_name.is_empty() {
            self.error(
                Code::PublisherMember,
                format!("{path}.displayName"),
                "publisher.displayName is required and must not be empty",
            );
        }
    }

    fn validate_timestamp(&mut self, value: &str, path: &str) {
        if value.is_empty() || OffsetDateTime::parse(value, &Rfc3339).is_ok() {
            return;
        }

        let name = path.rsplit('.').next().unwrap_or(path);

        self.error(
            Code::Timestamp,
            path,
            format!("{name} is not a valid RFC 3339 datetime: {value:?}"),
        );
    }

    fn validate_nested_catalog(&mut self, entry: &CatalogEntry, path: &str, depth: usize) {
        if !entry.is_nested_catalog() {
            return;
        }

        if depth >= self.max_depth {
            self.error(
                Code::NestedDepth,
                path,
                format!(
                    "nested catalog depth exceeds recommended limit of {}",
                    self.max_depth
                ),
            );
            return;
        }

        let Some(data) = &entry.data else {
            return;
        };

        match serde_json::from_value::<AiCatalog>(data.clone()) {
            Ok(nested) => self.validate_catalog(&nested, &format!("{path}.data"), depth + 1),
            Err(error) => self.error(
                Code::NestedInvalid,
                format!("{path}.data"),
                format!("nested catalog data is not a valid AI Catalog: {error}"),
            ),
        }
    }

    fn validate_extension_keys(
        &mut self,
        extensions: Option<&BTreeMap<String, serde_json::Value>>,
        path: &str,
    ) {
        for key in extensions.into_iter().flat_map(BTreeMap::keys) {
            if !is_extension_key(key) {
                self.error(
                    Code::ExtensionKey,
                    path,
                    format!("extension key {key:?} must be a valid URL or a reverse-DNS string"),
                );
            }
        }
    }

    fn validate_spec_version(&mut self, spec_version: &str, path: &str) {
        if spec_version.is_empty() {
            self.error(Code::SpecVersion, path, "specVersion must not be empty");
            return;
        }

        let parts: Vec<&str> = spec_version.split('.').collect();

        let [major, minor] = parts.as_slice() else {
            self.error(
                Code::SpecVersion,
                path,
                format!("specVersion must be in Major.Minor format (e.g., '1.0'), found {spec_version:?}"),
            );
            return;
        };

        let (Ok(major), Ok(_)) = (major.parse::<u64>(), minor.parse::<u64>()) else {
            self.error(
                Code::SpecVersion,
                path,
                format!(
                    "specVersion major and minor components must be non-negative integers, found {spec_version:?}"
                ),
            );
            return;
        };

        if major > MAX_SUPPORTED_MAJOR {
            self.error(
                Code::SpecVersion,
                path,
                format!(
                    "unsupported specVersion major version: {major} (this implementation supports major version {MAX_SUPPORTED_MAJOR})"
                ),
            );
        }
    }

    fn validate_policy_urls(&mut self, extensions: Option<&BTreeMap<String, Value>>, path: &str) {
        let Some(value) = extensions.and_then(|extensions| extensions.get(POLICY_URLS_KEY)) else {
            return;
        };

        let valid = value.as_object().is_some_and(|members| {
            ["privacyPolicyUrl", "termsOfServiceUrl"]
                .iter()
                .all(|name| members.get(*name).is_none_or(Value::is_string))
        });

        if !valid {
            self.error(
                Code::PolicyUrls,
                path,
                format!(
                    "{POLICY_URLS_KEY} must be an object whose privacyPolicyUrl and termsOfServiceUrl, when present, are strings"
                ),
            );
        }
    }
}

const POLICY_URLS_KEY: &str = "https://ai-catalog.org/extensions/policy-urls";

static ABSOLUTE_URI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.\-]*:\S+$").expect("URI pattern is valid"));

fn is_absolute_uri(value: &str) -> bool {
    ABSOLUTE_URI.is_match(value)
}

static REVERSE_DNS_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$",
    )
    .expect("reverse-DNS pattern is valid")
});

static URL_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/?#\s]+").expect("URL pattern is valid")
});

fn is_extension_key(key: &str) -> bool {
    URL_KEY.is_match(key) || REVERSE_DNS_KEY.is_match(key)
}

fn text(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or_default()
}
