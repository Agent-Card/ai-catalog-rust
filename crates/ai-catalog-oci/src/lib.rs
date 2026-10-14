// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use ai_catalog::{AiCatalog, CatalogEntry, HostInfo, MEDIA_TYPE_CATALOG, Publisher, TrustManifest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const ENTRY_CONFIG_MEDIA_TYPE: &str = "application/vnd.ai-catalog.entry.config.v1+json";
pub const OCI_LAYOUT_VERSION: &str = "1.0.0";
pub const OCI_REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";
pub const TRUST_MANIFEST_ARTIFACT_TYPE: &str = "application/vnd.ai-catalog.trust-manifest.v1+json";
pub const TRUST_MANIFEST_CONFIG_MEDIA_TYPE: &str =
    "application/vnd.ai-catalog.trust-manifest.config.v1+json";
pub const COSIGN_SIGNATURE_ARTIFACT_TYPE: &str = "application/vnd.ai-catalog.cosign.signature.v1";
pub const COSIGN_SIGNATURE_CONFIG_MEDIA_TYPE: &str =
    "application/vnd.ai-catalog.cosign.signature.config.v1+json";
pub const COSIGN_SIGNATURE_LAYER_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.cosign.signature";
pub const COSIGN_PUBLIC_KEY_ARTIFACT_TYPE: &str = "application/vnd.ai-catalog.cosign.public-key.v1";
pub const COSIGN_PUBLIC_KEY_CONFIG_MEDIA_TYPE: &str =
    "application/vnd.ai-catalog.cosign.public-key.config.v1+json";
pub const COSIGN_PUBLIC_KEY_LAYER_MEDIA_TYPE: &str =
    "application/vnd.dev.sigstore.cosign.public-key";

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("catalog entry '{0}' must contain exactly one of url or data before packing to OCI")]
    InvalidEntryContent(String),
    #[error("missing manifest for digest '{0}'")]
    MissingManifest(String),
    #[error("missing blob for digest '{0}'")]
    MissingBlob(String),
    #[error("OCI index artifactType must be '{MEDIA_TYPE_CATALOG}'")]
    UnsupportedIndexArtifactType,
    #[error("OCI index is missing ai-catalog.specVersion annotation")]
    MissingSpecVersion,
    #[error("entry '{0}' is missing both OCI layer content and external url")]
    MissingEntryContent(String),
    #[error("OCI layout tag must not be empty")]
    InvalidLayoutTag,
    #[error("OCI layout output directory '{0}' must be empty or not exist")]
    NonEmptyLayoutDirectory(String),
    #[error("invalid OCI digest '{0}'")]
    InvalidDigest(String),
    #[error("OCI layout version must be '{OCI_LAYOUT_VERSION}', found '{0}'")]
    UnsupportedLayoutVersion(String),
    #[error("OCI layout is missing ai-catalog root reference '{0}'")]
    MissingLayoutReference(String),
    #[error("OCI layout contains multiple ai-catalog root references; pass an explicit ref name")]
    AmbiguousLayoutReference,
    #[error("missing OCI subject descriptor for digest '{0}'")]
    MissingSubjectDescriptor(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciImageIndex {
    pub schema_version: u32,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub manifests: Vec<OciDescriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciImageManifest {
    pub schema_version: u32,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub config: OciDescriptor,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<OciDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<OciDescriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciArtifactSet {
    pub index: OciImageIndex,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub manifests: BTreeMap<String, OciImageManifest>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub referrers: BTreeMap<String, Vec<OciImageManifest>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub blobs: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciLayoutMetadata {
    image_layout_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryConfig {
    identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extensions: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publisher: Option<Publisher>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(flatten, default)]
    extra_fields: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CosignSignatureConfig {
    identity: String,
    payload_digest: String,
    payload_media_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CosignPublicKeyConfig {
    identity: String,
    payload_digest: String,
    format: String,
}

pub fn pack_catalog(catalog: &AiCatalog) -> Result<OciArtifactSet> {
    let mut blobs = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    let mut referrers = BTreeMap::new();
    let mut index_descriptors = Vec::new();

    for entry in &catalog.entries {
        let entry_config = EntryConfig::from(entry);
        let config_bytes = serde_json::to_vec(&entry_config)?;
        let config_descriptor = store_blob(
            &mut blobs,
            &config_bytes,
            ENTRY_CONFIG_MEDIA_TYPE,
            None,
            BTreeMap::new(),
        );

        let layers = match (&entry.url, &entry.data) {
            (Some(_), None) => Vec::new(),
            (None, Some(data)) => {
                let layer_bytes = serde_json::to_vec(data)?;
                vec![store_blob(
                    &mut blobs,
                    &layer_bytes,
                    &entry.entry_type,
                    None,
                    BTreeMap::new(),
                )]
            }
            _ => return Err(Error::InvalidEntryContent(entry.identifier.clone())),
        };

        let entry_annotations = entry_annotations(entry);
        let manifest = OciImageManifest {
            schema_version: 2,
            media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_owned(),
            artifact_type: Some(entry.entry_type.clone()),
            config: config_descriptor,
            layers,
            subject: None,
            annotations: entry_annotations.clone(),
        };
        let manifest_descriptor = descriptor_for_bytes(
            &serde_json::to_vec(&manifest)?,
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            Some(entry.entry_type.clone()),
            entry_annotations,
        );

        if let Some(trust_manifest) = &entry.trust_manifest {
            let trust_manifest_bytes = serde_json::to_vec(trust_manifest)?;
            let trust_config = store_blob(
                &mut blobs,
                &trust_manifest_bytes,
                TRUST_MANIFEST_CONFIG_MEDIA_TYPE,
                None,
                BTreeMap::new(),
            );
            let trust_referrer = OciImageManifest {
                schema_version: 2,
                media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_owned(),
                artifact_type: Some(TRUST_MANIFEST_ARTIFACT_TYPE.to_owned()),
                config: trust_config,
                layers: Vec::new(),
                subject: Some(manifest_descriptor.clone()),
                annotations: trust_manifest_annotations(trust_manifest),
            };
            referrers
                .entry(manifest_descriptor.digest.clone())
                .or_insert_with(Vec::new)
                .push(trust_referrer);
        }

        index_descriptors.push(manifest_descriptor.clone());
        manifests.insert(manifest_descriptor.digest.clone(), manifest);
    }

    Ok(OciArtifactSet {
        index: OciImageIndex {
            schema_version: 2,
            media_type: OCI_IMAGE_INDEX_MEDIA_TYPE.to_owned(),
            artifact_type: Some(MEDIA_TYPE_CATALOG.to_owned()),
            manifests: index_descriptors,
            annotations: catalog_annotations(catalog)?,
        },
        manifests,
        referrers,
        blobs,
    })
}

pub fn unpack_catalog(artifacts: &OciArtifactSet) -> Result<AiCatalog> {
    if artifacts.index.artifact_type.as_deref() != Some(MEDIA_TYPE_CATALOG) {
        return Err(Error::UnsupportedIndexArtifactType);
    }

    let spec_version = artifacts
        .index
        .annotations
        .get("ai-catalog.specVersion")
        .cloned()
        .ok_or(Error::MissingSpecVersion)?;
    let host = annotations_json::<HostInfo>(&artifacts.index.annotations, "ai-catalog.host")?;
    let extensions = annotations_json::<BTreeMap<String, Value>>(
        &artifacts.index.annotations,
        "ai-catalog.extensions",
    )?;
    let signature = artifacts
        .index
        .annotations
        .get("ai-catalog.signature")
        .cloned();
    let extra_fields = annotations_json::<BTreeMap<String, Value>>(
        &artifacts.index.annotations,
        "ai-catalog.extraFields",
    )?
    .unwrap_or_default();

    let mut entries = Vec::with_capacity(artifacts.index.manifests.len());

    for descriptor in &artifacts.index.manifests {
        let manifest = artifacts
            .manifests
            .get(&descriptor.digest)
            .ok_or_else(|| Error::MissingManifest(descriptor.digest.clone()))?;
        let config_bytes = artifacts
            .blobs
            .get(&manifest.config.digest)
            .ok_or_else(|| Error::MissingBlob(manifest.config.digest.clone()))?;
        let config: EntryConfig = serde_json::from_slice(config_bytes)?;

        let (url, data) = if let Some(url) = config.url.clone() {
            (Some(url), None)
        } else if let Some(layer) = manifest.layers.first() {
            let layer_bytes = artifacts
                .blobs
                .get(&layer.digest)
                .ok_or_else(|| Error::MissingBlob(layer.digest.clone()))?;
            (None, Some(serde_json::from_slice(layer_bytes)?))
        } else {
            return Err(Error::MissingEntryContent(config.identifier.clone()));
        };

        let trust_manifest = artifacts
            .referrers
            .get(&descriptor.digest)
            .and_then(|items| {
                items.iter().find(|item| {
                    item.artifact_type.as_deref() == Some(TRUST_MANIFEST_ARTIFACT_TYPE)
                })
            })
            .map(|referrer| {
                let bytes = artifacts
                    .blobs
                    .get(&referrer.config.digest)
                    .ok_or_else(|| Error::MissingBlob(referrer.config.digest.clone()))?;

                serde_json::from_slice(bytes).map_err(Error::from)
            })
            .transpose()?;

        entries.push(CatalogEntry {
            identifier: config.identifier,
            display_name: config.display_name,
            entry_type: descriptor
                .artifact_type
                .clone()
                .or_else(|| manifest.artifact_type.clone())
                .unwrap_or_default(),
            url,
            data,
            version: config.version,
            description: config.description,
            tags: config.tags,
            publisher: config.publisher,
            trust_manifest,
            updated_at: config.updated_at,
            extensions: config.extensions,
            extra_fields: config.extra_fields,
        });
    }

    Ok(AiCatalog {
        spec_version,
        host,
        entries,
        signature,
        extensions,
        extra_fields,
    })
}

pub fn attach_cosign_verification_artifacts(
    artifacts: &mut OciArtifactSet,
    subject_digest: &str,
    identity: &str,
    payload_digest: &str,
    signature: &[u8],
    public_key: &[u8],
) -> Result<()> {
    let subject = artifacts
        .index
        .manifests
        .iter()
        .find(|descriptor| descriptor.digest == subject_digest)
        .cloned()
        .ok_or_else(|| Error::MissingSubjectDescriptor(subject_digest.to_owned()))?;

    let signature_config = CosignSignatureConfig {
        identity: identity.to_owned(),
        payload_digest: payload_digest.to_owned(),
        payload_media_type: TRUST_MANIFEST_ARTIFACT_TYPE.to_owned(),
    };
    let signature_config_bytes = serde_json::to_vec(&signature_config)?;
    let signature_config_descriptor = store_blob(
        &mut artifacts.blobs,
        &signature_config_bytes,
        COSIGN_SIGNATURE_CONFIG_MEDIA_TYPE,
        None,
        BTreeMap::new(),
    );
    let signature_layer_descriptor = store_blob(
        &mut artifacts.blobs,
        signature,
        COSIGN_SIGNATURE_LAYER_MEDIA_TYPE,
        None,
        BTreeMap::new(),
    );
    let signature_manifest = OciImageManifest {
        schema_version: 2,
        media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_owned(),
        artifact_type: Some(COSIGN_SIGNATURE_ARTIFACT_TYPE.to_owned()),
        config: signature_config_descriptor,
        layers: vec![signature_layer_descriptor],
        subject: Some(subject.clone()),
        annotations: cosign_signature_annotations(identity, payload_digest),
    };

    let public_key_config = CosignPublicKeyConfig {
        identity: identity.to_owned(),
        payload_digest: payload_digest.to_owned(),
        format: "pem".to_owned(),
    };
    let public_key_config_bytes = serde_json::to_vec(&public_key_config)?;
    let public_key_config_descriptor = store_blob(
        &mut artifacts.blobs,
        &public_key_config_bytes,
        COSIGN_PUBLIC_KEY_CONFIG_MEDIA_TYPE,
        None,
        BTreeMap::new(),
    );
    let public_key_layer_descriptor = store_blob(
        &mut artifacts.blobs,
        public_key,
        COSIGN_PUBLIC_KEY_LAYER_MEDIA_TYPE,
        None,
        BTreeMap::new(),
    );
    let public_key_manifest = OciImageManifest {
        schema_version: 2,
        media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_owned(),
        artifact_type: Some(COSIGN_PUBLIC_KEY_ARTIFACT_TYPE.to_owned()),
        config: public_key_config_descriptor,
        layers: vec![public_key_layer_descriptor],
        subject: Some(subject),
        annotations: cosign_public_key_annotations(identity, payload_digest),
    };

    artifacts
        .referrers
        .entry(subject_digest.to_owned())
        .or_default()
        .push(signature_manifest);
    artifacts
        .referrers
        .entry(subject_digest.to_owned())
        .or_default()
        .push(public_key_manifest);

    Ok(())
}

pub fn export_layout(
    artifacts: &OciArtifactSet,
    layout_dir: impl AsRef<Path>,
    tag: &str,
) -> Result<()> {
    let layout_dir = layout_dir.as_ref();

    prepare_layout_directory(layout_dir)?;

    if tag.trim().is_empty() {
        return Err(Error::InvalidLayoutTag);
    }

    let root_index_bytes = serde_json::to_vec(&artifacts.index)?;
    let mut root_annotations = BTreeMap::new();
    root_annotations.insert(OCI_REF_NAME_ANNOTATION.to_owned(), tag.to_owned());
    let root_descriptor = descriptor_for_bytes(
        &root_index_bytes,
        OCI_IMAGE_INDEX_MEDIA_TYPE,
        artifacts.index.artifact_type.clone(),
        root_annotations,
    );
    let mut layout_descriptors = Vec::with_capacity(1 + artifacts.index.manifests.len());

    layout_descriptors.push(root_descriptor.clone());
    layout_descriptors.extend(artifacts.index.manifests.clone());

    write_layout_blob(layout_dir, &root_descriptor.digest, &root_index_bytes)?;

    for (digest, manifest) in &artifacts.manifests {
        let manifest_bytes = serde_json::to_vec(manifest)?;
        write_layout_blob(layout_dir, digest, &manifest_bytes)?;
    }

    for manifests in artifacts.referrers.values() {
        for manifest in manifests {
            let manifest_bytes = serde_json::to_vec(manifest)?;
            let descriptor = descriptor_for_bytes(
                &manifest_bytes,
                OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                manifest.artifact_type.clone(),
                manifest.annotations.clone(),
            );

            layout_descriptors.push(descriptor.clone());
            write_layout_blob(layout_dir, &descriptor.digest, &manifest_bytes)?;
        }
    }

    for (digest, bytes) in &artifacts.blobs {
        write_layout_blob(layout_dir, digest, bytes)?;
    }

    let layout_index = OciImageIndex {
        schema_version: 2,
        media_type: OCI_IMAGE_INDEX_MEDIA_TYPE.to_owned(),
        artifact_type: None,
        manifests: layout_descriptors,
        annotations: BTreeMap::new(),
    };
    let layout_metadata = OciLayoutMetadata {
        image_layout_version: OCI_LAYOUT_VERSION.to_owned(),
    };

    fs::write(
        layout_dir.join("index.json"),
        serde_json::to_vec_pretty(&layout_index)?,
    )?;
    fs::write(
        layout_dir.join("oci-layout"),
        serde_json::to_vec_pretty(&layout_metadata)?,
    )?;

    Ok(())
}

pub fn import_layout(
    layout_dir: impl AsRef<Path>,
    ref_name: Option<&str>,
) -> Result<OciArtifactSet> {
    let layout_dir = layout_dir.as_ref();
    let metadata: OciLayoutMetadata =
        serde_json::from_slice(&fs::read(layout_dir.join("oci-layout"))?)?;

    if metadata.image_layout_version != OCI_LAYOUT_VERSION {
        return Err(Error::UnsupportedLayoutVersion(
            metadata.image_layout_version,
        ));
    }

    let layout_index: OciImageIndex =
        serde_json::from_slice(&fs::read(layout_dir.join("index.json"))?)?;
    let root_descriptor = select_layout_root_descriptor(&layout_index, ref_name)?;
    let root_index: OciImageIndex = read_layout_json_blob(layout_dir, &root_descriptor.digest)?;
    let entry_digests: BTreeSet<String> = root_index
        .manifests
        .iter()
        .map(|descriptor| descriptor.digest.clone())
        .collect();
    let mut manifests = BTreeMap::new();
    let mut referrers = BTreeMap::new();
    let mut blobs = BTreeMap::new();

    for descriptor in &root_index.manifests {
        let manifest: OciImageManifest = read_layout_json_blob(layout_dir, &descriptor.digest)?;

        load_manifest_blobs(layout_dir, &manifest, &mut blobs)?;
        manifests.insert(descriptor.digest.clone(), manifest);
    }

    for descriptor in &layout_index.manifests {
        if descriptor.digest == root_descriptor.digest || entry_digests.contains(&descriptor.digest)
        {
            continue;
        }

        if descriptor.media_type != OCI_IMAGE_MANIFEST_MEDIA_TYPE {
            continue;
        }

        let manifest: OciImageManifest = read_layout_json_blob(layout_dir, &descriptor.digest)?;
        let Some(subject) = manifest.subject.as_ref() else {
            continue;
        };

        if !entry_digests.contains(&subject.digest) {
            continue;
        }

        load_manifest_blobs(layout_dir, &manifest, &mut blobs)?;
        referrers
            .entry(subject.digest.clone())
            .or_insert_with(Vec::new)
            .push(manifest);
    }

    Ok(OciArtifactSet {
        index: root_index,
        manifests,
        referrers,
        blobs,
    })
}

fn catalog_annotations(catalog: &AiCatalog) -> Result<BTreeMap<String, String>> {
    let mut annotations = BTreeMap::new();

    annotations.insert(
        "ai-catalog.specVersion".to_owned(),
        catalog.spec_version.clone(),
    );

    if let Some(host) = &catalog.host {
        annotations.insert("ai-catalog.host".to_owned(), serde_json::to_string(host)?);
    }

    if let Some(extensions) = &catalog.extensions {
        annotations.insert(
            "ai-catalog.extensions".to_owned(),
            serde_json::to_string(extensions)?,
        );
    }

    if let Some(signature) = &catalog.signature {
        annotations.insert("ai-catalog.signature".to_owned(), signature.clone());
    }

    if !catalog.extra_fields.is_empty() {
        annotations.insert(
            "ai-catalog.extraFields".to_owned(),
            serde_json::to_string(&catalog.extra_fields)?,
        );
    }

    Ok(annotations)
}

fn select_layout_root_descriptor<'a>(
    layout_index: &'a OciImageIndex,
    ref_name: Option<&str>,
) -> Result<&'a OciDescriptor> {
    let root_descriptors: Vec<&OciDescriptor> = layout_index
        .manifests
        .iter()
        .filter(|descriptor| {
            descriptor.media_type == OCI_IMAGE_INDEX_MEDIA_TYPE
                && descriptor.artifact_type.as_deref() == Some(MEDIA_TYPE_CATALOG)
        })
        .collect();

    if let Some(ref_name) = ref_name {
        return root_descriptors
            .into_iter()
            .find(|descriptor| {
                descriptor
                    .annotations
                    .get(OCI_REF_NAME_ANNOTATION)
                    .map(String::as_str)
                    == Some(ref_name)
            })
            .ok_or_else(|| Error::MissingLayoutReference(ref_name.to_owned()));
    }

    match root_descriptors.as_slice() {
        [descriptor] => Ok(*descriptor),
        [] => Err(Error::MissingLayoutReference("latest".to_owned())),
        _ => Err(Error::AmbiguousLayoutReference),
    }
}

fn read_layout_json_blob<T: for<'de> Deserialize<'de>>(
    layout_dir: &Path,
    digest: &str,
) -> Result<T> {
    serde_json::from_slice(&read_layout_blob(layout_dir, digest)?).map_err(Error::from)
}

fn read_layout_blob(layout_dir: &Path, digest: &str) -> Result<Vec<u8>> {
    let (algorithm, encoded) = split_digest(digest)?;

    Ok(fs::read(
        layout_dir.join("blobs").join(algorithm).join(encoded),
    )?)
}

fn load_manifest_blobs(
    layout_dir: &Path,
    manifest: &OciImageManifest,
    blobs: &mut BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    load_blob(layout_dir, &manifest.config.digest, blobs)?;

    for layer in &manifest.layers {
        load_blob(layout_dir, &layer.digest, blobs)?;
    }

    Ok(())
}

fn load_blob(layout_dir: &Path, digest: &str, blobs: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    if blobs.contains_key(digest) {
        return Ok(());
    }

    blobs.insert(digest.to_owned(), read_layout_blob(layout_dir, digest)?);
    Ok(())
}

fn prepare_layout_directory(layout_dir: &Path) -> Result<()> {
    if layout_dir.exists() {
        if fs::read_dir(layout_dir)?.next().transpose()?.is_some() {
            return Err(Error::NonEmptyLayoutDirectory(
                layout_dir.display().to_string(),
            ));
        }
    } else {
        fs::create_dir_all(layout_dir)?;
    }

    fs::create_dir_all(layout_dir.join("blobs"))?;

    Ok(())
}

fn write_layout_blob(layout_dir: &Path, digest: &str, bytes: &[u8]) -> Result<()> {
    let (algorithm, encoded) = split_digest(digest)?;
    let blob_dir = layout_dir.join("blobs").join(algorithm);

    fs::create_dir_all(&blob_dir)?;
    fs::write(blob_dir.join(encoded), bytes)?;

    Ok(())
}

fn split_digest(digest: &str) -> Result<(&str, &str)> {
    match digest.split_once(':') {
        Some((algorithm, encoded)) if !algorithm.is_empty() && !encoded.is_empty() => {
            Ok((algorithm, encoded))
        }
        _ => Err(Error::InvalidDigest(digest.to_owned())),
    }
}

fn entry_annotations(entry: &CatalogEntry) -> BTreeMap<String, String> {
    let mut annotations = BTreeMap::new();

    annotations.insert("ai-catalog.identifier".to_owned(), entry.identifier.clone());
    if let Some(display_name) = &entry.display_name {
        annotations.insert("ai-catalog.displayName".to_owned(), display_name.clone());
    }

    if let Some(version) = &entry.version {
        annotations.insert("ai-catalog.version".to_owned(), version.clone());
    }

    annotations
}

fn trust_manifest_annotations(manifest: &TrustManifest) -> BTreeMap<String, String> {
    BTreeMap::from([("ai-catalog.identity".to_owned(), manifest.identity.clone())])
}

fn cosign_signature_annotations(identity: &str, payload_digest: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ai-catalog.identity".to_owned(), identity.to_owned()),
        (
            "ai-catalog.payloadDigest".to_owned(),
            payload_digest.to_owned(),
        ),
        (
            "ai-catalog.payloadMediaType".to_owned(),
            TRUST_MANIFEST_ARTIFACT_TYPE.to_owned(),
        ),
        (
            "ai-catalog.verificationMaterial".to_owned(),
            "cosign-signature".to_owned(),
        ),
    ])
}

fn cosign_public_key_annotations(identity: &str, payload_digest: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ai-catalog.identity".to_owned(), identity.to_owned()),
        (
            "ai-catalog.payloadDigest".to_owned(),
            payload_digest.to_owned(),
        ),
        (
            "ai-catalog.payloadMediaType".to_owned(),
            TRUST_MANIFEST_ARTIFACT_TYPE.to_owned(),
        ),
        (
            "ai-catalog.verificationMaterial".to_owned(),
            "cosign-public-key".to_owned(),
        ),
    ])
}

fn store_blob(
    blobs: &mut BTreeMap<String, Vec<u8>>,
    bytes: &[u8],
    media_type: &str,
    artifact_type: Option<String>,
    annotations: BTreeMap<String, String>,
) -> OciDescriptor {
    let descriptor = descriptor_for_bytes(bytes, media_type, artifact_type, annotations);

    blobs.insert(descriptor.digest.clone(), bytes.to_vec());
    descriptor
}

fn descriptor_for_bytes(
    bytes: &[u8],
    media_type: &str,
    artifact_type: Option<String>,
    annotations: BTreeMap<String, String>,
) -> OciDescriptor {
    OciDescriptor {
        media_type: media_type.to_owned(),
        digest: format!("sha256:{}", digest_hex(Sha256::digest(bytes).as_slice())),
        size: bytes.len() as u64,
        artifact_type,
        annotations,
    }
}

fn annotations_json<T: for<'de> Deserialize<'de>>(
    annotations: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<T>> {
    annotations
        .get(key)
        .map(|value| serde_json::from_str(value).map_err(Error::from))
        .transpose()
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        use std::fmt::Write as _;

        let _ = write!(&mut hex, "{byte:02x}");
    }

    hex
}

impl From<&CatalogEntry> for EntryConfig {
    fn from(entry: &CatalogEntry) -> Self {
        Self {
            identifier: entry.identifier.clone(),
            display_name: entry.display_name.clone(),
            description: entry.description.clone(),
            tags: entry.tags.clone(),
            version: entry.version.clone(),
            updated_at: entry.updated_at.clone(),
            extensions: entry.extensions.clone(),
            publisher: entry.publisher.clone(),
            url: entry.url.clone(),
            extra_fields: entry.extra_fields.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use ai_catalog::{AiCatalog, MEDIA_TYPE_CATALOG, parse_file, parse_str};

    use super::{
        COSIGN_PUBLIC_KEY_ARTIFACT_TYPE, COSIGN_SIGNATURE_ARTIFACT_TYPE, Error,
        OCI_REF_NAME_ANNOTATION, OciImageIndex, TRUST_MANIFEST_ARTIFACT_TYPE,
        attach_cosign_verification_artifacts, export_layout, import_layout, pack_catalog,
        unpack_catalog,
    };

    const INLINE: &str = r#"{
        "specVersion": "1.0",
        "entries": [{
            "identifier": "urn:example:inline",
            "type": "application/json",
            "data": {"name": "inline"},
            "trustManifest": {"identity": "urn:example:inline"}
        }]
    }"#;

    fn spec_example() -> AiCatalog {
        let path = format!(
            "{}/../../fixtures/spec-example.json",
            env!("CARGO_MANIFEST_DIR")
        );

        parse_file(&path).expect("fixture should parse")
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();

        std::env::temp_dir().join(format!("{prefix}-{unique}"))
    }

    #[test]
    fn pack_and_unpack_round_trip() {
        for catalog in [spec_example(), parse_str(INLINE).expect("inline parses")] {
            let artifacts = pack_catalog(&catalog).expect("catalog should pack");

            assert_eq!(
                artifacts.index.artifact_type.as_deref(),
                Some(MEDIA_TYPE_CATALOG)
            );
            assert_eq!(artifacts.index.manifests.len(), catalog.entries.len());
            assert_eq!(unpack_catalog(&artifacts).expect("unpacks"), catalog);
        }
    }

    #[test]
    fn trust_manifest_becomes_a_referrer() {
        let artifacts = pack_catalog(&parse_str(INLINE).expect("parses")).expect("packs");
        let entry = &artifacts.index.manifests[0].digest;

        assert_eq!(
            artifacts.referrers[entry]
                .iter()
                .map(|referrer| referrer.artifact_type.as_deref())
                .collect::<Vec<_>>(),
            [Some(TRUST_MANIFEST_ARTIFACT_TYPE)]
        );
    }

    #[test]
    fn rejects_entry_without_content() {
        let catalog = parse_str(
            r#"{"specVersion":"1.0","entries":[{"identifier":"urn:example:empty","type":"application/json"}]}"#,
        )
        .expect("parses");

        assert!(matches!(
            pack_catalog(&catalog),
            Err(Error::InvalidEntryContent(identifier)) if identifier == "urn:example:empty"
        ));
    }

    #[test]
    fn layout_round_trip_keeps_referrers() {
        let catalog = parse_str(INLINE).expect("parses");
        let mut artifacts = pack_catalog(&catalog).expect("packs");
        let entry = artifacts.index.manifests[0].digest.clone();
        let dir = temp_dir("ai-catalog-layout");

        attach_cosign_verification_artifacts(
            &mut artifacts,
            &entry,
            "urn:example:inline",
            "sha256:1234abcd",
            b"cosign-signature",
            b"-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----\n",
        )
        .expect("cosign artifacts attach");
        export_layout(&artifacts, &dir, "inline").expect("exports");

        let index: OciImageIndex =
            serde_json::from_slice(&fs::read(dir.join("index.json")).expect("index exists"))
                .expect("index parses");

        assert!(index.manifests.iter().any(|descriptor| {
            descriptor
                .annotations
                .get(OCI_REF_NAME_ANNOTATION)
                .is_some_and(|name| name == "inline")
        }));

        let imported = import_layout(&dir, Some("inline")).expect("imports");
        let mut types: Vec<_> = imported.referrers[&entry]
            .iter()
            .filter_map(|referrer| referrer.artifact_type.as_deref())
            .collect();
        types.sort_unstable();

        let mut want = [
            TRUST_MANIFEST_ARTIFACT_TYPE,
            COSIGN_SIGNATURE_ARTIFACT_TYPE,
            COSIGN_PUBLIC_KEY_ARTIFACT_TYPE,
        ];
        want.sort_unstable();

        assert_eq!(types, want);
        assert_eq!(unpack_catalog(&imported).expect("unpacks"), catalog);

        fs::remove_dir_all(&dir).expect("temp layout removed");
    }

    #[test]
    fn layout_rejects_bad_input() {
        let artifacts = pack_catalog(&spec_example()).expect("packs");
        let dir = temp_dir("ai-catalog-layout-bad");

        fs::create_dir_all(&dir).expect("dir created");
        fs::write(dir.join("stale.txt"), b"stale").expect("stale file written");

        assert!(matches!(
            export_layout(&artifacts, &dir, "latest"),
            Err(Error::NonEmptyLayoutDirectory(path)) if path == dir.display().to_string()
        ));

        fs::remove_dir_all(&dir).expect("temp dir removed");

        export_layout(&artifacts, &dir, "latest").expect("exports");

        assert!(matches!(
            import_layout(&dir, Some("missing")),
            Err(Error::MissingLayoutReference(reference)) if reference == "missing"
        ));

        fs::remove_dir_all(&dir).expect("temp layout removed");
    }
}
