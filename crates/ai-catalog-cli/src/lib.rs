// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ai_catalog::{AiCatalog, parse_file, parse_reader, write_writer};
use ai_catalog_oci::{
    OciArtifactSet, attach_cosign_verification_artifacts, export_layout, import_layout,
    pack_catalog, unpack_catalog,
};
use ai_catalog_trust::{
    CatalogTrustReport, Finding as TrustFinding, ManifestReport, Severity, analyze_catalog,
    canonicalize_trust_manifest,
};
use ai_catalog_validate::{ConformanceLevel, Diagnostic, validate};
use serde_json::json;
use sha2::{Digest as _, Sha256};

const BIN_NAME: &str = "ai-catalog-cli";
const DEFAULT_OCI_LAYOUT_TAG: &str = "latest";
const ORAS_BIN_ENV: &str = "AI_CATALOG_ORAS_BIN";
const COSIGN_BIN_ENV: &str = "AI_CATALOG_COSIGN_BIN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValidateOptions<'a> {
    output_format: OutputFormat,
    path: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustOptions<'a> {
    output_format: OutputFormat,
    path: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OciExportLayoutOptions<'a> {
    path: &'a str,
    layout_path: &'a str,
    tag: &'a str,
    cosign_key: Option<&'a str>,
    cosign_public_key: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OciUnpackLayoutOptions<'a> {
    layout_path: &'a str,
    ref_name: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OciPushOptions<'a> {
    path: &'a str,
    target: &'a str,
    tag: &'a str,
    to_oci_layout_path: Option<&'a str>,
    plain_http: bool,
    insecure: bool,
    cosign_key: Option<&'a str>,
    cosign_public_key: Option<&'a str>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CosignBlobBundle {
    message_signature: CosignMessageSignature,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CosignMessageSignature {
    signature: String,
}

pub fn run<I, S, R, W, E>(args: I, stdin: &mut R, stdout: &mut W, stderr: &mut E) -> io::Result<i32>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
    R: Read,
    W: Write,
    E: Write,
{
    let mut args = args.into_iter();
    let _program = args.next();

    let Some(command) = args.next().map(|arg| arg.as_ref().to_owned()) else {
        print_help(stdout)?;
        return Ok(0);
    };

    let remaining: Vec<String> = args.map(|arg| arg.as_ref().to_owned()).collect();

    match command.as_str() {
        "help" | "--help" | "-h" => {
            print_help(stdout)?;
            Ok(0)
        }
        "version" | "--version" | "-V" => {
            writeln!(stdout, "{BIN_NAME} {}", env!("CARGO_PKG_VERSION"))?;
            Ok(0)
        }
        "validate" => validate_command(&remaining, stdin, stdout, stderr),
        "format" => format_command(&remaining, stdin, stdout, stderr),
        "trust" => trust_command(&remaining, stdin, stdout, stderr),
        "oci" => oci_command(&remaining, stdin, stdout, stderr),
        other => {
            writeln!(stderr, "unknown command: {other}")?;
            write_usage(stderr)?;
            Ok(2)
        }
    }
}

fn validate_command<R: Read, W: Write, E: Write>(
    args: &[String],
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    let Some(options) = parse_validate_options(args, stderr)? else {
        return Ok(2);
    };

    let catalog = match read_catalog(options.path, stdin) {
        Ok(catalog) => catalog,
        Err(error) => {
            write_parse_error(options.output_format, options.path, error, stdout, stderr)?;
            return Ok(1);
        }
    };

    let result = validate(&catalog);

    match options.output_format {
        OutputFormat::Text => {
            if result.is_valid {
                writeln!(stdout, "catalog is valid")?;
                writeln!(
                    stdout,
                    "conformance: {}",
                    conformance_level_name(result.conformance_level)
                )?;

                if !result.warnings.is_empty() {
                    write_diagnostics(stdout, "warnings", &result.warnings)?;
                }

                Ok(0)
            } else {
                writeln!(stderr, "catalog is invalid")?;
                writeln!(
                    stderr,
                    "conformance: {}",
                    conformance_level_name(result.conformance_level)
                )?;
                write_diagnostics(stderr, "errors", &result.errors)?;

                if !result.warnings.is_empty() {
                    write_diagnostics(stderr, "warnings", &result.warnings)?;
                }

                Ok(1)
            }
        }
        OutputFormat::Json => {
            write_validation_result_json(
                stdout,
                result.is_valid,
                Some(result.conformance_level),
                &result.errors,
                &result.warnings,
            )?;

            Ok(if result.is_valid { 0 } else { 1 })
        }
    }
}

fn format_command<R: Read, W: Write, E: Write>(
    args: &[String],
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    let Some(path) = expect_single_path("format", args, stderr)? else {
        return Ok(2);
    };

    let catalog = match read_catalog(path, stdin) {
        Ok(catalog) => catalog,
        Err(error) => {
            writeln!(stderr, "{}", parse_error_message(path, &error))?;
            return Ok(1);
        }
    };

    write_writer(&mut *stdout, &catalog).map_err(io::Error::other)?;
    writeln!(stdout)?;

    Ok(0)
}

fn trust_command<R: Read, W: Write, E: Write>(
    args: &[String],
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    let Some((subcommand, remaining)) = args.split_first() else {
        writeln!(stderr, "trust expects a subcommand")?;
        write_usage(stderr)?;
        return Ok(2);
    };

    match subcommand.as_str() {
        "inspect" => trust_inspect_command(remaining, stdin, stdout, stderr),
        "help" => {
            write_usage(stdout)?;
            Ok(0)
        }
        other => {
            writeln!(stderr, "unknown trust subcommand: {other}")?;
            write_usage(stderr)?;
            Ok(2)
        }
    }
}

fn trust_inspect_command<R: Read, W: Write, E: Write>(
    args: &[String],
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    let Some(options) = parse_trust_options(args, stderr)? else {
        return Ok(2);
    };

    let catalog = match read_catalog(options.path, stdin) {
        Ok(catalog) => catalog,
        Err(error) => {
            write_parse_error(options.output_format, options.path, error, stdout, stderr)?;
            return Ok(1);
        }
    };

    let report = analyze_catalog(&catalog);
    let has_errors = trust_report_has_errors(&report);

    match options.output_format {
        OutputFormat::Text => {
            if has_errors {
                write_trust_report(stderr, &report)?;
            } else {
                write_trust_report(stdout, &report)?;
            }
        }
        OutputFormat::Json => write_trust_report_json(stdout, &report)?,
    }

    Ok(if has_errors { 1 } else { 0 })
}

fn oci_command<R: Read, W: Write, E: Write>(
    args: &[String],
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    let Some((subcommand, remaining)) = args.split_first() else {
        writeln!(stderr, "oci expects a subcommand")?;
        write_usage(stderr)?;
        return Ok(2);
    };

    match subcommand.as_str() {
        "pack" => oci_pack_command(remaining, stdin, stdout, stderr),
        "unpack" => oci_unpack_command(remaining, stdin, stdout, stderr),
        "export-layout" => oci_export_layout_command(remaining, stdin, stdout, stderr),
        "unpack-layout" => oci_unpack_layout_command(remaining, stdout, stderr),
        "push" => oci_push_command(remaining, stdin, stdout, stderr),
        "help" => {
            write_usage(stdout)?;
            Ok(0)
        }
        other => {
            writeln!(stderr, "unknown oci subcommand: {other}")?;
            write_usage(stderr)?;
            Ok(2)
        }
    }
}

fn oci_pack_command<R: Read, W: Write, E: Write>(
    args: &[String],
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    let Some(path) = expect_single_path("oci pack", args, stderr)? else {
        return Ok(2);
    };

    let catalog = match read_catalog(path, stdin) {
        Ok(catalog) => catalog,
        Err(error) => {
            writeln!(stderr, "{}", parse_error_message(path, &error))?;
            return Ok(1);
        }
    };

    let artifacts = match pack_catalog(&catalog) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            writeln!(stderr, "failed to pack '{path}' as OCI artifacts: {error}")?;
            return Ok(1);
        }
    };

    serde_json::to_writer_pretty(&mut *stdout, &artifacts).map_err(io::Error::other)?;
    writeln!(stdout)?;

    Ok(0)
}

fn oci_unpack_command<R: Read, W: Write, E: Write>(
    args: &[String],
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    let Some(path) = expect_single_path("oci unpack", args, stderr)? else {
        return Ok(2);
    };

    let bytes = match read_bytes(path, stdin) {
        Ok(bytes) => bytes,
        Err(error) => {
            writeln!(stderr, "failed to read {}: {error}", input_label(path))?;
            return Ok(1);
        }
    };

    let artifacts: OciArtifactSet = match serde_json::from_slice(&bytes) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            writeln!(
                stderr,
                "failed to parse OCI artifact set from {}: {error}",
                input_label(path)
            )?;
            return Ok(1);
        }
    };

    let catalog = match unpack_catalog(&artifacts) {
        Ok(catalog) => catalog,
        Err(error) => {
            writeln!(
                stderr,
                "failed to unpack OCI artifact set from {}: {error}",
                input_label(path)
            )?;
            return Ok(1);
        }
    };

    write_writer(&mut *stdout, &catalog).map_err(io::Error::other)?;
    writeln!(stdout)?;

    Ok(0)
}

fn oci_export_layout_command<R: Read, W: Write, E: Write>(
    args: &[String],
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    let Some(options) = parse_oci_export_layout_options(args, stderr)? else {
        return Ok(2);
    };

    let catalog = match read_catalog(options.path, stdin) {
        Ok(catalog) => catalog,
        Err(error) => {
            writeln!(stderr, "{}", parse_error_message(options.path, &error))?;
            return Ok(1);
        }
    };

    let artifacts = match pack_catalog(&catalog) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            writeln!(
                stderr,
                "failed to pack '{}' as OCI artifacts: {error}",
                options.path
            )?;
            return Ok(1);
        }
    };

    let mut artifacts = artifacts;

    if let Some(cosign_key) = options.cosign_key {
        match attach_cosign_material(
            &catalog,
            &mut artifacts,
            cosign_key,
            options.cosign_public_key,
        ) {
            Ok(attached) => {
                if attached > 0 {
                    writeln!(stdout, "attached Cosign verification artifacts for {attached} trust manifest(s)")?;
                }
            }
            Err(error) => {
                writeln!(stderr, "failed to attach Cosign verification artifacts: {error}")?;
                return Ok(1);
            }
        }
    }

    match export_layout(&artifacts, options.layout_path, options.tag) {
        Ok(()) => {
            writeln!(
                stdout,
                "exported OCI image layout to '{}' with tag '{}'",
                options.layout_path, options.tag
            )?;
            Ok(0)
        }
        Err(error) => {
            writeln!(
                stderr,
                "failed to export OCI layout to '{}': {error}",
                options.layout_path
            )?;
            Ok(1)
        }
    }
}

fn oci_unpack_layout_command<W: Write, E: Write>(
    args: &[String],
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    let Some(options) = parse_oci_unpack_layout_options(args, stderr)? else {
        return Ok(2);
    };

    let artifacts = match import_layout(options.layout_path, options.ref_name) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            writeln!(
                stderr,
                "failed to import OCI layout from '{}': {error}",
                options.layout_path
            )?;
            return Ok(1);
        }
    };

    let catalog = match unpack_catalog(&artifacts) {
        Ok(catalog) => catalog,
        Err(error) => {
            writeln!(
                stderr,
                "failed to unpack OCI layout from '{}': {error}",
                options.layout_path
            )?;
            return Ok(1);
        }
    };

    write_writer(&mut *stdout, &catalog).map_err(io::Error::other)?;
    writeln!(stdout)?;

    Ok(0)
}

fn oci_push_command<R: Read, W: Write, E: Write>(
    args: &[String],
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    let Some(options) = parse_oci_push_options(args, stderr)? else {
        return Ok(2);
    };

    let catalog = match read_catalog(options.path, stdin) {
        Ok(catalog) => catalog,
        Err(error) => {
            writeln!(stderr, "{}", parse_error_message(options.path, &error))?;
            return Ok(1);
        }
    };

    let artifacts = match pack_catalog(&catalog) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            writeln!(
                stderr,
                "failed to pack '{}' as OCI artifacts: {error}",
                options.path
            )?;
            return Ok(1);
        }
    };

    let mut artifacts = artifacts;

    if let Some(cosign_key) = options.cosign_key {
        match attach_cosign_material(
            &catalog,
            &mut artifacts,
            cosign_key,
            options.cosign_public_key,
        ) {
            Ok(attached) => {
                if attached > 0 {
                    writeln!(stdout, "attached Cosign verification artifacts for {attached} trust manifest(s)")?;
                }
            }
            Err(error) => {
                writeln!(stderr, "failed to attach Cosign verification artifacts: {error}")?;
                return Ok(1);
            }
        }
    }

    let layout_dir = temporary_layout_dir("ai-catalog-oras-layout");
    let result = push_artifacts_via_oras(&artifacts, &layout_dir, options, stdout, stderr);
    let _ = fs::remove_dir_all(&layout_dir);

    result
}

fn push_artifacts_via_oras<W: Write, E: Write>(
    artifacts: &ai_catalog_oci::OciArtifactSet,
    layout_dir: &Path,
    options: OciPushOptions<'_>,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<i32> {
    if let Err(error) = export_layout(artifacts, layout_dir, options.tag) {
        writeln!(
            stderr,
            "failed to export temporary OCI layout for '{}': {error}",
            options.target
        )?;
        return Ok(1);
    }

    let args = build_oras_cp_args(
        layout_dir,
        options.tag,
        options.target,
        options.to_oci_layout_path,
        options.plain_http,
        options.insecure,
    );
    let output = match execute_oras(&args) {
        Ok(output) => output,
        Err(error) => {
            writeln!(stderr, "failed to invoke oras: {error}")?;
            return Ok(1);
        }
    };

    write_process_output(stdout, &output.stdout)?;
    write_process_output(stderr, &output.stderr)?;

    if output.status.success() {
        let repository = target_repository(options.target);

        for digest in artifacts.referrers.keys() {
            let referrer_args = build_oras_cp_referrer_args(
                layout_dir,
                digest,
                repository,
                options.to_oci_layout_path,
                options.plain_http,
                options.insecure,
            );
            let referrer_output = match execute_oras(&referrer_args) {
                Ok(output) => output,
                Err(error) => {
                    writeln!(stderr, "failed to invoke oras: {error}")?;
                    return Ok(1);
                }
            };

            write_process_output(stdout, &referrer_output.stdout)?;
            write_process_output(stderr, &referrer_output.stderr)?;

            if !referrer_output.status.success() {
                if referrer_output.stdout.is_empty() && referrer_output.stderr.is_empty() {
                    writeln!(stderr, "oras exited with status {}", referrer_output.status)?;
                }

                return Ok(referrer_output.status.code().unwrap_or(1));
            }
        }

        Ok(0)
    } else {
        if output.stdout.is_empty() && output.stderr.is_empty() {
            writeln!(stderr, "oras exited with status {}", output.status)?;
        }

        Ok(output.status.code().unwrap_or(1))
    }
}

fn read_catalog<R: Read>(path: &str, stdin: &mut R) -> ai_catalog::Result<ai_catalog::AiCatalog> {
    if path == "-" {
        parse_reader(&mut *stdin)
    } else {
        parse_file(path)
    }
}

fn read_bytes<R: Read>(path: &str, stdin: &mut R) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut bytes = Vec::new();
        stdin.read_to_end(&mut bytes)?;
        Ok(bytes)
    } else {
        fs::read(path)
    }
}

fn parse_validate_options<'a>(
    args: &'a [String],
    stderr: &mut impl Write,
) -> io::Result<Option<ValidateOptions<'a>>> {
    let mut output_format = OutputFormat::Text;
    let mut path = None;

    for arg in args {
        match arg.as_str() {
            "--json" => output_format = OutputFormat::Json,
            "-" => {
                if path.replace(arg.as_str()).is_some() {
                    writeln!(stderr, "validate expects exactly one <path> argument")?;
                    write_usage(stderr)?;
                    return Ok(None);
                }
            }
            value if value.starts_with('-') => {
                writeln!(stderr, "unknown validate option: {value}")?;
                write_usage(stderr)?;
                return Ok(None);
            }
            value => {
                if path.replace(value).is_some() {
                    writeln!(stderr, "validate expects exactly one <path> argument")?;
                    write_usage(stderr)?;
                    return Ok(None);
                }
            }
        }
    }

    if let Some(path) = path {
        Ok(Some(ValidateOptions {
            output_format,
            path,
        }))
    } else {
        writeln!(stderr, "validate expects exactly one <path> argument")?;
        write_usage(stderr)?;
        Ok(None)
    }
}

fn parse_trust_options<'a>(
    args: &'a [String],
    stderr: &mut impl Write,
) -> io::Result<Option<TrustOptions<'a>>> {
    let mut output_format = OutputFormat::Text;
    let mut path = None;

    for arg in args {
        match arg.as_str() {
            "--json" => output_format = OutputFormat::Json,
            "-" => {
                if path.replace(arg.as_str()).is_some() {
                    writeln!(stderr, "trust inspect expects exactly one <path> argument")?;
                    write_usage(stderr)?;
                    return Ok(None);
                }
            }
            value if value.starts_with('-') => {
                writeln!(stderr, "unknown trust inspect option: {value}")?;
                write_usage(stderr)?;
                return Ok(None);
            }
            value => {
                if path.replace(value).is_some() {
                    writeln!(stderr, "trust inspect expects exactly one <path> argument")?;
                    write_usage(stderr)?;
                    return Ok(None);
                }
            }
        }
    }

    if let Some(path) = path {
        Ok(Some(TrustOptions {
            output_format,
            path,
        }))
    } else {
        writeln!(stderr, "trust inspect expects exactly one <path> argument")?;
        write_usage(stderr)?;
        Ok(None)
    }
}

fn parse_oci_export_layout_options<'a>(
    args: &'a [String],
    stderr: &mut impl Write,
) -> io::Result<Option<OciExportLayoutOptions<'a>>> {
    let mut tag = DEFAULT_OCI_LAYOUT_TAG;
    let mut cosign_key = None;
    let mut cosign_public_key = None;
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--tag" => {
                index += 1;

                let Some(value) = args.get(index) else {
                    writeln!(stderr, "oci export-layout requires a value for --tag")?;
                    write_usage(stderr)?;
                    return Ok(None);
                };

                tag = value;
            }
            "--cosign-key" => {
                index += 1;

                let Some(value) = args.get(index) else {
                    writeln!(stderr, "oci export-layout requires a value for --cosign-key")?;
                    write_usage(stderr)?;
                    return Ok(None);
                };

                cosign_key = Some(value.as_str());
            }
            "--cosign-public-key" => {
                index += 1;

                let Some(value) = args.get(index) else {
                    writeln!(stderr, "oci export-layout requires a value for --cosign-public-key")?;
                    write_usage(stderr)?;
                    return Ok(None);
                };

                cosign_public_key = Some(value.as_str());
            }
            "-" => positional.push("-"),
            value if value.starts_with('-') => {
                writeln!(stderr, "unknown oci export-layout option: {value}")?;
                write_usage(stderr)?;
                return Ok(None);
            }
            value => positional.push(value),
        }

        index += 1;
    }

    if cosign_public_key.is_some() && cosign_key.is_none() {
        writeln!(
            stderr,
            "oci export-layout requires --cosign-key when --cosign-public-key is set"
        )?;
        write_usage(stderr)?;
        return Ok(None);
    }

    if positional.len() != 2 {
        writeln!(
            stderr,
            "oci export-layout expects exactly one <path|-> and one <layout-dir> argument"
        )?;
        write_usage(stderr)?;
        return Ok(None);
    }

    Ok(Some(OciExportLayoutOptions {
        path: positional[0],
        layout_path: positional[1],
        tag,
        cosign_key,
        cosign_public_key,
    }))
}

fn parse_oci_push_options<'a>(
    args: &'a [String],
    stderr: &mut impl Write,
) -> io::Result<Option<OciPushOptions<'a>>> {
    let mut tag = DEFAULT_OCI_LAYOUT_TAG;
    let mut to_oci_layout_path = None;
    let mut plain_http = false;
    let mut insecure = false;
    let mut cosign_key = None;
    let mut cosign_public_key = None;
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--tag" => {
                index += 1;

                let Some(value) = args.get(index) else {
                    writeln!(stderr, "oci push requires a value for --tag")?;
                    write_usage(stderr)?;
                    return Ok(None);
                };

                tag = value;
            }
            "--cosign-key" => {
                index += 1;

                let Some(value) = args.get(index) else {
                    writeln!(stderr, "oci push requires a value for --cosign-key")?;
                    write_usage(stderr)?;
                    return Ok(None);
                };

                cosign_key = Some(value.as_str());
            }
            "--cosign-public-key" => {
                index += 1;

                let Some(value) = args.get(index) else {
                    writeln!(stderr, "oci push requires a value for --cosign-public-key")?;
                    write_usage(stderr)?;
                    return Ok(None);
                };

                cosign_public_key = Some(value.as_str());
            }
            "--to-oci-layout-path" => {
                index += 1;

                let Some(value) = args.get(index) else {
                    writeln!(stderr, "oci push requires a value for --to-oci-layout-path")?;
                    write_usage(stderr)?;
                    return Ok(None);
                };

                to_oci_layout_path = Some(value.as_str());
            }
            "--plain-http" => plain_http = true,
            "--insecure" => insecure = true,
            "-" => positional.push("-"),
            value if value.starts_with('-') => {
                writeln!(stderr, "unknown oci push option: {value}")?;
                write_usage(stderr)?;
                return Ok(None);
            }
            value => positional.push(value),
        }

        index += 1;
    }

    if cosign_public_key.is_some() && cosign_key.is_none() {
        writeln!(
            stderr,
            "oci push requires --cosign-key when --cosign-public-key is set"
        )?;
        write_usage(stderr)?;
        return Ok(None);
    }

    if positional.len() != 2 {
        writeln!(
            stderr,
            "oci push expects exactly one <path|-> and one <target> argument"
        )?;
        write_usage(stderr)?;
        return Ok(None);
    }

    Ok(Some(OciPushOptions {
        path: positional[0],
        target: positional[1],
        tag,
        to_oci_layout_path,
        plain_http,
        insecure,
        cosign_key,
        cosign_public_key,
    }))
}

fn parse_oci_unpack_layout_options<'a>(
    args: &'a [String],
    stderr: &mut impl Write,
) -> io::Result<Option<OciUnpackLayoutOptions<'a>>> {
    let mut ref_name = None;
    let mut layout_path = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--ref-name" => {
                index += 1;

                let Some(value) = args.get(index) else {
                    writeln!(stderr, "oci unpack-layout requires a value for --ref-name")?;
                    write_usage(stderr)?;
                    return Ok(None);
                };

                ref_name = Some(value.as_str());
            }
            value if value.starts_with('-') => {
                writeln!(stderr, "unknown oci unpack-layout option: {value}")?;
                write_usage(stderr)?;
                return Ok(None);
            }
            value => {
                if layout_path.replace(value).is_some() {
                    writeln!(
                        stderr,
                        "oci unpack-layout expects exactly one <layout-dir> argument"
                    )?;
                    write_usage(stderr)?;
                    return Ok(None);
                }
            }
        }

        index += 1;
    }

    if let Some(layout_path) = layout_path {
        Ok(Some(OciUnpackLayoutOptions {
            layout_path,
            ref_name,
        }))
    } else {
        writeln!(
            stderr,
            "oci unpack-layout expects exactly one <layout-dir> argument"
        )?;
        write_usage(stderr)?;
        Ok(None)
    }
}

fn expect_single_path<'a>(
    command: &str,
    args: &'a [String],
    stderr: &mut impl Write,
) -> io::Result<Option<&'a str>> {
    if args.len() == 1 {
        return Ok(Some(args[0].as_str()));
    }

    writeln!(stderr, "{command} expects exactly one <path> argument")?;
    write_usage(stderr)?;
    Ok(None)
}

fn print_help(stdout: &mut impl Write) -> io::Result<()> {
    writeln!(stdout, "{BIN_NAME}")?;
    writeln!(stdout)?;
    write_usage(stdout)
}

fn write_usage(writer: &mut impl Write) -> io::Result<()> {
    writeln!(writer, "Usage:")?;
    writeln!(writer, "  {BIN_NAME} validate [--json] <path|->")?;
    writeln!(writer, "  {BIN_NAME} format <path|->")?;
    writeln!(writer, "  {BIN_NAME} trust inspect [--json] <path|->")?;
    writeln!(writer, "  {BIN_NAME} oci pack <path|->")?;
    writeln!(writer, "  {BIN_NAME} oci unpack <path|->")?;
    writeln!(
        writer,
        "  {BIN_NAME} oci export-layout [--tag <tag>] [--cosign-key <path>] [--cosign-public-key <path>] <path|-> <layout-dir>"
    )?;
    writeln!(
        writer,
        "  {BIN_NAME} oci unpack-layout [--ref-name <name>] <layout-dir>"
    )?;
    writeln!(
        writer,
        "  {BIN_NAME} oci push [--tag <tag>] [--plain-http] [--insecure] [--to-oci-layout-path <layout-dir>] [--cosign-key <path>] [--cosign-public-key <path>] <path|-> <target>"
    )?;
    writeln!(writer, "  {BIN_NAME} help")?;
    writeln!(writer, "  {BIN_NAME} version")?;
    writeln!(writer)?;
    writeln!(writer, "Use '-' as <path> to read from stdin.")?;
    Ok(())
}

fn build_oras_cp_args(
    layout_dir: &Path,
    tag: &str,
    target: &str,
    to_oci_layout_path: Option<&str>,
    plain_http: bool,
    insecure: bool,
) -> Vec<String> {
    let mut args = vec![
        "cp".to_owned(),
        "-r".to_owned(),
        "--from-oci-layout".to_owned(),
    ];

    if let Some(layout_path) = to_oci_layout_path {
        args.push("--to-oci-layout-path".to_owned());
        args.push(layout_path.to_owned());
    }

    if plain_http {
        args.push("--to-plain-http".to_owned());
    }

    if insecure {
        args.push("--to-insecure".to_owned());
    }

    args.push(format!("{}:{tag}", layout_dir.display()));
    args.push(target.to_owned());
    args
}

fn build_oras_cp_referrer_args(
    layout_dir: &Path,
    digest: &str,
    target_repository: &str,
    to_oci_layout_path: Option<&str>,
    plain_http: bool,
    insecure: bool,
) -> Vec<String> {
    let mut args = vec![
        "cp".to_owned(),
        "-r".to_owned(),
        "--from-oci-layout".to_owned(),
    ];

    if let Some(layout_path) = to_oci_layout_path {
        args.push("--to-oci-layout-path".to_owned());
        args.push(layout_path.to_owned());
    }

    if plain_http {
        args.push("--to-plain-http".to_owned());
    }

    if insecure {
        args.push("--to-insecure".to_owned());
    }

    args.push(format!("{}@{digest}", layout_dir.display()));
    args.push(target_repository.to_owned());
    args
}

fn target_repository(target: &str) -> &str {
    if let Some((repository, _)) = target.split_once('@') {
        return repository;
    }

    let last_slash = target.rfind('/');
    let last_colon = target.rfind(':');

    match last_colon {
        Some(index) if last_slash.is_none_or(|slash| index > slash) => &target[..index],
        _ => target,
    }
}

fn execute_oras(args: &[String]) -> io::Result<std::process::Output> {
    let oras_bin = std::env::var(ORAS_BIN_ENV).unwrap_or_else(|_| "oras".to_owned());

    Command::new(oras_bin).args(args).output()
}

fn attach_cosign_material(
    catalog: &AiCatalog,
    artifacts: &mut OciArtifactSet,
    cosign_key: &str,
    cosign_public_key: Option<&str>,
) -> io::Result<usize> {
    let targets = catalog
        .entries
        .iter()
        .zip(artifacts.index.manifests.iter())
        .filter_map(|(entry, descriptor)| {
            entry
                .trust_manifest
                .clone()
                .map(|trust_manifest| (descriptor.digest.clone(), trust_manifest))
        })
        .collect::<Vec<_>>();

    if targets.is_empty() {
        return Ok(0);
    }

    let public_key = load_cosign_public_key(cosign_key, cosign_public_key)?;

    for (subject_digest, trust_manifest) in targets {
        let canonical_manifest =
            canonicalize_trust_manifest(&trust_manifest).map_err(io::Error::other)?;
        let canonical_bytes = canonical_manifest.into_bytes();
        let payload_digest = format!(
            "sha256:{}",
            digest_hex(Sha256::digest(&canonical_bytes).as_slice())
        );
        let signature = sign_blob_with_cosign(&canonical_bytes, cosign_key)?;

        attach_cosign_verification_artifacts(
            artifacts,
            &subject_digest,
            &trust_manifest.identity,
            &payload_digest,
            &signature,
            &public_key,
        )
        .map_err(io::Error::other)?;
    }

    Ok(catalog
        .entries
        .iter()
        .filter(|entry| entry.trust_manifest.is_some())
        .count())
}

fn load_cosign_public_key(
    cosign_key: &str,
    cosign_public_key: Option<&str>,
) -> io::Result<Vec<u8>> {
    if let Some(path) = cosign_public_key {
        return fs::read(path);
    }

    let args = build_cosign_public_key_args(cosign_key);
    let output = execute_cosign(&args)?;

    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(command_failure("cosign public-key", &output))
    }
}

fn sign_blob_with_cosign(payload: &[u8], cosign_key: &str) -> io::Result<Vec<u8>> {
    let work_dir = temporary_layout_dir("ai-catalog-cosign");
    let payload_path = work_dir.join("trust-manifest.json");
    let bundle_path = work_dir.join("trust-manifest.bundle.json");

    fs::create_dir_all(&work_dir)?;
    fs::write(&payload_path, payload)?;

    let args = build_cosign_sign_blob_args(cosign_key, &payload_path, &bundle_path);
    let output = execute_cosign(&args)?;
    let result = if output.status.success() {
        let bundle_bytes = fs::read(&bundle_path)?;
        let bundle: CosignBlobBundle = serde_json::from_slice(&bundle_bytes).map_err(io::Error::other)?;

        Ok(bundle.message_signature.signature.into_bytes())
    } else {
        Err(command_failure("cosign sign-blob", &output))
    };

    let _ = fs::remove_dir_all(&work_dir);
    result
}

fn build_cosign_sign_blob_args(
    cosign_key: &str,
    payload_path: &Path,
    bundle_path: &Path,
) -> Vec<String> {
    vec![
        "sign-blob".to_owned(),
        "--yes".to_owned(),
        "--key".to_owned(),
        cosign_key.to_owned(),
        "--bundle".to_owned(),
        bundle_path.display().to_string(),
        payload_path.display().to_string(),
    ]
}

fn build_cosign_public_key_args(cosign_key: &str) -> Vec<String> {
    vec!["public-key".to_owned(), "--key".to_owned(), cosign_key.to_owned()]
}

fn execute_cosign(args: &[String]) -> io::Result<std::process::Output> {
    let cosign_bin = std::env::var(COSIGN_BIN_ENV).unwrap_or_else(|_| "cosign".to_owned());

    Command::new(cosign_bin).args(args).output()
}

fn command_failure(command: &str, output: &std::process::Output) -> io::Error {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let details = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exited with status {}", output.status)
    };

    io::Error::other(format!("{command} failed: {details}"))
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        use std::fmt::Write as _;

        let _ = write!(&mut hex, "{byte:02x}");
    }

    hex
}

fn write_process_output(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }

    writer.write_all(bytes)?;

    if !bytes.ends_with(b"\n") {
        writeln!(writer)?;
    }

    Ok(())
}

fn temporary_layout_dir(prefix: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();

    std::env::temp_dir().join(format!("{prefix}-{}-{unique}", std::process::id()))
}

fn write_diagnostics(
    writer: &mut impl Write,
    label: &str,
    diagnostics: &[Diagnostic],
) -> io::Result<()> {
    writeln!(writer, "{label}:")?;

    for diagnostic in diagnostics {
        writeln!(writer, "  - {}: {}", diagnostic.path, diagnostic.message)?;
    }

    Ok(())
}

fn write_parse_error(
    output_format: OutputFormat,
    path: &str,
    error: ai_catalog::Error,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<()> {
    match output_format {
        OutputFormat::Text => writeln!(stderr, "{}", parse_error_message(path, &error)),
        OutputFormat::Json => write_validation_result_json(
            stdout,
            false,
            None,
            &[Diagnostic {
                path: path.to_owned(),
                message: format!("failed to parse input: {error}"),
            }],
            &[],
        ),
    }
}

fn write_validation_result_json(
    stdout: &mut impl Write,
    is_valid: bool,
    conformance_level: Option<ConformanceLevel>,
    errors: &[Diagnostic],
    warnings: &[Diagnostic],
) -> io::Result<()> {
    let payload = json!({
        "valid": is_valid,
        "conformanceLevel": conformance_level.map(conformance_level_name),
        "errors": diagnostics_to_json(errors),
        "warnings": diagnostics_to_json(warnings),
    });

    serde_json::to_writer_pretty(&mut *stdout, &payload).map_err(io::Error::other)?;
    writeln!(stdout)
}

fn diagnostics_to_json(diagnostics: &[Diagnostic]) -> Vec<serde_json::Value> {
    diagnostics
        .iter()
        .map(|diagnostic| {
            json!({
                "path": diagnostic.path,
                "message": diagnostic.message,
            })
        })
        .collect()
}

fn parse_error_message(path: &str, error: &ai_catalog::Error) -> String {
    if path == "-" {
        format!("failed to parse stdin: {error}")
    } else {
        format!("failed to parse '{path}': {error}")
    }
}

fn write_trust_report(writer: &mut impl Write, report: &CatalogTrustReport) -> io::Result<()> {
    let status = if trust_report_has_errors(report) {
        "errors found"
    } else if report.findings.is_empty() {
        "ok"
    } else {
        "warnings found"
    };

    writeln!(writer, "trust report: {status}")?;

    if report.host.is_none() && report.entries.is_empty() {
        writeln!(writer, "no trust manifests found")?;
        return Ok(());
    }

    if let Some(host) = &report.host {
        write_manifest_report(writer, "host", host)?;
    }

    for entry in &report.entries {
        write_manifest_report(writer, "entry", entry)?;
    }

    Ok(())
}

fn write_manifest_report(
    writer: &mut impl Write,
    label: &str,
    report: &ManifestReport,
) -> io::Result<()> {
    writeln!(writer, "{label}: {}", report.path)?;
    writeln!(writer, "  identity: {}", report.identity)?;
    writeln!(
        writer,
        "  signature: {}",
        if report.has_signature {
            "present"
        } else {
            "absent"
        }
    )?;
    writeln!(writer, "  attestations: {}", report.attestation_count)?;
    writeln!(writer, "  provenance: {}", report.provenance_count)?;

    for finding in &report.findings {
        writeln!(
            writer,
            "  - {} {}: {}",
            severity_name(finding.severity),
            finding.path,
            finding.message
        )?;
    }

    Ok(())
}

fn write_trust_report_json(stdout: &mut impl Write, report: &CatalogTrustReport) -> io::Result<()> {
    let payload = json!({
        "ok": !trust_report_has_errors(report),
        "findings": report.findings.iter().map(trust_finding_to_json).collect::<Vec<_>>(),
        "host": report.host.as_ref().map(trust_manifest_report_to_json),
        "entries": report.entries.iter().map(trust_manifest_report_to_json).collect::<Vec<_>>(),
    });

    serde_json::to_writer_pretty(&mut *stdout, &payload).map_err(io::Error::other)?;
    writeln!(stdout)
}

fn trust_manifest_report_to_json(report: &ManifestReport) -> serde_json::Value {
    json!({
        "path": report.path,
        "identity": report.identity,
        "hasSignature": report.has_signature,
        "attestationCount": report.attestation_count,
        "provenanceCount": report.provenance_count,
        "findings": report.findings.iter().map(trust_finding_to_json).collect::<Vec<_>>(),
    })
}

fn trust_finding_to_json(finding: &TrustFinding) -> serde_json::Value {
    json!({
        "severity": severity_name(finding.severity),
        "path": finding.path,
        "message": finding.message,
    })
}

fn trust_report_has_errors(report: &CatalogTrustReport) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.severity == Severity::Error)
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
    }
}

fn input_label(path: &str) -> String {
    if path == "-" {
        "stdin".to_owned()
    } else {
        format!("'{path}'")
    }
}

fn conformance_level_name(level: ConformanceLevel) -> &'static str {
    match level {
        ConformanceLevel::Minimal => "minimal",
        ConformanceLevel::Discoverable => "discoverable",
        ConformanceLevel::Trusted => "trusted",
    }
}

#[cfg(test)]
mod tests {
    use ai_catalog_oci::{
        COSIGN_PUBLIC_KEY_ARTIFACT_TYPE, COSIGN_SIGNATURE_ARTIFACT_TYPE,
        TRUST_MANIFEST_ARTIFACT_TYPE, import_layout,
    };
    use super::run;

    use serde_json::Value;
    use std::env;
    use std::fs;
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    #[test]
    fn prints_help_without_arguments() {
        let (exit_code, stdout, stderr) = run_command(["ai-catalog-cli"], "");

        assert_eq!(exit_code, 0);
        assert!(stdout.contains("Usage:"));
        assert!(stdout.contains("validate [--json] <path|->"));
        assert!(stdout.contains("trust inspect [--json] <path|->"));
        assert!(stdout.contains("oci pack <path|->"));
        assert!(stdout.contains("oci export-layout [--tag <tag>] [--cosign-key <path>] [--cosign-public-key <path>] <path|-> <layout-dir>"));
        assert!(stdout.contains("oci unpack-layout [--ref-name <name>] <layout-dir>"));
        assert!(stdout.contains("oci push [--tag <tag>] [--plain-http] [--insecure] [--to-oci-layout-path <layout-dir>] [--cosign-key <path>] [--cosign-public-key <path>] <path|-> <target>"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn prints_version() {
        let (exit_code, stdout, stderr) = run_command(["ai-catalog-cli", "version"], "");

        assert_eq!(exit_code, 0);
        assert_eq!(
            stdout,
            format!("ai-catalog-cli {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn validates_canonical_fixture() {
        let fixture = canonical_fixture_path();
        let (exit_code, stdout, stderr) = run_command(
            [
                "ai-catalog-cli",
                "validate",
                fixture.to_str().expect("path should be utf-8"),
            ],
            "",
        );

        assert_eq!(exit_code, 0);
        assert!(stdout.contains("catalog is valid"));
        assert!(stdout.contains("conformance: discoverable"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn formats_canonical_fixture() {
        let fixture = canonical_fixture_path();
        let (exit_code, stdout, stderr) = run_command(
            [
                "ai-catalog-cli",
                "format",
                fixture.to_str().expect("path should be utf-8"),
            ],
            "",
        );

        assert_eq!(exit_code, 0);
        assert!(stdout.contains("\"entries\": ["));
        assert!(stdout.ends_with('\n'));
        assert!(stderr.is_empty());
    }

    #[test]
    fn validates_canonical_fixture_as_json() {
        let fixture = canonical_fixture_path();
        let (exit_code, stdout, stderr) = run_command(
            [
                "ai-catalog-cli",
                "validate",
                "--json",
                fixture.to_str().expect("path should be utf-8"),
            ],
            "",
        );
        let payload: Value = serde_json::from_str(&stdout).expect("stdout should be valid json");

        assert_eq!(exit_code, 0);
        assert_eq!(payload["valid"], true);
        assert_eq!(payload["conformanceLevel"], "discoverable");
        assert_eq!(payload["errors"], Value::Array(vec![]));
        assert!(stderr.is_empty());
    }

    #[test]
    fn validates_from_stdin() {
        let fixture = canonical_fixture_text();
        let (exit_code, stdout, stderr) =
            run_command(["ai-catalog-cli", "validate", "-"], &fixture);

        assert_eq!(exit_code, 0);
        assert!(stdout.contains("catalog is valid"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn formats_from_stdin() {
        let fixture = canonical_fixture_text();
        let (exit_code, stdout, stderr) = run_command(["ai-catalog-cli", "format", "-"], &fixture);

        assert_eq!(exit_code, 0);
        assert!(stdout.contains("\"specVersion\": \"1.0\""));
        assert!(stdout.ends_with('\n'));
        assert!(stderr.is_empty());
    }

    #[test]
    fn reports_validation_errors() {
        let invalid_fixture = r#"{
    "specVersion": "1.0",
    "entries": [
        {
            "identifier": "urn:example:model",
            "displayName": "Example Model",
            "mediaType": "application/json",
            "url": "https://example.com/model.json",
            "data": {}
        }
    ]
}"#;
        let (exit_code, stdout, stderr) =
            run_command(["ai-catalog-cli", "validate", "-"], invalid_fixture);

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert!(stderr.contains("catalog is invalid"));
        assert!(stderr.contains("exactly one of 'url' or 'data', found both"));
    }

    #[test]
    fn reports_validation_errors_as_json() {
        let invalid_fixture = r#"{
    "specVersion": "1.0",
    "entries": [
        {
            "identifier": "urn:example:model",
            "displayName": "Example Model",
            "mediaType": "application/json",
            "url": "https://example.com/model.json",
            "data": {}
        }
    ]
}"#;
        let (exit_code, stdout, stderr) = run_command(
            ["ai-catalog-cli", "validate", "--json", "-"],
            invalid_fixture,
        );
        let payload: Value = serde_json::from_str(&stdout).expect("stdout should be valid json");

        assert_eq!(exit_code, 1);
        assert_eq!(payload["valid"], false);
        assert_eq!(payload["conformanceLevel"], "minimal");
        assert!(
            payload["errors"]
                .as_array()
                .expect("errors should be an array")
                .iter()
                .any(|diagnostic| diagnostic["message"]
                    .as_str()
                    .expect("message should be a string")
                    .contains("exactly one of 'url' or 'data', found both"))
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn reports_parse_errors() {
        let (exit_code, stdout, stderr) =
            run_command(["ai-catalog-cli", "validate", "-"], "not json");

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert!(stderr.contains("failed to parse stdin"));
    }

    #[test]
    fn reports_parse_errors_as_json() {
        let (exit_code, stdout, stderr) =
            run_command(["ai-catalog-cli", "validate", "--json", "-"], "not json");
        let payload: Value = serde_json::from_str(&stdout).expect("stdout should be valid json");

        assert_eq!(exit_code, 1);
        assert_eq!(payload["valid"], false);
        assert_eq!(payload["conformanceLevel"], Value::Null);
        assert!(
            payload["errors"]
                .as_array()
                .expect("errors should be an array")
                .iter()
                .any(|diagnostic| diagnostic["path"] == "-")
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn rejects_unknown_validate_option() {
        let (exit_code, stdout, stderr) =
            run_command(["ai-catalog-cli", "validate", "--yaml", "-"], "");

        assert_eq!(exit_code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("unknown validate option: --yaml"));
    }

    #[test]
    fn rejects_missing_format_path() {
        let (exit_code, stdout, stderr) = run_command(["ai-catalog-cli", "format"], "");

        assert_eq!(exit_code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("format expects exactly one <path> argument"));
    }

    #[test]
    fn rejects_unknown_command() {
        let (exit_code, stdout, stderr) = run_command(["ai-catalog-cli", "bogus"], "");

        assert_eq!(exit_code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("unknown command: bogus"));
    }

    #[test]
    fn trust_inspect_reports_clean_catalog() {
        let fixture = canonical_fixture_text();
        let (exit_code, stdout, stderr) =
            run_command(["ai-catalog-cli", "trust", "inspect", "-"], &fixture);

        assert_eq!(exit_code, 0);
        assert!(stdout.contains("trust report: ok"));
        assert!(stdout.contains("no trust manifests found"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn trust_inspect_reports_findings_as_json() {
        let invalid_fixture = r#"{
    "specVersion": "1.0",
    "entries": [
        {
            "identifier": "urn:example:model",
            "displayName": "Example Model",
            "mediaType": "application/json",
            "url": "https://example.com/model.json",
            "trustManifest": {
                "identity": "plain-identifier",
                "signature": "header.payload.signature"
            }
        }
    ]
}"#;
        let (exit_code, stdout, stderr) = run_command(
            ["ai-catalog-cli", "trust", "inspect", "--json", "-"],
            invalid_fixture,
        );
        let payload: Value = serde_json::from_str(&stdout).expect("stdout should be valid json");

        assert_eq!(exit_code, 1);
        assert_eq!(payload["ok"], false);
        assert!(
            payload["findings"]
                .as_array()
                .expect("findings should be an array")
                .iter()
                .any(|finding| finding["severity"] == "error")
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn oci_pack_outputs_artifact_set_json() {
        let fixture = canonical_fixture_text();
        let (exit_code, stdout, stderr) =
            run_command(["ai-catalog-cli", "oci", "pack", "-"], &fixture);
        let payload: Value = serde_json::from_str(&stdout).expect("stdout should be valid json");

        assert_eq!(exit_code, 0);
        assert_eq!(
            payload["index"]["artifactType"],
            "application/ai-catalog+json"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn oci_unpack_round_trips_packed_catalog() {
        let fixture = canonical_fixture_text();
        let (_, packed_stdout, packed_stderr) =
            run_command(["ai-catalog-cli", "oci", "pack", "-"], &fixture);

        assert!(packed_stderr.is_empty());

        let (exit_code, stdout, stderr) =
            run_command(["ai-catalog-cli", "oci", "unpack", "-"], &packed_stdout);

        assert_eq!(exit_code, 0);
        assert!(stdout.contains("\"specVersion\": \"1.0\""));
        assert!(stdout.contains("\"entries\": ["));
        assert!(stderr.is_empty());
    }

    #[test]
    fn oci_export_layout_writes_standard_layout_directory() {
        let fixture = canonical_fixture_text();
        let layout_dir = unique_temp_dir("ai-catalog-cli-layout");
        let (exit_code, stdout, stderr) = run_command(
            [
                "ai-catalog-cli",
                "oci",
                "export-layout",
                "--tag",
                "demo",
                "-",
                layout_dir.to_str().expect("path should be utf-8"),
            ],
            &fixture,
        );

        assert_eq!(exit_code, 0);
        assert!(stdout.contains("exported OCI image layout"));
        assert!(layout_dir.join("oci-layout").exists());
        assert!(layout_dir.join("index.json").exists());
        assert!(stderr.is_empty());

        fs::remove_dir_all(layout_dir).expect("layout dir should be removable");
    }

    #[test]
    fn rejects_cosign_public_key_without_cosign_key() {
        let layout_dir = unique_temp_dir("ai-catalog-cli-layout-cosign-option");
        let (exit_code, stdout, stderr) = run_command(
            [
                "ai-catalog-cli",
                "oci",
                "export-layout",
                "--cosign-public-key",
                "cosign.pub",
                "-",
                layout_dir.to_str().expect("path should be utf-8"),
            ],
            &canonical_fixture_text(),
        );

        assert_eq!(exit_code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("requires --cosign-key when --cosign-public-key is set"));
    }

    #[test]
    #[cfg(unix)]
    fn oci_export_layout_with_cosign_writes_signature_and_key_referrers() {
        let fixture = r#"{
    "specVersion": "1.0",
    "entries": [
        {
            "identifier": "urn:example:model",
            "displayName": "Example Model",
            "mediaType": "application/json",
            "data": { "name": "example" },
            "trustManifest": {
                "identity": "urn:example:model"
            }
        }
    ]
}"#;
        let layout_dir = unique_temp_dir("ai-catalog-cli-layout-cosign");
        let tool_dir = unique_temp_dir("ai-catalog-cli-fake-cosign");

        fs::create_dir_all(&tool_dir).expect("tool dir should exist");
        let script_path = write_fake_cosign_script(&tool_dir);

        let (exit_code, stdout, stderr) = with_env_var(super::COSIGN_BIN_ENV, script_path.as_os_str(), || {
            run_command(
                [
                    "ai-catalog-cli",
                    "oci",
                    "export-layout",
                    "--cosign-key",
                    "fake.key",
                    "--tag",
                    "demo",
                    "-",
                    layout_dir.to_str().expect("path should be utf-8"),
                ],
                fixture,
            )
        });

        assert_eq!(exit_code, 0);
        assert!(stdout.contains("attached Cosign verification artifacts for 1 trust manifest(s)"));
        assert!(stderr.is_empty());

        let imported = import_layout(&layout_dir, Some("demo")).expect("layout should import");
        let entry_digest = imported.index.manifests[0].digest.clone();
        let referrer_types = imported.referrers[&entry_digest]
            .iter()
            .filter_map(|manifest| manifest.artifact_type.as_deref())
            .collect::<Vec<_>>();

        assert!(referrer_types.contains(&TRUST_MANIFEST_ARTIFACT_TYPE));
        assert!(referrer_types.contains(&COSIGN_SIGNATURE_ARTIFACT_TYPE));
        assert!(referrer_types.contains(&COSIGN_PUBLIC_KEY_ARTIFACT_TYPE));

        fs::remove_dir_all(layout_dir).expect("layout dir should be removable");
        fs::remove_dir_all(tool_dir).expect("tool dir should be removable");
    }

    #[test]
    fn oci_unpack_layout_round_trips_exported_layout() {
        let fixture = canonical_fixture_text();
        let layout_dir = unique_temp_dir("ai-catalog-cli-unpack-layout");
        let (_, export_stdout, export_stderr) = run_command(
            [
                "ai-catalog-cli",
                "oci",
                "export-layout",
                "--tag",
                "demo",
                "-",
                layout_dir.to_str().expect("path should be utf-8"),
            ],
            &fixture,
        );

        assert!(export_stdout.contains("exported OCI image layout"));
        assert!(export_stderr.is_empty());

        let (exit_code, stdout, stderr) = run_command(
            [
                "ai-catalog-cli",
                "oci",
                "unpack-layout",
                "--ref-name",
                "demo",
                layout_dir.to_str().expect("path should be utf-8"),
            ],
            "",
        );

        assert_eq!(exit_code, 0);
        assert!(stdout.contains("\"specVersion\": \"1.0\""));
        assert!(stdout.contains("\"entries\": ["));
        assert!(stderr.is_empty());

        fs::remove_dir_all(layout_dir).expect("layout dir should be removable");
    }

    #[test]
    fn builds_oras_copy_arguments() {
        let args = super::build_oras_cp_args(
            Path::new("/tmp/source-layout"),
            "demo",
            "example.com/catalog:demo",
            Some("/tmp/dest-layout"),
            true,
            true,
        );

        assert_eq!(
            args,
            vec![
                "cp",
                "-r",
                "--from-oci-layout",
                "--to-oci-layout-path",
                "/tmp/dest-layout",
                "--to-plain-http",
                "--to-insecure",
                "/tmp/source-layout:demo",
                "example.com/catalog:demo",
            ]
        );
    }

    #[test]
    fn builds_oras_copy_arguments_for_entry_referrers() {
        let args = super::build_oras_cp_referrer_args(
            Path::new("/tmp/source-layout"),
            "sha256:deadbeef",
            "example.com/catalog",
            Some("/tmp/dest-layout"),
            true,
            false,
        );

        assert_eq!(
            args,
            vec![
                "cp",
                "-r",
                "--from-oci-layout",
                "--to-oci-layout-path",
                "/tmp/dest-layout",
                "--to-plain-http",
                "/tmp/source-layout@sha256:deadbeef",
                "example.com/catalog",
            ]
        );
    }

    #[test]
    fn builds_cosign_sign_blob_arguments() {
        let args = super::build_cosign_sign_blob_args(
            "cosign.key",
            Path::new("/tmp/trust-manifest.json"),
            Path::new("/tmp/trust-manifest.sig"),
        );

        assert_eq!(
            args,
            vec![
                "sign-blob",
                "--yes",
                "--key",
                "cosign.key",
                "--bundle",
                "/tmp/trust-manifest.sig",
                "/tmp/trust-manifest.json",
            ]
        );
    }

    #[test]
    fn builds_cosign_public_key_arguments() {
        let args = super::build_cosign_public_key_args("cosign.key");

        assert_eq!(args, vec!["public-key", "--key", "cosign.key"]);
    }

    #[test]
    fn strips_tags_from_target_repositories() {
        assert_eq!(
            super::target_repository("example.com/catalog:demo"),
            "example.com/catalog"
        );
        assert_eq!(
            super::target_repository("localhost:5000/example/catalog:demo"),
            "localhost:5000/example/catalog"
        );
        assert_eq!(
            super::target_repository("example.com/catalog@sha256:deadbeef"),
            "example.com/catalog"
        );
        assert_eq!(
            super::target_repository("example.com/catalog"),
            "example.com/catalog"
        );
    }

    fn canonical_fixture_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/spec-example.json")
    }

    fn canonical_fixture_text() -> String {
        fs::read_to_string(canonical_fixture_path()).expect("fixture should be readable")
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();

        std::env::temp_dir().join(format!("{prefix}-{unique}"))
    }

    fn run_command<const N: usize>(args: [&str; N], stdin_text: &str) -> (i32, String, String) {
        let mut stdin = stdin_text.as_bytes();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            run(args, &mut stdin, &mut stdout, &mut stderr).expect("run should succeed");

        (
            exit_code,
            String::from_utf8(stdout).expect("stdout should be utf-8"),
            String::from_utf8(stderr).expect("stderr should be utf-8"),
        )
    }

    fn with_env_var<T>(key: &str, value: &std::ffi::OsStr, f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock should be available");
        let previous = env::var_os(key);
        unsafe {
            env::set_var(key, value);
        }
        let result = f();

        if let Some(previous) = previous {
            unsafe {
                env::set_var(key, previous);
            }
        } else {
            unsafe {
                env::remove_var(key);
            }
        }

        result
    }

    #[cfg(unix)]
    fn write_fake_cosign_script(dir: &Path) -> PathBuf {
        let script_path = dir.join("fake-cosign.sh");
        let mut file = fs::File::create(&script_path).expect("script should be creatable");

        write!(
            file,
            "{}",
            "#!/bin/sh\nset -eu\ncmd=\"$1\"\nshift\ncase \"$cmd\" in\n  public-key)\n    echo '-----BEGIN PUBLIC KEY-----'\n    echo 'RkFLRUNPU0lHTlBVQkxJQ0tFWQ=='\n    echo '-----END PUBLIC KEY-----'\n    ;;\n  sign-blob)\n    bundle=''\n    while [ $# -gt 0 ]; do\n      case \"$1\" in\n        --bundle)\n          bundle=\"$2\"\n          shift 2\n          ;;\n        --key)\n          shift 2\n          ;;\n        --yes)\n          shift 1\n          ;;\n        *)\n          shift 1\n          ;;\n      esac\n    done\n    printf '{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"messageSignature\":{\"signature\":\"fake-cosign-signature\"}}' > \"$bundle\"\n    ;;\n  *)\n    echo \"unexpected cosign command: $cmd\" >&2\n    exit 1\n    ;;\nesac"
        )
        .expect("script should be writable");

        let mut permissions = fs::metadata(&script_path)
            .expect("script metadata should exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("script should be executable");

        script_path
    }
}
