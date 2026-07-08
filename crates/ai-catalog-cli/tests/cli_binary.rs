// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

#[test]
fn binary_help_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-catalog"))
        .arg("help")
        .output()
        .expect("help command should run");

    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .expect("stdout should be utf-8")
            .contains("Usage:")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn binary_validate_json_from_stdin_succeeds() {
    let fixture = fs::read_to_string(format!(
        "{}/../../fixtures/spec-example.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture should be readable");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-catalog"))
        .args(["validate", "--json", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("validate command should start");

    child
        .stdin
        .as_mut()
        .expect("stdin should be piped")
        .write_all(fixture.as_bytes())
        .expect("fixture should be written to stdin");

    let output = child
        .wait_with_output()
        .expect("validate command should finish");
    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid json");

    assert!(output.status.success());
    assert_eq!(payload["valid"], true);
    assert_eq!(payload["conformanceLevel"], "discoverable");
    assert!(output.stderr.is_empty());
}

#[test]
fn binary_oci_pack_from_stdin_succeeds() {
    let fixture = fs::read_to_string(format!(
        "{}/../../fixtures/spec-example.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture should be readable");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-catalog"))
        .args(["oci", "pack", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("oci pack command should start");

    child
        .stdin
        .as_mut()
        .expect("stdin should be piped")
        .write_all(fixture.as_bytes())
        .expect("fixture should be written to stdin");

    let output = child
        .wait_with_output()
        .expect("oci pack command should finish");
    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid json");

    assert!(output.status.success());
    assert_eq!(
        payload["index"]["artifactType"],
        "application/ai-catalog+json"
    );
    assert!(output.stderr.is_empty());
}
