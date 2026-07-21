// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

const FIXTURE_CATALOG: &str = r#"{
  "specVersion": "1.0",
  "host": {"displayName": "Test Registry"},
  "entries": [
    {
      "identifier": "urn:test:agent-alpha",
      "displayName": "Alpha Agent",
      "type": "application/a2a-agent-card+json",
      "description": "A test agent for integration tests",
      "tags": ["test", "alpha"],
      "url": "https://example.com/agents/alpha.json"
    },
    {
      "identifier": "urn:test:dataset-beta",
      "displayName": "Beta Dataset",
      "type": "application/parquet",
      "description": "A test dataset",
      "tags": ["dataset", "beta"],
      "url": "https://example.com/data/beta.parquet"
    }
  ]
}"#;

/// Write the shared fixture catalog to a temp file and return its `file://` URL.
fn write_fixture_catalog(dir: &Path) -> String {
    let path = dir.join("test-catalog.json");
    fs::write(&path, FIXTURE_CATALOG).expect("fixture catalog should be writable");
    format!("file://{}", path.display())
}

/// Run the binary with an isolated HOME so the real `~/.ai-catalog/` is never touched.
fn cmd_with_home(tmp_home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ai-catalog"));
    c.env("HOME", tmp_home);
    c
}

/// Run a command and return (success, stdout_string, stderr_string).
fn run(cmd: &mut Command) -> (bool, String, String) {
    let out = cmd.output().expect("command should run");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (out.status.success(), stdout, stderr)
}

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

// ── Consumer command integration tests ───────────────────────────────────────

#[test]
fn catalog_list_empty_prints_message() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, stdout, _) = run(cmd_with_home(home.path()).args(["catalog", "list"]));
    assert!(ok);
    assert!(stdout.contains("No catalogs registered"));
}

#[test]
fn catalog_list_json_empty_returns_valid_json() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, stdout, _) = run(cmd_with_home(home.path()).args(["catalog", "list", "--json"]));
    assert!(ok);
    let v: Value = serde_json::from_str(&stdout).expect("catalog list --json should emit JSON");
    assert_eq!(v["specVersion"], "1.0");
    assert!(v["entries"].as_array().unwrap().is_empty());
}

#[test]
fn catalog_add_then_list_shows_entry() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    let (ok, _, stderr) =
        run(cmd_with_home(home.path()).args(["catalog", "add", "my-test-catalog", &catalog_url]));
    assert!(ok, "catalog add failed: {stderr}");

    let (ok, stdout, _) = run(cmd_with_home(home.path()).args(["catalog", "list"]));
    assert!(ok);
    assert!(stdout.contains("my-test-catalog"));
}

#[test]
fn catalog_add_then_list_json_contains_entry() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "json-test", &catalog_url]));

    let (ok, stdout, _) = run(cmd_with_home(home.path()).args(["catalog", "list", "--json"]));
    assert!(ok);
    let v: Value = serde_json::from_str(&stdout).unwrap();
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["displayName"], "json-test");
}

#[test]
fn catalog_add_duplicate_name_fails() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "dup-catalog", &catalog_url]));
    let (ok, _, stderr) =
        run(cmd_with_home(home.path()).args(["catalog", "add", "dup-catalog", &catalog_url]));
    assert!(!ok, "duplicate add should fail");
    assert!(
        stderr.contains("dup-catalog") || stderr.contains("already registered"),
        "error should mention duplicate: {stderr}"
    );
}

#[test]
fn catalog_add_then_remove_clears_list() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "to-remove", &catalog_url]));
    let (ok, _, stderr) = run(cmd_with_home(home.path()).args(["catalog", "remove", "to-remove"]));
    assert!(ok, "catalog remove failed: {stderr}");

    let (ok, stdout, _) = run(cmd_with_home(home.path()).args(["catalog", "list"]));
    assert!(ok);
    assert!(stdout.contains("No catalogs registered"));
}

#[test]
fn catalog_remove_nonexistent_fails() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, _, stderr) =
        run(cmd_with_home(home.path()).args(["catalog", "remove", "does-not-exist"]));
    assert!(!ok);
    assert!(
        stderr.contains("does-not-exist") || stderr.contains("not found"),
        "error should mention the missing catalog: {stderr}"
    );
}

#[test]
fn catalog_update_existing_succeeds() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "updatable", &catalog_url]));
    let (ok, stdout, stderr) =
        run(cmd_with_home(home.path()).args(["catalog", "update", "updatable"]));
    assert!(ok, "catalog update failed: {stderr}");
    assert!(
        stdout.contains("up to date") || stdout.contains("updated"),
        "unexpected output: {stdout}"
    );
}

#[test]
fn catalog_update_nonexistent_fails() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, _, stderr) = run(cmd_with_home(home.path()).args(["catalog", "update", "ghost"]));
    assert!(!ok);
    assert!(
        stderr.contains("ghost") || stderr.contains("not found"),
        "error should name the missing catalog: {stderr}"
    );
}

#[test]
fn search_with_no_catalogs_returns_no_results() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, stdout, _) = run(cmd_with_home(home.path()).args(["search", "anything"]));
    assert!(ok);
    assert!(stdout.contains("No entries found") || stdout.is_empty());
}

#[test]
fn search_after_add_finds_matching_entry() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "search-test", &catalog_url]));

    let (ok, stdout, stderr) = run(cmd_with_home(home.path()).args(["search", "alpha"]));
    assert!(ok, "search failed: {stderr}");
    assert!(
        stdout.contains("alpha") || stdout.contains("Alpha"),
        "search result should contain 'alpha': {stdout}"
    );
}

#[test]
fn search_json_after_add_returns_valid_catalog() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "search-json", &catalog_url]));

    let (ok, stdout, _) = run(cmd_with_home(home.path()).args(["search", "--json", "dataset"]));
    assert!(ok);
    let v: Value = serde_json::from_str(&stdout).expect("search --json should emit JSON");
    assert_eq!(v["specVersion"], "1.0");
    let entries = v["entries"].as_array().unwrap();
    assert!(!entries.is_empty());
    assert!(
        entries
            .iter()
            .any(|e| e["identifier"].as_str().unwrap_or("").contains("beta"))
    );
}

#[test]
fn search_regex_after_add_finds_by_pattern() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "regex-test", &catalog_url]));

    let (ok, stdout, stderr) =
        run(cmd_with_home(home.path()).args(["search", "--regex", "urn:test:(agent|dataset)"]));
    assert!(ok, "regex search failed: {stderr}");
    assert!(
        stdout.contains("alpha") || stdout.contains("beta"),
        "regex search should match entries: {stdout}"
    );
}

#[test]
fn show_after_add_displays_entry() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "show-test", &catalog_url]));

    let (ok, stdout, stderr) =
        run(cmd_with_home(home.path()).args(["show", "urn:test:agent-alpha"]));
    assert!(ok, "show failed: {stderr}");
    assert!(
        stdout.contains("urn:test:agent-alpha") || stdout.contains("Alpha"),
        "show output should contain the entry: {stdout}"
    );
}

#[test]
fn show_json_after_add_returns_entry_json() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "show-json", &catalog_url]));

    let (ok, stdout, _) =
        run(cmd_with_home(home.path()).args(["show", "--json", "urn:test:dataset-beta"]));
    assert!(ok);
    let v: Value = serde_json::from_str(&stdout).expect("show --json should emit JSON");
    assert_eq!(v["identifier"], "urn:test:dataset-beta");
    assert_eq!(v["type"], "application/parquet");
}

#[test]
fn show_nonexistent_entry_fails() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, _, _) = run(cmd_with_home(home.path()).args(["show", "urn:test:nonexistent"]));
    assert!(!ok);
}

#[test]
fn pull_unknown_entry_fails() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, _, stderr) = run(cmd_with_home(home.path()).args(["pull", "urn:test:ghost"]));
    assert!(!ok);
    assert!(
        stderr.contains("urn:test:ghost") || stderr.contains("not found"),
        "error should name the missing entry: {stderr}"
    );
}

#[test]
fn catalog_missing_subcommand_fails() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, _, stderr) = run(cmd_with_home(home.path()).arg("catalog"));
    assert!(!ok);
    assert!(
        stderr.contains("subcommand"),
        "should mention subcommand: {stderr}"
    );
}

#[test]
fn search_missing_keyword_fails() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, _, stderr) = run(cmd_with_home(home.path()).arg("search"));
    assert!(!ok);
    assert!(
        stderr.contains("usage") || stderr.contains("keyword"),
        "{stderr}"
    );
}

#[test]
fn show_missing_identifier_fails() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, _, stderr) = run(cmd_with_home(home.path()).arg("show"));
    assert!(!ok);
    assert!(
        stderr.contains("usage") || stderr.contains("identifier"),
        "{stderr}"
    );
}

#[test]
fn pull_missing_identifier_fails() {
    let home = tempfile::TempDir::new().unwrap();
    let (ok, _, stderr) = run(cmd_with_home(home.path()).arg("pull"));
    assert!(!ok);
    assert!(
        stderr.contains("usage") || stderr.contains("identifier"),
        "{stderr}"
    );
}

// ── --media-type tests ────────────────────────────────────────────────────────

/// Write a parent catalog whose single entry is a nested catalog pointing at `child_url`.
/// Returns the `file://` URL of the parent.
fn write_nested_catalog(dir: &Path, child_url: &str) -> String {
    let parent_json = format!(
        r#"{{
  "specVersion": "1.0",
  "entries": [
    {{
      "identifier": "urn:test:nested-catalog",
      "displayName": "Nested Catalog",
      "type": "application/ai-catalog+json",
      "url": "{child_url}"
    }}
  ]
}}"#
    );
    let path = dir.join("parent-catalog.json");
    fs::write(&path, parent_json).expect("parent catalog should be writable");
    format!("file://{}", path.display())
}

/// Write a child catalog with one entry of type `application/json` (inline data).
fn write_child_catalog(dir: &Path) -> String {
    let child_json = r#"{
  "specVersion": "1.0",
  "entries": [
    {
      "identifier": "urn:test:child-agent",
      "displayName": "Child Agent",
      "type": "application/json",
      "data": {"name": "child"}
    }
  ]
}"#;
    let path = dir.join("child-catalog.json");
    fs::write(&path, child_json).expect("child catalog should be writable");
    format!("file://{}", path.display())
}

/// Write a child catalog with TWO entries of the same type (for ambiguity tests).
fn write_child_catalog_two_json(dir: &Path) -> String {
    let child_json = r#"{
  "specVersion": "1.0",
  "entries": [
    {
      "identifier": "urn:test:child-a",
      "type": "application/json",
      "data": {"name": "a"}
    },
    {
      "identifier": "urn:test:child-b",
      "type": "application/json",
      "data": {"name": "b"}
    }
  ]
}"#;
    let path = dir.join("child-two.json");
    fs::write(&path, child_json).expect("child catalog (two) should be writable");
    format!("file://{}", path.display())
}

#[test]
fn pull_catalog_entry_without_media_type_errors() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let child_url = write_child_catalog(catalog_dir.path());
    let child_url = child_url.strip_prefix("file://").unwrap().to_owned();
    let parent_url = write_nested_catalog(catalog_dir.path(), &child_url);

    run(cmd_with_home(home.path()).args(["catalog", "add", "nested-test", &parent_url]));

    let (ok, _, stderr) = run(cmd_with_home(home.path()).args(["pull", "urn:test:nested-catalog"]));
    assert!(
        !ok,
        "pull should fail when id is a catalog without --media-type"
    );
    assert!(
        stderr.contains("refers to a catalog"),
        "error should mention catalog: {stderr}"
    );
    assert!(
        stderr.contains("--media-type"),
        "error should suggest --media-type: {stderr}"
    );
}

#[test]
fn pull_catalog_entry_with_catalog_media_type_writes_file() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let child_url = write_child_catalog(catalog_dir.path());
    let child_url_path = child_url.strip_prefix("file://").unwrap().to_owned();
    let parent_url = write_nested_catalog(catalog_dir.path(), &child_url_path);

    run(cmd_with_home(home.path()).args(["catalog", "add", "nested-catalog-mt", &parent_url]));

    let out_dir = tempfile::TempDir::new().unwrap();
    let (ok, _, stderr) = run(cmd_with_home(home.path()).args([
        "pull",
        "--media-type",
        "application/ai-catalog+json",
        "--output",
        out_dir.path().to_str().unwrap(),
        "urn:test:nested-catalog",
    ]));
    assert!(ok, "pull with catalog media-type should succeed: {stderr}");
    // At least one file should be written
    let files: Vec<_> = fs::read_dir(out_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(!files.is_empty(), "output directory should contain a file");
}

#[test]
fn pull_catalog_entry_with_child_media_type_pulls_child() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let child_url = write_child_catalog(catalog_dir.path());
    let child_url_path = child_url.strip_prefix("file://").unwrap().to_owned();
    let parent_url = write_nested_catalog(catalog_dir.path(), &child_url_path);

    run(cmd_with_home(home.path()).args(["catalog", "add", "nested-child-mt", &parent_url]));

    let out_dir = tempfile::TempDir::new().unwrap();
    let (ok, _, stderr) = run(cmd_with_home(home.path()).args([
        "pull",
        "--media-type",
        "application/json",
        "--output",
        out_dir.path().to_str().unwrap(),
        "urn:test:nested-catalog",
    ]));
    assert!(ok, "pull with child media-type should succeed: {stderr}");
    let files: Vec<_> = fs::read_dir(out_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        !files.is_empty(),
        "output directory should contain the child entry file"
    );
}

#[test]
fn pull_catalog_entry_with_ambiguous_media_type_errors() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let child_url = write_child_catalog_two_json(catalog_dir.path());
    let child_url_path = child_url.strip_prefix("file://").unwrap().to_owned();
    let parent_url = write_nested_catalog(catalog_dir.path(), &child_url_path);

    run(cmd_with_home(home.path()).args(["catalog", "add", "ambiguous-mt", &parent_url]));

    let (ok, _, stderr) = run(cmd_with_home(home.path()).args([
        "pull",
        "--media-type",
        "application/json",
        "urn:test:nested-catalog",
    ]));
    assert!(
        !ok,
        "pull should fail when multiple children match the media type"
    );
    assert!(
        stderr.contains("2") || stderr.contains("entries of type"),
        "error should mention multiple matches: {stderr}"
    );
}

#[test]
fn pull_leaf_entry_with_wrong_media_type_errors() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "leaf-mt-test", &catalog_url]));

    let (ok, _, stderr) = run(cmd_with_home(home.path()).args([
        "pull",
        "--media-type",
        "text/plain",
        "urn:test:agent-alpha",
    ]));
    assert!(!ok, "pull should fail on type mismatch");
    assert!(
        stderr.contains("--media-type") || stderr.contains("type"),
        "error should mention type mismatch: {stderr}"
    );
}

#[test]
fn show_catalog_entry_without_media_type_succeeds() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let child_url = write_child_catalog(catalog_dir.path());
    let child_url_path = child_url.strip_prefix("file://").unwrap().to_owned();
    let parent_url = write_nested_catalog(catalog_dir.path(), &child_url_path);

    run(cmd_with_home(home.path()).args(["catalog", "add", "show-cat-no-mt", &parent_url]));

    let (ok, stdout, stderr) =
        run(cmd_with_home(home.path()).args(["show", "urn:test:nested-catalog"]));
    assert!(
        ok,
        "show should succeed for a catalog entry without --media-type: {stderr}"
    );
    assert!(
        stdout.contains("urn:test:nested-catalog"),
        "show output should contain the identifier: {stdout}"
    );
}

#[test]
fn show_catalog_entry_with_child_media_type_shows_child() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let child_url = write_child_catalog(catalog_dir.path());
    let child_url_path = child_url.strip_prefix("file://").unwrap().to_owned();
    let parent_url = write_nested_catalog(catalog_dir.path(), &child_url_path);

    run(cmd_with_home(home.path()).args(["catalog", "add", "show-child-mt", &parent_url]));

    let (ok, stdout, stderr) = run(cmd_with_home(home.path()).args([
        "show",
        "--media-type",
        "application/json",
        "urn:test:nested-catalog",
    ]));
    assert!(ok, "show with child media-type should succeed: {stderr}");
    assert!(
        stdout.contains("urn:test:child-agent"),
        "show output should contain the child entry: {stdout}"
    );
}

#[test]
fn show_leaf_entry_with_wrong_media_type_errors() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    run(cmd_with_home(home.path()).args(["catalog", "add", "show-leaf-mt", &catalog_url]));

    let (ok, _, stderr) = run(cmd_with_home(home.path()).args([
        "show",
        "--media-type",
        "text/plain",
        "urn:test:agent-alpha",
    ]));
    assert!(!ok, "show should fail on type mismatch");
    assert!(
        stderr.contains("--media-type") || stderr.contains("type"),
        "error should mention type mismatch: {stderr}"
    );
}

// ── --scope URI tests ─────────────────────────────────────────────────────────

#[test]
fn show_scope_by_file_url_finds_entry() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_url = write_fixture_catalog(catalog_dir.path());

    // Use --scope with the file:// URL directly, without registering the catalog
    let (ok, stdout, stderr) = run(cmd_with_home(home.path()).args([
        "show",
        "--scope",
        &catalog_url,
        "urn:test:agent-alpha",
    ]));
    assert!(ok, "show --scope <file-url> should succeed: {stderr}");
    assert!(
        stdout.contains("urn:test:agent-alpha"),
        "output should contain the entry: {stdout}"
    );
}

#[test]
fn pull_scope_by_file_url_pulls_entry() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let child_json = r#"{
  "specVersion": "1.0",
  "entries": [
    {
      "identifier": "urn:test:scoped-agent",
      "type": "application/json",
      "data": {"name": "scoped"}
    }
  ]
}"#;
    let catalog_path = catalog_dir.path().join("scoped-catalog.json");
    fs::write(&catalog_path, child_json).unwrap();
    let catalog_url = format!("file://{}", catalog_path.display());

    let out_dir = tempfile::TempDir::new().unwrap();
    let (ok, _, stderr) = run(cmd_with_home(home.path()).args([
        "pull",
        "--scope",
        &catalog_url,
        "--output",
        out_dir.path().to_str().unwrap(),
        "urn:test:scoped-agent",
    ]));
    assert!(ok, "pull --scope <file-url> should succeed: {stderr}");
    let files: Vec<_> = fs::read_dir(out_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(!files.is_empty(), "output should contain the pulled file");
}

#[test]
fn pull_output_stdout_streams_bytes() {
    let home = tempfile::TempDir::new().unwrap();
    let catalog_dir = tempfile::TempDir::new().unwrap();
    let catalog_json = r#"{
  "specVersion": "1.0",
  "entries": [
    {
      "identifier": "urn:test:stdout-entry",
      "type": "application/json",
      "data": {"hello": "world"}
    }
  ]
}"#;
    let catalog_path = catalog_dir.path().join("stdout-catalog.json");
    fs::write(&catalog_path, catalog_json).unwrap();
    let catalog_url = format!("file://{}", catalog_path.display());

    run(cmd_with_home(home.path()).args(["catalog", "add", "stdout-test", &catalog_url]));

    let (ok, stdout, stderr) = run(cmd_with_home(home.path()).args([
        "pull",
        "--output",
        "-",
        "urn:test:stdout-entry",
    ]));
    assert!(ok, "pull -o - should succeed: {stderr}");
    // stdout should contain JSON bytes, not write a file named "-"
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(parsed["hello"], "world");
}
