//! `clauth login <name> --setup-token` against the real binary, with the mint
//! piped on stdin (a non-TTY stdin reads it as one line): pins that the
//! dispatch hands an existing account and a new name to the capture each one
//! needs. The capture's own decisions are pinned in-process
//! (`tests/inline/cli.rs`, `a_cli_login_lands_on_its_own_account`).
//!
//! Unix only, for the reason `tests/closed_reader.rs` gives: the child resolves
//! its home through `$HOME`, which only Unix lets a test point at a sandbox.
//! Off macOS too, per `tests/oauth_token_cli.rs`'s precedent: an `env_clear()`ed
//! child there has no `USER` for the Keychain arm.
#![cfg(all(unix, not(target_os = "macos")))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const MINT: &str = "sk-ant-oat01-setup-token-cli-fixture-0123456789abcdef";

fn run_setup_token(home: &Path, name: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_clauth"))
        .args(["login", name, "--setup-token"])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("CLAUTH_NO_UPDATE", "1")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clauth login --setup-token");
    // A child that refuses before reading stdin closes the pipe; the write
    // failing then is no verdict, the child's exit and stderr are.
    let _ = child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{MINT}\n").as_bytes());
    child.wait_with_output().expect("wait")
}

fn sidecar(home: &Path, name: &str) -> String {
    std::fs::read_to_string(
        home.join(".clauth/profiles")
            .join(name)
            .join("session-token.json"),
    )
    .unwrap_or_default()
}

/// An existing account takes the mint in place: no create, no refusal.
#[test]
fn a_piped_setup_token_lands_on_an_existing_account() {
    let home = tempfile::tempdir().unwrap();
    let clauth = home.path().join(".clauth");
    std::fs::create_dir_all(clauth.join("profiles/acme")).unwrap();
    std::fs::write(clauth.join("profiles.toml"), "profiles = [\"acme\"]\n").unwrap();

    let out = run_setup_token(home.path(), "acme");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(sidecar(home.path(), "acme").contains(MINT));
}

/// A new name is created, then takes the mint.
#[test]
fn a_piped_setup_token_creates_a_new_account() {
    let home = tempfile::tempdir().unwrap();

    let out = run_setup_token(home.path(), "fresh");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(sidecar(home.path(), "fresh").contains(MINT));
    let roster = std::fs::read_to_string(home.path().join(".clauth/profiles.toml")).unwrap();
    assert!(
        roster.contains("\"fresh\""),
        "the roster holds it: {roster}"
    );
}
