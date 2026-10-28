//! A torn `credentials.json` against the real binary: the roster still loads,
//! and the command names the unreadable account once on stderr. Spawning is the
//! only way to see what a caller captures.
//!
//! Unix only, for the reason `tests/oauth_token_cli.rs` gives: the child
//! resolves its home through `$HOME`, which only Unix lets a test point at a
//! sandbox.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::path::Path;
use std::process::{Command, Output, Stdio};

const NOTICE: &str = "clauth: p1: its stored login could not be read (credentials.json does not parse), so it shows as logged out until `clauth login p1`";

fn seed(home: &Path, name: &str, config: &str) -> std::path::PathBuf {
    let dir = home.join(".clauth").join("profiles").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.toml"), config).unwrap();
    dir
}

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_clauth"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("CLAUTH_NO_UPDATE", "1")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .expect("run clauth")
}

/// `p1`'s store does not parse; `p2` is a plain api-key account. `clauth list`
/// exits 0, lists both, and prints the notice for `p1` exactly once.
#[test]
fn a_torn_store_lists_the_roster_and_names_the_account_once() {
    let home = tempfile::tempdir().unwrap();
    let p1 = seed(home.path(), "p1", "");
    let torn = "{\"claudeAiOauth\": {\"accessToken\": ";
    std::fs::write(p1.join("credentials.json"), torn).unwrap();
    seed(
        home.path(),
        "p2",
        "base_url = \"https://api.deepseek.com/anthropic\"\napi_key = \"sk-p2-fixture\"\n",
    );
    std::fs::write(
        home.path().join(".clauth").join("profiles.toml"),
        "active_profile = \"p2\"\nprofiles = [\"p1\", \"p2\"]\n",
    )
    .unwrap();

    let out = run(home.path(), &["list"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stdout
            .lines()
            .any(|l| l.split_whitespace().any(|w| w == "p1")),
        "p1 is listed:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|l| l.split_whitespace().any(|w| w == "p2")),
        "p2 is listed:\n{stdout}"
    );
    assert_eq!(
        stderr.lines().filter(|l| *l == NOTICE).count(),
        1,
        "the notice names p1 once:\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(p1.join("credentials.json")).unwrap(),
        torn,
        "the command leaves the torn store as it was"
    );
}

const TORN: &str = "{\"claudeAiOauth\": {\"accessToken\": ";

/// Seed torn `p1` and api-key `p2` with `active` as the active account.
/// Returns `p1`'s store path.
fn seed_pair(home: &Path, active: &str) -> std::path::PathBuf {
    let p1 = seed(home, "p1", "");
    std::fs::write(p1.join("credentials.json"), TORN).unwrap();
    seed(
        home,
        "p2",
        "base_url = \"https://api.deepseek.com/anthropic\"\napi_key = \"sk-p2-fixture\"\n",
    );
    std::fs::write(
        home.join(".clauth").join("profiles.toml"),
        format!("active_profile = \"{active}\"\nprofiles = [\"p1\", \"p2\"]\n"),
    )
    .unwrap();
    p1.join("credentials.json")
}

/// The torn store is the active account's and the global login links to it,
/// the way Claude Code writes through that link: switching away still works,
/// and the torn bytes stay where they were.
///
/// Off macOS only: there a switch reaches the login Keychain, which this
/// sandboxed child (no `USER`) cannot name and a developer's real one must
/// never be touched by a test; the Keychain arm's verdict is pinned by
/// `keychain_mirror_verdict_routes_an_unreadable_source_as_absent`.
#[cfg(not(target_os = "macos"))]
#[test]
fn switching_away_from_a_torn_linked_active_account_succeeds() {
    let home = tempfile::tempdir().unwrap();
    let store = seed_pair(home.path(), "p1");
    let claude = home.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    std::os::unix::fs::symlink(&store, claude.join(".credentials.json")).unwrap();

    let out = run(home.path(), &["switch", "p2"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stderr.lines().filter(|l| *l == NOTICE).count(),
        1,
        "the notice names p1 once:\n{stderr}"
    );
    assert_eq!(
        stderr,
        format!("{NOTICE}\n"),
        "the notice is all the switch prints on stderr"
    );
    assert_eq!(std::fs::read_to_string(&store).unwrap(), TORN);
}

/// Switching to the torn account behaves like switching to any logged-out
/// one: it succeeds and links nothing, so the global login never points at
/// the torn file.
///
/// Off macOS only, for the Keychain reason the test above gives.
#[cfg(not(target_os = "macos"))]
#[test]
fn switching_to_a_torn_account_links_nothing() {
    let home = tempfile::tempdir().unwrap();
    let store = seed_pair(home.path(), "p2");

    let out = run(home.path(), &["switch", "p1"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    let live = home.path().join(".claude").join(".credentials.json");
    assert!(
        std::fs::canonicalize(&live).ok() != std::fs::canonicalize(&store).ok(),
        "the global login does not resolve to the torn store"
    );
    assert_eq!(std::fs::read_to_string(&store).unwrap(), TORN);
}

/// A machine channel never carries the notice, even where the command loads
/// the roster: `__oauth-token` on the keyed account refuses with its own line
/// and nothing else.
#[test]
fn the_oauth_token_helper_prints_no_notice_beside_a_torn_store() {
    let home = tempfile::tempdir().unwrap();
    seed_pair(home.path(), "p2");

    let out = run(home.path(), &["__oauth-token", "p2"]);

    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "Error: profile 'p2' has no OAuth login\n",
        "no notice on a machine channel"
    );
}
