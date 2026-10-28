#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The codex credential engine: the auth model's tolerant reads and
//! key-preserving rotation, the refresh classification, and the standby
//! pass's whole decision table — age gate, memo, kick, stand-down, belt.

use super::*;
use crate::testutil::{
    HomeSandbox, codex_auth_body, fresh_activity, jwt_with_exp, read_codex_store, write_codex_store,
};

// Per-test profile NAMES: the attempt memo, kick, and bad-read maps are
// process-global statics keyed by name, and these tests run in parallel.

#[test]
fn jwt_exp_reads_the_payload_and_shrugs_at_garbage() {
    assert_eq!(
        jwt_exp_ms(&jwt_with_exp(1_700_000_000)),
        Some(1_700_000_000_000)
    );
    assert_eq!(jwt_exp_ms("not-a-jwt"), None);
    assert_eq!(jwt_exp_ms("a.!!!!.c"), None);
}

#[test]
fn a_rotation_preserves_every_unknown_key() {
    let auth = CodexAuth::parse(codex_auth_body("at.old", "rt.old").as_bytes()).expect("parse");
    let tok = CodexTokenResponse {
        id_token: Some("id.new".into()),
        access_token: "at.new".into(),
        refresh_token: "rt.new".into(),
    };
    let rotated = auth.with_rotated(&tok, "2026-08-13T00:00:00Z");
    let v: serde_json::Value = serde_json::from_slice(&rotated.to_bytes()).expect("reparse");
    assert_eq!(v["tokens"]["access_token"], "at.new");
    assert_eq!(v["tokens"]["refresh_token"], "rt.new");
    assert_eq!(v["tokens"]["id_token"], "id.new");
    assert_eq!(v["tokens"]["account_id"], "acc", "untouched slots survive");
    assert_eq!(v["keep_me"], 7, "unknown top-level keys survive");
    assert_eq!(v["last_refresh"], "2026-08-13T00:00:00Z");
}

#[test]
fn refresh_failures_classify_the_way_codex_does() {
    assert!(matches!(
        classify_refresh_failure(400, r#"{"error":"refresh_token_reused"}"#),
        CodexRefreshError::Reused
    ));
    assert!(matches!(
        classify_refresh_failure(400, r#"{"error":"refresh_token_expired"}"#),
        CodexRefreshError::Dead("expired")
    ));
    assert!(matches!(
        classify_refresh_failure(400, r#"{"error":"refresh_token_invalidated"}"#),
        CodexRefreshError::Dead("invalidated")
    ));
    assert!(matches!(
        classify_refresh_failure(403, "nope"),
        CodexRefreshError::Dead("rejected"),
    ));
    assert!(matches!(
        classify_refresh_failure(429, "slow down"),
        CodexRefreshError::Transient(_)
    ));
    assert!(matches!(
        classify_refresh_failure(502, "bad gateway"),
        CodexRefreshError::Transient(_)
    ));
}

/// The wire shape against a local stub: JSON body carrying the spec's three
/// fields, and the rotated pair parsed back.
#[test]
fn the_refresh_wire_shape_is_the_specs() {
    let (addr, handle) = crate::testutil::serve_endpoints(1, |_path, _i| {
        (
            200,
            r#"{"id_token":"id.n","access_token":"at.n","refresh_token":"rt.n"}"#.to_string(),
        )
    });
    let tok =
        refresh_codex_chain_at(&format!("{addr}/oauth/token"), "rt.old").expect("refresh succeeds");
    assert_eq!(tok.access_token, "at.n");
    assert_eq!(tok.refresh_token, "rt.n");
    let seen = handle.join().expect("join stub");
    assert_eq!(seen, ["/oauth/token"], "one call, to the token endpoint");

    // The body contract, pinned as a value (the stub records paths only):
    // exactly the spec's three fields.
    let body = refresh_request_body("rt.old");
    let obj = body.as_object().expect("object");
    assert_eq!(obj.len(), 3, "exactly the verified fields, nothing extra");
    // The literal the spec verified against rust-v0.145.0, never the constant
    // compared to itself.
    assert_eq!(body["client_id"], "app_EMoamEEZ73f0CkXaXp7hrann");
    assert_eq!(body["grant_type"], "refresh_token");
    assert_eq!(body["refresh_token"], "rt.old");
}

/// The standby decision table, driven through one profile with an injected
/// refresher. Each verdict is asserted as [`StandbyOutcome`] AND as its
/// on-disk consequence.
#[test]
fn the_standby_pass_walks_its_decision_table() {
    let _home = HomeSandbox::new();
    let name = "cx-table";
    let now: i64 = 1_700_000_000_000;
    let stamp = || "2026-08-13T00:00:00Z".to_string();
    let ok = |t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        assert_eq!(t, "rt.a", "only the post-guard token feeds the wire");
        Ok(CodexTokenResponse {
            id_token: None,
            access_token: jwt_with_exp((now / 1000) + 3600),
            refresh_token: "rt.b".into(),
        })
    };
    let fail = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Err(CodexRefreshError::Transient("stubbed".into()))
    };

    // Fresh token, parked: not due.
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 86_400), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            stamp(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle
    );

    // Due (inside the lead), parked: rotates, preserves keys, records the belt.
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            stamp(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Rotated
    );
    let stored = read_codex_store(name);
    assert!(stored.contains("rt.b") && stored.contains("keep_me"));
    let lkg = crate::profile::profile_dir(&crate::profile::ProfileName::from(name))
        .expect("dir")
        .join("auth.lkg.json");
    assert_eq!(
        std::fs::read_to_string(&lkg).expect("lkg"),
        stored,
        "the belt records the rotated store"
    );

    // Due but the refresh fails: Failed, and the SAME token is memo-blocked
    // on the next tick.
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            stamp(),
            &fail,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            stamp(),
            &fail,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle,
        "no replay of a spent attempt on the routine leg"
    );

    // A kick buys exactly one forced retry of that same token…
    kick_codex(name);
    assert_eq!(
        standby_pass(
            name,
            now,
            stamp(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Rotated
    );
    // A successful rotation does NOT reset the breaker (only a successful poll
    // does); reset here to test the breaker from a clean count.
    kick_reset(name);

    // …and the breaker stops the third consecutive kick.
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            stamp(),
            &fail,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    kick_codex(name);
    assert_eq!(
        standby_pass(
            name,
            now,
            stamp(),
            &fail,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    kick_codex(name);
    assert_eq!(
        standby_pass(
            name,
            now,
            stamp(),
            &fail,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    kick_codex(name);
    assert_eq!(
        standby_pass(
            name,
            now,
            stamp(),
            &fail,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle,
        "past two consecutive kicks nothing fires — re-login territory"
    );
    kick_reset(name);
}

/// The stand-down is SCOPED to a live codex session (the #51-accepted
/// one-liner) and to codex's own window, pinned at the BOUNDARY as a literal
/// (300_000 ms, the verified 5 minutes): one second inside stands down, one
/// second outside rotates under the same live session, so a window constant
/// moved by a minute in either direction reds. A parked profile inside the
/// window still rotates — waiting there is how parked chains die at the wham
/// 401.
#[test]
fn the_stand_down_is_scoped_to_a_live_session() {
    let home = HomeSandbox::new();
    let name = "cx-standdown";
    let now: i64 = 1_700_000_000_000;
    let ok = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Ok(CodexTokenResponse {
            id_token: None,
            access_token: jwt_with_exp((now / 1000) + 3600),
            refresh_token: "rt.b".into(),
        })
    };
    let exp_secs = |lead_ms: i64| (now + lead_ms) / 1000;

    // A LIVE session holds the chain for the rest of the test.
    let sessions = home.home().join(".clauth/profiles/cx-standdown/sessions");
    std::fs::create_dir_all(&sessions).expect("mkdir sessions");
    let pid = crate::runtime::open_pid_file(&sessions.join("99999")).expect("open pid");
    pid.lock().expect("lock pid");

    // One second inside the verified 5-minute window (300_000 ms): stood down.
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp(exp_secs(300_000 - 1_000)), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::StoodDown
    );
    assert!(
        read_codex_store(name).contains("rt.a"),
        "a stood-down pass spends nothing"
    );

    // One second outside it, same live session: due (inside the standby lead)
    // and safe, so the rotation runs.
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp(exp_secs(300_000 + 1_000)), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Rotated
    );
    drop(pid);
    std::fs::remove_dir_all(&sessions).expect("clear sessions");

    // Inside the window, parked: the rotation runs.
    write_codex_store(
        name,
        &codex_auth_body(
            &jwt_with_exp(exp_secs(CODEX_SELF_REFRESH_WINDOW_MS - 1_000)),
            "rt.a",
        ),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Rotated
    );
}

/// The belt restores only after the store reads bad continuously for a real
/// wall-clock interval (past any single codex write) with NO live session —
/// two adjacent ticks are not confirmation, so a slow write is never stomped.
#[test]
fn the_belt_restores_after_two_confirmed_bad_reads() {
    let _home = HomeSandbox::new();
    let name = "cx-belt";
    let now: i64 = 1_700_000_000_000;
    let ok = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Err(CodexRefreshError::Transient("unused".into()))
    };

    // A good pass records the belt.
    let good = codex_auth_body(&jwt_with_exp((now / 1000) + 86_400), "rt.a");
    write_codex_store(name, &good);
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle
    );

    // The store goes bad (a crash mid-truncate). The first strike stamps the
    // clock; a second read microseconds later is NOT confirmation.
    write_codex_store(name, "{ half a wri");
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle
    );
    assert_eq!(
        standby_pass(
            name,
            now + 1,
            "2026-08-13T00:00:00Z".into(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle,
        "two adjacent ticks are not confirmation — a slow write could still land"
    );
    assert_eq!(
        read_codex_store(name),
        "{ half a wri",
        "nothing restored while the bad window is short"
    );
    // Past the confirmation interval, still bad, still parked: restore.
    assert_eq!(
        standby_pass(
            name,
            now + 31_000,
            "2026-08-13T00:00:00Z".into(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Restored
    );
    assert_eq!(
        read_codex_store(name),
        good,
        "the belt restored the last good bytes"
    );
}

/// The no-replay memo is DURABLE: after a failed refresh the fingerprint sits
/// on disk beside the store, so a fresh process (a daemon restart) that
/// forgets every in-memory map still refuses to replay the token — the
/// decision-7 permanent-death hole.
#[test]
fn the_no_replay_memo_survives_on_disk() {
    let _home = HomeSandbox::new();
    let name = "cx-durable";
    let now: i64 = 1_700_000_000_000;
    let fail = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Err(CodexRefreshError::Transient("stub".into()))
    };
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &fail,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    // The fingerprint is on disk — not merely in a static map.
    let memo = crate::profile::profile_dir(&crate::profile::ProfileName::from(name))
        .expect("dir")
        .join("auth.attempt");
    assert!(
        memo.exists(),
        "the attempt memo is persisted beside the store"
    );
    assert_eq!(
        std::fs::read_to_string(&memo)
            .expect("read memo")
            .trim()
            .len(),
        16,
        "an 8-byte fingerprint, hex"
    );
    // A capture/login installing a fresh chain retires the memo.
    crate::codex_auth::forget_attempt(name);
    assert!(!memo.exists());
}

/// An UNREADABLE access-token exp does not make the chain due every tick: it
/// falls back to last_refresh age (codex's own 8-day interval), so a
/// recently-refreshed chain with a non-JWT token is NOT rotated.
#[test]
fn an_unreadable_exp_falls_back_to_last_refresh_age() {
    let _home = HomeSandbox::new();
    let name = "cx-noexp";
    let now: i64 = 1_700_000_000_000;
    let boom = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        panic!("must not hit the wire — not due");
    };
    // Non-JWT access token, last_refresh one hour ago: not due.
    let recent = chrono::DateTime::from_timestamp_millis(now - 3_600_000)
        .expect("ts")
        .to_rfc3339();
    write_codex_store(
        name,
        &format!(
            "{{ \"tokens\": {{\"access_token\": \"not-a-jwt\", \"refresh_token\": \"rt.a\", \
             \"account_id\": \"acc\"}}, \"last_refresh\": \"{recent}\" }}"
        ),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &boom,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle,
        "a fresh chain with an unreadable exp is not due every tick"
    );

    // last_refresh nine days ago: now due, rotates.
    let old = chrono::DateTime::from_timestamp_millis(now - 9 * 24 * 3_600_000)
        .expect("ts")
        .to_rfc3339();
    write_codex_store(
        name,
        &format!(
            "{{ \"tokens\": {{\"access_token\": \"not-a-jwt\", \"refresh_token\": \"rt.a\", \
             \"account_id\": \"acc\"}}, \"last_refresh\": \"{old}\" }}"
        ),
    );
    let ok = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Ok(CodexTokenResponse {
            id_token: None,
            access_token: "not-a-jwt-2".into(),
            refresh_token: "rt.b".into(),
        })
    };
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Rotated,
        "past the 8-day fallback it rotates"
    );
}

/// Under the fake transport a live session holds a SEPARATE copy of the
/// chain, so the standby stands down for ANY live session — not only inside
/// codex's 5-minute window — and that stand-down burns no kick.
#[test]
fn fake_transport_stands_down_for_any_live_session_and_keeps_the_kick() {
    let home = HomeSandbox::new();
    let name = "cx-fake";
    let now: i64 = 1_700_000_000_000;
    let boom = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        panic!("must not rotate a fake-mode live carrier");
    };
    // Due (inside the lead) but NOT inside codex's own 5-min window.
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 400), "rt.a"),
    );
    let sessions = home.home().join(".clauth/profiles/cx-fake/sessions");
    std::fs::create_dir_all(&sessions).expect("mkdir sessions");
    let pid = crate::runtime::open_pid_file(&sessions.join("99999")).expect("pid");
    pid.lock().expect("lock");

    let forced = crate::runtime::ForcedFakeLinkMode::new();
    // Even a kick must not force a rotation while a fake-mode carrier is live.
    kick_codex(name);
    let out = standby_pass(
        name,
        now,
        "2026-08-13T00:00:00Z".into(),
        &boom,
        &fresh_activity(),
        &std::sync::atomic::AtomicBool::new(false),
    );
    drop(forced);
    drop(pid);
    assert_eq!(out, StandbyOutcome::StoodDown);
    // The kick was not consumed by the stand-down.
    assert!(
        kick_available(name),
        "a stand-down must not burn the one forced attempt"
    );
    kick_reset(name);
}

/// A live codex session BLOCKS the belt restore: the session is the writer,
/// and stomping its in-place write with the pre-rotation belt is the one path
/// where the belt is worse than doing nothing (it resurrects a spent token).
#[test]
fn the_belt_never_restores_under_a_live_session() {
    let home = HomeSandbox::new();
    let name = "cx-belt-live";
    let now: i64 = 1_700_000_000_000;
    let unused = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Err(CodexRefreshError::Transient("unused".into()))
    };
    // Record a belt from a good read, then the store goes bad.
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 86_400), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "x".into(),
            &unused,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle
    );
    write_codex_store(name, "{ half a wri");

    // A live session — codex is the writer.
    let sessions = home.home().join(".clauth/profiles/cx-belt-live/sessions");
    std::fs::create_dir_all(&sessions).expect("mkdir");
    let pid = crate::runtime::open_pid_file(&sessions.join("1")).expect("pid");
    pid.lock().expect("lock");

    // Even well past the confirmation interval, the restore is refused.
    assert_eq!(
        standby_pass(
            name,
            now + 1,
            "x".into(),
            &unused,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle
    );
    assert_eq!(
        standby_pass(
            name,
            now + 120_000,
            "x".into(),
            &unused,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle,
        "a live session is the writer — never stomp its in-place write"
    );
    assert_eq!(
        read_codex_store(name),
        "{ half a wri",
        "the store is left for codex"
    );
    drop(pid);
}

/// A successful rotation does NOT reset the kick breaker — only a successful
/// poll does. Otherwise a non-token 401 (a suspended account) would rotate
/// fine each cycle, reset the breaker, and force-refresh forever.
#[test]
fn a_successful_rotation_does_not_reset_the_breaker() {
    let _home = HomeSandbox::new();
    let name = "cx-breaker";
    let now: i64 = 1_700_000_000_000;
    let ok = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Ok(CodexTokenResponse {
            id_token: None,
            access_token: jwt_with_exp((now / 1000) + 3600),
            refresh_token: "rt.rot".into(),
        })
    };
    let fail = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Err(CodexRefreshError::Transient("stub".into()))
    };

    // Memo-block the routine leg so only a kick can drive a refresh.
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "x".into(),
            &fail,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );

    // Kick 1 → forced attempt → SUCCEEDS. If this wrongly reset the breaker,
    // the strike count would return to 0.
    kick_codex(name);
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "x".into(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Rotated
    );

    // Kick 2 → still under the breaker (strikes=2) → forced attempt fires.
    kick_codex(name);
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "x".into(),
            &fail,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );

    // Kick 3 → strikes=3 > breaker → nothing fires. This only holds because
    // the successful rotation at kick 1 did NOT reset the count.
    kick_codex(name);
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "x".into(),
            &fail,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle,
        "a rotation that reset the breaker would let this third kick fire"
    );
    kick_reset(name);
}

/// The post-guard re-read catches a live codex rotating the store in the
/// window between the pre-guard capture and the guarded read — clauth must
/// NOT then spend the token codex just rotated away.
#[test]
fn a_rotation_under_the_guard_window_is_caught() {
    let _home = HomeSandbox::new();
    let name = "cx-reread";
    let now: i64 = 1_700_000_000_000;
    let boom = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        panic!("must not hit the wire — the token changed under the guard");
    };
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );

    // Between the pre-guard capture of rt.a and the post-guard re-read, a live
    // codex rotates the store to rt.b.
    let n = name.to_string();
    crate::codex_auth::set_pre_reread_hook(
        name,
        std::sync::Arc::new(move || {
            write_codex_store(&n, &codex_auth_body("at.b", "rt.b"));
        }),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "x".into(),
            &boom,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle,
        "a token changed under the guard is not spent"
    );
    assert!(
        read_codex_store(name).contains("rt.b"),
        "the live codex's fresh chain is left untouched"
    );
}

/// A terminal verdict out of the refresher leaves the quarantine record the
/// walk, the feed and the start/switch refusals read; `Transient` leaves none;
/// a rotation that lands clears it. Kinds are the words
/// `classify_refresh_failure` produces, the stamp is the pass's own clock.
#[test]
fn a_terminal_verdict_leaves_a_quarantine_record_and_a_rotation_clears_it() {
    let _home = HomeSandbox::new();
    let name = "cx-quarantine";
    let now: i64 = 1_700_000_000_000;
    let due = || codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a");
    let reused = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Err(CodexRefreshError::Reused)
    };
    let expired = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Err(CodexRefreshError::Dead("expired"))
    };
    let transient = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Err(CodexRefreshError::Transient("HTTP 502".into()))
    };
    let ok = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Ok(CodexTokenResponse {
            id_token: None,
            access_token: jwt_with_exp((now / 1000) + 3600),
            refresh_token: "rt.b".into(),
        })
    };
    let record = crate::profile::profile_dir(&crate::profile::ProfileName::from(name))
        .expect("dir")
        .join("auth.quarantine.json");

    // Transient: no record.
    write_codex_store(name, &due());
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &transient,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    assert_eq!(
        read_quarantine(name),
        None,
        "a retry-later verdict quarantines nothing"
    );
    assert!(!record.exists());

    // Reused: the record, on disk, with the kind and the pass's stamp.
    kick_codex(name);
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &reused,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    assert_eq!(
        read_quarantine(name),
        Some(CodexQuarantine {
            kind: "reused".into(),
            at: "2026-08-13T00:00:00Z".into(),
            token_fingerprint: token_fingerprint("rt.a"),
        })
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&record).expect("record"))
            .expect("json")["kind"],
        "reused",
        "the record is the file beside the store, not a static"
    );
    assert_eq!(
        refuse_if_quarantined(name)
            .expect_err("a quarantined chain refuses")
            .to_string(),
        "'cx-quarantine': codex chain is broken (reused since 2026-08-13T00:00:00Z), \
         run `clauth login cx-quarantine --codex --browser`"
    );
    // A later kick re-hearing the same verdict keeps the first stamp: `since`
    // names when the chain died, not the last time the server said so.
    kick_codex(name);
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T06:00:00Z".into(),
            &reused,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    assert_eq!(
        read_quarantine(name).map(|q| q.at),
        Some("2026-08-13T00:00:00Z".to_string())
    );
    kick_reset(name);

    // Dead(expired), on a fresh chain: the kind moves with the verdict.
    clear_quarantine(name);
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.c"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-14T00:00:00Z".into(),
            &expired,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    assert_eq!(
        read_quarantine(name),
        Some(CodexQuarantine {
            kind: "expired".into(),
            at: "2026-08-14T00:00:00Z".into(),
            token_fingerprint: token_fingerprint("rt.c"),
        })
    );

    // A rotation that lands retires the verdict.
    kick_codex(name);
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-15T00:00:00Z".into(),
            &ok,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Rotated
    );
    assert_eq!(
        read_quarantine(name),
        None,
        "a landed rotation clears the record"
    );
    assert!(!record.exists());
    assert!(refuse_if_quarantined(name).is_ok());
    kick_reset(name);
}

/// The record binds to the token it judged: a fresh chain landing in the
/// store by a path that calls no clear (codex's own `codex login` through a
/// still-linked slot) reads as no verdict, the judged token back in the store
/// reads the record again, a store that cannot be read keeps it standing, and
/// a new chain's death is a new verdict with its own stamp.
#[test]
fn a_quarantine_record_speaks_only_for_the_token_it_judged() {
    let _home = HomeSandbox::new();
    let name = "cx-bound";
    let now: i64 = 1_700_000_000_000;
    let on = |token: &str| codex_auth_body(&jwt_with_exp((now / 1000) + 60), token);
    let reused = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Err(CodexRefreshError::Reused)
    };
    let dir = crate::profile::profile_dir(&crate::profile::ProfileName::from(name)).expect("dir");

    write_codex_store(name, &on("rt.a"));
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &reused,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    let verdict = CodexQuarantine {
        kind: "reused".into(),
        at: "2026-08-13T00:00:00Z".into(),
        token_fingerprint: token_fingerprint("rt.a"),
    };
    assert_eq!(read_quarantine(name), Some(verdict.clone()));

    // A fresh chain lands with no clear call: the verdict has no claim on it.
    write_codex_store(name, &on("rt.b"));
    assert_eq!(
        read_quarantine(name),
        None,
        "a verdict about rt.a says nothing about rt.b"
    );
    assert!(refuse_if_quarantined(name).is_ok());
    assert!(
        dir.join("auth.quarantine.json").exists(),
        "the file stays; it is the token that moved"
    );

    // The judged token back in the store: the verdict speaks again.
    write_codex_store(name, &on("rt.a"));
    assert_eq!(read_quarantine(name), Some(verdict.clone()));

    // A store that cannot be read keeps the record standing: the verdict is
    // about a chain that may still be there.
    std::fs::remove_file(dir.join("auth.json")).expect("drop store");
    assert_eq!(read_quarantine(name), Some(verdict));

    // The fresh chain dies too: its own record, its own stamp, not the old
    // chain's `since`.
    write_codex_store(name, &on("rt.b"));
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-20T00:00:00Z".into(),
            &reused,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    assert_eq!(
        read_quarantine(name),
        Some(CodexQuarantine {
            kind: "reused".into(),
            at: "2026-08-20T00:00:00Z".into(),
            token_fingerprint: token_fingerprint("rt.b"),
        })
    );
}

/// Which verdicts quarantine: the three the server spells about the chain
/// (`reused`, `expired`, `invalidated`). An unrecognized 4xx (`rejected`) is
/// a statement about the front door — a WAF 403 here — and keeps what it had
/// before the record existed: the memo blocks the routine leg, a kick forces
/// one attempt, and no record is written on either.
#[test]
fn an_unrecognized_4xx_leaves_no_quarantine_record() {
    assert_eq!(CodexRefreshError::Reused.quarantine_kind(), Some("reused"));
    assert_eq!(
        CodexRefreshError::Dead("expired").quarantine_kind(),
        Some("expired")
    );
    assert_eq!(
        CodexRefreshError::Dead("invalidated").quarantine_kind(),
        Some("invalidated")
    );
    assert_eq!(CodexRefreshError::Dead("rejected").quarantine_kind(), None);
    assert_eq!(
        CodexRefreshError::Transient("HTTP 502".into()).quarantine_kind(),
        None
    );

    let _home = HomeSandbox::new();
    let name = "cx-rejected";
    let now: i64 = 1_700_000_000_000;
    let rejected = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        Err(classify_refresh_failure(403, "<html>Access denied</html>"))
    };
    let record = crate::profile::profile_dir(&crate::profile::ProfileName::from(name))
        .expect("dir")
        .join("auth.quarantine.json");

    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &rejected,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    assert_eq!(read_quarantine(name), None);
    assert!(
        !record.exists(),
        "a front-door failure is no verdict about the chain"
    );
    assert!(refuse_if_quarantined(name).is_ok());

    // The memo blocks the routine leg; a kick forces one attempt; still no record.
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:01:00Z".into(),
            &rejected,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Idle,
        "memo-blocked, not re-sent"
    );
    kick_codex(name);
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:02:00Z".into(),
            &rejected,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Failed
    );
    assert!(!record.exists());
    kick_reset(name);
}

/// One normalizer for the plan word wherever it was read: trimmed,
/// lowercased, and an empty word is no word, so the id_token reader falls
/// back on `""` exactly as on an absent claim.
#[test]
fn a_plan_word_is_trimmed_lowercased_and_empty_is_absent() {
    assert_eq!(plan_word(" Plus "), Some("plus".to_string()));
    assert_eq!(plan_word("pro"), Some("pro".to_string()));
    assert_eq!(plan_word(""), None);
    assert_eq!(plan_word("   "), None);

    let with_claim = |plan: &str| {
        let id_token = crate::testutil::codex_jwt(&format!(
            r#"{{"https://api.openai.com/auth":{{"chatgpt_plan_type":"{plan}"}}}}"#
        ));
        CodexAuth::parse(format!(r#"{{"tokens":{{"id_token":"{id_token}"}}}}"#).as_bytes())
            .expect("parses")
    };
    assert_eq!(
        with_claim(" Plus ").id_token_plan(),
        Some("plus".to_string())
    );
    assert_eq!(with_claim("").id_token_plan(), None);
}

/// No token reaches the wire without its memo on disk. A memo path that cannot
/// be written ends the pass before the refresher runs and hands back the kick
/// the pass took; the same fixture, writable, sends exactly once.
#[test]
fn an_unwritable_memo_sends_nothing_and_keeps_the_kick() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let _home = HomeSandbox::new();
    let name = "cx-memo-fail";
    let now: i64 = 1_700_000_000_000;
    let calls = AtomicUsize::new(0);
    let counting = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(CodexTokenResponse {
            id_token: None,
            access_token: jwt_with_exp((now / 1000) + 3600),
            refresh_token: "rt.b".into(),
        })
    };

    // A fresh chain (not due) that a 401 kicked: only the forced attempt can
    // drive a refresh, so a consumed-then-lost kick would be observable.
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 86_400), "rt.a"),
    );
    let memo = crate::profile::profile_dir(&crate::profile::ProfileName::from(name))
        .expect("dir")
        .join("auth.attempt");
    // A directory where the memo file would land: the atomic rename onto it
    // fails on every platform.
    std::fs::create_dir(&memo).expect("occupy the memo path");
    kick_codex(name);

    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &counting,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::MemoFailed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing went on the wire");
    assert!(
        kick_available(name),
        "the forced attempt is still owed: the kick the pass took is handed back"
    );
    assert!(
        read_codex_store(name).contains("rt.a"),
        "the store is untouched"
    );

    // Writable again: the owed attempt fires once and lands.
    std::fs::remove_dir(&memo).expect("free the memo path");
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".into(),
            &counting,
            &fresh_activity(),
            &std::sync::atomic::AtomicBool::new(false)
        ),
        StandbyOutcome::Rotated
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        !kick_available(name),
        "the attempt that reached the wire consumed the kick"
    );
    kick_reset(name);
}

/// The daemon's leg through its own entry point: `standby_tick` reads the
/// roster itself and runs the production refresher, which the token-URL seam
/// points at a local stub. Every due chain rotates, so a tick that visits only
/// the first member — or none — reds.
#[test]
fn standby_tick_rotates_every_due_chain_through_the_wire() {
    let home = HomeSandbox::new();
    let now: i64 = 1_700_000_000_000;
    let (addr, handle) = crate::testutil::serve_endpoints(2, |_path, i| {
        (
            200,
            format!(
                r#"{{"id_token":"id.n","access_token":"at.n{i}","refresh_token":"rt.new{i}"}}"#
            ),
        )
    });
    // RAII, borrowing the home: a fixture panic below must not leave the
    // override pointing the next test at this port.
    let _token_url = crate::testutil::CodexTokenUrlSandbox::new(&home, &addr);

    crate::testutil::write_codex_roster(&["cx-tick-a", "cx-tick-b"]);
    for name in ["cx-tick-a", "cx-tick-b"] {
        write_codex_store(
            name,
            &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.old"),
        );
    }

    standby_tick(
        now,
        "2026-08-13T00:00:00Z",
        &fresh_activity(),
        &std::sync::atomic::AtomicBool::new(false),
    );

    let seen = handle.join().expect("join stub");
    assert_eq!(
        seen,
        ["/oauth/token", "/oauth/token"],
        "one refresh per due chain, both to the token endpoint"
    );
    let rotated: std::collections::BTreeSet<String> = ["cx-tick-a", "cx-tick-b"]
        .into_iter()
        .map(|name| {
            let v: serde_json::Value =
                serde_json::from_str(&read_codex_store(name)).expect("store parses");
            assert_eq!(v["last_refresh"], "2026-08-13T00:00:00Z", "{name} stamped");
            v["tokens"]["refresh_token"]
                .as_str()
                .expect("refresh token")
                .to_string()
        })
        .collect();
    assert_eq!(
        rotated,
        ["rt.new0".to_string(), "rt.new1".to_string()]
            .into_iter()
            .collect(),
        "BOTH stores hold a rotated pair, one per wire call"
    );
}

/// A codex refresh token is single-use, so the pass runs its refresh under a
/// scheduler spend claim, the one a TUI quit waits on and the save cue names,
/// and the claim is gone once the pass returned (the claim's span through the
/// store write is `a_standby_refresh_holds_its_claim_until_its_store_lands`).
#[test]
fn a_standby_refresh_runs_under_its_spend_claim() {
    let _home = HomeSandbox::new();
    let name = "cx-marked";
    let now: i64 = 1_700_000_000_000;
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    let activity = fresh_activity();
    let shutting_down = std::sync::atomic::AtomicBool::new(false);

    let during = std::cell::RefCell::new(None);
    let refresher = |_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
        *during.borrow_mut() = Some((
            crate::usage::spending_account(&activity),
            crate::usage::token_spend_in_flight(&activity),
        ));
        Ok(CodexTokenResponse {
            id_token: None,
            access_token: jwt_with_exp((now / 1000) + 3600),
            refresh_token: "rt.b".into(),
        })
    };

    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".to_string(),
            &refresher,
            &activity,
            &shutting_down,
        ),
        StandbyOutcome::Rotated
    );
    assert_eq!(
        *during.borrow(),
        Some((Some(name.to_string()), true)),
        "the refresh runs under the profile's own spend claim"
    );
    assert!(read_codex_store(name).contains("rt.b"), "the pair landed");
    assert_eq!(
        crate::usage::spending_account(&activity),
        None,
        "the claim is gone once the pass returned"
    );
}

/// A refresher that panics still drops its claim: a stranded claim would hold
/// every later quit for the whole of `shutdown`'s backstop.
#[test]
fn a_panicking_standby_refresh_clears_its_spend_marker() {
    let _home = HomeSandbox::new();
    let name = "cx-panics";
    let now: i64 = 1_700_000_000_000;
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    let activity = fresh_activity();
    let shutting_down = std::sync::atomic::AtomicBool::new(false);

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".to_string(),
            &|_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
                panic!("the refresh dies mid-spend")
            },
            &activity,
            &shutting_down,
        )
    }));

    assert!(unwound.is_err(), "the refresher's panic propagates");
    assert_eq!(
        crate::usage::spending_account(&activity),
        None,
        "an unwinding refresh leaves no spend marker behind"
    );
}

/// Once shutdown began, a due chain is left alone: no refresh, no marker, and
/// no attempt memo, so the next process still refreshes that same token
/// instead of reading it as already spent.
#[test]
fn a_shutting_down_standby_pass_spends_nothing_and_writes_no_memo() {
    let _home = HomeSandbox::new();
    let name = "cx-quitting";
    let now: i64 = 1_700_000_000_000;
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    let activity = fresh_activity();

    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".to_string(),
            &|_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
                panic!("no refresh may start once shutdown began")
            },
            &activity,
            &std::sync::atomic::AtomicBool::new(true),
        ),
        StandbyOutcome::Idle
    );
    assert_eq!(crate::usage::spending_account(&activity), None);
    assert!(
        read_codex_store(name).contains("rt.a"),
        "the store is untouched"
    );

    // No memo: the same due token still rotates on the next, live pass.
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".to_string(),
            &|t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
                assert_eq!(t, "rt.a");
                Ok(CodexTokenResponse {
                    id_token: None,
                    access_token: jwt_with_exp((now / 1000) + 3600),
                    refresh_token: "rt.b".into(),
                })
            },
            &activity,
            &std::sync::atomic::AtomicBool::new(false),
        ),
        StandbyOutcome::Rotated,
        "the refused pass left no memo blocking the token"
    );
}

/// The standby pass's claim is its own: it refreshes beside a marker the TUI
/// holds on the account and leaves that marker standing.
#[test]
fn a_standby_pass_runs_beside_a_tui_marker_and_leaves_it() {
    let _home = HomeSandbox::new();
    let name = "cx-busy";
    let now: i64 = 1_700_000_000_000;
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    let activity = fresh_activity();
    let profile = crate::profile::ProfileName::from(name);
    crate::usage::mark_activity(
        &activity,
        &profile,
        crate::usage::ProfileActivity::Refreshing,
    );

    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".to_string(),
            &|t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
                assert_eq!(t, "rt.a");
                Ok(CodexTokenResponse {
                    id_token: None,
                    access_token: jwt_with_exp((now / 1000) + 3600),
                    refresh_token: "rt.b".into(),
                })
            },
            &activity,
            &std::sync::atomic::AtomicBool::new(false),
        ),
        StandbyOutcome::Rotated,
        "the pass refreshes beside the TUI's marker"
    );
    assert_eq!(
        crate::usage::spending_account(&activity),
        Some(name.to_string()),
        "the TUI's marker survives the pass"
    );
    crate::usage::clear_activity(&activity, &profile);
    assert!(
        !crate::usage::token_spend_in_flight(&activity),
        "the pass's own claim is gone once it returned"
    );
}

/// A TUI-side clear of the account slot while the standby refresh runs leaves
/// the pass's claim standing: the quit still waits for the single-use spend.
#[test]
fn a_tui_clear_during_a_standby_refresh_leaves_its_claim() {
    let _home = HomeSandbox::new();
    let name = "cx-tui-clear";
    let now: i64 = 1_700_000_000_000;
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    let activity = fresh_activity();
    let profile = crate::profile::ProfileName::from(name);

    let after_clear = std::cell::Cell::new(None);
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".to_string(),
            &|_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
                crate::usage::clear_activity(&activity, &profile);
                after_clear.set(Some(crate::usage::token_spend_in_flight(&activity)));
                Ok(CodexTokenResponse {
                    id_token: None,
                    access_token: jwt_with_exp((now / 1000) + 3600),
                    refresh_token: "rt.b".into(),
                })
            },
            &activity,
            &std::sync::atomic::AtomicBool::new(false),
        ),
        StandbyOutcome::Rotated
    );
    assert_eq!(
        after_clear.get(),
        Some(true),
        "the pass's claim survives a TUI clear of the account slot"
    );
    assert!(!crate::usage::token_spend_in_flight(&activity));
}

/// The pass's claim stands until the rotated store is on disk: a codex refresh
/// token is single-use, so a quit landing between the POST's answer and the
/// store write would lose the chain until a browser re-login.
#[test]
fn a_standby_refresh_holds_its_claim_until_its_store_lands() {
    let _home = HomeSandbox::new();
    let name = "cx-holds-to-store";
    let now: i64 = 1_700_000_000_000;
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.a"),
    );
    let activity = fresh_activity();
    let at_store_write = std::sync::Arc::new(std::sync::Mutex::new(None));
    {
        let activity = std::sync::Arc::clone(&activity);
        let at_store_write = std::sync::Arc::clone(&at_store_write);
        let n = name.to_string();
        crate::codex_auth::set_pre_store_write_hook(
            name,
            std::sync::Arc::new(move || {
                *at_store_write.lock().expect("record") = Some((
                    crate::usage::token_spend_in_flight(&activity),
                    read_codex_store(&n).contains("rt.a"),
                ));
            }),
        );
    }

    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".to_string(),
            &|_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
                Ok(CodexTokenResponse {
                    id_token: None,
                    access_token: jwt_with_exp((now / 1000) + 3600),
                    refresh_token: "rt.b".into(),
                })
            },
            &activity,
            &std::sync::atomic::AtomicBool::new(false),
        ),
        StandbyOutcome::Rotated
    );
    assert_eq!(
        *at_store_write.lock().expect("record"),
        Some((true, true)),
        "the claim still stands just before the rotated store is written"
    );
    assert!(read_codex_store(name).contains("rt.b"), "the pair landed");
    assert!(!crate::usage::token_spend_in_flight(&activity));
}

/// A refused pass hands back the forced attempt a kick bought: the chain is not
/// due, so only the kick can force it, and the kick must still be there for the
/// next live pass.
#[test]
fn a_refused_standby_pass_keeps_the_kick_it_took() {
    let _home = HomeSandbox::new();
    let name = "cx-kick-kept";
    let now: i64 = 1_700_000_000_000;
    write_codex_store(
        name,
        &codex_auth_body(&jwt_with_exp((now / 1000) + 3600), "rt.a"),
    );
    let activity = fresh_activity();
    kick_codex(name);

    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".to_string(),
            &|_t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
                panic!("no refresh may start once shutdown began")
            },
            &activity,
            &std::sync::atomic::AtomicBool::new(true),
        ),
        StandbyOutcome::Idle
    );
    assert_eq!(
        standby_pass(
            name,
            now,
            "2026-08-13T00:00:00Z".to_string(),
            &|t: &str| -> std::result::Result<CodexTokenResponse, CodexRefreshError> {
                assert_eq!(t, "rt.a");
                Ok(CodexTokenResponse {
                    id_token: None,
                    access_token: jwt_with_exp((now / 1000) + 7200),
                    refresh_token: "rt.b".into(),
                })
            },
            &activity,
            &std::sync::atomic::AtomicBool::new(false),
        ),
        StandbyOutcome::Rotated,
        "the kick survived the refused pass and forces this one"
    );
    kick_reset(name);
}

/// `standby_tick` hands its caller's store and flag down to every pass: the
/// production refresher's POST reaches the stub while the marker stands.
#[test]
fn standby_tick_refreshes_under_its_callers_spend_marker() {
    let home = HomeSandbox::new();
    let now: i64 = 1_700_000_000_000;
    let activity = fresh_activity();
    let marked_at_post = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (addr, handle) = {
        let activity = std::sync::Arc::clone(&activity);
        let marked_at_post = std::sync::Arc::clone(&marked_at_post);
        crate::testutil::serve_endpoints(1, move |_path, _i| {
            marked_at_post
                .lock()
                .expect("record")
                .push(crate::usage::spending_account(&activity));
            (
                200,
                r#"{"id_token":"id.n","access_token":"at.n","refresh_token":"rt.new"}"#.to_string(),
            )
        })
    };
    let _token_url = crate::testutil::CodexTokenUrlSandbox::new(&home, &addr);
    crate::testutil::write_codex_roster(&["cx-tick-marked"]);
    write_codex_store(
        "cx-tick-marked",
        &codex_auth_body(&jwt_with_exp((now / 1000) + 60), "rt.old"),
    );

    standby_tick(
        now,
        "2026-08-13T00:00:00Z",
        &activity,
        &std::sync::atomic::AtomicBool::new(false),
    );

    assert_eq!(handle.join().expect("join stub"), ["/oauth/token"]);
    assert_eq!(
        *marked_at_post.lock().expect("record"),
        vec![Some("cx-tick-marked".to_string())],
        "the POST went out under the caller's marker"
    );
    assert_eq!(crate::usage::spending_account(&activity), None);
    assert!(read_codex_store("cx-tick-marked").contains("rt.new"));
}

/// A torn `auth.json` names the position of the syntax error. The parser's
/// syntax message never quotes a value, so the pin is the position alone.
#[test]
fn a_torn_auth_json_names_the_position() {
    let bytes = b"{ \"tokens\": { \"refresh_token\": \"sk-c2probe-NOTAKEY";
    let err = CodexAuth::parse(bytes).expect_err("a torn auth.json fails the parse");
    let rendered = format!("{err:#}");
    assert_eq!(rendered, "auth.json did not parse (line 1, column 50)");
    assert!(
        err.source().is_none(),
        "the parse error must not ride as a source: {err:?}"
    );
}

/// A 200 token body that does not parse carries the position in the transient
/// failure. The syntax message never quotes a value, so the pin is the
/// position alone.
#[test]
fn a_torn_token_body_names_the_position() {
    let (addr, handle) = crate::testutil::serve_endpoints(1, |_path, _i| {
        (200, "{\"access_token\": \"sk-c2probe-NOTAKEY".to_string())
    });
    let err = refresh_codex_chain_at(&format!("{addr}/oauth/token"), "rt.old")
        .expect_err("a torn body fails the refresh");
    let rendered = match &err {
        CodexRefreshError::Transient(message) => message.clone(),
        other => panic!("expected a transient failure, got {other:?}"),
    };
    assert_eq!(rendered, "token response did not parse (line 1, column 36)");
    let _ = handle.join();
}

/// An empty 2xx body is an end-of-input error at line 1, column 0: a token
/// body is a network reply, never a file, so it still names line 1 (the
/// endpoint truncated its reply) instead of staying bare like an empty file.
#[test]
fn an_empty_token_body_names_line_1() {
    let (addr, handle) = crate::testutil::serve_endpoints(1, |_path, _i| (200, String::new()));
    let err = refresh_codex_chain_at(&format!("{addr}/oauth/token"), "rt.old")
        .expect_err("an empty body fails the refresh");
    let rendered = match &err {
        CodexRefreshError::Transient(message) => message.clone(),
        other => panic!("expected a transient failure, got {other:?}"),
    };
    assert_eq!(rendered, "token response did not parse (line 1)");
    let _ = handle.join();
}

/// Serve one POST a reply whose body read fails: it declares `content_length`
/// but writes only `body` bytes, then closes. A `body` shorter than
/// `content_length` cuts the reply mid-body; a `body` of invalid UTF-8 (with an
/// honest `content_length`) fails the read's UTF-8 check. Both read failures
/// reach the caller before any parse, so no position exists to name.
fn serve_unreadable_body(
    status: u16,
    body: &'static [u8],
    content_length: usize,
) -> (String, std::thread::JoinHandle<()>) {
    use std::io::Write;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        crate::testutil::drain_http_request(&mut sock);
        let _ = sock.write_all(
            format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        );
        let _ = sock.write_all(body);
        let _ = sock.shutdown(std::net::Shutdown::Write);
    });
    (format!("http://127.0.0.1:{port}"), handle)
}

/// A 2xx reply whose body read fails (the connection cut mid-body) is a
/// transport failure, never `token response did not parse (line 1)`: the reply
/// was never read, so it has no position. Pinned by equality to the transport
/// rendering — the read error's own Display.
#[test]
fn a_2xx_body_cut_short_is_a_transport_failure() {
    let (addr, handle) = serve_unreadable_body(
        200,
        b"{\"access_token\": \"at\", \"refresh_token\": \"rt\"",
        300,
    );
    let err = refresh_codex_chain_at(&format!("{addr}/oauth/token"), "rt.old")
        .expect_err("a cut body fails the refresh");
    let rendered = match &err {
        CodexRefreshError::Transient(message) => message.clone(),
        other => panic!("expected a transient failure, got {other:?}"),
    };
    assert_ne!(rendered, "token response did not parse (line 1)");
    assert_eq!(rendered, "io: Peer disconnected");
    let _ = handle.join();
}

/// A 2xx reply whose body is not UTF-8 fails the read itself, so it too is a
/// transport failure — never a parse position. The read error carries no body
/// byte.
#[test]
fn a_non_utf8_body_is_a_transport_failure() {
    let (addr, handle) = serve_unreadable_body(200, &[0xFF, 0xFE, 0x00, 0x01], 4);
    let err = refresh_codex_chain_at(&format!("{addr}/oauth/token"), "rt.old")
        .expect_err("a non-UTF-8 body fails the refresh");
    let rendered = match &err {
        CodexRefreshError::Transient(message) => message.clone(),
        other => panic!("expected a transient failure, got {other:?}"),
    };
    assert_eq!(rendered, "io: stream did not contain valid UTF-8");
    let _ = handle.join();
}

/// A non-2xx reply still classifies by its status even when its body is
/// unreadable: the non-2xx arm needs only the status split, so the unread body
/// falls back to `""` and the 400 names `rejected`.
#[test]
fn a_non_2xx_reply_with_an_unreadable_body_classifies_by_status() {
    let (addr, handle) = serve_unreadable_body(400, b"short", 300);
    let err = refresh_codex_chain_at(&format!("{addr}/oauth/token"), "rt.old")
        .expect_err("a 400 fails the refresh");
    match &err {
        CodexRefreshError::Dead("rejected") => {}
        other => panic!("expected Dead(rejected), got {other:?}"),
    }
    let _ = handle.join();
}
