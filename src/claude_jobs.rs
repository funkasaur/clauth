//! Reader for Claude Code's background-job store
//! (`~/.claude/jobs/<id>/state.json`).
//!
//! `claude --bg` hands its session to Claude Code's background service and
//! returns at once, so a `clauth start <p> --bg` teardown — and any later GC
//! sweep — can find the runtime tree still in use by a session clauth's marker
//! flock never sees (the session is orphaned: `starting…`, no pid). The job
//! record is Claude Code's own statement that a session uses a config dir.
//!
//! One read walks the global `~/.claude/jobs` store and, beside it, each
//! runtime tree's own `jobs/` dir where that store is authoritative — a copy
//! host keeps the record inside the tree (its mirror never carries `jobs/`),
//! and an isolated tree links no `jobs/` so its store is tree-local too; a
//! symlinked `jobs/` is the global store already read and is never followed. A
//! tree-local record names only its own tree, so a record naming a different
//! tree is a stale copy — a copy-host mirror's leftover — and is skipped. One
//! read yields the tree and settings-file name sets. The spare term
//! ([`JobTrees::spares`] / [`JobTrees::spares_under`], GC and the destructive
//! gates) counts a job as live while its job dir exists (until `claude rm`),
//! whatever its `state`: a finished job may be revived (`claude attach`) and
//! the cost of sparing its tree is disk — except in an ISOLATED tree, which no
//! session can re-enter, where only an UNFINISHED job spares. A record-less job
//! dir that is a removed job's leftover — an empty `tmp/` and/or an
//! `exit-cause` file — reads as no job; every other record-less dir stays
//! unreadable and spares, so a job caught mid-create never reads as collected.
//! The settings term ([`JobTrees::spares_settings`]) spares a spawn-settings
//! file a job's `respawnFlags` name. The rotation term
//! ([`JobTrees::unfinished_under`]) counts only UNFINISHED jobs: a
//! `stopped`/`done`/`failed` job must not freeze the chain, and only `state`
//! can say "finished" — `firstTerminalAt` cannot (a revived `running` job keeps
//! the stamp). A global-store failure is global; a tree-local or profile-dir
//! failure is SCOPED to that account's trees.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::profile::claude_dir;
use crate::session_record::LenientString;

// Test seam: how many times THIS thread has read the job store, so a
// pass-level caller's test can pin "one read per pass". Thread-local: a
// concurrent test thread's reads land in its own cell and never pollute this
// count.
#[cfg(test)]
thread_local! {
    static JOB_TREES_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn job_trees_reads() -> usize {
    JOB_TREES_READS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn reset_job_trees_reads() {
    JOB_TREES_READS.with(|c| c.set(0));
}

/// A job's `state.json`, reduced to the fields the spare, rotation and
/// settings-file rules need. Unknown fields are ignored: the record's key set
/// grew across Claude Code versions.
#[derive(Deserialize)]
struct JobState {
    #[serde(rename = "providerEnv")]
    provider_env: Option<ProviderEnv>,
    /// `String`, never a closed enum and never a strict parse: a future Claude
    /// Code shape writing `state` as a non-string reads empty
    /// ([`crate::session_record::lenient_string`]), and empty reads unfinished —
    /// a false "finished" would sign a running session out.
    #[serde(default, deserialize_with = "crate::session_record::lenient_string")]
    state: String,
    /// Never a strict parse: absent reads [`RespawnFlags::Absent`]; a list
    /// decodes through [`read_respawn_flags`] to [`RespawnFlags::Named`] or
    /// [`RespawnFlags::Unknown`]; any other value, or a token serde_json
    /// refuses inside it, fails this parse and [`JobCore`] reads the flags
    /// [`RespawnFlags::Unknown`]. Of the record's parse faults, only one that
    /// fails that parse too flips the store `Unreadable`.
    #[serde(
        default,
        rename = "respawnFlags",
        deserialize_with = "read_respawn_flags"
    )]
    respawn_flags: RespawnFlags,
    /// The conversation the job runs: its transcript lines carry this id
    /// (measured on 2.1.310). Lenient like `state`, so a retyped value names
    /// no conversation rather than flip the store unreadable.
    #[serde(
        default,
        rename = "sessionId",
        deserialize_with = "crate::session_record::lenient_string"
    )]
    session_id: String,
}

/// [`JobState`] minus the `respawnFlags` field: the fallback parse when
/// [`JobState`] fails. `respawnFlags` is unmodelled, so serde skips it through
/// [`serde::de::IgnoredAny`] — a path a token serde_json rejects inside the
/// field survives — and a record only this struct parses is one whose sole
/// fault is in `respawnFlags`. `providerEnv` and `state` share [`JobState`]'s
/// attributes, so a fault in either still fails both parses.
#[derive(Deserialize)]
struct JobCore {
    #[serde(rename = "providerEnv")]
    provider_env: Option<ProviderEnv>,
    #[serde(default, deserialize_with = "crate::session_record::lenient_string")]
    state: String,
    #[serde(
        default,
        rename = "sessionId",
        deserialize_with = "crate::session_record::lenient_string"
    )]
    session_id: String,
}

/// Claude Code's terminal agent states. `stopped` measured on 2.1.304
/// (`claude stop`); `done`/`failed` from `claude agents --json`'s state list,
/// never seen in a record; any other string reads unfinished.
const FINISHED_STATES: [&str; 3] = ["stopped", "done", "failed"];

#[derive(Deserialize)]
struct ProviderEnv {
    #[serde(rename = "CLAUDE_CONFIG_DIR")]
    claude_config_dir: Option<String>,
}

/// The name sets one readable job-store walk yields. The fields are private
/// behind the query methods: `unfinished ⊆ named` must hold, and a caller
/// reading one set directly could break it.
#[derive(Debug)]
pub(crate) struct NamedTrees {
    /// Canonical identities of every config dir a live job names, whatever its
    /// `state`. Empty when no job names a tree (or no job exists). A job
    /// naming a dir that no longer resolves contributes nothing: its tree is
    /// already gone.
    named: HashSet<PathBuf>,
    /// Canonical tree id -> the job ids (job dir names) whose record names that
    /// tree, from the global store or a tree-local one. Two jobs can name one
    /// tree, so the set — not the tree's presence in `named` — says when the
    /// jobs naming a tree changed.
    named_by_job: HashMap<PathBuf, HashSet<String>>,
    /// Canonical identities of every config dir an UNFINISHED job names — a
    /// subset of `named` (an unfinished job is also live for the spare term).
    unfinished: HashSet<PathBuf>,
    /// Conversation id -> the canonical config dir the job running it names,
    /// for every job in `named` whose record names its conversation.
    tree_by_session: HashMap<String, PathBuf>,
    /// Conversation ids a job record names with no config dir: a plain
    /// `claude --bg` on `~/.claude`.
    global_sessions: HashSet<String>,
    /// Canonical identities of every settings file a job's `respawnFlags` name
    /// (a path following a `--settings` element).
    named_settings: HashSet<PathBuf>,
    /// Canonical identities of every config dir whose job's `respawnFlags` are
    /// not a list of strings, so no settings file is recoverable from them and
    /// the caller falls back to the tree rule.
    unknown_flags_trees: HashSet<PathBuf>,
    /// Scoped fail-closed: every dir (a runtime tree, or a profile dir) whose
    /// OWN job store could not be read. Only trees under one of these read as
    /// unreadable — a global store failure is the separate
    /// [`JobTrees::Unreadable`] arm.
    unreadable: Vec<UnreadableStore>,
}

/// One scoped unreadable: the canonical identity a spare/block query matches
/// against, and the store dir to name in the rotation refusal's `{path}`.
#[derive(Debug)]
struct UnreadableStore {
    /// Canonical identity of the tree or profile dir whose store failed.
    scope: PathBuf,
    /// The store dir the operator can act on (the tree's `jobs/`, or the
    /// profile dir).
    store: PathBuf,
}

/// The answer to "which runtime trees and settings files must a sweep or gate
/// spare?".
#[derive(Debug)]
pub(crate) enum JobTrees {
    /// A readable store, as [`NamedTrees`]. Boxed: `NamedTrees` dwarfs the
    /// `Unreadable` arm (clippy::large_enum_variant).
    Named(Box<NamedTrees>),
    /// The store could not be trusted — a job dir's `state.json` was missing,
    /// unreadable, or unparseable, or a named config dir could not be
    /// canonicalized while it might still exist. `offending` is the deep dir a
    /// log line names (never the record's contents); `store` is the store dir
    /// the rotation refusal names (the conventional global store, or the tree's
    /// `jobs/`).
    Unreadable { offending: PathBuf, store: PathBuf },
}

/// What the job store says about the tree one conversation runs in
/// ([`JobTrees::session_tree`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionTree {
    /// No job record names the conversation.
    Untracked,
    /// A job runs the conversation on `~/.claude`: a plain `claude --bg`.
    Global,
    /// The canonical config dir the job running the conversation names.
    Named(PathBuf),
    /// The store could not be read, so the answer is missing.
    Unknown,
}

impl JobTrees {
    /// The tree the job running conversation `session_id` names, off the
    /// record's `sessionId` and `providerEnv.CLAUDE_CONFIG_DIR`.
    pub(crate) fn session_tree(&self, session_id: &str) -> SessionTree {
        match self {
            JobTrees::Unreadable { .. } => SessionTree::Unknown,
            JobTrees::Named(sets) => match sets.tree_by_session.get(session_id) {
                Some(tree) => SessionTree::Named(tree.clone()),
                None if sets.global_sessions.contains(session_id) => SessionTree::Global,
                None => SessionTree::Untracked,
            },
        }
    }

    /// Whether `tree` must be spared: a live job names it, the store was
    /// unreadable (fail closed, the direction `is_session_alive` takes), or a
    /// scoped unreadable covers the tree (its own store, or its profile dir,
    /// could not be read).
    ///
    /// `tree` is canonicalized here so it and the named set share one spelling
    /// ([`crate::canonical::identity`], the compare-or-key purpose). A
    /// `NotFound` canonicalize — the tree is already gone — reads as unnamed:
    /// nothing to spare, and the caller still collects an orphaned sessions
    /// dir. Any other canonicalize failure reads as named.
    pub(crate) fn spares(&self, tree: &Path) -> bool {
        match self {
            JobTrees::Unreadable { .. } => true,
            JobTrees::Named(sets) if sets.named.is_empty() && sets.unreadable.is_empty() => false,
            JobTrees::Named(sets) => named_or_affected(tree, &sets.named, &sets.unreadable),
        }
    }

    /// Whether a live job NAMES `tree` (the named set holds its canonical
    /// identity), distinct from [`JobTrees::spares`], which also spares a tree
    /// covered by a scoped unreadable. The GC per-pair spare log uses this so a
    /// scoped-unreadable spare never claims a job names the tree.
    pub(crate) fn names(&self, tree: &Path) -> bool {
        match self {
            JobTrees::Unreadable { .. } => false,
            JobTrees::Named(sets) => {
                if sets.named.is_empty() {
                    return false;
                }
                match crate::canonical::identity(tree) {
                    Ok(id) => sets.named.contains(&id),
                    Err(_) => false,
                }
            }
        }
    }

    /// Whether an UNFINISHED job names `tree` — the subset of
    /// [`JobTrees::names`] that still blocks a macOS rotation — or the tree's
    /// own store is unreadable (fail closed). Distinct from
    /// [`JobTrees::spares`], which covers a LIVE job of any state, and from
    /// [`JobTrees::names`], which covers any live job.
    pub(crate) fn unfinished_names(&self, tree: &Path) -> bool {
        match self {
            JobTrees::Unreadable { .. } => true,
            JobTrees::Named(sets) if sets.unfinished.is_empty() && sets.unreadable.is_empty() => {
                false
            }
            JobTrees::Named(sets) => named_or_affected(tree, &sets.unfinished, &sets.unreadable),
        }
    }

    /// The set of job ids whose record names `tree`, from any store that names
    /// it (the global store or the tree's own `jobs/`). Empty when no job names
    /// it or the store is unreadable. Distinct from [`JobTrees::names`]: two
    /// jobs can name one tree, and the daemon's copy-host gate re-arms its one
    /// re-check when THIS set changes (a new job beside an older one), not only
    /// when it empties.
    pub(crate) fn job_ids_naming(&self, tree: &Path) -> HashSet<String> {
        match self {
            JobTrees::Unreadable { .. } => HashSet::new(),
            JobTrees::Named(sets) => match crate::canonical::identity(tree) {
                Ok(id) => sets.named_by_job.get(&id).cloned().unwrap_or_default(),
                Err(_) => HashSet::new(),
            },
        }
    }

    /// Whether a scoped unreadable is `profile` itself — the account's profile
    /// dir could not be enumerated. The daemon skips such an account: the
    /// adoption build reads its config and probes its link mode under that
    /// dir, so queueing it would start a failing backoff streak that re-takes
    /// the locks every interval. A tree-local store failure (a scope UNDER the
    /// profile) does not count: adoption never reads a tree's own `jobs/`.
    pub(crate) fn profile_dir_unreadable(&self, profile: &Path) -> bool {
        match self {
            JobTrees::Unreadable { .. } => true,
            JobTrees::Named(sets) => {
                if sets.unreadable.is_empty() {
                    return false;
                }
                match crate::canonical::identity(profile) {
                    Ok(id) => sets.unreadable.iter().any(|u| u.scope == id),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => false,
                    Err(_) => true,
                }
            }
        }
    }

    /// The store dir every scoped unreadable names, for the sweep-level GC log:
    /// one entry per scoped unreadable, once per sweep, empty under a global
    /// [`JobTrees::Unreadable`] (the global line already covers that).
    pub(crate) fn scoped_unreadable_stores(&self) -> Vec<&Path> {
        match self {
            JobTrees::Unreadable { .. } => Vec::new(),
            JobTrees::Named(sets) => sets.unreadable.iter().map(|u| u.store.as_path()).collect(),
        }
    }

    /// Whether a live job names a tree UNDER `dir`, the store is unreadable, or
    /// a scoped unreadable covers `dir` (its own profile dir, or a tree-local
    /// store under it). Used by [`crate::runtime::has_live_session`]: a job
    /// naming any tree under a profile's dir is a live session for every gate
    /// that carries (delete, disable, rename), since the marker flock never
    /// sees the `claude --bg` session still reading its config dir. The macOS
    /// rotation gate uses the narrower [`JobTrees::unfinished_under`] term
    /// instead.
    pub(crate) fn spares_under(&self, dir: &Path) -> bool {
        match self {
            JobTrees::Unreadable { .. } => true,
            JobTrees::Named(sets) => {
                named_under(&sets.named, dir) || unreadable_under(dir, &sets.unreadable)
            }
        }
    }

    /// Whether `file` must be spared: a job's `respawnFlags` name it, a job
    /// whose flags are unreadable names one of `own_trees` (the tree rule's
    /// fallback), the store was unreadable (fail closed), or a scoped
    /// unreadable covers one of `own_trees`. `file` and each own tree are
    /// canonicalized like the tree set. The fallback is loose by design: when
    /// `own_trees` holds both layouts of a shared file, a job naming the bare
    /// fake `runtime` spares the Real-mode file beside it too.
    pub(crate) fn spares_settings(&self, file: &Path, own_trees: &[PathBuf]) -> bool {
        match self {
            JobTrees::Unreadable { .. } => true,
            JobTrees::Named(sets) => {
                if sets.named_settings.is_empty()
                    && sets.unknown_flags_trees.is_empty()
                    && sets.unreadable.is_empty()
                {
                    return false;
                }
                holds_canonical(&sets.named_settings, file)
                    || own_trees
                        .iter()
                        .any(|tree| holds_canonical(&sets.unknown_flags_trees, tree))
                    || own_trees
                        .iter()
                        .any(|tree| named_or_affected(tree, &HashSet::new(), &sets.unreadable))
            }
        }
    }

    /// The canonical tree paths every UNFINISHED job names UNDER `dir`, so the
    /// rotation gate can read each tree's `.credentials.json` and apply the
    /// same holds-a-refresh-token narrowing the marker term gets. `Err(store)`
    /// when the store (or a scoped store under `dir`) is unreadable — fail
    /// closed: the caller blocks and names the store. A finished job
    /// (`stopped`/`done`/`failed`) is not mid-task, so it names nothing here;
    /// an unknown or missing `state` reads unfinished by construction.
    ///
    /// `dir` is canonicalized so it and the set share one spelling; a
    /// `NotFound` canonicalize — the dir is already gone — reads as empty, and
    /// any other failure reads as unreadable, like [`JobTrees::spares`].
    pub(crate) fn unfinished_under(&self, dir: &Path) -> Result<Vec<PathBuf>, PathBuf> {
        match self {
            JobTrees::Unreadable { store, .. } => Err(store.clone()),
            JobTrees::Named(sets) => {
                let dir_id = match crate::canonical::identity(dir) {
                    Ok(id) => id,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
                    Err(_) => return Err(dir.to_path_buf()),
                };
                if let Some(unreadable) = sets
                    .unreadable
                    .iter()
                    .find(|u| u.scope == dir_id || u.scope.starts_with(&dir_id))
                {
                    return Err(unreadable.store.clone());
                }
                Ok(sets
                    .unfinished
                    .iter()
                    .filter(|named| named.starts_with(&dir_id))
                    .cloned()
                    .collect())
            }
        }
    }
}

/// Whether `path`'s canonical identity is named OR lies under a scoped
/// unreadable. A `NotFound` canonicalize — the path is already gone — reads as
/// not spared, any other failure as spared (fail closed).
fn named_or_affected(
    path: &Path,
    named: &HashSet<PathBuf>,
    unreadable: &[UnreadableStore],
) -> bool {
    match crate::canonical::identity(path) {
        Ok(id) => {
            named.contains(&id)
                || unreadable
                    .iter()
                    .any(|u| id == u.scope || id.starts_with(&u.scope))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// Whether `dir`'s canonical identity IS a scoped unreadable, or has one under
/// it (a tree-local store in this account failed).
fn unreadable_under(dir: &Path, unreadable: &[UnreadableStore]) -> bool {
    match crate::canonical::identity(dir) {
        Ok(dir_id) => unreadable
            .iter()
            .any(|u| u.scope == dir_id || u.scope.starts_with(&dir_id)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// Whether any canonical identity in `set` lies under `dir`'s canonical
/// identity. `dir` is canonicalized so it and the set share one spelling (the
/// same [`crate::canonical::identity`] form `spares` uses). A `NotFound`
/// canonicalize — the dir is already gone — reads as unnamed: nothing under it
/// exists to spare. Any other failure reads as named.
fn named_under(set: &HashSet<PathBuf>, dir: &Path) -> bool {
    if set.is_empty() {
        return false;
    }
    match crate::canonical::identity(dir) {
        Ok(dir_id) => set.iter().any(|named| named.starts_with(&dir_id)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// Whether `set` holds `path`'s canonical identity, fail closed: a `NotFound`
/// canonicalize — the path is already gone — reads as not held (nothing to
/// spare), any other failure as held.
fn holds_canonical(set: &HashSet<PathBuf>, path: &Path) -> bool {
    match crate::canonical::identity(path) {
        Ok(id) => set.contains(&id),
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// Deserializer for [`JobState::respawn_flags`]: walks the value into a
/// [`RespawnFlags`] without ever building a `serde_json::Value`; a non-list
/// value errors, and [`JobCore`]'s fallback then reads the flags
/// [`RespawnFlags::Unknown`].
fn read_respawn_flags<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<RespawnFlags, D::Error> {
    deserializer.deserialize_any(RespawnFlagsVisitor)
}

/// What a job's `respawnFlags` name: [`RespawnFlags::Absent`] when the field
/// is missing, [`RespawnFlags::Named`] the settings values after `--settings`
/// (either spelling), or [`RespawnFlags::Unknown`] when the field is present
/// but not a list of strings, and the caller must fall back to the tree rule.
#[derive(Default)]
enum RespawnFlags {
    #[default]
    Absent,
    Named(Vec<String>),
    Unknown,
}

struct RespawnFlagsVisitor;

impl<'de> serde::de::Visitor<'de> for RespawnFlagsVisitor {
    type Value = RespawnFlags;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a list of strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<RespawnFlags, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut named = Vec::new();
        let mut unknown = false;
        while let Some(flag) = seq.next_element::<LenientString>()? {
            let Some(flag) = flag.0 else {
                unknown = true;
                continue;
            };
            if unknown {
                continue;
            }
            if let Some(value) = flag.strip_prefix("--settings=") {
                named.push(value.to_string());
            } else if flag == "--settings" {
                match seq.next_element::<LenientString>()? {
                    Some(LenientString(Some(value))) => named.push(value),
                    _ => unknown = true,
                }
            }
        }
        if unknown {
            Ok(RespawnFlags::Unknown)
        } else {
            Ok(RespawnFlags::Named(named))
        }
    }
}

/// Read Claude Code's job stores once: the global `~/.claude/jobs` and, beside
/// it, each runtime tree's own `jobs/` dir where that store is authoritative —
/// a REAL directory in an ISOLATED tree (which never links the store) or in a
/// SHARED tree (a linked-host shared tree's `jobs` is a symlink, already read
/// above, so a real dir there was written by Claude Code itself). A tree-local
/// record names only its own tree — Claude Code writes `CLAUDE_CONFIG_DIR` =
/// the tree — so a record naming a different tree is a stale copy and is
/// skipped.
///
/// Every entry that is a DIRECTORY is a job (plain files like `pins.json` are
/// not); a missing store dir reads as no jobs. A global-store failure makes the
/// whole read unreadable; a tree-local or profile-dir failure is SCOPED to that
/// dir's trees. Any job dir whose `state.json` is missing, unreadable, or
/// unparseable makes its STORE unreadable — EXCEPT a missing record whose dir
/// is a removed job's leftover ([`removed_jobs_leftover`]), which reads as no
/// job.
pub(crate) fn job_trees() -> JobTrees {
    #[cfg(test)]
    JOB_TREES_READS.with(|c| c.set(c.get() + 1));
    let mut sets = NamedTrees {
        named: HashSet::new(),
        named_by_job: HashMap::new(),
        unfinished: HashSet::new(),
        tree_by_session: HashMap::new(),
        global_sessions: HashSet::new(),
        named_settings: HashSet::new(),
        unknown_flags_trees: HashSet::new(),
        unreadable: Vec::new(),
    };

    let jobs_dir = match claude_dir() {
        Ok(dir) => dir.join("jobs"),
        // Fail closed: a store this reader cannot even locate must spare, never
        // collect. `claude_dir` fails only when `home_dir` fails (no home), so
        // there is no real path to name — log the conventional location rather
        // than an empty path.
        Err(_) => {
            return JobTrees::Unreadable {
                offending: PathBuf::from("~/.claude/jobs"),
                store: PathBuf::from("~/.claude/jobs"),
            };
        }
    };
    // The global store is authoritative for every account, so a failure here
    // stays global and the refusal names the conventional store location.
    if let Err(offending) = read_jobs_dir(&jobs_dir, None, false, &mut sets) {
        return JobTrees::Unreadable {
            offending,
            store: PathBuf::from("~/.claude/jobs"),
        };
    }

    let runtime_trees = match crate::runtime::runtime_trees() {
        Ok(trees) => trees,
        // A `profiles/` root this walk cannot enumerate means no tree's store
        // can be seen: global.
        Err(dir) => {
            return JobTrees::Unreadable {
                offending: dir.clone(),
                store: dir,
            };
        }
    };
    for profile in runtime_trees.unreadable_profiles {
        record_unreadable(&mut sets.unreadable, &profile, &profile);
    }
    for tree in runtime_trees.trees {
        let jobs = tree.join("jobs");
        match std::fs::symlink_metadata(&jobs) {
            // A symlinked `jobs` IS the global store (the SHARED link on a
            // linked host), already read above; following it would read every
            // record twice.
            Ok(meta) if meta.file_type().is_symlink() => {}
            Ok(meta) if meta.file_type().is_dir() => {
                let isolated = tree
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| !crate::runtime::is_shared_runtime_dir_name(name));
                let owner = match crate::canonical::identity(&tree) {
                    Ok(id) => id,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(_) => tree.clone(),
                };
                if read_jobs_dir(&jobs, Some(&owner), isolated, &mut sets).is_err() {
                    record_unreadable(&mut sets.unreadable, &tree, &jobs);
                }
            }
            Ok(_) => record_unreadable(&mut sets.unreadable, &tree, &jobs),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => record_unreadable(&mut sets.unreadable, &tree, &jobs),
        }
    }

    JobTrees::Named(Box::new(sets))
}

/// Push one scoped unreadable: `scope` (a tree or profile dir) is canonicalized
/// for the spare/block matches, and `store` is the dir the refusal names.
fn record_unreadable(unreadable: &mut Vec<UnreadableStore>, scope: &Path, store: &Path) {
    let scope = match crate::canonical::identity(scope) {
        Ok(id) => id,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return,
        Err(_) => scope.to_path_buf(),
    };
    unreadable.push(UnreadableStore {
        scope,
        store: store.to_path_buf(),
    });
}

/// Read one job-store dir into the sets. `owner` is `Some(canonical tree id)`
/// for a tree-local store and `None` for the global store: a tree-local record
/// naming a DIFFERENT tree is a stale copy (a copy-host mirror's leftover) and
/// is skipped. `isolated`
/// keeps only UNFINISHED jobs — a finished job in an isolated tree (which no
/// session can re-enter) spares nothing and blocks nothing. A missing dir reads
/// as no jobs; any other failure returns the offending dir, which the caller
/// maps to a global or scoped unreadable. The record rules are [`job_trees`]'s:
/// a plain file is no job, a job naming no config dir contributes nothing, and
/// a record-less dir is either a removed job's leftover (no job) or unreadable.
fn read_jobs_dir(
    jobs_dir: &Path,
    owner: Option<&Path>,
    isolated: bool,
    sets: &mut NamedTrees,
) -> Result<(), PathBuf> {
    let entries = match std::fs::read_dir(jobs_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(jobs_dir.to_path_buf()),
    };
    for entry in entries {
        let entry = entry.map_err(|_| jobs_dir.to_path_buf())?;
        let job_dir = entry.path();
        let is_dir = entry.file_type().map_err(|_| job_dir.clone())?.is_dir();
        if !is_dir {
            continue;
        }
        let record = match std::fs::read(job_dir.join("state.json")) {
            Ok(bytes) => bytes,
            // `claude rm` CAN leave the supervisor running — measured with a
            // second tree's supervisor sharing the roster — and that supervisor
            // recreates the job dir with no record — an empty `tmp/`, then
            // `exit-cause` once signalled. A lone bare job's supervisor exits
            // instead. A creation never makes those shapes (`tmp/` follows
            // `state.json`), so the leftover reads as no job; every other
            // record-less dir stays unreadable (fail closed).
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match removed_jobs_leftover(&job_dir) {
                    Ok(true) => continue,
                    Ok(false) | Err(_) => return Err(job_dir.clone()),
                }
            }
            Err(_) => return Err(job_dir.clone()),
        };
        let state: JobState = match serde_json::from_slice(&record) {
            Ok(state) => state,
            // A non-list `respawnFlags`, a repeated `respawnFlags` key, or a
            // token serde_json refuses as one of its elements fails the derive
            // parse; re-read the record without the field rather than spare
            // every tree. A record that fails this too stays unreadable.
            Err(_) => match serde_json::from_slice::<JobCore>(&record) {
                Ok(core) => JobState {
                    provider_env: core.provider_env,
                    state: core.state,
                    respawn_flags: RespawnFlags::Unknown,
                    session_id: core.session_id,
                },
                Err(_) => return Err(job_dir.clone()),
            },
        };
        let Some(config_dir) = state.provider_env.and_then(|env| env.claude_config_dir) else {
            // A plain `claude --bg` on `~/.claude` names no tree, only its
            // conversation.
            if !state.session_id.is_empty() {
                sets.global_sessions.insert(state.session_id);
            }
            continue;
        };
        let tree_id = match crate::canonical::identity(&config_dir) {
            Ok(id) => id,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(job_dir.clone()),
        };
        // A tree-local record names only its own tree; anything else is a
        // stale copy of the old global store.
        if owner.is_some_and(|owner| tree_id.as_path() != owner) {
            continue;
        }
        let finished = FINISHED_STATES.contains(&state.state.as_str());
        if isolated && finished {
            continue;
        }
        sets.named.insert(tree_id.clone());
        if let Some(job_id) = job_dir.file_name().and_then(|name| name.to_str()) {
            sets.named_by_job
                .entry(tree_id.clone())
                .or_default()
                .insert(job_id.to_owned());
        }
        if !finished {
            sets.unfinished.insert(tree_id.clone());
        }
        if !state.session_id.is_empty() {
            sets.tree_by_session
                .insert(state.session_id, tree_id.clone());
        }
        match state.respawn_flags {
            RespawnFlags::Absent => {}
            RespawnFlags::Named(values) => {
                for value in values {
                    // Inline JSON names no file; a value that cannot
                    // resolve as a path scopes the fallback to this
                    // job's own tree, never the whole store.
                    if crate::cc_exempt::is_inline_settings(&value) {
                        continue;
                    }
                    match crate::canonical::identity(&value) {
                        Ok(settings_id) => {
                            sets.named_settings.insert(settings_id);
                        }
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(_) => {
                            sets.unknown_flags_trees.insert(tree_id.clone());
                        }
                    }
                }
            }
            RespawnFlags::Unknown => {
                sets.unknown_flags_trees.insert(tree_id);
            }
        }
    }
    Ok(())
}

/// Whether a record-less job dir is a removed job's leftover: its entries are a
/// NON-EMPTY subset of {`tmp` = an empty directory, `exit-cause` = a regular
/// file}. A creation never makes that shape — an empty dir and a
/// `state.json.tmp.*` staged record are mid-create, and a `tmp/` holding
/// anything is not the leftover — so only a supervisor that outlived `claude rm`
/// does. A list that cannot be read is `Err`, which the caller reads as
/// unreadable (fail closed).
fn removed_jobs_leftover(job_dir: &Path) -> io::Result<bool> {
    let mut seen = false;
    for entry in std::fs::read_dir(job_dir)? {
        let entry = entry?;
        seen = true;
        let name = entry.file_name();
        if name == "tmp" {
            if !entry.file_type()?.is_dir() {
                return Ok(false);
            }
            if std::fs::read_dir(entry.path())?.next().is_some() {
                return Ok(false);
            }
        } else if name == "exit-cause" {
            if !entry.file_type()?.is_file() {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }
    Ok(seen)
}
