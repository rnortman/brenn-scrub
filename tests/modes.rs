//! End-to-end behavior of the modes whose *contract* is consumed by something
//! other than a human reading stderr: `range`'s warn-only rollout switch,
//! `tree`'s captured stdout, `staged`'s reliance on the git environment a
//! hook hands it, and `history`'s reach past the tip tree.
//!
//! The first two were covered only at the argument-parsing layer, where an
//! inverted or dropped branch downstream leaves every test green. These drive
//! the real binary against a real repo instead.
//!
//! Skipped with a message when the pinned gitleaks is absent, matching
//! `rules.rs`.

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use brenn_git_fixture::{git, init_repo, try_git};
use common::{gitleaks_available, scrub_bin};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A token the built-in rules catch, assembled at runtime so this file never
/// contains a literal the gate would flag.
fn canary() -> String {
    format!(
        "let gh = \"{}_{}\";\n",
        "ghp", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    )
}

fn write_file(repo: &Path, rel: &str, body: &str) {
    let path = repo.join(rel);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, body).expect("write fixture");
}

/// A repo carrying the real public config, so these exercise the shipped rules.
fn repo_with(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let p = dir.path();
    init_repo(p);
    std::fs::copy(repo_root().join(".gitleaks.toml"), p.join(".gitleaks.toml"))
        .expect("copy public config");
    for (rel, body) in files {
        write_file(p, rel, body);
    }
    git(p, &["add", "-A"]);
    git(p, &["commit", "-qm", "fixture"]);
    dir
}

struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_in(repo: &Path, args: &[&str], stdin: &str) -> Output {
    run_in_env(repo, args, stdin, &[])
}

fn run_in_env(repo: &Path, args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
    run_in_full(repo, args, stdin, env, None)
}

/// `run_in_env`, with `path_prefix` searched first for the programs the
/// binary under test and its gitleaks spawn.
fn run_in_full(
    repo: &Path,
    args: &[&str],
    stdin: &str,
    env: &[(&str, &str)],
    path_prefix: Option<&Path>,
) -> Output {
    let mut cmd = Command::new(scrub_bin());
    cmd.current_dir(repo)
        // The overlay is a local convention; these assertions are about the
        // public rules only, so a machine's local overlay must not leak in.
        .env_remove("BRENN_SCRUB_DENYLIST")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // The fixture repo is the whole subject here; a `GIT_DIR` from a hook
    // environment would point the spawned binary — and the `gitleaks` it
    // spawns — at some other repo entirely.
    brenn_git_fixture::hermetic(&mut cmd);
    common::prepend_path(&mut cmd, path_prefix);
    // The case's own variables are a deliberate injection and must survive
    // the `GIT_*` strip above, which would otherwise erase `GIT_TRACE`.
    cmd.envs(env.iter().copied());
    let mut child = cmd.spawn().expect("failed to spawn brenn-scrub");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    Output {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn head(repo: &Path) -> String {
    git(repo, &["rev-parse", "HEAD"]).trim().to_string()
}

/// Pre-push stdin for pushing `main` over a remote that holds `remote_sha`.
fn update_line(repo: &Path, remote_sha: &str) -> String {
    format!(
        "refs/heads/main {} refs/heads/main {remote_sha}\n",
        head(repo)
    )
}

/// Pre-push stdin for pushing `main` as a ref the remote does not have.
fn new_ref_line(repo: &Path) -> String {
    update_line(repo, &"0".repeat(40))
}

/// Pre-push ships warn-only and later flips to enforcing by deleting the flag.
/// Only the flag's *parsing* was asserted, so an inverted branch could leave
/// the push gate off with nothing red -- or block every push before the tree
/// is green.
#[test]
fn warn_only_reports_the_same_findings_it_would_have_blocked_on() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", &canary())]);
    let stdin = new_ref_line(dir.path());

    let warned = run_in(dir.path(), &["range", "--warn-only"], &stdin);
    assert_eq!(
        warned.code,
        Some(0),
        "warn-only must let the push through; stderr: {}",
        warned.stderr
    );
    assert!(
        warned.stderr.contains("would fail the scrub gate"),
        "the findings must still be visible: {}",
        warned.stderr
    );

    let blocked = run_in(dir.path(), &["range"], &stdin);
    assert_eq!(
        blocked.code,
        Some(1),
        "the same findings must block without the flag; stderr: {}",
        blocked.stderr
    );
    assert!(
        blocked.stderr.contains("blocked this push"),
        "{}",
        blocked.stderr
    );
}

#[test]
fn a_clean_repo_passes_range_either_way() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let stdin = new_ref_line(dir.path());
    for args in [&["range"][..], &["range", "--warn-only"][..]] {
        let out = run_in(dir.path(), args, &stdin);
        assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    }
}

/// The audit a repository with private history is published on: a string
/// committed and later removed is gone from the tree, and `tree` rightly
/// passes, so only a scan of every commit can find it.
#[test]
fn history_finds_what_a_later_commit_removed_and_tree_does_not() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", &canary())]);
    let p = dir.path();
    let leaked = head(p);
    write_file(p, "src/a.rs", "let user = \"alice\";\n");
    git(p, &["commit", "-qam", "remove it"]);

    let tree = run_in(p, &["tree"], "");
    assert_eq!(tree.code, Some(0), "stderr: {}", tree.stderr);

    let history = run_in(p, &["history"], "");
    assert_eq!(history.code, Some(1), "stderr: {}", history.stderr);
    assert!(
        history
            .stderr
            .contains("found matches in the commit history"),
        "{}",
        history.stderr
    );
    assert!(
        history.stderr.contains(&format!("commit {leaked}")),
        "the finding must name the commit that added the string: {}",
        history.stderr
    );
    assert!(
        history.stderr.contains("rewrite the history")
            && !history.stderr.contains("Rewrite the string"),
        "a committed string is not fixed by editing the tree: {}",
        history.stderr
    );
}

/// A commit only another ref reaches is history too: the scan covers every
/// ref, not just the checked-out branch.
#[test]
fn history_scans_commits_only_another_branch_reaches() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let p = dir.path();
    git(p, &["checkout", "-qb", "side"]);
    write_file(p, "src/b.rs", &canary());
    git(p, &["add", "-A"]);
    git(p, &["commit", "-qm", "side"]);
    let side = git(p, &["rev-parse", "side"]).trim().to_string();
    git(p, &["checkout", "-q", "main"]);

    let history = run_in(p, &["history"], "");
    assert_eq!(history.code, Some(1), "stderr: {}", history.stderr);
    assert!(
        history
            .stderr
            .contains("found matches in the commit history")
            && history.stderr.contains(&format!("commit {side}")),
        "the finding must come from the side branch's commit: {}",
        history.stderr
    );
}

/// A merge's own change -- here a conflict resolution, the only commit that
/// ever carries the string -- is history too, though `git log -p` shows a
/// merge no diff.
#[test]
fn history_scans_what_only_a_merge_resolution_introduces() {
    if !gitleaks_available() {
        return;
    }
    let (dir, _, merge) = repo_with_conflicted_merge(&canary(), "merge");
    let p = dir.path();
    write_file(p, "src/b.rs", "let both = 1;\n");
    git(p, &["commit", "-qam", "remove it"]);

    let history = run_in(p, &["history"], "");
    assert_eq!(history.code, Some(1), "stderr: {}", history.stderr);
    assert!(
        history.stderr.contains(&format!("commit {merge}")),
        "the finding must name the merge: {}",
        history.stderr
    );
}

/// The diff-only rules are part of the audit: `tree` filters them out, and
/// `history` must not. Its remedy is accepting or rewriting, so the
/// fix-forward note the gate appends for this rule is left out.
#[test]
fn history_reports_diff_only_rules() {
    if !gitleaks_available() {
        return;
    }
    let section = format!("// see design {}3\n", '\u{a7}');
    let dir = repo_with(&[("src/a.rs", &section)]);
    let p = dir.path();

    let history = run_in(p, &["history"], "");
    assert_eq!(history.code, Some(1), "stderr: {}", history.stderr);
    assert!(
        history.stderr.contains("[ephemeral-reference]"),
        "{}",
        history.stderr
    );
    assert!(
        !history.stderr.contains("Cite stable published specs"),
        "{}",
        history.stderr
    );
}

/// `history` reads nothing: piped text is neither a protocol nor a refusal,
/// and a clean history says so.
#[test]
fn history_ignores_stdin_and_reports_a_clean_history() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let stdin = format!("{}{}", new_ref_line(dir.path()), canary());
    let out = run_in(dir.path(), &["history"], &stdin);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("brenn-scrub history: clean"),
        "{}",
        out.stderr
    );
}

fn tree_json(out: &Output) -> serde_json::Value {
    serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("tree stdout must be JSON ({e}): {:?}", out.stdout))
}

/// Tree stdout is captured as the burndown worklist, and it self-documents its
/// scope so the artifact can never be read as covering more than it scanned.
/// A field rename or serializer change would silently break that.
#[test]
fn tree_stdout_carries_findings_and_an_empty_exclusion_list_by_default() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", &canary())]);
    let out = run_in(dir.path(), &["tree"], "");
    let json = tree_json(&out);

    assert_eq!(
        json["excluded"],
        serde_json::json!([]),
        "a bare scan excludes nothing"
    );
    let findings = json["findings"].as_array().expect("findings is an array");
    assert_eq!(findings.len(), 1, "{:?}", out.stdout);
    assert_eq!(findings[0]["File"], "src/a.rs");
    assert_eq!(out.code, Some(1), "findings must fail the scan");
}

/// Exclusion has to drop files *before* the mirror. Moving or dropping the
/// partition call would scan excluded content anyway, which surfaces as a
/// confusing red rather than as a failing test.
#[test]
fn an_excluded_prefix_is_neither_scanned_nor_counted() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[
        ("docs/adr/leak.rs", &canary()),
        ("src/clean.rs", "let user = \"alice\";\n"),
    ]);

    let out = run_in(dir.path(), &["tree", "--exclude", "docs/adr"], "");
    let json = tree_json(&out);
    assert_eq!(
        json["excluded"],
        serde_json::json!(["docs/adr"]),
        "the scope must be recorded verbatim"
    );
    assert_eq!(
        json["findings"].as_array().expect("array").len(),
        0,
        "excluded content must not be scanned: {:?}",
        out.stdout
    );
    assert_eq!(out.code, Some(0));
    assert!(
        out.stderr.contains("EXCLUDED: docs/adr"),
        "exclusion must be loud: {}",
        out.stderr
    );

    // Without the flag the same repo is red -- so the assertions above cannot
    // be passing merely because the scan found nothing anywhere.
    let bare = run_in(dir.path(), &["tree"], "");
    assert_eq!(bare.code, Some(1), "stderr: {}", bare.stderr);
    assert_eq!(
        tree_json(&bare)["findings"]
            .as_array()
            .expect("array")
            .len(),
        1
    );
}

/// `staged` runs as a pre-commit hook, and a hook is exactly where git exports
/// `GIT_DIR` and `GIT_INDEX_FILE`. Scrub must scan the index those name -- that
/// is how `git commit --only` and linked-worktree commits get scanned at all --
/// so its production spawns deliberately inherit the environment. Every other
/// harness here strips `GIT_*`, which would let that inheritance rot unnoticed.
///
/// The observable is staged *content*, not the resolved repo root: with
/// `GIT_DIR` set and no `GIT_WORK_TREE`, git treats the cwd as the work tree,
/// so the root follows the cwd while the index comes from `GIT_DIR`.
#[test]
fn staged_mode_scans_the_index_named_by_the_hook_environment() {
    if !gitleaks_available() {
        return;
    }
    let fixture = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    write_file(fixture.path(), "src/planted.rs", &canary());
    git(fixture.path(), &["add", "-A"]);

    // Somewhere else entirely: not a git repo, carrying only the public rules
    // so config resolution has something to load once the root lands here.
    let elsewhere = tempfile::tempdir().expect("temp dir");
    std::fs::copy(
        repo_root().join(".gitleaks.toml"),
        elsewhere.path().join(".gitleaks.toml"),
    )
    .expect("copy public config");

    // Hermetic first, then one explicit `GIT_DIR`: the contract under test is
    // that the environment passed to scrub overrides its cwd, and stripping
    // ambient `GIT_*` first means only this test's variable can decide that.
    let mut cmd = Command::new(scrub_bin());
    brenn_git_fixture::hermetic(&mut cmd);
    common::prepend_path(&mut cmd, None);
    cmd.current_dir(elsewhere.path())
        .env_remove("BRENN_SCRUB_DENYLIST")
        .env("GIT_DIR", fixture.path().join(".git"))
        .arg("staged")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().expect("failed to spawn brenn-scrub");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("blocked this commit"),
        "the planted finding must block: {stderr}"
    );
    assert!(
        stderr.contains("src/planted.rs"),
        "the finding must be attributed to the staged path: {stderr}"
    );
}

/// A tracked path absent from the worktree used to be skipped silently, which
/// reads as a narrower scan reported as a full green. A staged deletion is the
/// one legitimate case and is announced.
#[test]
fn a_staged_deletion_is_skipped_out_loud_and_does_not_fail_the_scan() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[
        ("src/a.rs", "let user = \"alice\";\n"),
        ("src/gone.rs", "let peer = \"bob\";\n"),
    ]);
    std::fs::remove_file(dir.path().join("src/gone.rs")).expect("remove");

    let out = run_in(dir.path(), &["tree"], "");
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("SKIPPED: src/gone.rs"),
        "an unmirrored tracked path must be named: {}",
        out.stderr
    );
}

/// The commit id a fixture submodule is pinned at. Nothing dereferences it, so
/// no object has to exist: git records a gitlink's id without resolving it,
/// which is what lets these fixtures stay hermetic and network-free.
const SUBMODULE_PIN: &str = "0123456789abcdef0123456789abcdef01234567";

/// Add a tracked gitlink at `rel`, the way a `git submodule add` would leave
/// the index, without a submodule repository behind it.
fn add_gitlink(repo: &Path, rel: &str) {
    git(
        repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{SUBMODULE_PIN},{rel}"),
        ],
    );
    git(repo, &["commit", "-qm", "gitlink"]);
}

/// An overlay whose one rule matches the fixture's pointer *line*, so a scan
/// that reads the pointer as the text git records reports a finding, and one
/// that skips it -- or renders it differently from a diff -- does not.
fn overlay_matching_the_pin(dir: &Path) -> PathBuf {
    let path = dir.join("overlay.toml");
    std::fs::write(
        &path,
        format!(
            "[[rules]]\nid = \"fixture-submodule-pin\"\n\
             description = \"fixture rule matching a submodule pointer\"\n\
             regex = '''Subproject commit {SUBMODULE_PIN}'''\n"
        ),
    )
    .expect("write overlay");
    path
}

/// The worktree states a submodule can legitimately be in. Typed rather than
/// stringly, so a label and the fixture it selects cannot drift apart: a
/// misspelled arm would silently run one state twice while every failure
/// message still named the other.
#[derive(Debug, Clone, Copy)]
enum WorktreeState {
    Absent,
    Empty,
    Populated,
}

/// Put `path` into `state` and assert it really is in it -- the setup is what
/// the case is about, so an assertion on the fixture belongs with it.
fn set_up_worktree_state(path: &Path, state: WorktreeState) {
    match state {
        WorktreeState::Absent => {
            assert!(!path.exists(), "the absent case must have no path at all");
        }
        WorktreeState::Empty => {
            std::fs::create_dir_all(path).expect("mkdir");
            assert!(path.is_dir(), "the empty case must be a directory");
            assert_eq!(
                std::fs::read_dir(path).expect("read_dir").count(),
                0,
                "the empty case must be an empty directory"
            );
        }
        WorktreeState::Populated => {
            std::fs::create_dir_all(path).expect("mkdir");
            std::fs::write(path.join("upstream.rs"), "let user = \"bob\";\n").expect("write");
            // Untracked, inside the checkout, and matching a built-in rule: the
            // one thing that separates "the pointer was scanned" from "the
            // submodule's whole tree was swept under our rules". Descending is
            // rejected by design -- it would run the operator's private overlay
            // across third-party code -- and only an assertion keeps a later
            // widening of the gitlink arm from doing it unnoticed.
            std::fs::write(path.join("leak.rs"), canary()).expect("write");
            assert!(
                path.join("upstream.rs").exists() && path.join("leak.rs").exists(),
                "the populated case must have a checkout in it"
            );
        }
    }
}

/// All three worktree states a submodule can be in (absent, empty directory,
/// populated checkout) are legitimate, so none of them may decide anything —
/// only the index pointer matters.
#[test]
fn a_tracked_submodule_is_scanned_as_its_pointer_in_every_worktree_state() {
    if !gitleaks_available() {
        return;
    }
    for state in [
        WorktreeState::Absent,
        WorktreeState::Empty,
        WorktreeState::Populated,
    ] {
        let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
        add_gitlink(dir.path(), "vendor/thing");
        let path = dir.path().join("vendor/thing");
        set_up_worktree_state(&path, state);
        let state = format!("{state:?}");

        let out = run_in(dir.path(), &["tree"], "");
        assert_eq!(
            out.code,
            Some(0),
            "a clean tree with a submodule must pass ({state}); stderr: {}",
            out.stderr
        );
        assert_eq!(
            tree_json(&out)["findings"].as_array().expect("array").len(),
            0,
            "only the pointer is scanned; nothing inside the checkout is ({state}): {:?}",
            out.stdout
        );
        assert!(
            out.stderr.contains("SUBMODULE: vendor/thing"),
            "the submodule must be named on stderr ({state}): {}",
            out.stderr
        );
        assert!(
            out.stderr.contains("separate repository"),
            "the announcement must say the contents are out of scope ({state}): {}",
            out.stderr
        );
        assert!(
            !out.stderr.contains("SKIPPED: vendor/thing"),
            "a submodule pointer is scanned, not skipped ({state}): {}",
            out.stderr
        );
    }
}

/// The announcement alone would be satisfied by skipping the entry with a
/// friendlier message. A rule matching the pointer id has to fire, which is
/// only possible if the pointer text reached the scan.
#[test]
fn a_rule_matching_the_pointer_reports_a_finding_against_the_submodule_path() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    add_gitlink(dir.path(), "vendor/thing");
    let overlay = overlay_matching_the_pin(dir.path());

    let out = run_in_env(
        dir.path(),
        &["tree"],
        "",
        &[("BRENN_SCRUB_DENYLIST", overlay.to_str().expect("utf-8"))],
    );
    assert_eq!(
        out.code,
        Some(1),
        "a match must fail the scan: {:?}",
        out.stdout
    );
    let json = tree_json(&out);
    let findings = json["findings"].as_array().expect("findings is an array");
    assert_eq!(findings.len(), 1, "{:?}", out.stdout);
    assert_eq!(
        findings[0]["File"], "vendor/thing",
        "the finding must name the submodule path"
    );
    assert_eq!(findings[0]["RuleID"], "fixture-submodule-pin");
}

/// A gitlink under an excluded prefix is dropped and counted like any other
/// entry -- not announced, not scanned, and still credited to the prefix so the
/// inert-exclusion check does not misfire.
#[test]
fn an_excluded_submodule_is_dropped_and_counted_like_a_file() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    add_gitlink(dir.path(), "vendor/thing");
    let overlay = overlay_matching_the_pin(dir.path());
    let env = [("BRENN_SCRUB_DENYLIST", overlay.to_str().expect("utf-8"))];

    let out = run_in_env(dir.path(), &["tree", "--exclude", "vendor"], "", &env);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert_eq!(
        tree_json(&out)["findings"].as_array().expect("array").len(),
        0,
        "the excluded pointer must not be scanned: {:?}",
        out.stdout
    );
    assert!(
        out.stderr
            .contains("EXCLUDED: vendor (1 files not scanned)"),
        "the gitlink must be counted against the prefix: {}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("SUBMODULE:"),
        "an excluded entry is not announced as scanned: {}",
        out.stderr
    );
}

/// The gitlink arm is an exemption from the stat loop's refusal, and the
/// refusal is what holds "no tracked entry unscanned under a green". Widening
/// the arm to tolerate directories -- the plausible next edit, since a
/// populated submodule is one -- would turn every tracked non-file into a
/// silent skip inside a run still printing `clean`.
#[test]
fn a_tracked_path_that_is_neither_file_nor_symlink_still_refuses() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[
        ("src/a.rs", "let user = \"alice\";\n"),
        ("weird", "tracked as a regular file\n"),
    ]);
    // git cannot add a fifo or a directory, so the route to a tracked non-file
    // is to replace one in the worktree after the fact.
    let weird = dir.path().join("weird");
    std::fs::remove_file(&weird).expect("remove");
    std::fs::create_dir(&weird).expect("mkdir");

    let out = run_in(dir.path(), &["tree"], "");
    assert_eq!(
        out.code,
        Some(101),
        "an unmirrorable tracked path must abort the scan: {:?} / {}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stderr.contains("neither a regular file nor a symlink"),
        "the refusal must name what it will not scan: {}",
        out.stderr
    );
}

/// A path in an unresolved merge is three index entries, one per side. Without
/// the stage-zero guard, all three arrive: the first mirrors the worktree file
/// as a hardlink, the second falls through to `fs::copy` onto that same inode
/// and truncates the operator's conflicted file to zero, and the scan reports
/// the empty result as clean. Both halves are asserted here -- the content
/// survives, and no green is printed over it.
#[test]
fn an_unresolved_merge_refuses_instead_of_scanning_or_truncating() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let p = dir.path();
    git(p, &["checkout", "-q", "-b", "other"]);
    write_file(p, "src/a.rs", &format!("{}// other\n", canary()));
    git(p, &["commit", "-qam", "other side"]);
    git(p, &["checkout", "-q", "main"]);
    write_file(p, "src/a.rs", "let user = \"carol\";\n");
    git(p, &["commit", "-qam", "main side"]);
    assert!(
        !try_git(p, &["merge", "other"]),
        "the fixture merge must conflict"
    );

    let conflicted = std::fs::read_to_string(p.join("src/a.rs")).expect("read");
    assert!(
        conflicted.contains("<<<<<<<") && conflicted.contains(&canary()),
        "the fixture must leave a real conflict in the worktree: {conflicted:?}"
    );

    let out = run_in(p, &["tree"], "");
    assert_eq!(
        out.code,
        Some(101),
        "a mid-conflict tree must not be scanned: {:?} / {}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stderr.contains("unmerged entries"),
        "the refusal must name the unresolved merge: {}",
        out.stderr
    );
    assert_eq!(
        std::fs::read_to_string(p.join("src/a.rs")).expect("read"),
        conflicted,
        "the scan must not touch the conflicted worktree file"
    );
}

/// A second token the built-in rules catch, distinct from `canary()`.
fn second_canary() -> String {
    format!(
        "let gh2 = \"{}_{}\";\n",
        "ghp", "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
    )
}

/// Commit A (returned as `base`), then B adding `src/old.rs` with the canary,
/// then C removing it. Also returns B's blob id for `src/old.rs`. The canary
/// is absent from the tip, so only the commit walk can find it, and the tip
/// tree does not need the blob, so `git archive` still works once it is gone.
fn repo_with_removed_canary() -> (tempfile::TempDir, String, String) {
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let p = dir.path();
    let base = head(p);
    write_file(p, "src/old.rs", &canary());
    git(p, &["add", "src/old.rs"]);
    git(p, &["commit", "-qm", "add old"]);
    let blob = git(p, &["rev-parse", "HEAD:src/old.rs"]).trim().to_string();
    git(p, &["rm", "-q", "src/old.rs"]);
    git(p, &["commit", "-qm", "remove old"]);
    (dir, base, blob)
}

/// Delete `blob`'s loose object, so `git log -p` dies when it reaches it.
fn damage_blob(repo: &Path, blob: &str) {
    let counts = git(repo, &["count-objects", "-v"]);
    assert!(
        counts.lines().any(|l| l == "in-pack: 0"),
        "fixture objects must be loose: {counts}"
    );
    let path = repo.join(".git/objects").join(&blob[..2]).join(&blob[2..]);
    assert!(path.is_file(), "missing loose object {}", path.display());
    std::fs::remove_file(path).expect("remove loose object");
}

fn assert_blocked_push(out: &Output) {
    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert!(out.stderr.contains("blocked this push"), "{}", out.stderr);
    assert!(out.stderr.contains("src/old.rs"), "{}", out.stderr);
}

fn assert_history_findings(out: &Output) {
    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("found matches in the commit history"),
        "{}",
        out.stderr
    );
}

fn assert_incomplete(out: &Output) {
    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert!(out.stderr.contains("did not complete"), "{}", out.stderr);
}

const TRACE: &[(&str, &str)] = &[("GIT_TRACE", "1")];

/// gitleaks exits 0 with an empty report when its `git log` writes a trace
/// line to stderr; the push must be refused, not passed as clean.
#[test]
fn range_refuses_when_git_traces_instead_of_passing_an_empty_walk() {
    if !gitleaks_available() {
        return;
    }
    let (dir, base, _) = repo_with_removed_canary();
    let p = dir.path();
    let stdin = update_line(p, &base);
    assert_blocked_push(&run_in(p, &["range"], &stdin));

    let traced = run_in_env(p, &["range"], &stdin, TRACE);
    assert_incomplete(&traced);
    assert!(
        traced.stderr.contains("trace: built-in: git log"),
        "{}",
        traced.stderr
    );
    assert!(
        !traced.stderr.contains("blocked this push"),
        "{}",
        traced.stderr
    );
}

#[test]
fn history_refuses_when_git_traces() {
    if !gitleaks_available() {
        return;
    }
    let (dir, _, _) = repo_with_removed_canary();
    let p = dir.path();
    assert_history_findings(&run_in(p, &["history"], ""));

    let traced = run_in_env(p, &["history"], "", TRACE);
    assert_incomplete(&traced);
    assert!(
        traced.stderr.contains("trace: built-in: git log"),
        "{}",
        traced.stderr
    );
}

/// A historical blob missing from the object store kills gitleaks' `git log`
/// part way; gitleaks still exits 0, and the push must be refused.
#[test]
fn range_refuses_when_a_historical_blob_is_unreadable() {
    if !gitleaks_available() {
        return;
    }
    let (dir, base, blob) = repo_with_removed_canary();
    let p = dir.path();
    let stdin = update_line(p, &base);
    assert_blocked_push(&run_in(p, &["range"], &stdin));

    damage_blob(p, &blob);
    let out = run_in(p, &["range"], &stdin);
    assert_incomplete(&out);
    assert!(
        out.stderr.contains(&format!("unable to read {blob}")),
        "{}",
        out.stderr
    );
}

#[test]
fn history_refuses_when_a_historical_blob_is_unreadable() {
    if !gitleaks_available() {
        return;
    }
    let (dir, _, blob) = repo_with_removed_canary();
    let p = dir.path();
    assert_history_findings(&run_in(p, &["history"], ""));

    damage_blob(p, &blob);
    let out = run_in(p, &["history"], "");
    assert_incomplete(&out);
    assert!(
        out.stderr.contains(&format!("unable to read {blob}")),
        "{}",
        out.stderr
    );
}

/// `--warn-only` lifts findings, never a walk that did not complete.
#[test]
fn warn_only_does_not_lift_an_incomplete_scan() {
    if !gitleaks_available() {
        return;
    }
    let (dir, base, blob) = repo_with_removed_canary();
    let p = dir.path();
    let stdin = update_line(p, &base);

    let warned = run_in(p, &["range", "--warn-only"], &stdin);
    assert_eq!(warned.code, Some(0), "stderr: {}", warned.stderr);
    assert!(
        warned.stderr.contains("would fail the scrub gate"),
        "{}",
        warned.stderr
    );

    damage_blob(p, &blob);
    let out = run_in(p, &["range", "--warn-only"], &stdin);
    assert_incomplete(&out);
    assert!(
        !out.stderr.contains("would fail the scrub gate"),
        "{}",
        out.stderr
    );
}

/// Re-validates against the real engine that gitleaks still signals a dying
/// `git log` through stderr while newer commits with findings are in flight.
/// Whether the newer finding reaches the report is non-deterministic on the
/// pinned engine, so only the refusal is asserted; that a non-empty report
/// does not rescue an incomplete scan is pinned by the unit test
/// `a_non_empty_report_does_not_rescue_an_incomplete_scan` in
/// `src/gitleaks.rs`.
#[test]
fn an_incomplete_walk_refuses_with_findings_in_newer_commits() {
    if !gitleaks_available() {
        return;
    }
    let (dir, base, blob) = repo_with_removed_canary();
    let p = dir.path();
    write_file(p, "src/new.rs", &second_canary());
    git(p, &["add", "src/new.rs"]);
    git(p, &["commit", "-qm", "add new"]);
    git(p, &["rm", "-q", "src/new.rs"]);
    git(p, &["commit", "-qm", "remove new"]);
    let stdin = update_line(p, &base);
    assert_blocked_push(&run_in(p, &["range"], &stdin));
    assert_history_findings(&run_in(p, &["history"], ""));

    damage_blob(p, &blob);
    assert_incomplete(&run_in(p, &["range"], &stdin));
    assert_incomplete(&run_in(p, &["history"], ""));
}

/// A ref naming no object fails `history`'s `git log -n0` probe. The refusal
/// quotes git rather than blaming the git version, and comes from the probe,
/// not from the scan's incomplete-walk check.
#[test]
fn history_probe_refuses_a_broken_ref_and_quotes_git() {
    if !gitleaks_available() {
        return;
    }
    let (dir, _, _) = repo_with_removed_canary();
    let p = dir.path();
    assert_history_findings(&run_in(p, &["history"], ""));

    write_file(
        p,
        ".git/refs/heads/broken",
        &format!("{}\n", "1".repeat(40)),
    );
    let out = run_in(p, &["history"], "");
    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert!(out.stderr.contains("git log -n0"), "{}", out.stderr);
    assert!(
        out.stderr.contains("bad object refs/heads/broken"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("did not complete"), "{}", out.stderr);
}

/// A key the built-in `aws-access-token` rule catches, for commit messages.
/// Assembled at runtime so this file never contains a literal the gate would
/// flag.
fn message_canary() -> String {
    format!("{}{}", "AKIA", "Z7QWERTY5UIOXPLK")
}

/// A clean-diff commit on top of a clean repo whose message is `message`.
/// Returns the repo, the base sha and the commit's sha.
fn repo_with_message(message: &str) -> (tempfile::TempDir, String, String) {
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let p = dir.path();
    let base = head(p);
    write_file(p, "src/b.rs", "let peer = \"bob\";\n");
    git(p, &["add", "src/b.rs"]);
    git(p, &["commit", "-qm", message]);
    let commit = head(p);
    (dir, base, commit)
}

fn message_location(sha: &str, line: u32) -> String {
    format!("commit {sha}, message line {line}")
}

/// A merge that must conflict: `main` and `side` both add `src/b.rs`, and
/// the merge resolves it to `resolution`, committed with `merge_message`.
/// Returns the repo, `main` before the merge, and the merge sha.
fn repo_with_conflicted_merge(
    resolution: &str,
    merge_message: &str,
) -> (tempfile::TempDir, String, String) {
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let p = dir.path();
    git(p, &["checkout", "-qb", "side"]);
    write_file(p, "src/b.rs", "let side = 1;\n");
    git(p, &["add", "-A"]);
    git(p, &["commit", "-qm", "side"]);
    git(p, &["checkout", "-q", "main"]);
    write_file(p, "src/b.rs", "let main = 1;\n");
    git(p, &["add", "-A"]);
    git(p, &["commit", "-qm", "main"]);
    let before = head(p);
    assert!(
        !try_git(p, &["merge", "-q", "side"]),
        "the fixture needs a conflict"
    );
    write_file(p, "src/b.rs", resolution);
    git(p, &["add", "-A"]);
    git(p, &["commit", "-qm", merge_message]);
    let merge = head(p);
    (dir, before, merge)
}

/// A pushed merge's own resolution is diffed: the string exists only in the
/// merge and is gone again at the tip, so neither the plain commit walk nor
/// the tip tree could see it.
#[test]
fn range_scans_what_only_a_merge_resolution_introduces() {
    if !gitleaks_available() {
        return;
    }
    let (dir, before, merge) = repo_with_conflicted_merge(&canary(), "merge");
    let p = dir.path();
    write_file(p, "src/b.rs", "let both = 1;\n");
    git(p, &["commit", "-qam", "remove it"]);

    let out = run_in(p, &["range"], &update_line(p, &before));
    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert!(out.stderr.contains("blocked this push"), "{}", out.stderr);
    assert!(
        out.stderr.contains(&format!("(commit {merge})")),
        "the finding must name the merge: {}",
        out.stderr
    );
}

/// A push through an object that does not exist fails `range`'s probe. The
/// refusal quotes git and names the version floor as the usual cause, and it
/// comes from the probe, not from the scan's incomplete-walk check -- under
/// `--warn-only` too.
#[test]
fn range_probe_refuses_a_broken_ref_and_quotes_git() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let p = dir.path();
    let missing = "1".repeat(40);
    write_file(p, ".git/refs/heads/broken", &format!("{missing}\n"));
    let stdin = format!(
        "refs/heads/broken {missing} refs/heads/broken {}\n",
        "0".repeat(40)
    );
    for args in [&["range"][..], &["range", "--warn-only"][..]] {
        let out = run_in(p, args, &stdin);
        assert_eq!(out.code, Some(1), "{args:?} stderr: {}", out.stderr);
        assert!(out.stderr.contains("git log -n0"), "{}", out.stderr);
        assert!(out.stderr.contains("bad object"), "{}", out.stderr);
        assert!(out.stderr.contains("2.36"), "{}", out.stderr);
        assert!(!out.stderr.contains("did not complete"), "{}", out.stderr);
        assert!(
            !out.stderr.contains("would fail the scrub gate"),
            "{}",
            out.stderr
        );
    }
}

/// A deletion has nothing to scan, so it must not reach the probe: a ref that
/// would fail any probe reaching every ref is in the repository, and the
/// push still passes without a word from git.
#[test]
fn a_deletion_only_push_needs_no_probe() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let p = dir.path();
    write_file(
        p,
        ".git/refs/heads/broken",
        &format!("{}\n", "1".repeat(40)),
    );
    let stdin = format!("(delete) {} refs/heads/old {}\n", "0".repeat(40), head(p));
    let out = run_in(p, &["range"], &stdin);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(!out.stderr.contains("git log -n0"), "{}", out.stderr);
}

/// A commit message is pushed with the commit: a key in it blocks the push
/// with the reword remedy, not the fix-forward ladder, and `--warn-only`
/// reports it and lets the push through.
#[test]
fn range_blocks_on_a_message_finding_and_warn_only_reports_it() {
    if !gitleaks_available() {
        return;
    }
    let (dir, base, commit) = repo_with_message(&format!("note {}", message_canary()));
    let p = dir.path();
    let stdin = update_line(p, &base);

    let blocked = run_in(p, &["range"], &stdin);
    assert_eq!(blocked.code, Some(1), "stderr: {}", blocked.stderr);
    assert!(
        blocked.stderr.contains("blocked this push"),
        "{}",
        blocked.stderr
    );
    assert!(
        blocked.stderr.contains(&message_location(&commit, 1)),
        "{}",
        blocked.stderr
    );
    assert!(
        blocked.stderr.contains("For a finding in a commit message"),
        "{}",
        blocked.stderr
    );
    assert!(
        !blocked.stderr.contains("How to resolve"),
        "a message is not fixed forward: {}",
        blocked.stderr
    );

    let warned = run_in(p, &["range", "--warn-only"], &stdin);
    assert_eq!(warned.code, Some(0), "stderr: {}", warned.stderr);
    assert!(
        warned.stderr.contains("would fail the scrub gate")
            && warned.stderr.contains(&message_location(&commit, 1)),
        "{}",
        warned.stderr
    );
}

#[test]
fn history_finds_a_message_finding_and_names_the_commit() {
    if !gitleaks_available() {
        return;
    }
    let (dir, _, commit) = repo_with_message(&format!("note {}", message_canary()));
    let out = run_in(dir.path(), &["history"], "");
    assert_history_findings(&out);
    assert!(
        out.stderr.contains(&message_location(&commit, 1)),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("rewrite the history"), "{}", out.stderr);
}

/// Messages get the tree rule set: the diff-only section-symbol rule fires
/// on a message, which has no `.md` path to allowlist it, and is dropped.
#[test]
fn a_section_symbol_in_a_message_is_not_reported() {
    if !gitleaks_available() {
        return;
    }
    let (dir, base, _) = repo_with_message(&format!("subject\n\nsee design {}3", '\u{a7}'));
    let p = dir.path();
    let range = run_in(p, &["range"], &update_line(p, &base));
    assert_eq!(range.code, Some(0), "stderr: {}", range.stderr);
    let history = run_in(p, &["history"], "");
    assert_eq!(history.code, Some(0), "stderr: {}", history.stderr);
}

#[test]
fn gitleaks_allow_in_a_message_line_is_honoured() {
    if !gitleaks_available() {
        return;
    }
    let marked = format!(
        "subject\n\nkey {} {}",
        message_canary(),
        concat!("gitleaks", ":allow")
    );
    let (dir, base, _) = repo_with_message(&marked);
    let p = dir.path();
    let range = run_in(p, &["range"], &update_line(p, &base));
    assert_eq!(range.code, Some(0), "stderr: {}", range.stderr);
    let history = run_in(p, &["history"], "");
    assert_eq!(history.code, Some(0), "stderr: {}", history.stderr);
}

/// An empty message lists as a record with an empty body.
#[test]
fn an_empty_message_is_scanned_clean() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let p = dir.path();
    let base = head(p);
    write_file(p, "src/b.rs", "let peer = \"bob\";\n");
    git(p, &["add", "src/b.rs"]);
    git(p, &["commit", "-q", "--allow-empty-message", "-m", ""]);
    let range = run_in(p, &["range"], &update_line(p, &base));
    assert_eq!(range.code, Some(0), "stderr: {}", range.stderr);
    let history = run_in(p, &["history"], "");
    assert_eq!(history.code, Some(0), "stderr: {}", history.stderr);
}

/// A conflicted merge is where merge diffs would break the message listing's
/// framing; its own message must still be read intact.
#[test]
fn message_walk_framing_survives_a_conflicted_merge() {
    if !gitleaks_available() {
        return;
    }
    let message = format!("merge side\n\nkey {}", message_canary());
    let (dir, before, merge) = repo_with_conflicted_merge("let both = 1;\n", &message);
    let p = dir.path();

    let history = run_in(p, &["history"], "");
    assert_history_findings(&history);
    assert!(
        history.stderr.contains(&message_location(&merge, 3)),
        "{}",
        history.stderr
    );

    let range = run_in(p, &["range"], &update_line(p, &before));
    assert_eq!(range.code, Some(1), "stderr: {}", range.stderr);
    assert!(
        range.stderr.contains(&message_location(&merge, 3)),
        "{}",
        range.stderr
    );
}

/// Two branches pushed at one tip list the same commits; the message is
/// scanned, and reported, once.
#[test]
fn a_message_only_canary_shared_by_two_refs_is_reported_once() {
    if !gitleaks_available() {
        return;
    }
    let (dir, base, commit) = repo_with_message(&format!("note {}", message_canary()));
    let p = dir.path();
    let stdin = format!(
        "refs/heads/main {commit} refs/heads/main {base}\n\
         refs/heads/release {commit} refs/heads/release {base}\n"
    );
    let out = run_in(p, &["range"], &stdin);
    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert_eq!(
        out.stderr.matches(&message_location(&commit, 1)).count(),
        1,
        "{}",
        out.stderr
    );
}

/// Site-local rules reach messages: a line only the overlay matches,
/// written in a message and nowhere else, blocks the push.
#[test]
fn an_overlay_rule_canary_in_a_message_is_caught() {
    if !gitleaks_available() {
        return;
    }
    let message = format!("subject\n\nSubproject commit {SUBMODULE_PIN}");
    let (dir, base, commit) = repo_with_message(&message);
    let p = dir.path();
    let stdin = update_line(p, &base);
    let public_only = run_in(p, &["range"], &stdin);
    assert_eq!(
        public_only.code,
        Some(0),
        "the public rules alone must pass: {}",
        public_only.stderr
    );

    let overlay = overlay_matching_the_pin(p);
    let out = run_in_env(
        p,
        &["range"],
        &stdin,
        &[("BRENN_SCRUB_DENYLIST", overlay.to_str().expect("utf-8"))],
    );
    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("[fixture-submodule-pin]")
            && out.stderr.contains(&message_location(&commit, 3)),
        "{}",
        out.stderr
    );
}

/// The wrapper's message flag is not part of `tree`'s captured JSON.
#[test]
fn tree_stdout_is_unchanged_by_the_finding_field() {
    if !gitleaks_available() {
        return;
    }
    let dir = repo_with(&[("src/a.rs", &canary())]);
    let out = run_in(dir.path(), &["tree"], "");
    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    let json = tree_json(&out);
    let finding = json["findings"][0].as_object().expect("one finding");
    assert!(!finding.contains_key("in_message"), "{:?}", out.stdout);
}

/// A subject that starts with a binary format's magic number (`MZ`, the PE
/// header) would make gitleaks skip a message mirrored from its first byte;
/// the body's key is still found, on the message's own line 3.
#[test]
fn a_message_whose_subject_starts_with_binary_magic_is_scanned() {
    if !gitleaks_available() {
        return;
    }
    let message = format!("MZ-1234: fix login\n\nkey {}", message_canary());
    let (dir, base, commit) = repo_with_message(&message);
    let p = dir.path();

    let range = run_in(p, &["range"], &update_line(p, &base));
    assert_eq!(range.code, Some(1), "stderr: {}", range.stderr);
    assert!(
        range.stderr.contains(&message_location(&commit, 3)),
        "{}",
        range.stderr
    );

    let history = run_in(p, &["history"], "");
    assert_history_findings(&history);
    assert!(
        history.stderr.contains(&message_location(&commit, 3)),
        "{}",
        history.stderr
    );
}

/// `main` stays at a clean commit and `feature` is one commit with
/// `message`, branched from `main` or, when `orphan`, sharing no history
/// with it. Returns the repo and the feature commit's sha.
fn repo_with_feature_message(message: &str, orphan: bool) -> (tempfile::TempDir, String) {
    let dir = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let p = dir.path();
    if orphan {
        git(p, &["checkout", "-q", "--orphan", "feature"]);
    } else {
        git(p, &["checkout", "-qb", "feature"]);
    }
    write_file(p, "src/b.rs", "let peer = \"bob\";\n");
    git(p, &["add", "-A"]);
    git(p, &["commit", "-qm", message]);
    let commit = head(p);
    (dir, commit)
}

fn feature_line(commit: &str, remote_sha: &str) -> String {
    format!("refs/heads/feature {commit} refs/heads/feature {remote_sha}\n")
}

/// A new branch, and an update whose remote sha this clone lacks, are both
/// bounded by the merge-base with the default branch; the message walk
/// reaches the new commit either way.
#[test]
fn range_scans_the_messages_of_a_new_branch() {
    if !gitleaks_available() {
        return;
    }
    let (dir, commit) = repo_with_feature_message(&format!("note {}", message_canary()), false);
    let p = dir.path();
    for remote in ["0".repeat(40), "1".repeat(40)] {
        let out = run_in(p, &["range"], &feature_line(&commit, &remote));
        assert_eq!(out.code, Some(1), "remote {remote}: {}", out.stderr);
        assert!(
            out.stderr.contains(&message_location(&commit, 1)),
            "remote {remote}: {}",
            out.stderr
        );
    }
}

/// With no merge-base, the selection falls back to the tip and its whole
/// ancestry, and the message is still listed and framed.
#[test]
fn range_scans_the_messages_of_a_new_branch_with_no_merge_base() {
    if !gitleaks_available() {
        return;
    }
    let (dir, commit) = repo_with_feature_message(&format!("note {}", message_canary()), true);
    let p = dir.path();
    let out = run_in(p, &["range"], &feature_line(&commit, &"0".repeat(40)));
    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains(&message_location(&commit, 1)),
        "{}",
        out.stderr
    );
}

/// A `git` on PATH that fails the commit-message listing, and only it, so
/// the probe and gitleaks' diff walk run the real git and succeed.
fn git_failing_the_message_listing() -> tempfile::TempDir {
    let real = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|d| d.join("git"))
        .find(|g| g.is_file())
        .expect("git on PATH");
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("git");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do\n  \
               if [ \"$a\" = '--format=%H%x00%B' ]; then\n    \
                 echo 'fatal: the fixture refuses the message listing' >&2\n    \
                 exit 128\n  \
               fi\n\
             done\n\
             exec '{}' \"$@\"\n",
            real.display()
        ),
    )
    .expect("write git shim");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    dir
}

/// A failed message listing refuses both modes with git's words: `range`
/// under `--warn-only`, where findings alone would exit 0, and `history`,
/// where nothing else is found.
#[test]
fn a_failed_message_listing_refuses_past_warn_only_and_in_history() {
    if !gitleaks_available() {
        return;
    }
    let (dir, base, _) = repo_with_message(&format!("note {}", message_canary()));
    let p = dir.path();
    let stdin = update_line(p, &base);
    let shim = git_failing_the_message_listing();

    let warned = run_in(p, &["range", "--warn-only"], &stdin);
    assert_eq!(warned.code, Some(0), "stderr: {}", warned.stderr);

    let refused = run_in_full(p, &["range", "--warn-only"], &stdin, &[], Some(shim.path()));
    assert_eq!(refused.code, Some(1), "stderr: {}", refused.stderr);
    assert!(
        refused.stderr.contains("did not complete")
            && refused
                .stderr
                .contains("the fixture refuses the message listing"),
        "{}",
        refused.stderr
    );
    assert!(
        !refused.stderr.contains("would fail the scrub gate"),
        "{}",
        refused.stderr
    );

    let clean = repo_with(&[("src/a.rs", "let user = \"alice\";\n")]);
    let history = run_in_full(clean.path(), &["history"], "", &[], Some(shim.path()));
    assert_eq!(history.code, Some(1), "stderr: {}", history.stderr);
    assert!(
        history.stderr.contains("did not complete")
            && history
                .stderr
                .contains("the fixture refuses the message listing"),
        "{}",
        history.stderr
    );
    assert!(
        !history.stderr.contains("history: clean"),
        "{}",
        history.stderr
    );
}
