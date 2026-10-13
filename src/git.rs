//! Git interrogation and parsing of the two textual git contracts this tool
//! consumes: staged diff output, and pre-push stdin.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Run `git <args>` in `repo`, returning stdout. Inherits the caller's environment.
pub fn run(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("failed to execute git");
    assert!(
        out.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    // Not lossy: `-z` output is raw path bytes, and replacing an
    // unrepresentable byte with U+FFFD yields a path that names no file. Every
    // downstream use would then quietly scan nothing for it, so an
    // unrepresentable name is fatal rather than skipped.
    String::from_utf8(out.stdout)
        .unwrap_or_else(|_| panic!("git {} emitted non-UTF-8 output", args.join(" ")))
}

fn try_run(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The value of a git config key as seen from `repo`, or `None` when unset.
pub fn config_get(repo: &Path, key: &str) -> Option<String> {
    try_run(repo, &["config", "--get", key])
}

/// Run `git log -n0 <opts>` in `repo`; `Err` carries git's stderr (lossy,
/// trimmed). Lists nothing, so it holds in a repository without commits. A
/// failure is any failed `git log -n0`, not only a rejected option: a broken
/// ref fails it too.
pub fn probe_log_opts(repo: &Path, opts: &str) -> Result<(), String> {
    let mut args = vec!["log", "-n0"];
    args.extend(opts.split_whitespace());
    git_output(repo, &args).map(drop)
}

/// Run `git <args>` in `repo`, returning stdout as raw bytes. A nonzero exit
/// is `Err` carrying git's stderr (lossy, trimmed) rather than a panic, for
/// callers that report a git failure as a refusal.
fn git_output(repo: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("failed to execute git");
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// One commit's identity and its full message, as `git log --format=%B`
/// prints it: subject, blank line, body, trailing newline. Raw bytes -- git
/// does not promise an encoding, and the scanner takes bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct CommitMessage {
    pub sha: String,
    pub body: Vec<u8>,
}

/// Every commit `revs` selects, with its message. `revs` is a revision
/// selection only (`a..b`, `<sha>`, `--all`); it must carry no diff options,
/// which would interleave patches with the records. `Err` is the reason the
/// listing cannot be trusted: git's stderr for a failed `git log`, or a
/// description of output that does not frame as `hash NUL body NUL` records.
///
/// Under `--format`, stdout is the format string's expansion plus whatever
/// per-commit text the user's config turns on. Signature verification
/// (`log.showSignature`) is the one such text, so `--no-show-signature` is
/// passed; any other option that writes to stdout here belongs beside it.
pub fn commit_messages(repo: &Path, revs: &str) -> Result<Vec<CommitMessage>, String> {
    let mut args = vec![
        "log",
        "-z",
        "--format=%H%x00%B",
        "--no-patch",
        "--no-show-signature",
    ];
    args.extend(revs.split_whitespace());
    args.push("--");
    let raw = git_output(repo, &args).map_err(|stderr| format!("git log failed:\n{stderr}"))?;
    parse_message_records(&raw)
}

/// Parse `git log -z --format=%H%x00%B` output: `hash NUL body NUL` per
/// commit. NUL is the only framing byte and git cannot put one inside a
/// message, so a wrong shape means the stream is not what was asked for; it
/// is refused rather than guessed at, since a mis-framed listing may leave a
/// message unscanned.
fn parse_message_records(raw: &[u8]) -> Result<Vec<CommitMessage>, String> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let Some(framed) = raw.strip_suffix(b"\0") else {
        return Err(
            "git log succeeded, but its output does not end with a NUL record terminator".into(),
        );
    };
    let fields: Vec<&[u8]> = framed.split(|&b| b == 0).collect();
    if !fields.len().is_multiple_of(2) {
        return Err(format!(
            "git log succeeded, but its output has {} NUL-separated fields; commit records come in hash/message pairs",
            fields.len()
        ));
    }
    fields
        .chunks_exact(2)
        .map(|pair| {
            let (hash, body) = (pair[0], pair[1]);
            if hash.is_empty() || !hash.iter().all(u8::is_ascii_hexdigit) {
                return Err(format!(
                    "git log succeeded, but its output has a record whose hash field is not a commit id: {:?}",
                    String::from_utf8_lossy(hash)
                ));
            }
            Ok(CommitMessage {
                sha: String::from_utf8_lossy(hash).into_owned(),
                body: body.to_vec(),
            })
        })
        .collect()
}

pub fn repo_root(from: &Path) -> PathBuf {
    let out = Command::new("git")
        .current_dir(from)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("failed to execute git");
    assert!(
        out.status.success(),
        "not inside a git repository: {}",
        from.display()
    );
    // Strip only the trailing newline, not `trim()`: a repo dirname ending in
    // whitespace is legal, and trimming it would yield a path naming no repo.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let root = stdout
        .strip_suffix('\n')
        .expect("git rev-parse --show-toplevel output was not newline-terminated");
    PathBuf::from(root)
}

/// The repo root containing `from`, or `None` when `from` is genuinely inside
/// no git repo. A resolution failure inside a security guard must fail closed
/// rather than read as "not a repo" and pass, so only two outcomes are
/// tolerated: a clean success (the repo root) or a clean "not a git repository"
/// (`None`). Every other non-zero exit -- dubious ownership, a locked or corrupt
/// repo, a probe stranded inside `.git` -- is a real error that panics rather
/// than collapsing into the not-a-repo answer and silently exempting a write.
/// `LC_ALL=C` pins the message so the recognition of the not-a-repo case does
/// not depend on the operator's locale. A failed spawn or non-UTF-8 output is
/// likewise fatal.
///
/// This function's `None` means "pass this write unscanned", so repo identity
/// must be a pure function of the probe directory. The inherited git discovery
/// variables (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_CEILING_DIRECTORIES`,
/// `GIT_COMMON_DIR`, `GIT_INDEX_FILE`) would let a stray `export` in the
/// session's environment redirect discovery -- reporting the wrong root, or
/// halting it with a clean "not a git repository" that reads as ungated -- so
/// they are stripped from the child.
pub fn try_repo_root(from: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .current_dir(from)
        .env("LC_ALL", "C")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_CEILING_DIRECTORIES")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("failed to execute git");
    if out.status.success() {
        let stdout = String::from_utf8(out.stdout)
            .unwrap_or_else(|_| panic!("git rev-parse --show-toplevel emitted non-UTF-8 output"));
        // Strip only the trailing newline, not `trim()`: a repo dirname ending
        // in whitespace is legal, and trimming it would yield a path naming no
        // repo whose config probe then reads absent -- a silent fail-open.
        let root = stdout
            .strip_suffix('\n')
            .expect("git rev-parse --show-toplevel output was not newline-terminated");
        return Some(PathBuf::from(root));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("not a git repository") {
        return None;
    }
    panic!(
        "git rev-parse --show-toplevel failed in {} (not a clean 'not a repository', \
         so failing closed): {}",
        from.display(),
        stderr.trim()
    );
}

/// The index mode git records for a submodule entry (a gitlink). Its whole
/// recorded content is the commit id of the submodule; the superproject stores
/// no file bytes for it.
const GITLINK_MODE: &str = "160000";

/// One tracked index entry.
#[derive(Debug, PartialEq, Eq)]
pub struct TrackedEntry {
    pub path: PathBuf,
    /// The commit id recorded for a gitlink; `None` for every other entry.
    pub gitlink: Option<String>,
}

/// Tracked entries, optionally scoped to a path.
///
/// The index mode comes along because it is the only reliable way to recognize
/// a submodule. The worktree cannot answer: a submodule path is legitimately
/// absent (never initialized), an empty directory (initialized, not fetched),
/// or a populated checkout, and only the index distinguishes any of those from
/// an ordinary file.
pub fn tracked_entries(repo: &Path, scope: Option<&str>) -> Vec<TrackedEntry> {
    let mut args = vec!["ls-files", "-s", "-z"];
    if let Some(s) = scope {
        args.push("--");
        args.push(s);
    }
    run(repo, &args)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(parse_index_entry)
        .collect()
}

/// Parse one `ls-files -s -z` record: `<mode> <object> <stage>\t<path>`.
///
/// The path starts after the first tab, so a filename containing a tab (or a
/// space, or a newline) survives intact. A record that does not have this shape
/// is fatal rather than skipped: a dropped entry is a tracked path silently
/// left out of a scan that then reports a clean tree.
///
/// Stage 0 is the only stage an index entry has outside a conflict. During an
/// unresolved merge the same path arrives three times, once per side, and none
/// of the three is the worktree content the operator is looking at. Picking one
/// would scan the wrong bytes; listing all three would hand the caller a
/// duplicate path. Both are guesses about a tree whose content is mid-decision,
/// so a nonzero stage is fatal.
fn parse_index_entry(record: &str) -> TrackedEntry {
    let (header, path) = record
        .split_once('\t')
        .unwrap_or_else(|| panic!("git ls-files -s record has no tab before the path: {record:?}"));
    let fields: Vec<&str> = header.split(' ').collect();
    assert!(
        fields.len() == 3,
        "git ls-files -s record header is not `<mode> <object> <stage>`: {record:?}"
    );
    let (mode, object, stage) = (fields[0], fields[1], fields[2]);
    assert!(
        stage == "0",
        "tracked path {path} is at merge stage {stage}: the index has unmerged entries. \
         Resolve the merge first; refusing to scan a tree whose content is mid-conflict"
    );
    TrackedEntry {
        path: PathBuf::from(path),
        gitlink: (mode == GITLINK_MODE).then(|| object.to_string()),
    }
}

/// The text git records for a gitlink, and the text a diff of one shows. Tree
/// scans mirror this so they see exactly what a staged or range scan sees.
pub fn gitlink_pointer_text(object: &str) -> String {
    format!("Subproject commit {object}\n")
}

/// Tracked paths with no file in the worktree: deleted, but not yet committed.
/// The only legitimate reason a tracked path is absent from disk.
pub fn deleted_files(repo: &Path) -> Vec<PathBuf> {
    run(repo, &["ls-files", "-z", "--deleted"])
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Staged paths, taken from `--name-only -z` rather than from diff headers.
/// NUL separation means no quoting or escaping is ever applied to the names.
pub fn staged_files(repo: &Path) -> Vec<PathBuf> {
    run(repo, &["diff", "--cached", "--name-only", "-z"])
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// The staged diff for exactly one path.
pub fn staged_diff_for(repo: &Path, path: &Path) -> String {
    run(
        repo,
        &[
            "diff",
            "--cached",
            "-U0",
            "--no-color",
            "--",
            &path.to_string_lossy(),
        ],
    )
}

/// Added text of a single-file unified diff.
///
/// Only hunk bodies are read, and a hunk starts at a `@@ ` line in column
/// zero. Every line inside a hunk carries a `+`/`-`/space prefix, so no
/// content can reach column zero looking like a header: an added line whose
/// own text is `++ /dev/null` arrives as `+++ /dev/null` and is read as the
/// content it is. Inferring file identity from `+++ ` headers instead would
/// let such a line retarget or discard the rest of the scan.
///
/// Deletions contribute nothing; only added text is ever scanned.
pub fn added_lines(diff: &str) -> String {
    let mut added = String::new();
    let mut in_hunk = false;
    for line in diff.lines() {
        if line.starts_with("@@ ") {
            in_hunk = true;
            continue;
        }
        if !in_hunk {
            continue;
        }
        if let Some(text) = line.strip_prefix('+') {
            added.push_str(text);
            added.push('\n');
        }
    }
    added
}

fn is_zero_sha(sha: &str) -> bool {
    !sha.is_empty() && sha.chars().all(|c| c == '0')
}

/// One line of the pre-push stdin contract.
#[derive(Debug, PartialEq, Eq)]
pub enum RefUpdate {
    /// Ref being deleted: nothing arrives at the remote, nothing to scan.
    Delete,
    /// Ref new to the remote: no remote SHA to bound the range against.
    New {
        local: String,
    },
    Update {
        remote: String,
        local: String,
    },
}

/// Parse `<local ref> <local sha> <remote ref> <remote sha>` lines.
pub fn parse_push_refs(stdin: &str) -> Vec<RefUpdate> {
    stdin
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            assert!(
                f.len() == 4,
                "malformed pre-push stdin line (expected 4 fields): {line:?}"
            );
            let (local_sha, remote_sha) = (f[1], f[3]);
            if is_zero_sha(local_sha) {
                RefUpdate::Delete
            } else if is_zero_sha(remote_sha) {
                RefUpdate::New {
                    local: local_sha.to_string(),
                }
            } else {
                RefUpdate::Update {
                    remote: remote_sha.to_string(),
                    local: local_sha.to_string(),
                }
            }
        })
        .collect()
}

/// Whether a commit object is present locally.
fn commit_exists(repo: &Path, sha: &str) -> bool {
    try_run(repo, &["cat-file", "-e", &format!("{sha}^{{commit}}")]).is_some()
}

/// Range bounded by the merge-base with the default branch; unrelated history
/// has no merge-base, so the whole reachable history gets scanned rather than
/// nothing.
fn merge_base_opts(repo: &Path, local: &str) -> String {
    match default_branch_ref(repo) {
        Some(base_ref) => match try_run(repo, &["merge-base", &base_ref, local]) {
            Some(base) if !base.is_empty() => format!("{base}..{local}"),
            _ => local.to_string(),
        },
        None => local.to_string(),
    }
}

/// `git log` range for a ref update.
///
/// The remote SHA is only usable as a bound if it is in the local object
/// store. The pre-push contract permits it not to be -- the remote can have
/// advanced from another clone since the last fetch -- and a range against a
/// missing object makes `git log` fail, which `scan_git` refuses as an
/// incomplete scan; the merge-base fallback keeps the push scannable instead,
/// over-scanning, which is safe.
pub fn log_opts_for(repo: &Path, update: &RefUpdate) -> Option<String> {
    match update {
        RefUpdate::Delete => None,
        RefUpdate::Update { remote, local } if commit_exists(repo, remote) => {
            Some(format!("{remote}..{local}"))
        }
        RefUpdate::Update { local, .. } | RefUpdate::New { local } => {
            Some(merge_base_opts(repo, local))
        }
    }
}

fn default_branch_ref(repo: &Path) -> Option<String> {
    try_run(
        repo,
        &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
    )
    .filter(|s| !s.is_empty())
    .or_else(|| {
        ["origin/main", "origin/master", "main", "master"]
            .into_iter()
            .find(|r| try_run(repo, &["rev-parse", "--verify", "--quiet", r]).is_some())
            .map(str::to_string)
    })
}

/// Extract a commit's tree into `dest`.
///
/// The scratch archive lives outside `dest`. Written inside it, a tree that
/// tracks a file of the same name would overwrite the archive mid-read and
/// then have its own content deleted from the mirror -- an attacker-choosable
/// filename that either crashes the push or exempts itself from the scan.
pub fn extract_tree(repo: &Path, sha: &str, dest: &Path) {
    let tar = tempfile::Builder::new()
        .prefix("brenn-scrub-archive")
        .suffix(".tar")
        .tempfile()
        .expect("cannot create temp archive");
    let tar_path = tar.path().to_string_lossy().into_owned();
    run(repo, &["archive", "--format=tar", "-o", &tar_path, sha]);
    let status = Command::new("tar")
        .args(["-xf", &tar_path, "-C", &dest.to_string_lossy()])
        .status()
        .expect("failed to execute tar");
    assert!(status.success(), "tar extraction of {sha} failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    use brenn_git_fixture::{assert_repo_is, git as fixture_git, init_repo};

    /// A git repo with one commit, for the functions that must shell out.
    ///
    /// Fixture mutations go through `brenn_git_fixture`, never through the
    /// production `run`: `run` inherits the environment (a contract the
    /// staged-scan path depends on), so under a git hook it would drive these
    /// mutations into whatever repo `GIT_DIR` names. The read-only production
    /// calls under test stay non-hermetic on purpose; `init_repo`'s canary is
    /// what catches an environment that would redirect them.
    fn repo_with_commit() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        init_repo(p);
        std::fs::write(p.join("f.rs"), "base\n").unwrap();
        fixture_git(p, &["add", "f.rs"]);
        fixture_git(p, &["commit", "-qm", "base"]);
        dir
    }

    #[test]
    fn diff_yields_added_lines_only() {
        let diff = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1 +1 @@
-let name = \"removed\";
+let name = \"added\";
";
        let added = added_lines(diff);
        assert_eq!(added, "let name = \"added\";\n");
        assert!(!added.contains("removed"));
    }

    #[test]
    fn diff_joins_multiple_hunks() {
        let diff = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1 +1 @@
+first
@@ -9 +9 @@
+second
";
        assert_eq!(added_lines(diff), "first\nsecond\n");
    }

    #[test]
    fn diff_of_a_deleted_file_adds_nothing() {
        let diff = "\
diff --git a/gone.rs b/gone.rs
--- a/gone.rs
+++ /dev/null
@@ -1 +0,0 @@
-let name = \"x\";
";
        assert!(added_lines(diff).is_empty());
    }

    #[test]
    fn diff_headers_are_never_read_as_added_content() {
        let diff = "\
diff --git a/src/a.rs b/src/a.rs
--- /dev/null
+++ b/src/a.rs
@@ -0,0 +1 @@
+real
";
        assert_eq!(added_lines(diff), "real\n");
    }

    /// An added line of literal `++ ...` reaches the diff as `+++ ...`.
    /// Header-prefix parsing consumed it and skipped everything after it.
    #[test]
    fn added_line_shaped_like_a_header_is_scanned_as_content() {
        let diff = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,0 +2,3 @@ base
+++ /dev/null
+let token = \"scanme\";
+++ b/docs/decoy.md
";
        let added = added_lines(diff);
        assert!(added.contains("let token = \"scanme\";"));
        // Each line keeps its own text with only the diff's `+` marker
        // removed; nothing is consumed as a header.
        assert_eq!(
            added,
            "++ /dev/null\nlet token = \"scanme\";\n++ b/docs/decoy.md\n"
        );
    }

    #[test]
    fn staged_files_and_per_file_diff_agree_end_to_end() {
        let dir = repo_with_commit();
        let p = dir.path();
        std::fs::write(
            p.join("f.rs"),
            "base\n++ /dev/null\nlet token = \"scanme\";\n",
        )
        .unwrap();
        std::fs::write(p.join("notes.md"), "doc line\n").unwrap();
        fixture_git(p, &["add", "f.rs", "notes.md"]);

        let files = staged_files(p);
        assert!(files.contains(&PathBuf::from("f.rs")));
        assert!(files.contains(&PathBuf::from("notes.md")));

        let added = added_lines(&staged_diff_for(p, Path::new("f.rs")));
        assert!(
            added.contains("let token = \"scanme\";"),
            "content after a header-shaped line must still be scanned: {added:?}"
        );
    }

    /// `-z` output is raw bytes, so a name needing quoting still round-trips.
    #[test]
    fn staged_files_handles_names_git_would_otherwise_quote() {
        let dir = repo_with_commit();
        let p = dir.path();
        std::fs::write(p.join("café.md"), "x\n").unwrap();
        fixture_git(p, &["add", "café.md"]);
        assert!(staged_files(p).contains(&PathBuf::from("café.md")));
    }

    #[test]
    fn push_refs_parse_a_normal_update() {
        let line = "refs/heads/main aaa111 refs/heads/main bbb222\n";
        assert_eq!(
            parse_push_refs(line),
            vec![RefUpdate::Update {
                remote: "bbb222".into(),
                local: "aaa111".into()
            }]
        );
    }

    #[test]
    fn push_refs_detect_a_new_branch() {
        let zero = "0".repeat(40);
        let line = format!("refs/heads/feat aaa111 refs/heads/feat {zero}\n");
        assert_eq!(
            parse_push_refs(&line),
            vec![RefUpdate::New {
                local: "aaa111".into()
            }]
        );
    }

    #[test]
    fn push_refs_detect_a_deletion() {
        let zero = "0".repeat(40);
        let line = format!("(delete) {zero} refs/heads/old bbb222\n");
        assert_eq!(parse_push_refs(&line), vec![RefUpdate::Delete]);
    }

    #[test]
    fn push_refs_handle_multiple_lines_and_blank_lines() {
        let zero = "0".repeat(64);
        let input = format!(
            "refs/heads/main aaa refs/heads/main bbb\n\n\
             refs/heads/feat ccc refs/heads/feat {zero}\n"
        );
        let refs = parse_push_refs(&input);
        assert_eq!(refs.len(), 2);
        assert_eq!(
            refs[1],
            RefUpdate::New {
                local: "ccc".into()
            }
        );
    }

    #[test]
    #[should_panic(expected = "malformed pre-push stdin line")]
    fn malformed_push_line_panics() {
        parse_push_refs("refs/heads/main aaa\n");
    }

    #[test]
    fn deletion_has_nothing_to_scan() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(log_opts_for(dir.path(), &RefUpdate::Delete), None);
    }

    /// Commit `n` more times on the current branch, returning the tip sha.
    fn commit_more(repo: &Path, n: usize) -> String {
        for i in 0..n {
            std::fs::write(repo.join(format!("extra{i}.rs")), "x\n").unwrap();
            fixture_git(repo, &["add", "."]);
            fixture_git(repo, &["commit", "-qm", "more"]);
        }
        fixture_git(repo, &["rev-parse", "HEAD"]).trim().to_string()
    }

    #[test]
    fn update_scans_exactly_the_pushed_range() {
        let dir = repo_with_commit();
        let p = dir.path();
        let remote = fixture_git(p, &["rev-parse", "HEAD"]).trim().to_string();
        let local = commit_more(p, 2);

        let update = RefUpdate::Update {
            remote: remote.clone(),
            local: local.clone(),
        };
        assert_eq!(log_opts_for(p, &update), Some(format!("{remote}..{local}")));
    }

    /// The remote can have advanced from another clone; its sha need not be
    /// in the local store. That must degrade to over-scanning, never fail.
    #[test]
    fn update_with_an_unfetched_remote_sha_falls_back_to_merge_base() {
        let dir = repo_with_commit();
        let p = dir.path();
        let base = fixture_git(p, &["rev-parse", "HEAD"]).trim().to_string();
        fixture_git(p, &["checkout", "-q", "-b", "feat"]);
        let local = commit_more(p, 1);

        let update = RefUpdate::Update {
            remote: "0123456789abcdef0123456789abcdef01234567".into(),
            local: local.clone(),
        };
        // Bounded by the merge-base with main, not the absent remote sha.
        assert_eq!(log_opts_for(p, &update), Some(format!("{base}..{local}")));
    }

    #[test]
    fn new_branch_is_bounded_by_the_merge_base_with_the_default_branch() {
        let dir = repo_with_commit();
        let p = dir.path();
        let base = fixture_git(p, &["rev-parse", "HEAD"]).trim().to_string();
        fixture_git(p, &["checkout", "-q", "-b", "feat"]);
        let local = commit_more(p, 2);

        let update = RefUpdate::New {
            local: local.clone(),
        };
        assert_eq!(log_opts_for(p, &update), Some(format!("{base}..{local}")));
    }

    /// No main/master to bound against: scan the whole reachable history
    /// rather than silently scanning nothing.
    #[test]
    fn new_branch_without_a_default_branch_scans_whole_history() {
        let dir = repo_with_commit();
        let p = dir.path();
        fixture_git(p, &["checkout", "-q", "-b", "solo"]);
        // The sharpest fixture in the suite: deleting `main` in the wrong repo
        // destroys real work. Re-confirm isolation immediately before it.
        assert_repo_is(p);
        fixture_git(p, &["branch", "-q", "-D", "main"]);
        let local = fixture_git(p, &["rev-parse", "HEAD"]).trim().to_string();

        let update = RefUpdate::New {
            local: local.clone(),
        };
        assert_eq!(log_opts_for(p, &update), Some(local));
    }

    fn tracked_paths(repo: &Path, scope: Option<&str>) -> Vec<PathBuf> {
        tracked_entries(repo, scope)
            .into_iter()
            .map(|e| e.path)
            .collect()
    }

    #[test]
    fn tracked_entries_lists_committed_paths_and_honors_a_scope() {
        let dir = repo_with_commit();
        let p = dir.path();
        std::fs::create_dir_all(p.join("docs")).unwrap();
        std::fs::write(p.join("docs/a.md"), "x\n").unwrap();
        std::fs::write(p.join("untracked.rs"), "x\n").unwrap();
        fixture_git(p, &["add", "docs/a.md"]);
        fixture_git(p, &["commit", "-qm", "docs"]);

        let all = tracked_paths(p, None);
        assert!(all.contains(&PathBuf::from("f.rs")));
        assert!(all.contains(&PathBuf::from("docs/a.md")));
        assert!(
            !all.contains(&PathBuf::from("untracked.rs")),
            "untracked files must never enter a tree scan"
        );

        assert_eq!(
            tracked_paths(p, Some("docs")),
            vec![PathBuf::from("docs/a.md")]
        );
    }

    #[test]
    fn a_regular_file_is_not_reported_as_a_gitlink() {
        let dir = repo_with_commit();
        let entries = tracked_entries(dir.path(), None);
        assert_eq!(
            entries,
            vec![TrackedEntry {
                path: PathBuf::from("f.rs"),
                gitlink: None
            }]
        );
    }

    #[test]
    fn a_submodule_entry_carries_its_recorded_commit_id() {
        let dir = repo_with_commit();
        let p = dir.path();
        let pin = "0123456789abcdef0123456789abcdef01234567";
        fixture_git(
            p,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{pin},vendor/thing"),
            ],
        );
        fixture_git(p, &["commit", "-qm", "gitlink"]);

        let entries = tracked_entries(p, None);
        assert!(
            entries.contains(&TrackedEntry {
                path: PathBuf::from("vendor/thing"),
                gitlink: Some(pin.to_string())
            }),
            "{entries:?}"
        );
        // Against git's own rendering, not a re-spelling of the function body:
        // the pointer text exists to be byte-identical to what a staged or
        // range scan reads out of a diff, so git is the only authority for it.
        let diff = fixture_git(p, &["show", "--format=", "HEAD"]);
        let pointer = gitlink_pointer_text(pin);
        assert!(
            diff.contains(&pointer),
            "the mirrored pointer must be the line git puts in a gitlink diff: \
             {pointer:?} not in {diff:?}"
        );
    }

    /// A conflicted path arrives three times, once per merge stage, and none of
    /// the three is the worktree content. Returning all three would hand the
    /// caller a duplicate path, which the tree mirror would process three times.
    #[test]
    #[should_panic(expected = "the index has unmerged entries")]
    fn an_unmerged_index_record_is_fatal() {
        parse_index_entry("100644 abc123 2\tf.txt");
    }

    /// The header ends at the first tab, so a tab in a filename cannot shorten
    /// the path and leave a scan pointed at a file that does not exist.
    #[test]
    fn an_index_record_splits_at_the_first_tab_only() {
        let entry = parse_index_entry("100644 abc123 0\tdocs/od\td\tname.md");
        assert_eq!(
            entry,
            TrackedEntry {
                path: PathBuf::from("docs/od\td\tname.md"),
                gitlink: None
            }
        );
    }

    #[test]
    #[should_panic(expected = "no tab before the path")]
    fn an_index_record_without_a_tab_is_fatal() {
        parse_index_entry("100644 abc123 0 docs/a.md");
    }

    #[test]
    #[should_panic(expected = "is not `<mode> <object> <stage>`")]
    fn an_index_record_with_an_unexpected_header_is_fatal() {
        parse_index_entry("100644 abc123\tdocs/a.md");
    }

    #[test]
    fn extract_tree_reproduces_the_tree_and_leaves_no_scratch_archive() {
        let dir = repo_with_commit();
        let p = dir.path();
        let dest = tempfile::tempdir().unwrap();
        extract_tree(p, "HEAD", dest.path());

        assert_eq!(
            std::fs::read_to_string(dest.path().join("f.rs")).unwrap(),
            "base\n"
        );
        // The scratch tar is written inside dest; if it ever survives, it
        // gets scanned as mirror content.
        let left: Vec<String> = std::fs::read_dir(dest.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["f.rs".to_string()]);
    }

    /// The scratch archive used to be written inside `dest` under a fixed
    /// name. A tree tracking that name overwrote the archive mid-extraction
    /// and then had its own content deleted from the mirror -- so committing
    /// scannable content under that filename exempted it from the tip scan.
    #[test]
    fn a_tracked_file_named_like_the_scratch_archive_is_still_mirrored() {
        let dir = repo_with_commit();
        let p = dir.path();
        std::fs::write(p.join("..tree.tar"), "let token = \"scanme\";\n").unwrap();
        fixture_git(p, &["add", "--", "..tree.tar"]);
        fixture_git(p, &["commit", "-qm", "collide"]);

        let dest = tempfile::tempdir().unwrap();
        extract_tree(p, "HEAD", dest.path());
        assert_eq!(
            std::fs::read_to_string(dest.path().join("..tree.tar")).unwrap(),
            "let token = \"scanme\";\n",
            "the repo's own file must survive extraction and be scannable"
        );
    }

    #[test]
    fn try_repo_root_finds_a_repo_and_returns_none_outside_one() {
        let dir = repo_with_commit();
        let inside = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(try_repo_root(dir.path()), Some(inside));

        // A bare tempdir is not a git repo (and, being under the system temp
        // root, is not nested inside this checkout either).
        let plain = tempfile::tempdir().unwrap();
        assert_eq!(try_repo_root(plain.path()), None);
    }

    /// A git error that is not a clean "not a git repository" must fail closed,
    /// never collapse into `None`. Probing from inside a repo's `.git` makes
    /// `rev-parse --show-toplevel` fail with "must be run in a work tree" -- a
    /// real error distinct from the no-repo case -- so the guard panics rather
    /// than reading the location as ungated and exempting a write.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn try_repo_root_fails_closed_on_a_git_error_that_is_not_not_a_repo() {
        let dir = repo_with_commit();
        try_repo_root(&dir.path().join(".git"));
    }

    #[test]
    fn deleted_files_lists_only_index_entries_absent_from_the_worktree() {
        let dir = repo_with_commit();
        let p = dir.path();
        assert!(deleted_files(p).is_empty());
        std::fs::remove_file(p.join("f.rs")).unwrap();
        assert_eq!(deleted_files(p), vec![PathBuf::from("f.rs")]);
    }

    #[test]
    fn probe_log_opts_tells_a_known_option_from_a_rejected_one() {
        let dir = repo_with_commit();
        assert_eq!(
            probe_log_opts(dir.path(), "--all --diff-merges=remerge"),
            Ok(())
        );
        let err = probe_log_opts(dir.path(), "--all --diff-merges=bogus").unwrap_err();
        assert!(err.contains("--diff-merges"), "{err}");

        let empty = tempfile::tempdir().unwrap();
        init_repo(empty.path());
        assert_eq!(
            probe_log_opts(empty.path(), "--all --diff-merges=remerge"),
            Ok(())
        );
    }

    /// `range` probes with an update's own revision selection, not `--all`.
    #[test]
    fn probe_log_opts_accepts_a_revision_with_merge_diffs() {
        let dir = repo_with_commit();
        let p = dir.path();
        let sha = fixture_git(p, &["rev-parse", "HEAD"]).trim().to_string();
        assert_eq!(
            probe_log_opts(p, &format!("{sha} --diff-merges=remerge")),
            Ok(())
        );
        let err = probe_log_opts(p, &format!("{sha} --diff-merges=bogus")).unwrap_err();
        assert!(err.contains("--diff-merges"), "{err}");
    }

    const SHA_A: &str = "0123456789abcdef0123456789abcdef01234567";
    const SHA_B: &str = "89abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn empty_message_listing_is_zero_records() {
        assert_eq!(parse_message_records(b""), Ok(Vec::new()));
    }

    #[test]
    fn message_records_parse_hash_and_body() {
        let raw = format!("{SHA_A}\0subject\n\nbody line\n\0{SHA_B}\0second\n\0");
        assert_eq!(
            parse_message_records(raw.as_bytes()),
            Ok(vec![
                CommitMessage {
                    sha: SHA_A.into(),
                    body: b"subject\n\nbody line\n".to_vec()
                },
                CommitMessage {
                    sha: SHA_B.into(),
                    body: b"second\n".to_vec()
                },
            ])
        );
    }

    #[test]
    fn an_empty_message_is_an_empty_body() {
        let raw = format!("{SHA_A}\0\0");
        assert_eq!(
            parse_message_records(raw.as_bytes()),
            Ok(vec![CommitMessage {
                sha: SHA_A.into(),
                body: Vec::new()
            }])
        );
    }

    #[test]
    fn a_non_utf8_body_is_kept_verbatim() {
        let mut raw = format!("{SHA_A}\0").into_bytes();
        raw.extend_from_slice(b"caf\xe9\n\0");
        let records = parse_message_records(&raw).expect("frames");
        assert_eq!(records[0].body, b"caf\xe9\n");
    }

    #[test]
    fn an_odd_field_count_is_refused() {
        let raw = format!("{SHA_A}\0body\0{SHA_B}\0");
        let err = parse_message_records(raw.as_bytes()).unwrap_err();
        assert!(err.contains("3 NUL-separated fields"), "{err}");
    }

    #[test]
    fn a_non_hex_hash_field_is_refused() {
        let err = parse_message_records(b"diff --git a/x b/x\0body\0").unwrap_err();
        assert!(err.contains("not a commit id"), "{err}");
        let err = parse_message_records(b"\0body\0").unwrap_err();
        assert!(err.contains("not a commit id"), "{err}");
    }

    #[test]
    fn a_listing_without_a_terminating_nul_is_refused() {
        let raw = format!("{SHA_A}\0body");
        let err = parse_message_records(raw.as_bytes()).unwrap_err();
        assert!(err.contains("terminator"), "{err}");
    }

    #[test]
    fn commit_messages_lists_a_commit_with_its_full_message() {
        let dir = repo_with_commit();
        let p = dir.path();
        std::fs::write(p.join("g.rs"), "x\n").unwrap();
        fixture_git(p, &["add", "g.rs"]);
        fixture_git(p, &["commit", "-qm", "subject", "-m", "body text"]);
        let head = fixture_git(p, &["rev-parse", "HEAD"]).trim().to_string();
        let base = fixture_git(p, &["rev-parse", "HEAD~1"]).trim().to_string();

        assert_eq!(
            commit_messages(p, &head),
            Ok(vec![
                CommitMessage {
                    sha: head.clone(),
                    body: b"subject\n\nbody text\n".to_vec()
                },
                CommitMessage {
                    sha: base.clone(),
                    body: b"base\n".to_vec()
                },
            ])
        );
        let ranged = commit_messages(p, &format!("{base}..{head}")).expect("lists");
        assert_eq!(ranged.len(), 1);
        assert_eq!(ranged[0].sha, head);
    }

    #[test]
    fn commit_messages_of_an_empty_range_is_empty() {
        let dir = repo_with_commit();
        let p = dir.path();
        let head = fixture_git(p, &["rev-parse", "HEAD"]).trim().to_string();
        assert_eq!(
            commit_messages(p, &format!("{head}..{head}")),
            Ok(Vec::new())
        );
    }

    #[test]
    fn commit_messages_of_a_bad_range_carries_git_s_words() {
        let dir = repo_with_commit();
        let err = commit_messages(dir.path(), "deadbeef..HEAD").unwrap_err();
        assert!(err.starts_with("git log failed:\n"), "{err}");
        assert!(err.contains("fatal:"), "{err}");
    }

    /// `log.showSignature` writes each signed commit's verification result
    /// to stdout ahead of its record; the listing must frame regardless.
    #[test]
    fn commit_messages_frames_a_signed_commit_under_show_signature() {
        let keys = tempfile::tempdir().unwrap();
        let key = keys.path().join("key");
        let keygen = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output();
        if !keygen.is_ok_and(|out| out.status.success()) {
            eprintln!("skipping: ssh-keygen is unavailable to sign a fixture commit");
            return;
        }
        let dir = repo_with_commit();
        let p = dir.path();
        let key = key.to_str().expect("utf-8 key path");
        fixture_git(p, &["config", "gpg.format", "ssh"]);
        fixture_git(p, &["config", "user.signingkey", key]);
        fixture_git(p, &["commit", "-q", "--allow-empty", "-S", "-m", "signed"]);
        fixture_git(p, &["config", "log.showSignature", "true"]);
        let head = fixture_git(p, &["rev-parse", "HEAD"]).trim().to_string();

        assert_eq!(
            commit_messages(p, &format!("{head}~1..{head}")),
            Ok(vec![CommitMessage {
                sha: head,
                body: b"signed\n".to_vec()
            }])
        );
    }
}
