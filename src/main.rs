//! brenn-scrub -- the one scrub entry point for every layer.
//!
//! Modes: `hook`, `staged`, `range`, `tree`, `history`, plus `init`, which lays the
//! consumer kit and verifies it -- see the `help` module for each mode's input
//! contract, scope, and exit codes.
//!
//! Diff-scanning modes enforce every rule. Tree-scanning modes drop the
//! diff-only rules (see gitleaks::DIFF_ONLY_RULES) so a grandfathered backlog
//! cannot make them permanently un-green-able.

mod config;
mod dest;
mod exclude;
mod git;
mod gitleaks;
mod help;
mod hook;
mod init;
mod message;
mod mirror;

use exclude::Exclusions;
use gitleaks::{Finding, Version};
use mirror::Mirror;
use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// PreToolUse blocks the write and feeds stderr back to the agent on exit 2.
const EXIT_BLOCK: u8 = 2;
const EXIT_FAIL: u8 = 1;
const EXIT_OK: u8 = 0;

/// Strict reader for a scrub file-discovery env var. An empty value is
/// deliberately *not* treated as unset: setting the var at all declares its
/// file required, so `VAR=""` (an unset variable expanded in a shell profile)
/// must reach the downstream discovery panic rather than silently degrade the
/// gate. A non-UTF-8 value violates the same contract and panics here for the
/// same reason. `declares` names the required file in the panic message.
fn strict_env(var: &str, declares: &str) -> Option<String> {
    std::env::var_os(var).map(|value| {
        value.into_string().unwrap_or_else(|raw| {
            panic!(
                "{var} is set to a non-UTF-8 value ({raw:?}); setting it declares the \
                 {declares} required, so it cannot be treated as unset"
            )
        })
    })
}

/// An empty `BRENN_SCRUB_DENYLIST` must reach the discovery panic rather than
/// silently degrade the gate to public-only rules.
fn overlay_env() -> Option<String> {
    strict_env(config::OVERLAY_ENV, "overlay")
}

fn resolve_for(repo: &Path) -> config::Resolved {
    config::resolve(repo, overlay_env().as_deref())
}

/// Shared opening of every gating mode: require a pinned gitleaks, locate the
/// repo, resolve the config, and emit the one info line naming what was loaded.
/// One copy, so the info line's shape and the version policy cannot drift
/// between modes.
///
/// Any deviation from the pin is fatal here, since a gate silently scanning
/// with an unvalidated engine is worse than no gate.
fn gate_preamble(mode: &str) -> Result<(PathBuf, config::Resolved), ExitCode> {
    if let Err(msg) = Version::require_pinned() {
        eprintln!("brenn-scrub: {msg}");
        return Err(ExitCode::from(EXIT_FAIL));
    }
    let repo = git::repo_root(&std::env::current_dir().expect("cannot read cwd"));
    let resolved = resolve_for(&repo);
    eprintln!("brenn-scrub {mode}: {}", resolved.summary());
    Ok((repo, resolved))
}

/// A git-mode scan of `log_opts`, or its refusal already printed: an
/// incomplete walk exits 1 under every flag. One copy, so the refusal's text
/// and exit code cannot drift between the git-walking modes.
fn scan_git_or_refuse(
    verb: &str,
    resolved: &config::Resolved,
    repo: &Path,
    log_opts: &str,
) -> Result<Vec<Finding>, ExitCode> {
    gitleaks::scan_git(&resolved.config_path, repo, log_opts).map_err(|incomplete| {
        eprintln!("{}", incomplete_scan_message(verb, &incomplete.git_output));
        ExitCode::from(EXIT_FAIL)
    })
}

// TODO(binary-sniff-skips-mirrored-files)
fn scan_mirror(resolved: &config::Resolved, mirror: &Mirror) -> Vec<Finding> {
    let raw = gitleaks::scan_dir(&resolved.config_path, mirror.root());
    gitleaks::relativize(raw, mirror.root())
}

/// The commit messages `revs` selects, or the refusal already printed: a
/// listing that failed or did not frame exits 1 under every flag.
fn commit_messages_or_refuse(
    verb: &str,
    repo: &Path,
    revs: &str,
) -> Result<Vec<git::CommitMessage>, ExitCode> {
    git::commit_messages(repo, revs).map_err(|detail| {
        eprintln!("{}", message_walk_message(verb, &detail));
        ExitCode::from(EXIT_FAIL)
    })
}

/// Scan the messages of `commits` as one mirror of sha-named files with the
/// tree rule set, attributing each finding to its commit. `commits` is
/// already deduplicated by sha; `Mirror` refuses a repeated path.
fn scan_messages(resolved: &config::Resolved, commits: &[git::CommitMessage]) -> Vec<Finding> {
    if commits.is_empty() {
        return Vec::new();
    }
    let mirror = Mirror::new();
    for c in commits {
        mirror.write(Path::new(&c.sha), &gitleaks::message_file(&c.body));
    }
    gitleaks::apply_tree_filter(gitleaks::attribute_to_messages(scan_mirror(
        resolved, &mirror,
    )))
}

fn report(findings: &[Finding], heading: &str) {
    eprintln!("{}", message::rejection(findings, heading));
}

/// `hook` and `range` consume a protocol produced by Claude Code and by git.
/// A terminal on stdin means neither producer is there, and reading would just
/// block with no output -- so say what was expected instead of hanging.
fn terminal_stdin_message(verb: &str) -> String {
    format!(
        "brenn-scrub {verb}: stdin is a terminal, but this mode reads a protocol on stdin \
         and is meant to be run by a hook, not by hand. Run `brenn-scrub {verb} --help` for \
         the exact format, or use `staged` / `tree` for hand-run scans."
    )
}

fn refuse_terminal_stdin(verb: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprintln!("{}", terminal_stdin_message(verb));
    true
}

fn misconfigured_hook_message(tool: &str) -> String {
    format!(
        "brenn-scrub: hook misconfigured -- tool `{tool}` reached the scrub check but \
         this wrapper cannot read its added text. Either narrow the PreToolUse matcher \
         or teach brenn-scrub about `{tool}`. Refusing to pass it unscanned."
    )
}

/// `text`'s lines, each indented two spaces, for quoting tool output inside a
/// refusal.
fn indented(text: &str) -> String {
    text.lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The refusal for a git-mode scan gitleaks did not run to the end. Says
/// "did not complete", not "nothing scanned": a partial report is real, and
/// `range` may have processed earlier ref lines. gitleaks' stderr follows
/// verbatim so the operator sees git's own words (`fatal: unable to read
/// <sha>`, a trace line).
fn incomplete_scan_message(verb: &str, git_output: &str) -> String {
    format!(
        "brenn-scrub {verb}: the scan did not complete. gitleaks exited 0 but the \
         `git log` it ran wrote to stderr, so its report cannot establish that the \
         {verb} is clean. git's output, as gitleaks relayed it:\n\n{}\n\n\
         A damaged object store, a broken ref, or a setting that makes git write to \
         stderr (GIT_TRACE, say) all do this. Fix the cause and rerun; no flag lifts \
         this refusal.",
        indented(git_output)
    )
}

/// The refusal for a git-walking mode whose `git log` options probe failed.
/// Shows whatever git printed and offers the version floor as the likely
/// cause rather than the diagnosis.
fn probe_message(verb: &str, log_opts: &str, git_output: &str) -> String {
    format!(
        "brenn-scrub {verb}: `git log -n0 {log_opts}` failed in this \
         repository; git said:\n\n{}\n\n\
         A git older than 2.36 (no {MERGE_DIFF_OPTS}) is the usual cause.",
        indented(git_output)
    )
}

/// The refusal for a commit-message listing that failed or did not frame;
/// `detail` says which. Same contract as the diff-walk refusal: exit 1, no
/// flag lifts it.
fn message_walk_message(verb: &str, detail: &str) -> String {
    format!(
        "brenn-scrub {verb}: the scan did not complete. The {verb}'s commit messages \
         could not be listed, so they cannot be established clean:\n\n{}\n\n\
         Fix the cause and rerun; no flag lifts this refusal.",
        indented(detail)
    )
}

fn size_cap_message(path: &Path, len: usize) -> String {
    format!(
        "brenn-scrub: skipping scan of {} ({len} bytes exceeds the {} byte cap); \
         the push gate scans it uncapped.",
        path.display(),
        hook::SIZE_CAP_BYTES
    )
}

/// The panic text when a resolved destination fails to strip its gated repo's
/// prefix -- a resolution bug that must block rather than mirror to the wrong
/// place. Agent-visible, so it carries the same neutrality bar as every other
/// emitted string.
fn not_inside_repo_message(dest: &Path, repo: &Path) -> String {
    format!(
        "resolved destination {} is not inside gated repo {}",
        dest.display(),
        repo.display()
    )
}

/// The one line an ungated-destination pass prints before exiting 0. Names the
/// resolved destination so the no-op is auditable. Local-only (a passing hook's
/// stderr ships nowhere), but it carries the same neutrality bar as every
/// emitted string.
fn ungated_dest_message(dest: &Path) -> String {
    format!(
        "brenn-scrub hook: {} is not inside a gated repo \
         (no .gitleaks.toml at the repo root); not scanned",
        dest.display()
    )
}

/// Hook mode fails *closed*.
///
/// Only exit 2 blocks a PreToolUse write; a panic exits 101, which Claude
/// Code reports as a hook error and lets the write through. Every internal
/// failure here -- broken overlay, gitleaks malfunction, unreadable report --
/// is therefore translated into a block. The gates keep panicking, where a
/// nonzero exit already means "refused".
fn mode_hook() -> ExitCode {
    if refuse_terminal_stdin("hook") {
        return ExitCode::from(EXIT_FAIL);
    }
    let hushed = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(mode_hook_inner);
    std::panic::set_hook(hushed);

    match result {
        Ok(code) => code,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("unknown internal error");
            eprintln!("brenn-scrub: internal error, refusing to pass this write unscanned: {msg}");
            ExitCode::from(EXIT_BLOCK)
        }
    }
}

fn mode_hook_inner() -> ExitCode {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .expect("cannot read hook input");
    let payload: serde_json::Value =
        serde_json::from_str(&raw).expect("hook input is not valid JSON");

    let added = match hook::extract(&payload) {
        Ok(a) => a,
        Err(hook::HookError::UnknownTool(tool)) => {
            eprintln!("{}", misconfigured_hook_message(&tool));
            return ExitCode::from(EXIT_BLOCK);
        }
    };

    // `cwd` is used only to absolutize a relative `file_path`; repo identity
    // comes from the destination, never from where the session happens to sit.
    let cwd = payload
        .get("cwd")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot read cwd"));

    // The write destination decides the repo. Resolving it before every other
    // step means an ungated destination -- no repo, or a repo without the
    // config -- passes without needing a scanner at all. A resolution panic
    // (bad tail, dangling symlink, dirty git error) becomes a block, per the
    // hook's fail-closed contract.
    let dest = dest::resolve(&added.file_path, &cwd);
    let Some(repo) = dest::gated_repo_containing(&dest.existing) else {
        eprintln!("{}", ungated_dest_message(&dest.resolved));
        return ExitCode::from(EXIT_OK);
    };

    // Missing or unpinned gitleaks must not block an author mid-edit; the
    // gates downstream are hard failures and will catch anything missed here.
    match Version::detect() {
        Version::Match => {}
        Version::Mismatch(found) => eprintln!("brenn-scrub: {}", Version::mismatch_message(&found)),
        Version::Missing => {
            eprintln!("brenn-scrub: {}", Version::missing_message());
            return ExitCode::from(EXIT_FAIL);
        }
    }

    if added.text.len() > hook::SIZE_CAP_BYTES {
        eprintln!("{}", size_cap_message(&added.file_path, added.text.len()));
        return ExitCode::from(EXIT_OK);
    }

    // The destination resolved inside `repo`, so the strip cannot fail; a
    // failure would mean a resolution bug and blocks rather than mirroring to
    // the wrong place.
    let rel = dest
        .resolved
        .strip_prefix(&repo)
        .unwrap_or_else(|_| panic!("{}", not_inside_repo_message(&dest.resolved, &repo)));
    let mirror = Mirror::new();
    mirror.write(rel, added.text.as_bytes());
    let findings = scan_mirror(&resolve_for(&repo), &mirror);

    if findings.is_empty() {
        return ExitCode::from(EXIT_OK);
    }
    report(
        &findings,
        "brenn-scrub blocked this write: the added text matches a scrub rule.",
    );
    ExitCode::from(EXIT_BLOCK)
}

fn mode_staged() -> ExitCode {
    let (repo, resolved) = match gate_preamble("staged") {
        Ok(v) => v,
        Err(code) => return code,
    };

    // Path identity comes from `--name-only`, never from diff headers, so
    // staged content cannot spoof the file a hunk is attributed to.
    let mirror = Mirror::new();
    let mut any = false;
    for path in git::staged_files(&repo) {
        let added = git::added_lines(&git::staged_diff_for(&repo, &path));
        if added.is_empty() {
            continue;
        }
        mirror.write(&path, added.as_bytes());
        any = true;
    }
    if !any {
        return ExitCode::from(EXIT_OK);
    }

    let findings = scan_mirror(&resolved, &mirror);
    if findings.is_empty() {
        return ExitCode::from(EXIT_OK);
    }
    report(
        &findings,
        "brenn-scrub blocked this commit: staged changes match a scrub rule.",
    );
    ExitCode::from(EXIT_FAIL)
}

fn mode_range(warn_only: bool) -> ExitCode {
    if refuse_terminal_stdin("range") {
        return ExitCode::from(EXIT_FAIL);
    }
    let (repo, resolved) = match gate_preamble("range") {
        Ok(v) => v,
        Err(code) => return code,
    };

    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .expect("cannot read pre-push input");

    let mut findings = Vec::new();
    let mut scanned_tips: Vec<String> = Vec::new();
    let mut probed = false;
    let mut messages: Vec<git::CommitMessage> = Vec::new();
    let mut seen_commits: HashSet<String> = HashSet::new();
    for update in git::parse_push_refs(&raw) {
        let Some(revs) = git::log_opts_for(&repo, &update) else {
            continue;
        };
        let log_opts = with_merge_diffs(&revs);
        // Probed once, with the first scannable update's own selection: a
        // deletion-only push never needs merge diffs, and a bare probe
        // without a revision fails on an unborn HEAD.
        if !probed {
            if let Err(git_output) = git::probe_log_opts(&repo, &log_opts) {
                eprintln!("{}", probe_message("range", &log_opts, &git_output));
                return ExitCode::from(EXIT_FAIL);
            }
            probed = true;
        }
        // Per-commit diffs, each merge's own resolution included: the full
        // rule set, diff-only rules included. An incomplete walk refuses
        // here, before `warn_only` is consulted.
        match scan_git_or_refuse("range", &resolved, &repo, &log_opts) {
            Ok(found) => findings.extend(found),
            Err(code) => return code,
        }
        // Messages are collected per update and scanned once below; tips
        // sharing history list the same commits.
        match commit_messages_or_refuse("range", &repo, &revs) {
            Ok(listed) => messages.extend(
                listed
                    .into_iter()
                    .filter(|c| seen_commits.insert(c.sha.clone())),
            ),
            Err(code) => return code,
        }

        // Tip tree: what the remote ends up holding, tree rule set.
        let tip = match &update {
            git::RefUpdate::New { local } => local,
            git::RefUpdate::Update { local, .. } => local,
            git::RefUpdate::Delete => continue,
        };
        // Pushing several refs at one tip (a branch and its tag) would
        // otherwise report every finding once per ref and inflate the
        // burndown count.
        if scanned_tips.iter().any(|t| t == tip) {
            continue;
        }
        scanned_tips.push(tip.clone());

        let mirror = Mirror::new();
        git::extract_tree(&repo, tip, mirror.root());
        findings.extend(gitleaks::apply_tree_filter(scan_mirror(&resolved, &mirror)));
    }
    findings.extend(scan_messages(&resolved, &messages));

    if findings.is_empty() {
        return ExitCode::from(EXIT_OK);
    }
    if warn_only {
        report(
            &findings,
            "brenn-scrub (warn-only): this push would fail the scrub gate.",
        );
        return ExitCode::from(EXIT_OK);
    }
    report(
        &findings,
        "brenn-scrub blocked this push: pushed commits match a scrub rule.",
    );
    ExitCode::from(EXIT_FAIL)
}

/// Revision selection of the history scan: every ref.
const HISTORY_REVISIONS: &str = "--all";

/// For each merge, the diff between git's automatic merge and the commit --
/// a conflict resolution or a change only the merge makes, which plain
/// `git log -p` never shows. Needs git 2.36. Shared by `range` and `history`;
/// never handed to the message walk, whose framing it breaks.
const MERGE_DIFF_OPTS: &str = "--diff-merges=remerge";

/// The diff walk's `git log` options for revision selection `revs`.
fn with_merge_diffs(revs: &str) -> String {
    format!("{revs} {MERGE_DIFF_OPTS}")
}

/// Every commit reachable from any ref, with the full rule set: each
/// non-merge commit's diff and what each merge changes beyond the automatic
/// merge; every commit's message with the tree rule set. The tip tree is
/// `tree`'s business, so none is extracted here.
fn mode_history() -> ExitCode {
    let (repo, resolved) = match gate_preamble("history") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let log_opts = with_merge_diffs(HISTORY_REVISIONS);
    // The option string is checked first so a git that rejects it is named as
    // such instead of surfacing as an incomplete scan with the scan's own
    // output.
    if let Err(git_output) = git::probe_log_opts(&repo, &log_opts) {
        eprintln!("{}", probe_message("history", &log_opts, &git_output));
        return ExitCode::from(EXIT_FAIL);
    }
    let mut findings = match scan_git_or_refuse("history", &resolved, &repo, &log_opts) {
        Ok(found) => found,
        Err(code) => return code,
    };
    // `--all` lists each commit once, so no dedup is needed.
    match commit_messages_or_refuse("history", &repo, HISTORY_REVISIONS) {
        Ok(listed) => findings.extend(scan_messages(&resolved, &listed)),
        Err(code) => return code,
    }
    if findings.is_empty() {
        eprintln!("brenn-scrub history: clean");
        return ExitCode::from(EXIT_OK);
    }
    eprintln!("{}", message::history_rejection(&findings));
    ExitCode::from(EXIT_FAIL)
}

/// Tree mode's stdout: the findings the exit code was decided on, together
/// with the scope that produced them, so a captured worklist can never be read
/// as a scan of more than it was.
#[derive(serde::Serialize)]
struct TreeOutput<'a> {
    findings: &'a [Finding],
    excluded: Vec<String>,
}

fn mode_tree(scope: Option<&str>, exclusions: &Exclusions) -> ExitCode {
    let (repo, resolved) = match gate_preamble("tree") {
        Ok(v) => v,
        Err(code) => return code,
    };

    let entries = git::tracked_entries(&repo, scope);
    // A scan of zero files is never a meaningful green -- it is a mistyped
    // scope.
    assert!(
        !entries.is_empty(),
        "scope matched no tracked files{}; refusing to report a clean tree",
        scope.map(|s| format!(" ({s})")).unwrap_or_default()
    );

    let paths = entries.iter().map(|e| e.path.clone()).collect();
    // The worktree is never consulted for a gitlink — git records only a
    // commit id for it.
    let gitlinks: HashMap<PathBuf, String> = entries
        .into_iter()
        .filter_map(|e| e.gitlink.map(|object| (e.path, object)))
        .collect();

    let (tracked, dropped) = exclusions.partition(paths);
    for (prefix, count) in &dropped {
        eprintln!("EXCLUDED: {prefix} ({count} files not scanned)");
    }
    assert!(
        !tracked.is_empty(),
        "every tracked file in scope was excluded; refusing to report a clean tree"
    );

    // Anything tracked but unmirrored narrows the scan while it still reports
    // a clean tree, so the only tolerated case -- a staged deletion, which has
    // no content -- is enumerated from git rather than inferred from a
    // stat failure, and it is announced.
    let deleted = git::deleted_files(&repo);
    let mirror = Mirror::new();
    for rel in tracked {
        // A gitlink's scannable content is its pointer text, whatever the
        // worktree holds at that path. Stating it here also keeps the pointer
        // out of the stat arms below, where every worktree state a submodule
        // can be in reads as an error.
        if let Some(object) = gitlinks.get(&rel) {
            eprintln!(
                "SUBMODULE: {} (pointer scanned; the submodule's own contents are \
                 a separate repository and are not covered by this scan)",
                rel.display()
            );
            mirror.write(&rel, git::gitlink_pointer_text(object).as_bytes());
            continue;
        }
        let src = repo.join(&rel);
        match std::fs::symlink_metadata(&src) {
            Ok(md) if md.is_file() => mirror.link_or_copy(&rel, &src),
            // git stores a symlink as a blob holding its target path and scans
            // that text; mirroring the target string keeps the tree scan
            // seeing what a history scan sees.
            Ok(md) if md.is_symlink() => {
                let target = std::fs::read_link(&src)
                    .unwrap_or_else(|e| panic!("cannot read symlink {}: {e}", src.display()));
                mirror.write(&rel, target.as_os_str().as_encoded_bytes());
            }
            Ok(_) => panic!(
                "tracked path {} is neither a regular file nor a symlink; \
                 refusing to report a clean tree with it unscanned",
                src.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                assert!(
                    deleted.contains(&rel),
                    "tracked path {} is missing from the worktree but is not a staged \
                     deletion; refusing to report a clean tree with it unscanned",
                    src.display()
                );
                eprintln!("SKIPPED: {} (staged deletion, no content)", rel.display());
            }
            Err(e) => panic!("cannot stat tracked path {}: {e}", src.display()),
        }
    }

    let findings = gitleaks::apply_tree_filter(scan_mirror(&resolved, &mirror));

    let output = TreeOutput {
        findings: &findings,
        excluded: exclusions.as_strings(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("cannot serialize findings")
    );

    if findings.is_empty() {
        eprintln!("brenn-scrub tree: clean");
        return ExitCode::from(EXIT_OK);
    }
    report(
        &findings,
        &format!("brenn-scrub tree: {} finding(s).", findings.len()),
    );
    ExitCode::from(EXIT_FAIL)
}

/// Whether this run is a CI job: `CI` set and non-empty, so `CI=` reads as
/// unset.
fn under_ci() -> bool {
    std::env::var_os("CI").is_some_and(|v| !v.is_empty())
}

fn mode_init(check: bool, repo: Option<&str>) -> ExitCode {
    let from = repo.map_or_else(
        || std::env::current_dir().expect("cannot read cwd"),
        PathBuf::from,
    );
    if !from.is_dir() {
        eprintln!("brenn-scrub init: {} is not a directory", from.display());
        return ExitCode::from(EXIT_FAIL);
    }
    let repo = git::repo_root(&from);
    if !check {
        init::lay_down(&repo);
        return ExitCode::from(EXIT_OK);
    }
    let failures = init::check(&repo, under_ci());
    if failures.is_empty() {
        eprintln!("brenn-scrub init --check: ok");
        return ExitCode::from(EXIT_OK);
    }
    for failure in &failures {
        eprintln!("brenn-scrub init --check: {failure}");
    }
    ExitCode::from(EXIT_FAIL)
}

/// Bad invocation: the mode's own help on stderr, nonzero exit.
///
/// A botched *hook* invocation blocks rather than warns. Exit 1 from the hook
/// path means "write landed unscanned", so a stray argument in the PreToolUse
/// command string would silently disable the write-time layer everywhere that
/// config is pulled; the rest of hook mode fails closed and so does this.
fn usage(verb: Option<&str>) -> ExitCode {
    eprintln!("{}", help::for_mode(verb));
    match verb {
        Some("hook") => ExitCode::from(EXIT_BLOCK),
        _ => ExitCode::from(EXIT_FAIL),
    }
}

/// What the command line asked for.
///
/// Unrecognized arguments are rejected rather than ignored: a mistyped
/// `--warnonly` would silently run the push gate *enforcing*, and a stray
/// flag in tree mode would be read as a git pathspec that matches nothing and
/// reports a clean tree.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Hook,
    Staged,
    Range {
        warn_only: bool,
    },
    Tree {
        scope: Option<String>,
        exclude: Vec<String>,
    },
    History,
    Init {
        check: bool,
        repo: Option<String>,
    },
    /// Help was asked for: the mode's text on stdout, exit 0.
    Help(Option<String>),
    /// Bad invocation: the mode's text on stderr, nonzero.
    Usage(Option<String>),
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h")
}

fn parse_tree(rest: &[String]) -> Mode {
    let mut scope: Option<String> = None;
    let mut exclude = Vec::new();
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        if arg == "--exclude" {
            match it.next() {
                Some(p) if !p.starts_with('-') && !p.is_empty() => exclude.push(p.clone()),
                _ => return Mode::Usage(Some("tree".into())),
            }
        } else if arg.starts_with('-') || scope.is_some() {
            return Mode::Usage(Some("tree".into()));
        } else {
            scope = Some(arg.clone());
        }
    }
    Mode::Tree { scope, exclude }
}

fn parse_init(rest: &[String]) -> Mode {
    let mut check = false;
    let mut repo: Option<String> = None;
    for arg in rest {
        if arg == "--check" && !check {
            check = true;
        } else if arg.starts_with('-') || arg.is_empty() || repo.is_some() {
            return Mode::Usage(Some("init".into()));
        } else {
            repo = Some(arg.clone());
        }
    }
    Mode::Init { check, repo }
}

fn dispatch(args: &[String]) -> Mode {
    let verb = args.first().map(String::as_str);
    let rest = args.get(1..).unwrap_or(&[]);
    if wants_help(args) {
        return Mode::Help(verb.filter(|v| !v.starts_with('-')).map(str::to_string));
    }
    let named = || verb.map(str::to_string);
    match verb {
        Some("hook") if rest.is_empty() => Mode::Hook,
        Some("staged") if rest.is_empty() => Mode::Staged,
        Some("range") => match rest {
            [] => Mode::Range { warn_only: false },
            [one] if one == "--warn-only" => Mode::Range { warn_only: true },
            _ => Mode::Usage(named()),
        },
        Some("history") if rest.is_empty() => Mode::History,
        Some("tree") => parse_tree(rest),
        Some("init") => parse_init(rest),
        Some("hook") | Some("staged") | Some("history") => Mode::Usage(named()),
        _ => Mode::Usage(None),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Mode::Hook => mode_hook(),
        Mode::Staged => mode_staged(),
        Mode::Range { warn_only } => mode_range(warn_only),
        Mode::Tree { scope, exclude } => mode_tree(
            scope.as_deref(),
            &Exclusions::new(exclude.into_iter().map(PathBuf::from).collect()),
        ),
        Mode::History => mode_history(),
        Mode::Init { check, repo } => mode_init(check, repo.as_deref()),
        Mode::Help(verb) => {
            println!("{}", help::for_mode(verb.as_deref()));
            ExitCode::from(EXIT_OK)
        }
        Mode::Usage(verb) => usage(verb.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatch_of(args: &[&str]) -> Mode {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        dispatch(&owned)
    }

    #[test]
    fn each_mode_is_selected_by_its_verb() {
        assert_eq!(dispatch_of(&["hook"]), Mode::Hook);
        assert_eq!(dispatch_of(&["staged"]), Mode::Staged);
        assert_eq!(dispatch_of(&["range"]), Mode::Range { warn_only: false });
        assert_eq!(dispatch_of(&["history"]), Mode::History);
        assert_eq!(
            dispatch_of(&["tree"]),
            Mode::Tree {
                scope: None,
                exclude: vec![]
            }
        );
    }

    #[test]
    fn warn_only_is_opt_in_and_exact() {
        assert_eq!(
            dispatch_of(&["range", "--warn-only"]),
            Mode::Range { warn_only: true }
        );
        // A typo must not silently enforce; enforcing is the destructive
        // direction during the warn-only rollout.
        assert_eq!(
            dispatch_of(&["range", "--warnonly"]),
            Mode::Usage(Some("range".into()))
        );
        assert_eq!(
            dispatch_of(&["range", "--warn-only", "x"]),
            Mode::Usage(Some("range".into()))
        );
    }

    #[test]
    fn tree_takes_a_scope_but_rejects_unknown_flags() {
        assert_eq!(
            dispatch_of(&["tree", "src"]),
            Mode::Tree {
                scope: Some("src".into()),
                exclude: vec![]
            }
        );
        // Would otherwise become a pathspec matching nothing -> false green.
        assert_eq!(
            dispatch_of(&["tree", "--anything"]),
            Mode::Usage(Some("tree".into()))
        );
        assert_eq!(
            dispatch_of(&["tree", "src", "extra"]),
            Mode::Usage(Some("tree".into()))
        );
    }

    #[test]
    fn tree_collects_repeated_exclusions_alongside_a_scope() {
        assert_eq!(
            dispatch_of(&["tree", "--exclude", "docs/adr", "--exclude", "prod.toml"]),
            Mode::Tree {
                scope: None,
                exclude: vec!["docs/adr".into(), "prod.toml".into()]
            }
        );
        assert_eq!(
            dispatch_of(&["tree", "--exclude", "docs/adr", "docs"]),
            Mode::Tree {
                scope: Some("docs".into()),
                exclude: vec!["docs/adr".into()]
            }
        );
    }

    /// A swallowed flag would silently become the excluded prefix, quietly
    /// widening the scan's blind spot.
    #[test]
    fn exclude_demands_a_value_that_is_not_another_flag() {
        assert_eq!(
            dispatch_of(&["tree", "--exclude"]),
            Mode::Usage(Some("tree".into()))
        );
        assert_eq!(
            dispatch_of(&["tree", "--exclude", "--warn-only"]),
            Mode::Usage(Some("tree".into()))
        );
    }

    #[test]
    fn init_takes_check_and_one_repo_path() {
        assert_eq!(
            dispatch_of(&["init"]),
            Mode::Init {
                check: false,
                repo: None
            }
        );
        assert_eq!(
            dispatch_of(&["init", "--check"]),
            Mode::Init {
                check: true,
                repo: None
            }
        );
        assert_eq!(
            dispatch_of(&["init", "../other", "--check"]),
            Mode::Init {
                check: true,
                repo: Some("../other".into())
            }
        );
    }

    /// `--force` in particular must not be quietly taken as a repo path: init
    /// never overwrites, and a caller expecting it to would be misled.
    #[test]
    fn init_rejects_unknown_flags_and_extra_paths() {
        for args in [
            &["init", "--force"][..],
            &["init", "--check", "--check"],
            &["init", "a", "b"],
            &["init", ""],
        ] {
            assert_eq!(
                dispatch_of(args),
                Mode::Usage(Some("init".into())),
                "{args:?}"
            );
        }
    }

    #[test]
    fn help_is_available_bare_and_per_mode() {
        assert_eq!(dispatch_of(&["--help"]), Mode::Help(None));
        assert_eq!(
            dispatch_of(&["tree", "--help"]),
            Mode::Help(Some("tree".into()))
        );
        assert_eq!(
            dispatch_of(&["range", "-h"]),
            Mode::Help(Some("range".into()))
        );
    }

    /// These are the strings an author is most likely to paste into a public
    /// issue, so they carry the same neutrality bar as the rejection ladder.
    #[test]
    fn every_message_this_module_emits_is_neutral() {
        use message::neutral::assert_neutral;
        assert_neutral(&Version::missing_message(), "install hint");
        for verb in ["hook", "range"] {
            assert_neutral(&terminal_stdin_message(verb), "terminal-stdin refusal");
        }
        assert_neutral(
            &misconfigured_hook_message("SomeFutureTool"),
            "hook-misconfigured message",
        );
        assert_neutral(
            &size_cap_message(Path::new("src/a.rs"), 1),
            "size-cap message",
        );
        assert_neutral(
            &ungated_dest_message(Path::new("/srv/data/scratch/a.rs")),
            "ungated destination audit line",
        );
        assert_neutral(
            &not_inside_repo_message(
                Path::new("/srv/data/project/src/a.rs"),
                Path::new("/srv/data/project"),
            ),
            "strip-prefix block message",
        );
        for verb in ["range", "history"] {
            assert_neutral(
                &incomplete_scan_message(verb, "ERR [git] fatal: unable to read abc"),
                "incomplete-scan refusal",
            );
        }
        for verb in ["range", "history"] {
            assert_neutral(
                &probe_message(
                    verb,
                    "--all --diff-merges=remerge",
                    "fatal: bad object refs/heads/broken",
                ),
                "probe refusal",
            );
            assert_neutral(
                &message_walk_message(verb, "fatal: bad revision 'x..y'"),
                "message-walk refusal",
            );
        }
    }

    #[test]
    fn incomplete_scan_message_quotes_git_and_refuses_without_a_way_out() {
        let git_output = "ERR [git] fatal: unable to read abc\nERR error=\"stderr is not empty\"\n";
        for verb in ["range", "history"] {
            let msg = incomplete_scan_message(verb, git_output);
            assert!(msg.contains("did not complete"), "{msg}");
            assert!(msg.contains(&format!("brenn-scrub {verb}:")), "{msg}");
            assert!(msg.contains(&format!("the {verb} is clean")), "{msg}");
            for line in git_output.lines() {
                assert!(msg.contains(&format!("  {line}")), "{msg}");
            }
            assert!(msg.contains("no flag lifts"), "{msg}");
            assert!(!msg.contains("nothing was scanned"), "{msg}");
            assert!(!msg.contains("--warn-only"), "{msg}");
        }
    }

    #[test]
    fn probe_message_shows_git_and_names_the_likely_cause() {
        let range_opts = with_merge_diffs("abc..def");
        for (verb, opts) in [
            ("history", with_merge_diffs(HISTORY_REVISIONS)),
            ("range", range_opts),
        ] {
            let msg = probe_message(verb, &opts, "fatal: bad object refs/heads/broken");
            assert!(msg.contains(&format!("brenn-scrub {verb}:")), "{msg}");
            assert!(msg.contains(&format!("`git log -n0 {opts}`")), "{msg}");
            assert!(
                msg.contains("  fatal: bad object refs/heads/broken"),
                "{msg}"
            );
            assert!(msg.contains("2.36"), "{msg}");
            assert!(!msg.contains("did not complete"), "{msg}");
        }
    }

    #[test]
    fn message_walk_message_quotes_git_and_refuses_without_a_way_out() {
        for verb in ["range", "history"] {
            let msg =
                message_walk_message(verb, "git log failed:\nfatal: bad revision 'x..y'\nsecond");
            assert!(msg.contains("did not complete"), "{msg}");
            assert!(msg.contains(&format!("brenn-scrub {verb}:")), "{msg}");
            assert!(msg.contains(&format!("{verb}'s commit messages")), "{msg}");
            assert!(msg.contains("  git log failed:"), "{msg}");
            assert!(msg.contains("  fatal: bad revision 'x..y'"), "{msg}");
            assert!(msg.contains("  second"), "{msg}");
            assert!(msg.contains("no flag lifts"), "{msg}");
            assert!(!msg.contains("--warn-only"), "{msg}");
        }
    }

    /// The probe and the diff walk run this one string, and the message walk
    /// runs the selection without it.
    #[test]
    fn merge_diffs_are_appended_to_the_revision_selection() {
        assert_eq!(
            with_merge_diffs(HISTORY_REVISIONS),
            "--all --diff-merges=remerge"
        );
        assert_eq!(with_merge_diffs("a..b"), "a..b --diff-merges=remerge");
    }

    /// The guard itself needs a pty to exercise and is deliberately left to
    /// manual use; its failure mode is a hang, not a scrub hole. What must not
    /// rot is the message, which is the only thing that tells a human why the
    /// command they typed by hand refused to run.
    #[test]
    fn terminal_stdin_refusal_names_the_producer_and_the_way_out() {
        for verb in ["hook", "range"] {
            let msg = terminal_stdin_message(verb);
            assert!(msg.contains("stdin is a terminal"), "{msg}");
            assert!(
                msg.contains(&format!("brenn-scrub {verb} --help")),
                "must point at the mode's own help: {msg}"
            );
            assert!(
                msg.contains("staged") && msg.contains("tree"),
                "must name the hand-runnable modes: {msg}"
            );
        }
    }

    #[test]
    fn stray_arguments_and_unknown_verbs_are_rejected() {
        assert_eq!(dispatch_of(&[]), Mode::Usage(None));
        assert_eq!(
            dispatch_of(&["hook", "--x"]),
            Mode::Usage(Some("hook".into()))
        );
        assert_eq!(
            dispatch_of(&["staged", "extra"]),
            Mode::Usage(Some("staged".into()))
        );
        assert_eq!(
            dispatch_of(&["history", "x"]),
            Mode::Usage(Some("history".into()))
        );
        assert_eq!(
            dispatch_of(&["history", "--all"]),
            Mode::Usage(Some("history".into()))
        );
        assert_eq!(dispatch_of(&["nonsense"]), Mode::Usage(None));
    }
}
