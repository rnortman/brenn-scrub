//! `init` and `init --check` over the real binary in fixture repos.
//!
//! Each `--check` case starts from a repo `init` has just laid, changes one
//! thing, and asserts the exit code and that the failure names the file (and
//! rule) it concerns -- every failure class fails on its own, and every
//! consumer-owned difference passes on its own.

mod common;

use common::PINNED_VERSION;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const STRIP_LINE: &str = r#"for var in $(compgen -v GIT_ || true); do unset "$var"; done"#;

/// Template file, destination, executable.
const KIT: &[(&str, &str, bool)] = &[
    ("gitleaks.toml", ".gitleaks.toml", false),
    (
        "claude-hooks/scrub-check.sh",
        ".claude/hooks/scrub-check.sh",
        true,
    ),
    ("githooks/pre-commit", ".githooks/pre-commit", true),
    ("githooks/pre-push", ".githooks/pre-push", true),
];

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn template(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("template")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// One run with `CI` set or removed explicitly, since the hooks-path check
/// depends on it, and a gitleaks stub ahead on `PATH` so the outcome does not
/// depend on what the machine has installed.
fn run_init(args: &[&str], cwd: &Path, ci: bool, gitleaks: &Path) -> Out {
    let mut cmd = Command::new(common::scrub_bin());
    cmd.args(args).current_dir(cwd);
    cmd.env_remove("BRENN_SCRUB_DENYLIST");
    brenn_git_fixture::hermetic(&mut cmd);
    if ci {
        cmd.env(common::CI_MARKER, "true");
    } else {
        cmd.env_remove(common::CI_MARKER);
    }
    common::prepend_path(&mut cmd, Some(gitleaks));
    let out = cmd.output().expect("failed to spawn brenn-scrub");
    Out {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn init(dir: &Path) -> Out {
    let stub = common::stub_gitleaks(PINNED_VERSION);
    run_init(&["init"], dir, false, stub.path())
}

fn check(dir: &Path, ci: bool) -> Out {
    let stub = common::stub_gitleaks(PINNED_VERSION);
    run_init(&["init", "--check"], dir, ci, stub.path())
}

fn fresh_repo() -> TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    brenn_git_fixture::init_repo(dir.path());
    dir
}

fn laid_repo() -> TempDir {
    let dir = fresh_repo();
    let out = init(dir.path());
    assert_eq!(out.code, Some(0), "init failed: {}", out.stderr);
    dir
}

fn read(dir: &Path, rel: &str) -> String {
    std::fs::read_to_string(dir.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn write(dir: &Path, rel: &str, content: &str) {
    std::fs::write(dir.join(rel), content).unwrap_or_else(|e| panic!("write {rel}: {e}"));
}

fn edit(dir: &Path, rel: &str, from: &str, to: &str) {
    let before = read(dir, rel);
    assert!(before.contains(from), "{rel} has no {from:?}");
    write(dir, rel, &before.replacen(from, to, 1));
}

/// Replace each line of the rule file starting with `key = ` by `line`.
fn set_rule_key(dir: &Path, key: &str, line: &str) {
    let before = read(dir, ".gitleaks.toml");
    let prefix = format!("{key} = ");
    assert!(before.lines().any(|l| l.starts_with(&prefix)), "no {key}");
    let after: Vec<&str> = before
        .lines()
        .map(|l| if l.starts_with(&prefix) { line } else { l })
        .collect();
    write(dir, ".gitleaks.toml", &(after.join("\n") + "\n"));
}

fn hooks_path(dir: &Path) -> String {
    brenn_git_fixture::git(dir, &["config", "--get", "core.hooksPath"])
        .trim()
        .to_string()
}

fn assert_check_fails(dir: &Path, names: &[&str]) {
    let out = check(dir, false);
    assert_eq!(
        out.code,
        Some(1),
        "expected a failure; stderr: {}",
        out.stderr
    );
    for name in names {
        assert!(
            out.stderr.contains(name),
            "failure does not name {name:?}: {}",
            out.stderr
        );
    }
}

fn assert_check_passes(dir: &Path) {
    let out = check(dir, false);
    assert_eq!(out.code, Some(0), "expected a pass; stderr: {}", out.stderr);
}

#[test]
fn init_lays_the_whole_kit_into_a_fresh_repo() {
    let dir = fresh_repo();
    let stock = dir.path().join(".git/hooks/pre-commit");
    std::fs::write(&stock, "#!/bin/sh\n").expect("stock hook");

    let out = init(dir.path());
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);

    for (source, dest, executable) in KIT {
        assert_eq!(read(dir.path(), dest), template(source), "{dest}");
        let mode = std::fs::metadata(dir.path().join(dest))
            .expect("laid file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o111 != 0, *executable, "{dest} exec bit");
        assert!(
            out.stderr.contains(&format!("wrote {dest}")),
            "{}",
            out.stderr
        );
    }
    assert!(read(dir.path(), ".gitignore").contains(".gitleaks.local.toml\n"));
    assert_eq!(hooks_path(dir.path()), ".githooks");
    assert!(!stock.exists(), "the stock pre-commit is removed");
    assert_eq!(out.stdout, template("settings-hooks.json"));
    assert!(
        out.stderr.contains(".claude/settings.json"),
        "{}",
        out.stderr
    );
    assert!(
        !dir.path().join(".claude/settings.json").exists(),
        "init never writes settings"
    );

    assert_check_passes(dir.path());
}

#[test]
fn init_never_overwrites_and_names_only_a_differing_file() {
    let dir = laid_repo();
    write(dir.path(), ".githooks/pre-push", "#!/bin/bash\nbespoke\n");

    let out = init(dir.path());
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert_eq!(
        read(dir.path(), ".githooks/pre-push"),
        "#!/bin/bash\nbespoke\n"
    );
    assert!(
        out.stderr
            .contains(".githooks/pre-push exists and differs from the template"),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("Delete it and re-run"),
        "{}",
        out.stderr
    );
    assert!(
        dir.path().join(".githooks/pre-commit").is_file(),
        "a re-run with core.hooksPath already set keeps the tracked pre-commit"
    );
    for (_, dest, _) in KIT.iter().filter(|(_, d, _)| *d != ".githooks/pre-push") {
        assert!(
            !out.stderr.contains(dest),
            "a matching {dest} must be silent: {}",
            out.stderr
        );
    }
    assert_eq!(
        read(dir.path(), ".gitignore")
            .matches(".gitleaks.local.toml")
            .count(),
        1,
        "the gitignore line is added once"
    );
}

#[test]
fn init_appends_to_an_existing_gitignore_without_a_trailing_newline() {
    let dir = fresh_repo();
    write(dir.path(), ".gitignore", "/target");
    assert_eq!(init(dir.path()).code, Some(0));
    assert_eq!(
        read(dir.path(), ".gitignore"),
        "/target\n.gitleaks.local.toml\n"
    );
}

#[test]
fn init_reports_a_missing_gitleaks_without_failing() {
    let dir = fresh_repo();
    let failing = common::failing_gitleaks();
    let out = run_init(&["init"], dir.path(), false, failing.path());
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(out.stderr.contains("gitleaks not found"), "{}", out.stderr);
    assert!(out.stderr.contains(PINNED_VERSION), "{}", out.stderr);
}

#[test]
fn init_takes_a_repo_path_from_elsewhere() {
    let dir = fresh_repo();
    let elsewhere = tempfile::tempdir().expect("temp dir");
    let stub = common::stub_gitleaks(PINNED_VERSION);
    let target = dir.path().to_str().expect("utf-8 path");
    let out = run_init(&["init", target], elsewhere.path(), false, stub.path());
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(dir.path().join(".githooks/pre-commit").is_file());
    let out = run_init(
        &["init", "--check", target],
        elsewhere.path(),
        false,
        stub.path(),
    );
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
}

#[test]
fn check_writes_nothing() {
    let dir = fresh_repo();
    let out = check(dir.path(), false);
    assert_eq!(out.code, Some(1));
    for (_, dest, _) in KIT {
        assert!(!dir.path().join(dest).exists(), "{dest} was written");
        assert!(out.stderr.contains(dest), "{}", out.stderr);
    }
    assert!(!dir.path().join(".gitignore").exists());
}

#[test]
fn a_missing_hook_invocation_fails() {
    let dir = laid_repo();
    edit(
        dir.path(),
        ".claude/hooks/scrub-check.sh",
        "exec brenn-scrub hook",
        "exec true",
    );
    assert_check_fails(
        dir.path(),
        &[".claude/hooks/scrub-check.sh", "brenn-scrub hook"],
    );
}

#[test]
fn a_missing_staged_or_range_invocation_fails() {
    let dir = laid_repo();
    edit(
        dir.path(),
        ".githooks/pre-commit",
        "brenn-scrub staged\n",
        "\n",
    );
    assert_check_fails(dir.path(), &[".githooks/pre-commit", "brenn-scrub staged"]);

    let dir = laid_repo();
    edit(
        dir.path(),
        ".githooks/pre-push",
        "exec brenn-scrub range",
        "exit 0",
    );
    assert_check_fails(dir.path(), &[".githooks/pre-push", "brenn-scrub range"]);
}

#[test]
fn an_invocation_only_in_a_comment_fails() {
    let dir = laid_repo();
    edit(
        dir.path(),
        ".githooks/pre-push",
        "exec brenn-scrub range",
        "# exec brenn-scrub range",
    );
    assert_check_fails(dir.path(), &[".githooks/pre-push"]);
}

#[test]
fn an_invocation_followed_by_a_word_character_fails() {
    for replacement in ["brenn-scrub staged-x\n", "brenn-scrub -- staged-x\n"] {
        let dir = laid_repo();
        edit(
            dir.path(),
            ".githooks/pre-commit",
            "brenn-scrub staged\n",
            replacement,
        );
        assert_check_fails(dir.path(), &[".githooks/pre-commit"]);
    }
}

#[test]
fn a_missing_or_inexact_strip_line_fails() {
    let dir = laid_repo();
    edit(dir.path(), ".githooks/pre-commit", STRIP_LINE, "");
    assert_check_fails(dir.path(), &[".githooks/pre-commit", "GIT_* strip line"]);

    let dir = laid_repo();
    edit(
        dir.path(),
        ".githooks/pre-commit",
        STRIP_LINE,
        &format!("    {STRIP_LINE}"),
    );
    assert_check_fails(dir.path(), &[".githooks/pre-commit", "GIT_* strip line"]);
}

#[test]
fn a_missing_kit_file_fails() {
    let dir = laid_repo();
    std::fs::remove_file(dir.path().join(".githooks/pre-push")).expect("remove");
    assert_check_fails(dir.path(), &[".githooks/pre-push", "missing"]);
}

#[test]
fn a_gitignore_without_the_overlay_line_fails() {
    let dir = laid_repo();
    write(dir.path(), ".gitignore", "/target\n");
    assert_check_fails(dir.path(), &[".gitignore", ".gitleaks.local.toml"]);
}

#[test]
fn an_unreadable_gitignore_is_reported_as_unreadable() {
    let dir = laid_repo();
    std::fs::remove_file(dir.path().join(".gitignore")).expect("remove");
    std::fs::create_dir(dir.path().join(".gitignore")).expect("mkdir");
    assert_check_fails(dir.path(), &[".gitignore: cannot be read"]);
    let out = check(dir.path(), false);
    assert!(
        !out.stderr.contains("does not ignore"),
        "an unreadable .gitignore is blamed on a missing line: {}",
        out.stderr
    );
}

#[test]
fn the_hooks_path_is_checked_outside_ci_only() {
    let dir = laid_repo();
    brenn_git_fixture::git(dir.path(), &["config", "core.hooksPath", ".git/hooks"]);
    assert_check_fails(dir.path(), &["core.hooksPath", ".git/hooks"]);
    let out = check(dir.path(), true);
    assert_eq!(out.code, Some(0), "under CI: {}", out.stderr);

    brenn_git_fixture::git(dir.path(), &["config", "--unset", "core.hooksPath"]);
    assert_check_fails(dir.path(), &["core.hooksPath is unset"]);
}

/// `CI=` is a developer lane: the hooks-path check still runs.
#[test]
fn an_empty_ci_variable_reads_as_unset() {
    let dir = laid_repo();
    brenn_git_fixture::git(dir.path(), &["config", "core.hooksPath", ".git/hooks"]);
    let stub = common::stub_gitleaks(PINNED_VERSION);
    let mut cmd = Command::new(common::scrub_bin());
    cmd.args(["init", "--check"]).current_dir(dir.path());
    cmd.env_remove("BRENN_SCRUB_DENYLIST");
    brenn_git_fixture::hermetic(&mut cmd);
    cmd.env(common::CI_MARKER, "");
    common::prepend_path(&mut cmd, Some(stub.path()));
    let out = cmd.output().expect("failed to spawn brenn-scrub");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("core.hooksPath"), "{stderr}");
}

#[test]
fn a_gitignore_line_git_does_not_honour_fails_and_init_repairs_it() {
    for gitignore in [
        "  .gitleaks.local.toml\n",
        ".gitleaks.local.toml\n!.gitleaks.local.toml\n",
    ] {
        let dir = laid_repo();
        write(dir.path(), ".gitignore", gitignore);
        assert_check_fails(dir.path(), &[".gitignore", ".gitleaks.local.toml"]);

        assert_eq!(init(dir.path()).code, Some(0));
        assert_eq!(
            read(dir.path(), ".gitignore"),
            format!("{gitignore}.gitleaks.local.toml\n")
        );
        write(dir.path(), ".gitleaks.local.toml", "");
        assert!(
            brenn_git_fixture::try_git(
                dir.path(),
                &["check-ignore", "-q", "--", ".gitleaks.local.toml"]
            ),
            "git ignores the overlay after init repairs {gitignore:?}"
        );
        assert_check_passes(dir.path());
    }
}

#[test]
fn a_tracked_overlay_fails() {
    let dir = laid_repo();
    write(dir.path(), ".gitleaks.local.toml", "");
    brenn_git_fixture::git(dir.path(), &["add", "-f", ".gitleaks.local.toml"]);
    assert_check_fails(
        dir.path(),
        &[".gitleaks.local.toml: tracked", "git rm --cached"],
    );
}

#[test]
fn a_non_executable_script_fails_and_init_names_it() {
    for (_, dest, _) in KIT.iter().filter(|(_, _, executable)| *executable) {
        let dir = laid_repo();
        let path = dir.path().join(dest);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_check_fails(dir.path(), &[&format!("{dest}: not executable")]);

        let out = init(dir.path());
        assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
        assert!(
            out.stderr.contains(&format!("{dest}: not executable")),
            "{}",
            out.stderr
        );
        assert!(
            !out.stderr.contains("differs"),
            "a matching file is not called different: {}",
            out.stderr
        );
    }
}

#[test]
fn init_on_a_path_that_is_not_a_directory_fails_naming_it() {
    let elsewhere = tempfile::tempdir().expect("temp dir");
    let missing = elsewhere.path().join("no-such-repo");
    let target = missing.to_str().expect("utf-8 path");
    let stub = common::stub_gitleaks(PINNED_VERSION);
    for args in [["init", target].as_slice(), &["init", "--check", target]] {
        let out = run_init(args, elsewhere.path(), false, stub.path());
        assert_eq!(out.code, Some(1), "{args:?}: {}", out.stderr);
        assert!(
            out.stderr.contains(&format!("{target} is not a directory")),
            "{}",
            out.stderr
        );
    }
}

/// From a linked worktree, the stock hook is removed from the common git dir,
/// and the tracked pre-commit just laid in the worktree is kept.
#[test]
fn init_from_a_linked_worktree_removes_the_common_stock_hook() {
    let dir = tempfile::tempdir().expect("temp dir");
    brenn_git_fixture::seed_repo(dir.path());
    let stock = dir.path().join(".git/hooks/pre-commit");
    std::fs::write(&stock, "#!/bin/sh\n").expect("stock hook");
    let worktrees = tempfile::tempdir().expect("temp dir");
    let tree = worktrees.path().join("side");
    let tree_arg = tree.to_str().expect("utf-8 path");
    brenn_git_fixture::git(
        dir.path(),
        &["worktree", "add", "-q", "-b", "side", tree_arg],
    );

    let stub = common::stub_gitleaks(PINNED_VERSION);
    let out = run_init(&["init", tree_arg], worktrees.path(), false, stub.path());
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(
        !stock.exists(),
        "the common dir's stock pre-commit is removed"
    );
    assert_eq!(
        read(&tree, ".githooks/pre-commit"),
        template("githooks/pre-commit")
    );
}

#[test]
fn init_never_writes_through_a_dangling_symlink() {
    let dir = fresh_repo();
    let outside = tempfile::tempdir().expect("temp dir");
    let target = outside.path().join("target");
    let link = dir.path().join(".githooks/pre-push");
    std::fs::create_dir_all(link.parent().expect("parent")).expect("mkdir");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let out = init(dir.path());
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(!target.exists(), "init wrote through the link");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("link")
            .file_type()
            .is_symlink()
    );
    assert!(
        out.stderr
            .contains(".githooks/pre-push exists and differs from the template"),
        "{}",
        out.stderr
    );
}

#[test]
fn a_changed_extend_fails() {
    let dir = laid_repo();
    edit(
        dir.path(),
        ".gitleaks.toml",
        "useDefault = true",
        "useDefault = false",
    );
    assert_check_fails(dir.path(), &[".gitleaks.toml", "[extend]"]);
}

#[test]
fn a_missing_or_extra_rule_fails_naming_it() {
    let dir = laid_repo();
    let config = read(dir.path(), ".gitleaks.toml");
    let header_end = config.find("[[rules]]").expect("template has a rule");
    write(dir.path(), ".gitleaks.toml", &config[..header_end]);
    assert_check_fails(
        dir.path(),
        &[".gitleaks.toml", "ephemeral-reference", "missing"],
    );

    let dir = laid_repo();
    let extra = format!("{config}\n[[rules]]\nid = \"local-only\"\nregex = '''zzz'''\n");
    write(dir.path(), ".gitleaks.toml", &extra);
    assert_check_fails(dir.path(), &[".gitleaks.toml", "local-only"]);
}

#[test]
fn a_changed_regex_or_keywords_fails_naming_rule_and_key() {
    let dir = laid_repo();
    set_rule_key(dir.path(), "regex", "regex = '''changed'''");
    assert_check_fails(
        dir.path(),
        &[".gitleaks.toml", "ephemeral-reference", "`regex`"],
    );

    let dir = laid_repo();
    set_rule_key(dir.path(), "keywords", "keywords = [\"changed\"]");
    assert_check_fails(
        dir.path(),
        &[".gitleaks.toml", "ephemeral-reference", "`keywords`"],
    );
}

#[test]
fn prose_around_an_invocation_may_change() {
    let dir = laid_repo();
    edit(
        dir.path(),
        ".claude/hooks/scrub-check.sh",
        "# Claude Code PreToolUse",
        "# Reworded header for",
    );
    edit(
        dir.path(),
        ".claude/hooks/scrub-check.sh",
        "brenn-scrub not on PATH",
        "the scrub binary is not installed",
    );
    assert_check_passes(dir.path());
}

#[test]
fn bespoke_hook_bodies_with_the_invocation_pass() {
    let dir = laid_repo();
    edit(
        dir.path(),
        ".githooks/pre-commit",
        "brenn-scrub staged\n",
        "run_scrub_staged() {\n    if ! brenn-scrub staged; then\n        exit 1\n    fi\n}\nrun_scrub_staged\n",
    );
    edit(
        dir.path(),
        ".githooks/pre-push",
        "exec brenn-scrub range",
        "refs=$(cat)\nprintf '%s\\n' \"$refs\" | brenn-scrub range",
    );
    assert_check_passes(dir.path());
}

#[test]
fn the_bazel_wrapper_shape_and_an_indented_invocation_pass() {
    let dir = laid_repo();
    edit(
        dir.path(),
        ".githooks/pre-commit",
        "brenn-scrub staged\n",
        "bazel run //tools/scrub:brenn-scrub -- staged\n",
    );
    edit(
        dir.path(),
        ".githooks/pre-push",
        "exec brenn-scrub range",
        "    exec brenn-scrub range",
    );
    assert_check_passes(dir.path());
}

#[test]
fn consumer_owned_rule_file_parts_may_change() {
    let dir = laid_repo();
    set_rule_key(dir.path(), "title", "title = \"this repo's rules\"");
    set_rule_key(dir.path(), "description", "description = \"reworded\"");
    assert_check_passes(dir.path());

    // Every `[[rules.allowlists]]` block dropped.
    let dir = laid_repo();
    let config = read(dir.path(), ".gitleaks.toml");
    let first = config
        .find("  # Markdown is where")
        .expect("allowlist comment");
    write(dir.path(), ".gitleaks.toml", &config[..first]);
    assert_check_passes(dir.path());

    // One allowlist added to the rule, and a top-level one.
    let dir = laid_repo();
    let added = format!(
        "{config}\n  [[rules.allowlists]]\n  paths = ['''^vendor/''']\n\n[allowlist]\npaths = ['''^fixtures/''']\n"
    );
    write(dir.path(), ".gitleaks.toml", &added);
    assert_check_passes(dir.path());
}
