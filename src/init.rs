//! `init` lays the scrub kit into a repo from the template compiled into this
//! binary; `init --check` verifies that a repo still carries what the gate
//! depends on.
//!
//! The check holds a consumer to the invocation lines and the public rules,
//! not to bytes: each shim is a few lines of prose around one call of the
//! binary, the prose changes between releases, and a byte rule would make
//! every wording change a fleet-wide re-init.

use crate::config::{OVERLAY_FILENAME, PUBLIC_FILENAME};
use crate::git;
use crate::gitleaks::Version;
use std::collections::BTreeMap;
use std::path::Path;
use toml::{Table, Value};

/// One file of the kit and where it lands in a consuming repo.
pub struct TemplateFile {
    pub dest: &'static str,
    pub contents: &'static str,
    pub executable: bool,
    /// The mode whose invocation line the file must carry; `None` for the
    /// rule file, which is compared by rules instead.
    pub mode: Option<&'static str>,
    /// Whether the file must carry the GIT_* strip line as a whole line.
    pub strip_line: bool,
}

pub const GITLEAKS_TOML: &str = include_str!("../template/gitleaks.toml");

pub const FILES: &[TemplateFile] = &[
    TemplateFile {
        dest: PUBLIC_FILENAME,
        contents: GITLEAKS_TOML,
        executable: false,
        mode: None,
        strip_line: false,
    },
    TemplateFile {
        dest: ".claude/hooks/scrub-check.sh",
        contents: include_str!("../template/claude-hooks/scrub-check.sh"),
        executable: true,
        mode: Some("hook"),
        strip_line: false,
    },
    TemplateFile {
        dest: ".githooks/pre-commit",
        contents: include_str!("../template/githooks/pre-commit"),
        executable: true,
        mode: Some("staged"),
        strip_line: true,
    },
    TemplateFile {
        dest: ".githooks/pre-push",
        contents: include_str!("../template/githooks/pre-push"),
        executable: true,
        mode: Some("range"),
        strip_line: false,
    },
];

/// The Claude Code PreToolUse stanza a repo merges into `.claude/settings.json`.
pub const SETTINGS_STANZA: &str = include_str!("../template/settings-hooks.json");

/// The pre-commit line that keeps a linked worktree's `GIT_DIR` and
/// `GIT_INDEX_FILE` out of the project's checks. Without it, every
/// git-spawning test run from such a commit targets the real repo instead of
/// its fixture.
pub const STRIP_LINE: &str = r#"for var in $(compgen -v GIT_ || true); do unset "$var"; done"#;

pub const HOOKS_PATH: &str = ".githooks";

const GITIGNORE: &str = ".gitignore";

/// Whether `content` has a line invoking `brenn-scrub <mode>` (or the
/// `brenn-scrub -- <mode>` form a `bazel run` wrapper produces).
///
/// A line counts when, after leading whitespace, it does not begin with `#`,
/// and the invocation is followed by end-of-line or a character outside
/// `[A-Za-z0-9_-]`. This is a plain line scan and a drift guard, not a shell
/// parser: a non-comment line that merely quotes the invocation counts.
pub fn invocation_present(content: &str, mode: &str) -> bool {
    let forms = [
        format!("brenn-scrub {mode}"),
        format!("brenn-scrub -- {mode}"),
    ];
    content.split('\n').any(|line| {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim_start().starts_with('#') {
            return false;
        }
        forms.iter().any(|form| {
            line.match_indices(form.as_str()).any(|(at, _)| {
                line[at + form.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            })
        })
    })
}

/// Whether the strip line is present as an exact whole line, with no
/// whitespace trimming.
pub fn has_strip_line(content: &str) -> bool {
    content.split('\n').any(|line| line == STRIP_LINE)
}

/// Whether a `.gitignore` ignores the overlay file by name: the last line
/// naming it, bare or `/`-anchored, is not a `!` negation.
///
/// Each line is read as git reads a pattern: trailing spaces are dropped, and
/// leading whitespace is part of the pattern, so an indented line names some
/// other path.
pub fn gitignore_names_overlay(content: &str) -> bool {
    let anchored = format!("/{OVERLAY_FILENAME}");
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim_end_matches(' ');
            let (ignores, pattern) = match line.strip_prefix('!') {
                Some(negated) => (false, negated),
                None => (true, line),
            };
            (pattern == OVERLAY_FILENAME || pattern == anchored).then_some(ignores)
        })
        .next_back()
        .unwrap_or(false)
}

/// The rule keys a consumer may change: a rule's description is prose, and
/// its allowlists are where a repo exempts its own paths.
const CONSUMER_RULE_KEYS: &[&str] = &["description", "allowlists"];

/// How a consumer's rule file differs from the template in what the gate
/// enforces, one message per difference; empty when rule-equal.
///
/// Compared: the `[extend]` table, the set of rule ids, and every key of each
/// rule other than `description` and `allowlists`. Everything else -- `title`,
/// a rule's allowlists, a top-level `[allowlist]` -- belongs to the consumer.
pub fn rule_drift(template: &str, consumer: &str) -> Vec<String> {
    let template: Table = toml::from_str(template).expect("the built-in template parses");
    let consumer: Table = match toml::from_str(consumer) {
        Ok(t) => t,
        Err(e) => return vec![format!("is not valid TOML: {}", e.message())],
    };

    let mut drift = Vec::new();
    if template.get("extend") != consumer.get("extend") {
        drift.push("[extend] differs from the template".to_string());
    }
    let ours = rules_by_id(&template).expect("the built-in template's rules are well-formed");
    let theirs = match rules_by_id(&consumer) {
        Ok(rules) => rules,
        Err(problem) => {
            drift.push(problem);
            return drift;
        }
    };
    for id in ours.keys().filter(|id| !theirs.contains_key(*id)) {
        drift.push(format!("rule `{id}` is missing"));
    }
    for id in theirs.keys().filter(|id| !ours.contains_key(*id)) {
        drift.push(format!(
            "rule `{id}` is not in the template; rules are added upstream, not per repo"
        ));
    }
    for (id, our_rule) in &ours {
        let Some(their_rule) = theirs.get(id) else {
            continue;
        };
        let mut keys: Vec<&String> = our_rule.keys().chain(their_rule.keys()).collect();
        keys.sort();
        keys.dedup();
        for key in keys {
            if CONSUMER_RULE_KEYS.contains(&key.as_str()) {
                continue;
            }
            match (our_rule.get(key), their_rule.get(key)) {
                (Some(a), Some(b)) if a == b => {}
                (Some(_), Some(_)) => {
                    drift.push(format!("rule `{id}`: `{key}` differs from the template"))
                }
                (Some(_), None) => drift.push(format!("rule `{id}`: `{key}` is missing")),
                (None, _) => drift.push(format!("rule `{id}`: `{key}` is not in the template")),
            }
        }
    }
    drift
}

/// The `[[rules]]` array keyed by id. A rule without a string id, a duplicate
/// id, or a `rules` key that is not an array of tables makes the file
/// incomparable, reported as one message.
fn rules_by_id(table: &Table) -> Result<BTreeMap<String, &Table>, String> {
    let mut rules = BTreeMap::new();
    let Some(value) = table.get("rules") else {
        return Ok(rules);
    };
    let Value::Array(entries) = value else {
        return Err("`rules` is not an array of tables".to_string());
    };
    for entry in entries {
        let Value::Table(rule) = entry else {
            return Err("`rules` is not an array of tables".to_string());
        };
        let Some(Value::String(id)) = rule.get("id") else {
            return Err("a rule has no string `id`".to_string());
        };
        if rules.insert(id.clone(), rule).is_some() {
            return Err(format!("rule `{id}` is defined more than once"));
        }
    }
    Ok(rules)
}

/// What a repo is missing for the gate, one message per failure, each led by
/// the file or setting it concerns. `under_ci` skips the hooks-path check: a
/// CI checkout runs no git hooks by design.
pub fn check(repo: &Path, under_ci: bool) -> Vec<String> {
    let mut failures = Vec::new();
    for file in FILES {
        let content = match std::fs::read_to_string(repo.join(file.dest)) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                failures.push(format!("{}: missing; run `brenn-scrub init`", file.dest));
                continue;
            }
            Err(e) => {
                failures.push(format!("{}: cannot be read: {e}", file.dest));
                continue;
            }
        };
        match file.mode {
            None => failures.extend(
                rule_drift(file.contents, &content)
                    .into_iter()
                    .map(|d| format!("{}: {d}", file.dest)),
            ),
            Some(mode) => {
                if !invocation_present(&content, mode) {
                    failures.push(format!(
                        "{}: no line invokes `brenn-scrub {mode}` (comment lines do not count)",
                        file.dest
                    ));
                }
            }
        }
        if file.executable && !is_executable(&repo.join(file.dest)) {
            failures.push(not_executable_message(file.dest));
        }
        if file.strip_line && !has_strip_line(&content) {
            failures.push(format!(
                "{}: does not carry the GIT_* strip line `{STRIP_LINE}` as a whole line; a \
                 commit from a linked worktree would run the project's checks with GIT_DIR \
                 set, and git-spawning tests would target the real repo instead of their \
                 fixtures",
                file.dest
            ));
        }
    }

    match std::fs::read_to_string(repo.join(GITIGNORE)) {
        Ok(c) if gitignore_names_overlay(&c) => {}
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            failures.push(format!("{GITIGNORE}: cannot be read: {e}"))
        }
        Ok(_) | Err(_) => failures.push(format!(
            "{GITIGNORE}: does not ignore {OVERLAY_FILENAME} by name, so a local overlay \
             could be committed"
        )),
    }
    if !git::run(repo, &["ls-files", "--", OVERLAY_FILENAME]).is_empty() {
        failures.push(tracked_overlay_message());
    }

    if !under_ci {
        let found = git::config_get(repo, "core.hooksPath");
        if found.as_deref() != Some(HOOKS_PATH) {
            failures.push(format!(
                "core.hooksPath is {}, not {HOOKS_PATH}; commits and pushes in this clone skip \
                 the scrub gate. Run `brenn-scrub init`",
                found.map_or_else(|| "unset".to_string(), |v| format!("`{v}`"))
            ));
        }
    }
    failures
}

/// Lay the kit into `repo`: every absent template file, the overlay line in
/// `.gitignore`, and `core.hooksPath`. An existing file is never written.
/// Prints the settings stanza to stdout and everything else to stderr, and
/// reports a missing or off-pin gitleaks without failing.
pub fn lay_down(repo: &Path) {
    for file in FILES {
        lay_file(repo, file);
    }
    ensure_gitignore(repo);
    set_hooks_path(repo);

    eprintln!(
        "brenn-scrub init: merge this PreToolUse stanza into .claude/settings.json \
         (init never edits that file):"
    );
    print!("{SETTINGS_STANZA}");

    if let Err(msg) = Version::require_pinned() {
        eprintln!("brenn-scrub init: {msg}");
    }
}

fn lay_file(repo: &Path, file: &TemplateFile) {
    let dest = repo.join(file.dest);
    // `symlink_metadata`, so a dangling symlink counts as present and is never
    // written through.
    if std::fs::symlink_metadata(&dest).is_ok() {
        let same = std::fs::read(&dest).is_ok_and(|bytes| bytes == file.contents.as_bytes());
        if !same {
            eprintln!("{}", differs_message(file.dest));
        }
        if file.executable && !is_executable(&dest) {
            eprintln!("brenn-scrub init: {}", not_executable_message(file.dest));
        }
        return;
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", parent.display()));
    }
    std::fs::write(&dest, file.contents)
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", dest.display()));
    if file.executable {
        make_executable(&dest);
    }
    eprintln!("brenn-scrub init: wrote {}", file.dest);
}

fn differs_message(dest: &str) -> String {
    format!(
        "brenn-scrub init: {dest} exists and differs from the template; left as is. \
         Delete it and re-run `init` to take the template."
    )
}

fn not_executable_message(dest: &str) -> String {
    format!(
        "{dest}: not executable, so git and Claude Code skip it. Run `chmod +x {dest}` and \
         commit the mode"
    )
}

fn tracked_overlay_message() -> String {
    format!(
        "{OVERLAY_FILENAME}: tracked, so its private terms are in the repo. Run `git rm \
         --cached {OVERLAY_FILENAME}` and keep it out of history"
    )
}

/// Whether any execute bit is set on `path`, following a symlink; a path that
/// cannot be read counts as not executable.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("cannot chmod {}: {e}", path.display()));
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

fn ensure_gitignore(repo: &Path) {
    let path = repo.join(GITIGNORE);
    let existing = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    };
    if gitignore_names_overlay(&existing) {
        return;
    }
    let separator = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    std::fs::write(&path, format!("{existing}{separator}{OVERLAY_FILENAME}\n"))
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
    eprintln!("brenn-scrub init: added {OVERLAY_FILENAME} to {GITIGNORE}");
}

/// Point git at the tracked hooks and remove the stock-location pre-commit,
/// which `core.hooksPath` would otherwise leave behind unseen.
fn set_hooks_path(repo: &Path) {
    git::run(repo, &["config", "core.hooksPath", HOOKS_PATH]);
    // The common dir, not `--git-path hooks/...`: git resolves that through
    // `core.hooksPath`, which would name the tracked hook just laid down.
    let common = git::run(repo, &["rev-parse", "--git-common-dir"]);
    let common = repo.join(common.strip_suffix('\n').unwrap_or(&common));
    let stock = common.join("hooks").join("pre-commit");
    if std::fs::symlink_metadata(&stock).is_ok() {
        std::fs::remove_file(&stock)
            .unwrap_or_else(|e| panic!("cannot remove {}: {e}", stock.display()));
        eprintln!("brenn-scrub init: removed {}", stock.display());
    }
    eprintln!("brenn-scrub init: core.hooksPath set to {HOOKS_PATH}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_matcher_takes_each_shape_the_fleet_uses() {
        assert!(invocation_present("exec brenn-scrub hook\n", "hook"));
        assert!(invocation_present("brenn-scrub staged\n", "staged"));
        assert!(invocation_present(
            "    if ! brenn-scrub staged; then\n",
            "staged"
        ));
        assert!(invocation_present(
            "printf '%s\\n' \"$refs\" | brenn-scrub range",
            "range"
        ));
        assert!(invocation_present(
            "echo \"pre-commit: running brenn-scrub staged\"",
            "staged"
        ));
        assert!(invocation_present(
            "bazel run //tools/scrub:brenn-scrub -- staged\n",
            "staged"
        ));
        assert!(invocation_present("\tbrenn-scrub range\r\n", "range"));
    }

    #[test]
    fn the_matcher_rejects_comments_wrong_modes_and_longer_words() {
        assert!(!invocation_present("# exec brenn-scrub hook\n", "hook"));
        assert!(!invocation_present("   # brenn-scrub staged\n", "staged"));
        assert!(!invocation_present("brenn-scrub staged-x\n", "staged"));
        assert!(!invocation_present("brenn-scrub -- staged-x\n", "staged"));
        assert!(!invocation_present("brenn-scrub staged_x\n", "staged"));
        assert!(!invocation_present("brenn-scrub stagedx\n", "staged"));
        assert!(!invocation_present("exec brenn-scrub range\n", "staged"));
        assert!(!invocation_present("", "hook"));
    }

    /// One occurrence followed by a word character must not hide a later
    /// valid one on the same line.
    #[test]
    fn the_matcher_considers_every_occurrence_on_a_line() {
        assert!(invocation_present(
            "brenn-scrub staged-x || brenn-scrub staged",
            "staged"
        ));
    }

    #[test]
    fn the_strip_line_must_be_exact_and_whole() {
        assert!(has_strip_line(&format!(
            "set -e\n{STRIP_LINE}\nmake check\n"
        )));
        assert!(!has_strip_line(&format!("    {STRIP_LINE}\n")));
        assert!(!has_strip_line(&format!("{STRIP_LINE} # trailing\n")));
        assert!(!has_strip_line(&format!("# {STRIP_LINE}\n")));
        assert!(!has_strip_line("set -e\n"));
    }

    #[test]
    fn the_template_carries_everything_check_requires() {
        for file in FILES {
            if let Some(mode) = file.mode {
                assert!(invocation_present(file.contents, mode), "{}", file.dest);
            }
        }
        let carriers: Vec<_> = FILES.iter().filter(|f| f.strip_line).collect();
        assert_eq!(carriers.len(), 1, "exactly one file carries the strip line");
        assert_eq!(carriers[0].dest, ".githooks/pre-commit");
        assert!(has_strip_line(carriers[0].contents));
        assert!(rule_drift(GITLEAKS_TOML, GITLEAKS_TOML).is_empty());
    }

    #[test]
    fn the_settings_stanza_is_the_pre_tool_use_scrub_hook() {
        let stanza: serde_json::Value =
            serde_json::from_str(SETTINGS_STANZA).expect("stanza is JSON");
        let entry = &stanza["hooks"]["PreToolUse"][0];
        assert_eq!(entry["matcher"], "Write|Edit");
        assert!(
            entry["hooks"][0]["command"]
                .as_str()
                .expect("command")
                .ends_with(".claude/hooks/scrub-check.sh")
        );
    }

    #[test]
    fn gitignore_names_the_overlay_on_its_own_line() {
        assert!(gitignore_names_overlay("/target\n.gitleaks.local.toml\n"));
        assert!(gitignore_names_overlay("/.gitleaks.local.toml"));
        assert!(gitignore_names_overlay(".gitleaks.local.toml  \n"));
        assert!(!gitignore_names_overlay("  .gitleaks.local.toml\n"));
        assert!(!gitignore_names_overlay("\t.gitleaks.local.toml\n"));
        assert!(!gitignore_names_overlay("# .gitleaks.local.toml\n"));
        assert!(!gitignore_names_overlay(".gitleaks.local.toml.bak\n"));
        assert!(!gitignore_names_overlay(""));
    }

    #[test]
    fn the_last_line_naming_the_overlay_decides() {
        assert!(!gitignore_names_overlay(
            ".gitleaks.local.toml\n!.gitleaks.local.toml\n"
        ));
        assert!(!gitignore_names_overlay(
            "/.gitleaks.local.toml\n!/.gitleaks.local.toml\n"
        ));
        assert!(gitignore_names_overlay(
            "!.gitleaks.local.toml\n.gitleaks.local.toml\n"
        ));
        assert!(!gitignore_names_overlay("!.gitleaks.local.toml\n"));
    }

    const BASE: &str = r#"
title = "rules"

[extend]
useDefault = true

[[rules]]
id = "one"
description = "first"
regex = 'aaa'
keywords = ["a"]

  [[rules.allowlists]]
  paths = ['\.md$']

[[rules]]
id = "two"
regex = 'bbb'
"#;

    fn drift_of(consumer: &str) -> Vec<String> {
        rule_drift(BASE, consumer)
    }

    #[test]
    fn consumer_owned_parts_may_differ() {
        assert!(drift_of(BASE).is_empty());
        assert!(drift_of(&BASE.replace("title = \"rules\"", "title = \"mine\"")).is_empty());
        assert!(
            drift_of(&BASE.replace("description = \"first\"", "description = \"x\"")).is_empty()
        );
        assert!(
            drift_of(&BASE.replace("  [[rules.allowlists]]\n  paths = ['\\.md$']\n", ""))
                .is_empty(),
            "an allowlist removed"
        );
        let added = BASE.replace(
            "[[rules]]\nid = \"two\"",
            "  [[rules.allowlists]]\n  paths = ['^vendor/']\n\n[[rules]]\nid = \"two\"",
        );
        assert!(drift_of(&added).is_empty(), "an allowlist added");
        let top_level = format!("{BASE}\n[allowlist]\npaths = ['^fixtures/']\n");
        assert!(drift_of(&top_level).is_empty(), "a top-level allowlist");
    }

    #[test]
    fn extend_must_match() {
        let drift = drift_of(&BASE.replace("useDefault = true", "useDefault = false"));
        assert_eq!(drift, ["[extend] differs from the template"]);
        let drift = drift_of(&BASE.replace("[extend]\nuseDefault = true\n", ""));
        assert_eq!(drift, ["[extend] differs from the template"]);
    }

    #[test]
    fn a_missing_or_extra_rule_is_named() {
        let missing = BASE.replace("[[rules]]\nid = \"two\"\nregex = 'bbb'\n", "");
        assert_eq!(drift_of(&missing), ["rule `two` is missing"]);
        let extra = format!("{BASE}\n[[rules]]\nid = \"three\"\nregex = 'ccc'\n");
        let drift = drift_of(&extra);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].starts_with("rule `three` is not in the template"));
    }

    #[test]
    fn an_enforced_key_change_names_the_rule_and_key() {
        assert_eq!(
            drift_of(&BASE.replace("regex = 'aaa'", "regex = 'zzz'")),
            ["rule `one`: `regex` differs from the template"]
        );
        assert_eq!(
            drift_of(&BASE.replace("keywords = [\"a\"]", "keywords = [\"a\", \"b\"]")),
            ["rule `one`: `keywords` differs from the template"]
        );
        assert_eq!(
            drift_of(&BASE.replace("keywords = [\"a\"]\n", "")),
            ["rule `one`: `keywords` is missing"]
        );
        assert_eq!(
            drift_of(&BASE.replace("regex = 'bbb'", "regex = 'bbb'\nentropy = 3.0")),
            ["rule `two`: `entropy` is not in the template"]
        );
    }

    #[test]
    fn an_incomparable_rule_file_is_one_named_failure() {
        let drift = drift_of("this is = = not toml");
        assert_eq!(drift.len(), 1);
        assert!(drift[0].starts_with("is not valid TOML"), "{drift:?}");
        let duplicate = format!("{BASE}\n[[rules]]\nid = \"two\"\nregex = 'bbb'\n");
        assert_eq!(
            drift_of(&duplicate),
            ["rule `two` is defined more than once"]
        );
        let no_id = BASE.replace("id = \"two\"\n", "");
        assert_eq!(drift_of(&no_id), ["a rule has no string `id`"]);
        for rules in ["rules = \"x\"\n", "rules = [1]\n"] {
            assert_eq!(
                drift_of(&format!("{rules}[extend]\nuseDefault = true\n")),
                ["`rules` is not an array of tables"],
                "{rules}"
            );
        }
    }

    #[test]
    fn every_message_this_module_emits_is_neutral() {
        use crate::message::neutral::assert_neutral;
        assert_neutral(&differs_message(".githooks/pre-commit"), "differs message");
        assert_neutral(
            &not_executable_message(".githooks/pre-commit"),
            "not-executable message",
        );
        assert_neutral(&tracked_overlay_message(), "tracked-overlay message");
        let dir = tempfile::tempdir().expect("temp dir");
        brenn_git_fixture::init_repo(dir.path());
        for failure in check(dir.path(), true) {
            assert_neutral(&failure, "check failure");
        }
        assert_neutral(SETTINGS_STANZA, "settings stanza");
    }
}
