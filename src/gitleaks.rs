//! Invoking gitleaks and interpreting its JSON report.
//!
//! gitleaks is the only scanning engine. This module never reimplements a
//! rule; it prepares arguments, runs the binary, and parses the report.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

/// Release this wrapper's CLI and config surface was validated against.
pub const PINNED_VERSION: &str = "8.30.0";

/// The section-symbol-reference rule id, shared by the tree filter and the rejection
/// message so the two cannot drift apart.
pub const EPHEMERAL_RULE: &str = "ephemeral-reference";

/// Rules enforced on diffs only. Tree scans drop findings with these ids:
/// the grandfathered backlog would otherwise make every tree scan permanently
/// red, while every diff-scanning layer still enforces them from day one.
pub const DIFF_ONLY_RULES: &[&str] = &[EPHEMERAL_RULE];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Finding {
    #[serde(rename = "RuleID")]
    pub rule_id: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "StartLine")]
    pub start_line: i64,
    #[serde(rename = "File")]
    pub file: String,
    #[serde(rename = "Match")]
    pub matched: String,
    #[serde(rename = "Commit", default)]
    pub commit: String,
}

impl Finding {
    /// `file:line` plus the commit when the scan was history-based.
    pub fn location(&self) -> String {
        if self.commit.is_empty() {
            format!("{}:{}", self.file, self.start_line)
        } else {
            format!(
                "{}:{} (commit {})",
                self.file, self.start_line, &self.commit
            )
        }
    }
}

/// Drop findings whose rule is diff-only. Expressed as a subtraction from the
/// full resolved config: narrowing the rule set gitleaks runs would silently
/// disable built-in and overlay rules too.
pub fn apply_tree_filter(findings: Vec<Finding>) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| !DIFF_ONLY_RULES.contains(&f.rule_id.as_str()))
        .collect()
}

/// Rewrite absolute scan paths as paths relative to the mirror root, so
/// reports name the file the user recognizes rather than a temp dir.
pub fn relativize(findings: Vec<Finding>, root: &Path) -> Vec<Finding> {
    findings
        .into_iter()
        .map(|mut f| {
            if let Ok(rel) = Path::new(&f.file).strip_prefix(root) {
                f.file = rel.to_string_lossy().into_owned();
            }
            f
        })
        .collect()
}

pub fn parse_report(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    serde_json::from_str(trimmed).expect("gitleaks emitted a report this wrapper cannot parse")
}

#[derive(Debug, PartialEq, Eq)]
pub enum Version {
    Match,
    Mismatch(String),
    Missing,
}

impl Version {
    pub fn detect() -> Version {
        let Ok(out) = Command::new("gitleaks").arg("version").output() else {
            return Version::Missing;
        };
        if !out.status.success() {
            return Version::Missing;
        }
        let found = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if found == PINNED_VERSION {
            Version::Match
        } else {
            Version::Mismatch(found)
        }
    }

    /// The pinned gitleaks is on `PATH`, or the message saying what is wrong
    /// instead. Callers decide whether that message is fatal.
    pub fn require_pinned() -> Result<(), String> {
        match Version::detect() {
            Version::Match => Ok(()),
            Version::Mismatch(found) => Err(Version::mismatch_message(&found)),
            Version::Missing => Err(Version::missing_message()),
        }
    }

    /// User-facing error for a missing gitleaks binary, naming the pinned release to install.
    pub fn missing_message() -> String {
        format!(
            "gitleaks not found on PATH. Install release {PINNED_VERSION} from \
             https://github.com/gitleaks/gitleaks/releases/tag/v{PINNED_VERSION} so scrub \
             checks can run."
        )
    }

    pub fn mismatch_message(found: &str) -> String {
        format!(
            "gitleaks version mismatch: found {found}, this wrapper is pinned to \
             {PINNED_VERSION}. Install the pinned release, or re-validate the wrapper \
             against the newer one and move the pin."
        )
    }
}

/// Shared flags. `--exit-code 0` makes leaks a *reporting* outcome rather than
/// a process failure, so any nonzero exit is an actual gitleaks malfunction
/// and gets to panic. In git mode exit 0 is not proof the `git log` gitleaks
/// ran completed; `scan_git` settles that from stderr.
fn base_args(config: &Path) -> Vec<String> {
    vec![
        "--config".into(),
        config.to_string_lossy().into_owned(),
        "--report-format".into(),
        "json".into(),
        "--report-path".into(),
        "-".into(),
        "--no-banner".into(),
        "--exit-code".into(),
        "0".into(),
        "--log-level".into(),
        "error".into(),
    ]
}

/// Run gitleaks and return its raw stdout and stderr, unparsed. A nonzero
/// exit panics with the stderr text.
fn run(args: &[String], cwd: Option<&Path>) -> (String, String) {
    let mut cmd = Command::new("gitleaks");
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let out = cmd.output().expect("failed to execute gitleaks");
    if !out.status.success() {
        panic!(
            "gitleaks exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Scan a directory tree. Findings carry absolute paths under `dir`.
pub fn scan_dir(config: &Path, dir: &Path) -> Vec<Finding> {
    let mut args = vec!["dir".to_string()];
    args.extend(base_args(config));
    args.push(dir.to_string_lossy().into_owned());
    let (stdout, _stderr) = run(&args, None);
    parse_report(&stdout)
}

/// A git-mode scan gitleaks finished without finishing the `git log` it
/// ran: exit 0 with text on its stderr. `git_output` is that stderr,
/// verbatim and colourless.
#[derive(Debug, PartialEq, Eq)]
pub struct IncompleteScan {
    pub git_output: String,
}

/// Exit-0 interpretation of a git-mode run. Pinned gitleaks 8.30.0 exits 0
/// whenever its `git log` wrote to stderr, whether git died or merely
/// traced, and its report then covers only what git emitted first --
/// usually nothing, sometimes a few findings. The report is not evidence
/// either way; stderr is. Any byte refuses: a healthy run writes none (the
/// real-engine tests in tests/modes.rs hold that). A `git log` killed
/// without writing to stderr is not detected: gitleaks logs git's exit
/// status only at debug level.
fn complete_git_report(stdout: &str, stderr: &str) -> Result<Vec<Finding>, IncompleteScan> {
    if !stderr.is_empty() {
        return Err(IncompleteScan {
            git_output: stderr.to_string(),
        });
    }
    Ok(parse_report(stdout))
}

/// Scan commit history. `log_opts` is passed to `git log` by gitleaks. `Err`
/// when gitleaks reports success but its `git log` did not run cleanly.
pub fn scan_git(
    config: &Path,
    repo: &Path,
    log_opts: &str,
) -> Result<Vec<Finding>, IncompleteScan> {
    let mut args = vec!["git".to_string()];
    args.extend(base_args(config));
    args.push("--no-color".into());
    args.push(format!("--log-opts={log_opts}"));
    args.push(repo.to_string_lossy().into_owned());
    let (stdout, stderr) = run(&args, Some(repo));
    complete_git_report(&stdout, &stderr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            description: "d".into(),
            start_line: 7,
            file: "/tmp/mirror/src/a.rs".into(),
            matched: "m".into(),
            commit: String::new(),
        }
    }

    #[test]
    fn tree_filter_drops_only_diff_only_rules() {
        let input = vec![
            finding("ephemeral-reference"),
            finding("local-rule-a"),
            finding("generic-api-key"),
            finding("example-host"),
        ];
        let kept = apply_tree_filter(input);
        let ids: Vec<&str> = kept.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(ids, vec!["local-rule-a", "generic-api-key", "example-host"]);
    }

    #[test]
    fn tree_filter_keeps_everything_when_no_diff_only_hits() {
        let input = vec![finding("local-rule-a"), finding("local-rule-b")];
        assert_eq!(apply_tree_filter(input.clone()), input);
    }

    #[test]
    fn tree_filter_can_empty_the_list() {
        assert!(apply_tree_filter(vec![finding("ephemeral-reference")]).is_empty());
    }

    #[test]
    fn relativize_strips_the_mirror_root() {
        let out = relativize(vec![finding("local-rule-a")], Path::new("/tmp/mirror"));
        assert_eq!(out[0].file, "src/a.rs");
    }

    #[test]
    fn relativize_leaves_unrelated_paths_alone() {
        let out = relativize(vec![finding("local-rule-a")], Path::new("/other/root"));
        assert_eq!(out[0].file, "/tmp/mirror/src/a.rs");
    }

    #[test]
    fn empty_report_parses_as_no_findings() {
        assert!(parse_report("").is_empty());
        assert!(parse_report("   \n").is_empty());
        assert!(parse_report("[]").is_empty());
    }

    #[test]
    fn report_parses_the_fields_the_wrapper_uses() {
        let json = concat!(
            r#"[{"RuleID":"ephemeral-reference","Description":"sec ref","StartLine":1,"#,
            r#""EndLine":1,"StartColumn":11,"EndColumn":12,"Match":"§","Secret":"§","#, // gitleaks:allow
            r#""File":"/m/src/a.rs","SymlinkFile":"","Commit":"","Entropy":0.5,"#,
            r#""Author":"","Email":"","Date":"","Message":"","Tags":[],"Fingerprint":"f"}]"#,
        );
        let findings = parse_report(json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "ephemeral-reference");
        assert_eq!(findings[0].start_line, 1);
        assert_eq!(findings[0].file, "/m/src/a.rs");
    }

    const ONE_FINDING: &str = concat!(
        r#"[{"RuleID":"local-rule-a","Description":"d","StartLine":3,"#,
        r#""Match":"m","File":"src/old.rs","Commit":"abc"}]"#,
    );

    #[test]
    fn a_silent_git_run_yields_its_report() {
        assert_eq!(complete_git_report("[]", ""), Ok(Vec::new()));
        let found = complete_git_report(ONE_FINDING, "").expect("complete");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "local-rule-a");
    }

    #[test]
    fn any_stderr_marks_the_git_scan_incomplete() {
        assert_eq!(
            complete_git_report("[]", "x"),
            Err(IncompleteScan {
                git_output: "x".into()
            })
        );
        assert_eq!(
            complete_git_report("[]", "\n"),
            Err(IncompleteScan {
                git_output: "\n".into()
            })
        );
    }

    #[test]
    fn a_non_empty_report_does_not_rescue_an_incomplete_scan() {
        let stderr = "ERR [git] fatal: unable to read abc\n";
        assert_eq!(
            complete_git_report(ONE_FINDING, stderr),
            Err(IncompleteScan {
                git_output: stderr.into()
            })
        );
    }

    #[test]
    fn location_names_the_commit_only_for_history_scans() {
        let mut f = finding("local-rule-a");
        assert_eq!(f.location(), "/tmp/mirror/src/a.rs:7");
        f.commit = "abc123".into();
        assert!(f.location().contains("commit abc123"));
    }

    #[test]
    fn mismatch_message_names_both_versions() {
        let msg = Version::mismatch_message("8.29.0");
        assert!(msg.contains("8.29.0"));
        assert!(msg.contains(PINNED_VERSION));
    }

    #[test]
    fn missing_message_names_the_pinned_release() {
        let msg = Version::missing_message();
        assert!(msg.contains(&format!("release {PINNED_VERSION}")), "{msg}");
        assert!(
            msg.contains(&format!("/releases/tag/v{PINNED_VERSION}")),
            "{msg}"
        );
    }
}
