//! Rejection messages.
//!
//! This is the education channel: on a blocked write the text below is the
//! only thing the author sees, so it names what matched, leads with the
//! preferred fix, and states both exemption mechanisms in the order they
//! should be reached for. It reports rule ids, never the matching regex, so an
//! overlay's rule definitions are not restated in its own failure output.

use crate::gitleaks::{EPHEMERAL_RULE, Finding};

fn ladder() -> String {
    [
        "How to resolve, in order of preference:",
        "  1. Rewrite the string. Use generic names -- alice, bob, charlie, ACME Co.,",
        "     example.com. Prefer this; every exemption is permanent review burden.",
        "  2. Contextual allowlist. For site-local rules this belongs in the local",
        "     overlay, not in tracked code -- ask a maintainer. An inline marker in",
        "     tracked code restates which rule matched here.",
        "  3. Inline `gitleaks:allow` on the offending line, where a context regex would",
        "     be awkward. Add the marker in the SAME COMMIT that introduces the",
        "     tolerated string -- pushed-range scans read every commit's diff, so a",
        "     marker added later still fails on the earlier commit.",
    ]
    .join("\n")
}

fn history_remedy() -> String {
    [
        "These strings are in past commits. Editing the tree, or adding a marker or an",
        "allowlist now, does not remove them from those commits: an allowlist only",
        "accepts them as published. For each finding, either:",
        "  - accept it -- it is safe to publish as it stands; or",
        "  - rewrite the history (amend, rebase or squash, or start a fresh root)",
        "    before publishing, then run `brenn-scrub history` again.",
    ]
    .join("\n")
}

fn message_remedy() -> String {
    [
        "For a finding in a commit message:",
        "  The string is in the commit itself; editing the tree does not change it.",
        "  Reword the message (amend, or rebase and reword) before pushing, or put",
        "  `gitleaks:allow` on that line of the message, or add a contextual allowlist",
        "  rule. The marker must be in the message as pushed.",
    ]
    .join("\n")
}

fn ephemeral_note() -> String {
    [
        "Section-symbol references to design and ADR docs rot: those docs are ephemeral",
        "point-in-time artifacts, not ground truth. Cite stable published specs or",
        "in-tree docs instead, or just describe what the code does.",
    ]
    .join("\n")
}

/// The neutrality tripwire, shared by every module that ships emitted prose.
///
/// The one-shot audit that removed private-context vocabulary from shipped
/// strings only stays true if something fails when it comes back, and the
/// strings most likely to be pasted into a public issue are help text and error
/// lines, not just this module's output.
#[cfg(test)]
pub mod neutral {
    /// Vocabulary that would tell a reader who runs this tooling or what it
    /// guards. Emitted text describes the mechanism only.
    pub const BANNED_TERMS: &[&str] = &[
        // Written as a join so this file does not itself contain the term.
        concat!("house", "hold"),
        "personal",
        "family",
        "the owner",
        "owner machine",
        "private denylist",
        "private rule",
        "private overlay",
    ];

    pub fn assert_neutral(text: &str, what: &str) {
        let lower = text.to_lowercase();
        for term in BANNED_TERMS {
            assert!(
                !lower.contains(term),
                "{what} contains private-context term {term:?}"
            );
        }
    }
}

/// Format findings for a blocked write or a failed gate. The fix-forward
/// ladder is for findings in content; a finding in a commit message gets the
/// reword remedy instead, after the ladder when both kinds are present.
pub fn rejection(findings: &[Finding], heading: &str) -> String {
    let mut out = listing(findings, heading);
    let in_content = findings.iter().any(|f| !f.in_message);
    let in_message = findings.iter().any(|f| f.in_message);
    if in_content {
        out.push_str(&ladder());
    }
    if in_message {
        if in_content {
            out.push_str("\n\n");
        }
        out.push_str(&message_remedy());
    }

    if findings.iter().any(|f| f.rule_id == EPHEMERAL_RULE) {
        out.push_str("\n\n");
        out.push_str(&ephemeral_note());
    }
    out
}

/// Format findings of the whole-history audit. They are already committed, so
/// the remedies are accepting them or rewriting history, not the fix-forward
/// ladder.
pub fn history_rejection(findings: &[Finding]) -> String {
    let mut out = listing(findings, "brenn-scrub found matches in the commit history.");
    out.push_str(&history_remedy());
    out
}

/// The heading, then one entry per finding, then a blank line.
fn listing(findings: &[Finding], heading: &str) -> String {
    let mut out = String::new();
    out.push_str(heading);
    out.push_str("\n\n");

    for f in findings {
        out.push_str(&format!(
            "  [{}] {} at {}\n      matched: {}\n",
            f.rule_id,
            f.description,
            f.location(),
            f.matched
        ));
    }

    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            description: "a description".into(),
            start_line: 12,
            file: "src/a.rs".into(),
            matched: "matched-text".into(),
            commit: String::new(),
            in_message: false,
        }
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn message_finding(rule: &str) -> Finding {
        Finding {
            file: String::new(),
            commit: SHA.into(),
            in_message: true,
            ..finding(rule)
        }
    }

    #[test]
    fn a_message_only_rejection_gets_the_reword_remedy_not_the_ladder() {
        let msg = rejection(&[message_finding("local-rule-a")], "Blocked.");
        assert!(
            msg.contains(&format!("commit {SHA}, message line 12")),
            "{msg}"
        );
        assert!(msg.contains("For a finding in a commit message"), "{msg}");
        assert!(msg.contains("Reword the message"), "{msg}");
        assert!(!msg.contains("How to resolve"), "{msg}");
    }

    #[test]
    fn a_content_only_rejection_gets_the_ladder_not_the_reword_remedy() {
        let msg = rejection(&[finding("local-rule-a")], "Blocked.");
        assert!(msg.contains("How to resolve"), "{msg}");
        assert!(!msg.contains("For a finding in a commit message"), "{msg}");
    }

    /// `hook` and `staged` never produce a message finding; their text must
    /// be exactly the listing and the ladder.
    #[test]
    fn a_content_only_rejection_is_the_listing_and_the_ladder() {
        let findings = [finding("local-rule-a")];
        assert_eq!(
            rejection(&findings, "Blocked."),
            format!("{}{}", listing(&findings, "Blocked."), ladder())
        );
    }

    #[test]
    fn a_mixed_rejection_gives_the_ladder_then_the_reword_remedy() {
        let msg = rejection(
            &[finding("local-rule-a"), message_finding("local-rule-b")],
            "Blocked.",
        );
        let ladder_at = msg.find("How to resolve").expect("ladder missing");
        let remedy_at = msg
            .find("For a finding in a commit message")
            .expect("remedy missing");
        assert!(ladder_at < remedy_at, "{msg}");
        assert!(
            msg.contains("\n\nFor a finding in a commit message"),
            "{msg}"
        );
    }

    #[test]
    fn a_message_rejection_still_gets_the_ephemeral_note() {
        let msg = rejection(
            &[message_finding("local-rule-a"), finding(EPHEMERAL_RULE)],
            "Blocked.",
        );
        assert!(msg.contains("For a finding in a commit message"), "{msg}");
        assert!(msg.contains("ADR docs rot"), "{msg}");
    }

    #[test]
    fn history_rejection_names_a_message_finding_by_commit_and_line() {
        let msg = history_rejection(&[message_finding("local-rule-a")]);
        assert!(
            msg.contains(&format!("commit {SHA}, message line")),
            "{msg}"
        );
        assert!(msg.contains("rewrite the history"), "{msg}");
    }

    #[test]
    fn names_the_rule_and_location() {
        let msg = rejection(&[finding("local-rule-a")], "Blocked.");
        assert!(msg.starts_with("Blocked."));
        assert!(msg.contains("[local-rule-a]"));
        assert!(msg.contains("src/a.rs:12"));
        assert!(msg.contains("matched-text"));
    }

    #[test]
    fn contains_the_three_option_exemption_ladder_in_order() {
        let msg = rejection(&[finding("local-rule-a")], "Blocked.");
        let rewrite = msg.find("Rewrite the string").expect("option 1 missing");
        let allowlist = msg.find("Contextual allowlist").expect("option 2 missing");
        let inline = msg.find("gitleaks:allow").expect("option 3 missing");
        assert!(
            rewrite < allowlist && allowlist < inline,
            "ladder must be in preference order"
        );
    }

    #[test]
    fn states_the_same_commit_marker_rule() {
        let msg = rejection(&[finding("local-rule-a")], "Blocked.");
        assert!(msg.contains("SAME COMMIT"));
    }

    #[test]
    fn states_the_generic_names_inline() {
        let msg = rejection(&[finding("local-rule-a")], "Blocked.");
        assert!(msg.contains("alice, bob, charlie, ACME Co.,"));
        assert!(
            !msg.contains("docs/"),
            "the consumer's tree has no docs of ours to point at: {msg}"
        );
    }

    #[test]
    fn adds_the_ephemeral_note_only_for_ephemeral_hits() {
        let plain = rejection(&[finding("local-rule-a")], "Blocked.");
        assert!(!plain.contains("ADR docs rot"));

        let ephemeral = rejection(&[finding(EPHEMERAL_RULE)], "Blocked.");
        assert!(ephemeral.contains("ADR docs rot"));
        assert!(!ephemeral.contains("comment-standard"));
    }

    #[test]
    fn mixed_findings_still_get_the_ephemeral_note() {
        let msg = rejection(
            &[finding("local-rule-a"), finding(EPHEMERAL_RULE)],
            "Blocked.",
        );
        assert!(msg.contains("ADR docs rot"));
        assert!(msg.contains("[local-rule-a]"));
    }

    #[test]
    fn never_leaks_a_regex() {
        let msg = rejection(&[finding("local-rule-a")], "Blocked.");
        assert!(!msg.contains("(?i)"));
    }

    #[test]
    fn history_gives_history_remedies_not_the_ladder() {
        let msg = history_rejection(&[finding("local-rule-a")]);
        assert!(msg.starts_with("brenn-scrub found matches in the commit history."));
        assert!(msg.contains("[local-rule-a]"));
        assert!(msg.contains("rewrite the history"));
        assert!(!msg.contains("Rewrite the string"));
        assert!(!msg.contains("How to resolve"));
    }

    use super::neutral::assert_neutral;

    #[test]
    fn every_message_variant_is_neutral() {
        assert_neutral(&ladder(), "ladder");
        assert_neutral(&ephemeral_note(), "ephemeral note");
        assert_neutral(&history_remedy(), "history remedy");
        assert_neutral(&message_remedy(), "message remedy");
        assert_neutral(
            &rejection(&[message_finding("local-rule-a")], "Blocked."),
            "message rejection",
        );
        assert_neutral(
            &rejection(
                &[finding("local-rule-a"), message_finding("local-rule-b")],
                "Blocked.",
            ),
            "mixed content and message rejection",
        );
        assert_neutral(
            &history_rejection(&[message_finding("local-rule-a")]),
            "history rejection of a message finding",
        );
        assert_neutral(
            &history_rejection(&[finding("local-rule-a")]),
            "history rejection",
        );
        assert_neutral(
            &rejection(&[finding("local-rule-a")], "Blocked."),
            "plain rejection",
        );
        assert_neutral(
            &rejection(&[finding(EPHEMERAL_RULE)], "Blocked."),
            "section-ref rejection",
        );
        assert_neutral(
            &rejection(
                &[finding("local-rule-a"), finding(EPHEMERAL_RULE)],
                "Blocked.",
            ),
            "mixed rejection",
        );
    }
}
