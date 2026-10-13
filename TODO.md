# TODOs

Deferred work, one `## \`slug\`` entry per item, joined by slug to the
`TODO(slug)` comment where the work belongs. This file ships publicly.

## `forgejo-tree-scan`

`.github/workflows/tree-scan.yml` serves GitHub-hosted consumers only; a
Forgejo-hosted repository cannot call it. Write a Forgejo copy-in workflow
body with the same steps (pinned gitleaks download with sha256 check,
`cargo install --locked brenn-scrub --version <X.Y.Z>`, `brenn-scrub init
--check`, `brenn-scrub tree`) when a Forgejo-hosted repository adopts the
scrub gate, and hold its pins to the same values as the GitHub workflow.

## `silent-git-kill-in-diff-walk`

A `git log` that gitleaks runs for `range` or `history` and that is killed
without writing to stderr (the OOM killer, a memory cap, an external
timeout) still reads as a clean or partial scan: gitleaks 8.30.0 reports
git's exit status only at debug level, and `complete_git_report` in
`src/gitleaks.rs` detects an incomplete walk from stderr alone.

## `binary-sniff-skips-mirrored-files`

gitleaks 8.30.0 `dir` skips, without a word and whatever the file's name,
any file whose bytes sniff as a known binary format (`MZ`, `%PDF`, `BZh`,
`PK\x03\x04`, `%!` and the like at the start; `ustar`, `DICM` and others at
fixed interior offsets). No `dir` flag disables it. `--max-archive-depth`,
which brenn-scrub does not pass, makes gitleaks open archives it identifies
by file extension (zip, tar and gzip verified) and scan their contents;
other sniffed files, and archives without such an extension, stay skipped.
Every mirror scan passes through `scan_mirror` in `src/main.rs` and so
through that sniff: `hook`, `staged`, `tree`, `range`'s tip-tree scan and
the commit-message scan. A tracked text file
that happens to start with such bytes, and any secret inside a real binary,
is therefore never scanned by the commit gate, the push gate's tip-tree
scan or `tree`, and nothing reports the skip. The newline lead
(`MESSAGE_LEAD`, `src/gitleaks.rs`) mitigates this for commit messages
only. Open decision: whether such files should be scanned, skipped loudly,
or skipped with the limitation stated in `--help`, the README and the
CHANGELOG, and what the pinned gitleaks allows.
