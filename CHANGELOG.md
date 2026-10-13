# Changelog

Notable changes to brenn-scrub. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-10-13

### Added

- New `brenn-scrub history` mode: an audit of a repository's entire commit
  history, meant to be run by hand before a repository whose history was
  private is published. The existing `tree` mode only checks files as they
  are now, so a secret committed and later deleted passes it; `history`
  checks every commit reachable from any branch or tag, with every rule, and
  names the commit each finding came from. Merge commits are checked for
  what they change beyond git's automatic merge (such as a hand-made
  conflict resolution), and every commit's message is checked too, a
  finding there naming its commit and line. Because its findings are
  already committed, its advice is to accept each one or rewrite the history before publishing,
  rather than to edit the files. Exits 0 when clean, 1 otherwise.
  Requires git 2.36 or later.

### Changed

- The pre-push check (`range`) now blocks a push on text in a pushed
  commit's message and on what a pushed merge changes beyond git's automatic
  merge (such as a hand-made conflict resolution); before, it saw neither.
  A finding in a message names its commit and line, and the advice is to
  reword the message (amend, or rebase and reword) before pushing. `range`
  now requires git 2.36 or later: an older git refuses the push with a
  message naming that floor. The pre-push hook runs whichever `brenn-scrub`
  is on `PATH`, so updating the binary is enough to pick this up; the Bazel
  recipe picks it up when its pinned version is bumped.

### Fixed

- The pre-push check (`range`) could pass a push it had not fully scanned.
  If the `git log` that gitleaks runs internally failed or wrote anything to
  stderr — a damaged repository, a broken ref, or a setting such as
  `GIT_TRACE` in the hook's environment — gitleaks still reported success
  with only the commits git reached, often none. `range` and the new
  `history` now refuse such a scan with exit 1 and a "scan did not complete"
  message quoting git's output. `--warn-only` does not soften this: it lets
  findings through, not an unscanned push. The pre-push hook runs whichever
  `brenn-scrub` is on `PATH`, so updating the binary is enough to pick this
  up.

### Known limitations

- A merge with three or more parents (an octopus merge) contributes no
  diff of its own in `range` or `history`; its message and the other
  commits are still scanned. A finding in a merge's own resolution names
  the path with git's `b/` prefix.
- gitleaks 8.30.0 skips, without a word, a file whose bytes sniff as a
  binary format. A commit message is scanned whatever its subject starts
  with, but one whose bytes match a format signature at an interior offset
  gitleaks checks (tar's `ustar` or DICOM's `DICM`, for example) is still
  skipped.
- A `git log` killed without writing to stderr (by the OOM killer, a memory
  cap, or an external timeout) still reads as a clean or partial scan in
  `range` and `history`: gitleaks 8.30.0 reports git's exit status only at
  debug level, which brenn-scrub does not enable.

## [0.1.0] — 2026-10-10

First public release, pinned to gitleaks 8.30.0. The tool was developed
inside the [brenn](https://github.com/rnortman/brenn) repository as `scrub`;
this repository starts from an import of that source.

brenn-scrub runs one pinned gitleaks release with one set of rules at every
point a secret could enter a repository: before an AI agent's file write
lands, at commit, at push, and over the whole tracked tree.

### Added

- `hook`, `staged`, `range` and `tree` modes: the Claude Code PreToolUse
  write gate, the pre-commit and pre-push gates, and the full tracked-file
  sweep, each documented by `brenn-scrub <mode> --help`.
- `init [--check] [<repo>]`: lays the hook shims and `.gitleaks.toml` from a
  template built into the binary, adds the overlay to `.gitignore`, sets
  `core.hooksPath`, and prints the Claude Code settings stanza; `--check`
  verifies each shim's invocation line and executable bit, the pre-commit
  `GIT_*` strip line, rule equality with the template, the `.gitignore`
  entry, that the overlay is untracked, and `core.hooksPath`.
- `.github/workflows/tree-scan.yml`: a reusable workflow that runs
  `init --check` and `tree` in a consumer's CI.
- `recipes/bazel/`: a Bazel module that builds the crate from crates.io and
  fetches gitleaks by sha256, so a Bazel repository runs the gate with
  nothing installed.

### Changed from brenn's `scrub`

- New `init` verb; the template that used to be copied by hand from brenn's
  `scrub/repo-template/` is embedded in the binary. The kit no longer
  includes `format.sh` or `setup-hooks.sh`.
- `src/lib.rs` is new: a library target holding only a doc comment, so that
  Bazel's crate_universe can depend on the package (cargo drops a dependency
  on a binary-only crate). It has no public items.
- The missing-gitleaks message names the pinned release and its download
  page instead of a brenn `make` target.
- The template's Claude Code hook says `cargo install --locked brenn-scrub`
  when the binary is missing, instead of pointing at a brenn checkout.
- Rejection messages no longer point at a brenn-internal comment-standard
  document; the guidance is stated inline.
