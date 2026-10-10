# Changelog

Notable changes to brenn-scrub. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
