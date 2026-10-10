# brenn-scrub

A secrets gate for git repositories, built on one pinned
[gitleaks](https://github.com/gitleaks/gitleaks) release. The same rules run
at four points:

| Mode | When | Input |
|---|---|---|
| `hook` | before a Claude Code `Write`/`Edit` lands | the PreToolUse event JSON on stdin |
| `staged` | pre-commit | none; scans the staged diff |
| `range` | pre-push | the git pre-push protocol on stdin |
| `tree` | by hand and in CI | none; scans every tracked file |

and one more verb, `init [--check]`, lays the hook shims and rule file into
a repository and verifies them. `brenn-scrub <mode> --help` documents each
mode's input, scope and exit codes.

## Install

```sh
cargo install --locked brenn-scrub
```

`--locked` builds against the dependency versions the release was tested
with. brenn-scrub needs gitleaks **8.30.0** on `PATH`, exactly that release;
it will not scan with any other version, and says which one it wants:
<https://github.com/gitleaks/gitleaks/releases/tag/v8.30.0>.

A Bazel repository can skip both installs: `recipes/bazel/` builds the crate
and fetches gitleaks hermetically (see "CI" below).

## Set up a repository

From inside the repository:

```sh
brenn-scrub init
```

This lays down, where absent:

| File | Role |
|---|---|
| `.gitleaks.toml` | the public rules |
| `.claude/hooks/scrub-check.sh` | runs `brenn-scrub hook` |
| `.githooks/pre-commit` | runs `brenn-scrub staged`, then `make check` if the repo has that target |
| `.githooks/pre-push` | runs `brenn-scrub range` |

It also adds `.gitleaks.local.toml` to `.gitignore`, sets `core.hooksPath`
to `.githooks`, and prints the PreToolUse stanza to merge into
`.claude/settings.json` (it never edits that file). A formatter or any other
Claude Code hook is the repository's own business.

`init` never overwrites. A file that exists and differs from the template is
named on stderr; to take the template, delete the file and re-run `init`.
There is no `--force`, so a bespoke hook is never clobbered.

Before activating the hooks, get `brenn-scrub tree` green: `pre-push` is
enforcing, and a finding blocks the push.

### Keeping it in place: `init --check`

Add `brenn-scrub init --check` to the repository's `check` target. It writes
nothing and exits 1, naming every failure, unless:

- each hook shim has a line, not a `#` comment, invoking its mode —
  `brenn-scrub hook`, `brenn-scrub staged`, `brenn-scrub range`, or the
  `brenn-scrub -- <mode>` form a `bazel run` wrapper gives. The prose around
  that line is the repository's; a bespoke hook body passes as long as it
  calls the binary;
- `.githooks/pre-commit` carries the `GIT_*` strip line exactly as the
  template has it. Without it, a commit from a linked worktree runs the
  project's checks with `GIT_DIR`/`GIT_INDEX_FILE` set, and any test that
  spawns git mutates the real repository;
- `.gitleaks.toml` has the template's `[extend]` table and the same rules,
  key for key. `title`, rule descriptions, a rule's `allowlists` and a
  top-level `[allowlist]` are the repository's own. Rules belong upstream,
  in this crate's template;
- each shim is executable; git and Claude Code skip one that is not;
- `.gitignore` ignores `.gitleaks.local.toml` by name: the last line naming
  it, with trailing spaces dropped as git drops them, is not a `!` negation,
  and the overlay is not tracked;
- `core.hooksPath` is `.githooks` (not checked when `CI` is set).

The reference is the template built into the running binary, so the check
always agrees with the hooks that binary serves.

## How the gate decides

The write-time `hook` decides which repository a write belongs to from the
write *destination*, not from the session's working directory. A destination
inside a gated repository — a git repository with a `.gitleaks.toml` at its
root — is scanned against that repository's config, at its repo-relative
path. A destination outside any gated repository is not the gate's concern:
it exits 0 with an audit line on stderr. The commit and push gates still scan
everything that lands in a gated repository, so nothing reaches a remote
unscanned. One hook registration is therefore safe from any session.

## Running it by hand

Two modes are meant for a human, and neither reads stdin:

- `brenn-scrub staged` scans what is staged right now, as the pre-commit
  hook does.
- `brenn-scrub tree` scans every tracked file, and is the one a green
  repository is declared on. `brenn-scrub tree <path>` narrows it to a
  subtree; `--exclude <prefix>` (repeatable) skips a repo-relative prefix,
  names each exclusion on stderr, and fails if a prefix matches no tracked
  file. Its stdout is a JSON object of the findings and the exclusions that
  produced them: capture it as a worklist.

`hook` and `range` consume protocols produced by Claude Code and by git, and
refuse to run with a terminal on stdin.

## A site-local overlay

Rules that must not be published — names, hosts, anything specific to one
site — go in an overlay, never in `.gitleaks.toml`. brenn-scrub discovers
one, first hit wins:

1. the file named by `BRENN_SCRUB_DENYLIST` (set but missing is fatal);
2. `.gitleaks.local.toml` at the repository root (gitignored; a dangling
   symlink is fatal);
3. none: the scan runs the public rules only, silently.

The overlay holds rules only, no `[extend]`. brenn-scrub synthesizes the
layering per invocation, extending the current repository's
`.gitleaks.toml`, so one overlay file can serve every repository. CI has no
overlay, so CI scans run the public rules.

## CI

**Cargo repositories (GitHub Actions).** Call the reusable workflow at an
exact release tag:

```yaml
jobs:
  scrub:
    uses: rnortman/brenn-scrub/.github/workflows/tree-scan.yml@v0.1.0
```

It installs this release and the gitleaks release it pins (verified by sha256),
then runs `brenn-scrub init --check` and `brenn-scrub tree` on the caller's
checkout. The check reports as `scrub / tree-scan`: a job that calls a
reusable workflow reports as `<caller job> / <called job>`, so that is the
string a branch ruleset must require. Move the tag when you move your local
install.

**Bazel repositories.** `recipes/bazel/` is a standalone Bazel module to
transcribe into your own `MODULE.bazel` and a `tools/scrub/` package. It
builds brenn-scrub from crates.io with your Rust toolchain and fetches
gitleaks by sha256; `bazel run //tools/scrub:brenn-scrub -- tree` and
`-- init --check` then go in `check` and in CI, with nothing installed. Its
README covers scoping the crate hub and pinning it.

## Development

```sh
make setup-hooks   # lay this repo's own kit with the binary this checkout builds
make check         # msrv, fmt, clippy, test, init --check — what CI and pre-commit run
```

The scan-reaching tests need gitleaks 8.30.0, from `PATH` or from the path
in `BRENN_SCRUB_TEST_GITLEAKS`. Without it they skip. With `CI` set they
fail instead, and `BRENN_SCRUB_TEST_GITLEAKS` is required.

Releases: bump `package.version` in `Cargo.toml`, the `--version` in
`.github/workflows/tree-scan.yml`, the `crate.spec` version in
`recipes/bazel/MODULE.bazel` and `CHANGELOG.md` together (`tests/pins.rs`
fails the commit if one lags); tag `vX.Y.Z`; push the tag once CI is green;
`cargo publish`; then dispatch CI on the tag, whose `release-smoke` jobs
install the published crate through both the workflow and the Bazel recipe.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
