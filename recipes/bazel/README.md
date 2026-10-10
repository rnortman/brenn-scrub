# Bazel recipe: brenn-scrub with no local install

This directory is a complete, standalone Bazel module that builds
`brenn-scrub` from crates.io with the module's own Rust toolchain, fetches
the gitleaks release it pins by sha256, and runs the binary with that
gitleaks first on `PATH`. A repository whose checks and CI are a Bazel graph
gets the scrub gate with no `cargo install` and nothing on the developer's
`PATH`: the same bytes on every machine and in CI.

It is files to copy, not a module to depend on. The hub builds the very
crate crates.io serves, with one pin: the `crate.spec` version.

| File | What it is |
|---|---|
| `MODULE.bazel` | The `scrub_crates` hub (`crate.spec`, `crate.annotation`, `crate.from_specs`) and the two gitleaks `http_archive`s. |
| `BUILD.bazel` | The `gitleaks` platform alias and the `brenn-scrub` `sh_binary` wrapper. |
| `gitleaks.BUILD.bazel` | Build file for an unpacked gitleaks release archive. |
| `scrub.sh` | The wrapper: resolves both binaries through runfiles, puts gitleaks first on `PATH`, `cd`s to where `bazel run` was invoked, `exec`s brenn-scrub. |
| `.bazelversion` | The Bazel this module was proven with. |

## Transcribing it

Into your repository's own `MODULE.bazel`:

- The `bazel_dep`s you do not already have (`platforms`, `rules_rust`,
  `rules_shell`). Keep your own Rust toolchain registration; drop this
  module's `module()` and `rust.toolchain` if you have them already. The
  crate needs Rust 1.95 or newer (its `rust-version`).
- The `crate.spec`, `crate.annotation`, `crate.from_specs` and `use_repo`
  lines for `scrub_crates`, with **every** `repositories` attribute kept
  (see "Scoping" below), and the hub pinned the way your other hubs are (see
  "Pinning").
- The gitleaks block: `GITLEAKS_VERSION`, both sha256s and both
  `http_archive`s, with `build_file` pointing at the package you copy the
  rest into — `//tools/scrub:gitleaks.BUILD.bazel`.

Into a `tools/scrub/` package: `BUILD.bazel`, `gitleaks.BUILD.bazel` and
`scrub.sh` (executable). The wrapper is then `//tools/scrub:brenn-scrub`.

Only linux x86_64 and linux aarch64 are pinned. Another platform needs its
own `http_archive` and a branch in the `gitleaks` `select()`.

## Scoping: every `crate.spec` in the module carries `repositories`

rules_rust applies a `crate.spec` without `repositories` to **every** hub
the module declares, `from_cargo` hubs included (rules_rust 0.73.0
`crate_universe/extensions.bzl:1116-1125` sorts unscoped specs into the
common set, `:1197` feeds that set into each hub, and the attribute's doc at
`:1519-1521` says "Defaults to all repositories"). So:

- The recipe's `repositories = ["scrub_crates"]` is not optional. Without it
  brenn-scrub and its dependencies join your workspace hub's resolution and
  feature unification, and churn that hub's pin on every scrub bump.
- If your module already has a hub with unscoped `crate.spec` tags, give
  each of them `repositories = ["<your hub>"]` before adding this one, or
  they flow into `scrub_crates`.

Nothing in this module can detect a leak, because it declares only one hub.
After transcribing, check that your main hub's pin did not change: its
cargo-bazel `lockfile` diff is empty, or, if it is pinned by
`MODULE.bazel.lock`, every `generatedRepoSpecs` key under your hub's prefix
is byte-identical to before and every new key is prefixed `scrub_crates`.

## Pinning: in your tree, the way your main hub is pinned

This module ships no lockfile. `crate.from_specs(name = "scrub_crates")` has
no `lockfile` and no `cargo_lockfile`, so here the hub resolves on every
fetch. A lock made in this module could not serve you anyway: the
cargo-bazel digest covers the rules_rust, cargo and rustc versions and the
rendered configuration, so it fails in any module whose toolchain or
rules_rust differs.

Pin the new hub exactly as your main hub is pinned — same attributes, same
command — on transcription and again on every version bump:

- **Hubs that carry `lockfile` and `cargo_lockfile`.** Give the transcribed
  `from_specs` both:

  ```starlark
  crate.from_specs(
      name = "scrub_crates",
      cargo_lockfile = "//tools/scrub:Cargo.lock",
      lockfile = "//tools/scrub:cargo-bazel-lock.json",
  )
  ```

  Create both files empty (rules_rust requires each to exist), then run
  `CARGO_BAZEL_REPIN=1 bazel mod deps`, which fills both. A stale lock then
  fails the build with rules_rust's digest-mismatch error naming that
  command. Set both attributes, not `lockfile` alone: the `crate` extension
  reports itself reproducible only if every hub carries both, and one hub
  missing either makes Bazel write every hub's full rendering into
  `MODULE.bazel.lock`. The only files the pin should touch are the two under
  `tools/scrub/`.
- **Modules pinned by a tracked `MODULE.bazel.lock`.** Transcribe
  `from_specs` as it is here and commit the `MODULE.bazel.lock` change the
  first `bazel` command produces. CI running with `--lockfile_mode=error`
  then refuses a resolution nobody committed.

If you never pin, `brenn-scrub` is still the exact `crate.spec` version, but
its four dependencies float to whatever cargo resolves on each clean fetch,
and a cargo-bazel `lockfile` module has nothing to catch that. Pin on
transcription.

## Running it

```sh
bazel run //tools/scrub:brenn-scrub -- init --check
bazel run //tools/scrub:brenn-scrub -- tree
```

Put those two in your `check` target and your CI's Bazel job; they replace
any hand-rolled gitleaks download and scan. The other modes work the same
way (`-- staged`, `-- range`, `-- hook`); stdin passes through.

The wrapper needs `BUILD_WORKING_DIRECTORY`, which `bazel run` sets to the
directory you invoked it from. Run from `bazel-bin` by hand, it exits 1
rather than scan the runfiles tree.

The git and Claude Code hooks are your call. A `bazel run` costs the Bazel
client's connect-and-analyse on every commit and every write, and a cold
server can exceed Claude Code's hook timeout. Either point the shims at
`bazel run //tools/scrub:brenn-scrub -- <mode>` and install nothing, or keep
`cargo install --locked brenn-scrub` for the hooks alone and still get a
hermetic `check` and CI. `brenn-scrub init --check` accepts both spellings
of the invocation: the target is named `brenn-scrub` so that `bazel run
//tools/scrub:brenn-scrub -- staged` contains `brenn-scrub -- staged`.

## Bumping

Move the `crate.spec` version and, when the crate's gitleaks pin moves,
`GITLEAKS_VERSION` and both sha256s, together; then repin. Each brenn-scrub
`CHANGELOG.md` entry names its gitleaks version. A gitleaks that is not the
crate's pinned release is fatal at every brenn-scrub gate, so a lagging pin
fails loudly on the first `bazel run` and never scans with an unvalidated
engine.
