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

## `prebuilt-release-binaries`

`tree-scan.yml` builds brenn-scrub with `cargo install` on every consumer CI
run. Attaching prebuilt, checksummed release binaries to each GitHub release
and downloading one in the workflow would cut that build from the job.

## `security-history-scan-skips-commit-messages-and-merges`

gitleaks' git mode scans patches only, so neither `history` nor `range`
reads commit messages, and `range` passes `git log` no `--diff-merges`, so a
pushed merge's conflict resolution goes unscanned too (`history` scans it
with `--diff-merges=remerge`). Scanning messages takes a second pass beside
gitleaks' git mode (each `git log --format` record through `gitleaks
stdin`, say) and settles which rules apply to message text, how a message
finding names its commit, and whether the pre-push gate blocks on a message,
which changes the gate for every consumer.

## `security-git-scan-passes-when-git-log-fails`

When the `git log` gitleaks 8.30.0 runs fails, gitleaks still exits 0. It
reports what it parsed from the commits git emitted before the failure,
which may be none, drops the rest without saying so, and writes the git
error and `error="stderr is not empty"` to its own stderr. brenn-scrub
reads gitleaks' stderr only on a non-zero exit, so every `scan_git` caller
takes a scan that stopped part way, or never started, as complete: `range`
passes a push, and `history` lists only the findings in the newer commits
it reached, or prints `clean`. Fixing those findings does not help: the
rerun stops at the same point. `history` probes `git log -n0` with its
options first (`git::accepts_log_opts`), which catches a git that rejects
the option string (git before 2.36 and `--diff-merges=remerge`) and nothing
else; a `git log` that fails while walking or building patches — a damaged
object store, for one — passes the probe and then passes the scan. `range`
has no probe, and one would not help it: its arguments are shas git
produced or verified. A zero exit from gitleaks, or a non-empty report, is
not evidence that the walk ran or finished; gitleaks' stderr is, and `run`
already captures it. Closing this means reading it in `run` or `scan_git`,
and deciding what `range --warn-only` does when it fires, since refusing a
push changes the gate for every consumer.
