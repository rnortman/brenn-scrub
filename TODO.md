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

## `security-history-scan-skips-commit-messages-and-merges`

gitleaks' git mode scans patches only, so neither `history` nor `range`
reads commit messages, and `range` passes `git log` no `--diff-merges`, so a
pushed merge's conflict resolution goes unscanned too (`history` scans it
with `--diff-merges=remerge`). Scanning messages takes a second pass beside
gitleaks' git mode (each `git log --format` record through `gitleaks
stdin`, say) and settles which rules apply to message text, how a message
finding names its commit, and whether the pre-push gate blocks on a message,
which changes the gate for every consumer.
