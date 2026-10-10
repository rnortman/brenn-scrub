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
