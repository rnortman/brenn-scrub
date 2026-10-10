//! Pin coherence across the files a release moves together.
//!
//! The gitleaks pin lives in `src/gitleaks.rs` and is restated in the test
//! harness, in every workflow that downloads gitleaks and in the Bazel
//! recipe's `MODULE.bazel`; the crate version lives in `Cargo.toml` and is
//! restated in `tree-scan.yml`'s install step and the recipe's `crate.spec`.
//! A release that moves one and not the others fails here, on the commit that
//! makes it.
//!
//! The recipe's hub shape is held here too: its `crate.spec` is scoped to its
//! own hub and the hub carries no lock attribute. So is the library target,
//! which must stay a doc comment with no items.

mod common;

use std::path::PathBuf;

const RECIPE: &str = "recipes/bazel/MODULE.bazel";

const WORKFLOWS: &[&str] = &[
    ".github/workflows/ci.yml",
    ".github/workflows/tree-scan.yml",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let path = root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The string literal assigned on the line declaring `const <name>`.
fn const_str(source: &str, name: &str) -> String {
    let decl = format!("const {name}: &str = \"");
    let mut hits = source.lines().filter_map(|line| {
        let rest = &line[line.find(&decl)? + decl.len()..];
        Some(rest[..rest.find('"')?].to_string())
    });
    let value = hits.next().unwrap_or_else(|| panic!("no `{decl}` line"));
    assert!(hits.next().is_none(), "more than one `{decl}` line");
    value
}

fn pinned_version() -> String {
    const_str(&read("src/gitleaks.rs"), "PINNED_VERSION")
}

fn crate_version() -> String {
    let manifest: toml::Table = read("Cargo.toml").parse().expect("Cargo.toml parses");
    manifest["package"]["version"]
        .as_str()
        .expect("package.version is a string")
        .to_string()
}

/// Every value of a YAML `key: value` line, after leading whitespace, with the
/// line number it sits on.
fn yaml_values(text: &str, key: &str) -> Vec<(usize, String)> {
    let prefix = format!("{key}:");
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let value = line.trim_start().strip_prefix(&prefix)?;
            Some((i + 1, value.trim().to_string()))
        })
        .collect()
}

/// The argument after `--version` on each non-comment line that runs
/// `cargo install` of brenn-scrub.
fn install_versions(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let line = line.trim_start();
            !line.starts_with('#') && line.contains("cargo install") && line.contains("brenn-scrub")
        })
        .map(|(i, line)| {
            let mut words = line.split_whitespace();
            let version = words
                .by_ref()
                .find(|w| *w == "--version")
                .and_then(|_| words.next())
                .unwrap_or_else(|| panic!("line {}: cargo install without --version", i + 1));
            (i + 1, version.to_string())
        })
        .collect()
}

/// The argument text of every call to `name(...)` that opens on a
/// non-comment line, parentheses balanced, string literals skipped.
fn starlark_calls(text: &str, name: &str) -> Vec<String> {
    let open = format!("{name}(");
    let mut calls = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let body = line.trim_start();
        let at_start = offset + (line.len() - body.len());
        offset += line.len();
        if body.starts_with('#') || !body.starts_with(&open) {
            continue;
        }
        let args_start = at_start + open.len();
        let mut depth = 1;
        let mut in_str = false;
        let mut end = None;
        for (i, c) in text[args_start..].char_indices() {
            match c {
                '"' => in_str = !in_str,
                '(' if !in_str => depth += 1,
                ')' if !in_str => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(args_start + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.unwrap_or_else(|| panic!("unbalanced `{open}`"));
        calls.push(text[args_start..end].to_string());
    }
    calls
}

/// The text after `key =` for a keyword argument named exactly `key`, if the
/// call has one.
fn kwarg<'a>(args: &'a str, key: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(i) = args[from..].find(key) {
        let at = from + i;
        from = at + key.len();
        let before_ok = args[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        let rest = args[from..].trim_start();
        if before_ok && let Some(value) = rest.strip_prefix('=') {
            return Some(value.trim_start());
        }
    }
    None
}

/// The string literal a keyword argument is set to.
fn kwarg_str(args: &str, key: &str) -> Option<String> {
    let value = kwarg(args, key)?.strip_prefix('"')?;
    Some(value[..value.find('"')?].to_string())
}

/// The string literals in the list a keyword argument is set to.
fn kwarg_list(args: &str, key: &str) -> Option<Vec<String>> {
    let value = kwarg(args, key)?.strip_prefix('[')?;
    let list = &value[..value.find(']')?];
    Some(
        list.split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| item.trim_matches('"').to_string())
            .collect(),
    )
}

/// The string literal assigned by a top-level `NAME = "..."` line.
fn starlark_assign(text: &str, name: &str) -> String {
    let prefix = format!("{name} = \"");
    let mut hits = text.lines().filter_map(|line| {
        let rest = line.strip_prefix(&prefix)?;
        Some(rest[..rest.find('"')?].to_string())
    });
    let value = hits
        .next()
        .unwrap_or_else(|| panic!("{RECIPE}: no `{name} = \"...\"` line"));
    assert!(
        hits.next().is_none(),
        "{RECIPE}: more than one `{name}` line"
    );
    value
}

fn recipe_spec() -> String {
    let specs = starlark_calls(&read(RECIPE), "crate.spec");
    assert_eq!(
        specs.len(),
        1,
        "{RECIPE}: expected one crate.spec, found {specs:?}"
    );
    let spec = specs.into_iter().next().unwrap();
    assert_eq!(
        kwarg_str(&spec, "package").as_deref(),
        Some("brenn-scrub"),
        "{RECIPE}: the crate.spec is not for brenn-scrub"
    );
    spec
}

#[test]
fn harness_mirror_matches_the_pin() {
    assert_eq!(common::PINNED_VERSION, pinned_version());
}

#[test]
fn every_workflow_downloads_the_pinned_gitleaks() {
    let pin = pinned_version();
    for rel in WORKFLOWS {
        let versions = yaml_values(&read(rel), "GITLEAKS_VERSION");
        assert!(!versions.is_empty(), "{rel}: no GITLEAKS_VERSION");
        for (line, version) in versions {
            assert_eq!(
                version, pin,
                "{rel}:{line}: GITLEAKS_VERSION is not PINNED_VERSION"
            );
        }
    }
}

#[test]
fn every_workflow_verifies_one_gitleaks_sha256() {
    let mut seen: Vec<(String, usize, String)> = Vec::new();
    for rel in WORKFLOWS {
        let hashes = yaml_values(&read(rel), "GITLEAKS_SHA256");
        assert!(!hashes.is_empty(), "{rel}: no GITLEAKS_SHA256");
        for (line, hash) in hashes {
            assert!(
                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "{rel}:{line}: GITLEAKS_SHA256 {hash:?} is not a sha256"
            );
            seen.push((rel.to_string(), line, hash));
        }
    }
    let (first_rel, first_line, first) = &seen[0];
    for (rel, line, hash) in &seen[1..] {
        assert_eq!(
            hash, first,
            "{rel}:{line} and {first_rel}:{first_line} verify different gitleaks archives"
        );
    }
}

#[test]
fn tree_scan_installs_this_crate_version() {
    let rel = ".github/workflows/tree-scan.yml";
    let installs = install_versions(&read(rel));
    assert_eq!(
        installs.len(),
        1,
        "{rel}: expected one brenn-scrub install, found {installs:?}"
    );
    let (line, version) = &installs[0];
    assert_eq!(
        *version,
        crate_version(),
        "{rel}:{line}: installs brenn-scrub {version}, Cargo.toml is at {}",
        crate_version()
    );
}

#[test]
fn ci_runs_release_smoke_through_tree_scan() {
    let text = read(".github/workflows/ci.yml");
    assert!(
        text.lines()
            .any(|l| l.trim() == "uses: ./.github/workflows/tree-scan.yml"),
        "ci.yml: no job calls ./.github/workflows/tree-scan.yml"
    );
}

#[test]
fn recipe_fetches_the_pinned_gitleaks() {
    let text = read(RECIPE);
    assert_eq!(
        starlark_assign(&text, "GITLEAKS_VERSION"),
        pinned_version(),
        "{RECIPE}: GITLEAKS_VERSION is not PINNED_VERSION"
    );
    let recipe_x86_64 = starlark_assign(&text, "GITLEAKS_SHA256_X86_64");
    for rel in WORKFLOWS {
        for (line, hash) in yaml_values(&read(rel), "GITLEAKS_SHA256") {
            assert_eq!(
                hash, recipe_x86_64,
                "{rel}:{line} and {RECIPE} verify different x86_64 gitleaks archives"
            );
        }
    }
}

#[test]
fn recipe_spec_pins_this_crate_version() {
    let version = kwarg_str(&recipe_spec(), "version")
        .unwrap_or_else(|| panic!("{RECIPE}: crate.spec has no version"));
    assert_eq!(
        version,
        format!("={}", crate_version()),
        "{RECIPE}: crate.spec version is not `=` Cargo.toml's package.version"
    );
}

#[test]
fn recipe_spec_is_scoped_to_its_hub() {
    assert_eq!(
        kwarg_list(&recipe_spec(), "repositories"),
        Some(vec!["scrub_crates".to_string()]),
        "{RECIPE}: crate.spec must carry repositories = [\"scrub_crates\"]; an unscoped spec joins every hub"
    );
}

#[test]
fn recipe_hub_carries_no_lock() {
    let hubs = starlark_calls(&read(RECIPE), "crate.from_specs");
    let hub = hubs
        .iter()
        .find(|args| kwarg_str(args, "name").as_deref() == Some("scrub_crates"))
        .unwrap_or_else(|| panic!("{RECIPE}: no crate.from_specs(name = \"scrub_crates\")"));
    for attr in ["lockfile", "cargo_lockfile"] {
        assert!(
            kwarg(hub, attr).is_none(),
            "{RECIPE}: the scrub_crates hub carries `{attr}`; the recipe ships no lock, the consumer pins in its own tree"
        );
    }
}

#[test]
fn library_target_has_no_items() {
    let text = read("src/lib.rs");
    for (i, line) in text.lines().enumerate() {
        assert!(
            line.trim().is_empty() || line.starts_with("//!"),
            "src/lib.rs:{}: only `//!` doc lines and blank lines belong here; the crate offers no Rust API",
            i + 1
        );
    }
}

#[test]
fn starlark_calls_balance_and_skip_comments() {
    let text = "# crate.spec(package = \"x\")\ncrate.spec(\n    package = \"a(b\",\n    v = f(1),\n)\nother()\n";
    assert_eq!(
        starlark_calls(text, "crate.spec"),
        vec!["\n    package = \"a(b\",\n    v = f(1),\n".to_string()]
    );
}

#[test]
fn kwarg_matches_whole_names_only() {
    let args = "name = \"hub\", cargo_lockfile = \"//:Cargo.lock\", repositories = [\"a\", \"b\"]";
    assert!(kwarg(args, "lockfile").is_none());
    assert_eq!(
        kwarg_str(args, "cargo_lockfile").as_deref(),
        Some("//:Cargo.lock")
    );
    assert_eq!(kwarg_str(args, "name").as_deref(), Some("hub"));
    assert_eq!(
        kwarg_list(args, "repositories"),
        Some(vec!["a".to_string(), "b".to_string()])
    );
}

#[test]
fn install_versions_reads_the_flag_argument() {
    let text = "# cargo install brenn-scrub --version 9.9.9\n  run: |\n    cargo install --locked brenn-scrub --version 1.2.3 --root x\n";
    assert_eq!(install_versions(text), vec![(3, "1.2.3".to_string())]);
}

#[test]
fn yaml_values_strip_indent_and_key() {
    let text = "env:\n  GITLEAKS_VERSION: 1.0.0\n  OTHER: x\n";
    assert_eq!(
        yaml_values(text, "GITLEAKS_VERSION"),
        vec![(2, "1.0.0".to_string())]
    );
}

#[test]
fn const_str_reads_the_literal() {
    let src = "/// doc\npub const PINNED_VERSION: &str = \"8.30.0\";\n";
    assert_eq!(const_str(src, "PINNED_VERSION"), "8.30.0");
}
