//! This package is the `brenn-scrub` binary: a gitleaks wrapper that scans
//! secrets at write time, at commit, at push and across a whole tree. See the
//! README for installation and use.
//!
//! The library target exists only so that Bazel's crate_universe can depend
//! on the package: cargo drops a normal dependency on a binary-only crate.
//!
//! The library has no public items and will not get any. This crate offers no
//! Rust API.
