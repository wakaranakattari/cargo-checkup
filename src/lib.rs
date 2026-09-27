//! Scan orchestrator: from CLI options to an ordered report.
//!
//! Pipeline architecture. A scan is the sequential composition of three
//! stages, each with a single responsibility:
//! 1. Metadata acquisition: one `cargo metadata` invocation materializes
//!    the workspace graph (packages, resolve nodes, manifests).
//! 2. Analysis: every enabled check executes over the metadata, each
//!    contributing findings independently (checks share no mutable state,
//!    so their relative order is semantically irrelevant).
//! 3. Canonicalization: findings are sorted by (check, package, detail),
//!    making every report diff-stable across runs and machines.
//!
//! Error doctrine. Metadata failure is fatal (a report computed from
//! partial inputs would be a false certificate). Per-check degradations
//! are non-fatal by design and surface as skip notes, so that absence of
//! findings is never ambiguous with absence of analysis.

pub mod checks;
pub mod model;
pub mod report;

use std::collections::HashSet;
use std::path::PathBuf;

pub use model::{CheckKind, Finding, Report, Severity};

/// The complete parameterization of one scan, mirroring the CLI surface.
/// Each field maps to exactly one flag; `None` denotes the flag's absence
/// (defaults apply), never an error.
pub struct ScanOptions {
    /// Manifest anchoring the `cargo metadata` invocation, i.e. `--manifest-path`.
    pub manifest_path: Option<PathBuf>,
    /// Reserved for network-dependent checks, i.e. `--offline`.
    pub offline: bool,
    /// Extend unused analysis to optional dependencies, i.e. `--strict-unused`.
    pub strict_unused: bool,
    /// Restrict execution to these checks, i.e. `--only` (absence runs all).
    pub only: Option<Vec<CheckKind>>,
    /// Exclude these checks from execution, i.e. `--skip`.
    pub skip: Option<Vec<CheckKind>>,
}

/// Runs all enabled checks and returns the canonical report.
/// Postcondition: findings are canonically ordered; every
/// executed-but-degraded check contributed its cause to `skipped`.
pub fn scan(opts: &ScanOptions) -> anyhow::Result<Report> {
    let mut cmd = cargo_metadata::MetadataCommand::new();
    if let Some(manifest) = &opts.manifest_path {
        cmd.manifest_path(manifest);
    }
    let metadata = cmd.exec()?;
    let workspace_root = metadata.workspace_root.as_std_path().to_path_buf();

    // Check selection: `--only` is a whitelist, `--skip` a blacklist,
    // absence of both is the full taxonomy. `--only` dominates `--skip`
    // when both are given (a check must be listed to run at all).
    let enabled: HashSet<CheckKind> = CheckKind::all()
        .iter()
        .copied()
        .filter(|k| {
            if let Some(only) = &opts.only {
                return only.contains(k);
            }
            if let Some(skip) = &opts.skip {
                return !skip.contains(k);
            }
            true
        })
        .collect();

    // Independent analyses over shared immutable metadata. Checks whose
    // modules arrive later (network, policy) are simply never enabled yet:
    // membership in `enabled` without an executor contributes nothing,
    // which keeps selection total over the taxonomy at every stage.
    let mut report = Report::default();

    if enabled.contains(&CheckKind::Unused) {
        report
            .findings
            .extend(checks::unused::check_unused(&metadata, opts.strict_unused));
    }
    if enabled.contains(&CheckKind::Hygiene) {
        report.findings.extend(checks::hygiene::check_hygiene(&metadata));
    }
    if enabled.contains(&CheckKind::Duplicate) {
        report.findings.extend(checks::duplicates::check_duplicates(&metadata, &workspace_root));
    }

    // Stable output for CI diffs.
    report.findings.sort_by(|a, b| {
        (a.check.as_str(), &a.package, &a.detail).cmp(&(b.check.as_str(), &b.package, &b.detail))
    });
    Ok(report)
}
