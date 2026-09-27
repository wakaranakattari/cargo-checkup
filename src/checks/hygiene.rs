//! Manifest hygiene: static well-formedness rules over member manifests.
//!
//! Doctrine. Certain defects are decidable from manifest metadata alone, with
//! no network access and no source analysis: absent package metadata that
//! registries and consumers require, pre-2021 edition declarations, and
//! requirement strings that defeat reproducible resolution. This module
//! evaluates four such rules per workspace member. Each rule is a pure
//! predicate over one member descriptor; the module contributes no
//! cross-member reasoning and no I/O.
//!
//! Severity assignment. Missing `license`/`license-file`, missing
//! `rust-version` and stale editions are `Info`: they degrade publishing and
//! MSRV transparency but break no build, so they inform without gating. A
//! wildcard requirement (`*`) is `Warn`: it makes resolution
//! non-reproducible across time (the same manifest resolves differently as
//! the registry grows), which is precisely the class of defect a CI gate
//! must catch.
//!
//! Repairability. The two absence rules name the exact field to set;
//! edition and wildcard findings are manual: changing the
//! edition requires source-level edits, and choosing a requirement range
//! is a semantic decision no tool may take unilaterally.

use cargo_metadata::Metadata;

use crate::model::{CheckKind, Finding, Severity};

/// Projects a package descriptor onto its owning manifest path as a string.
/// Centralizes the `Utf8PathBuf -> &str -> String` conversion so that every
/// finding in this module locates the same file by the same spelling, which
/// keeps fix-action deduplication (keyed on the manifest string) exact.
fn manifest_of(pkg: &cargo_metadata::Package) -> String {
    pkg.manifest_path
        .as_std_path()
        .to_string_lossy()
        .into_owned()
}

/// Evaluates the four hygiene predicates over all workspace members.
/// Non-members (registry dependencies) are out of scope: their manifests are
/// not owned by the repository and must never be diagnosed, let alone fixed.
/// Output order follows workspace membership; canonical ordering is imposed
/// downstream by the orchestrator.
pub fn check_hygiene(metadata: &Metadata) -> Vec<Finding> {
    let mut findings = Vec::new();
    let pkgs: std::collections::HashMap<_, _> =
        metadata.packages.iter().map(|p| (&p.id, p)).collect();

    for member_id in &metadata.workspace_members {
        let Some(pkg) = pkgs.get(member_id) else {
            continue;
        };
        let manifest = manifest_of(pkg);
        // Rule H1 (metadata completeness, license): a publishable package
        // declares its license via `license` or `license-file`. Absence of
        // both is reported; presence of either satisfies the rule.
        if pkg.license.is_none() && pkg.license_file.is_none() {
            findings.push(
                Finding::new(
                    CheckKind::Hygiene,
                    Severity::Info,
                    pkg.name.to_string(),
                    "missing `license` (or `license-file`) in [package]".to_string(),
                )
                .with_hint("set `license = \"MIT OR Apache-2.0\"` for crates.io or run with --fix"),
            );
        }
        // Rule H2 (metadata completeness, toolchain floor): a responsible
        // package declares the minimum compiler it supports via
        // `rust-version`, which documents the MSRV contract to consumers.
        if pkg.rust_version.is_none() {
            findings.push(
                Finding::new(
                    CheckKind::Hygiene,
                    Severity::Info,
                    pkg.name.to_string(),
                    "missing `rust-version` (MSRV) in [package]".to_string(),
                )
                .with_hint("set `rust-version` or run with --fix (needs [fix] rust_version)"),
            );
        }
        // Rule H3 (edition modernity): editions 2015 and 2018 predate the
        // current idiom set (resolved imports, async/await as keywords in
        // 2018+). The rule is advisory: changing the edition is
        // source-invasive and therefore never automated.
        match pkg.edition.as_str() {
            "2015" | "2018" => findings.push(
                Finding::new(
                    CheckKind::Hygiene,
                    Severity::Info,
                    pkg.name.to_string(),
                    format!("stale edition `{}`", pkg.edition),
                )
                .with_hint("consider `edition = \"2021\"` or `\"2024\"`"),
            ),
            _ => {}
        }
        // Rule H4 (requirement determinism): a wildcard requirement accepts
        // every version including future major releases, so two resolutions
        // of the same manifest at different times can diverge arbitrarily.
        // The rule fires per offending dependency edge.
        for dep in &pkg.dependencies {
            if dep.req.to_string() == "*" {
                findings.push(
                    Finding::new(
                        CheckKind::Hygiene,
                        Severity::Warn,
                        pkg.name.to_string(),
                        format!("wildcard requirement for `{}`", dep.name),
                    )
                    .with_hint("pin a semver range, `*` breaks reproducible builds"),
                );
            }
        }
    }
    findings
}
