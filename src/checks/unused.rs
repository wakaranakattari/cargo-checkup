//! Unused-dependency detection by textual reference analysis.
//!
//! Problem statement. Given the dependency set declared in each workspace
//! member manifest, determine which declared dependencies are never
//! referenced by the member's own source code. An exact solution requires
//! compiler internals (name resolution over the crate graph), which stable
//! Rust does not expose to external tools. This module therefore implements
//! a soundy heuristic in the style of `cargo-machete`: textual search for
//! the crate identifier across all Rust sources of the owning package.
//!
//! Decision procedure. For a dependency with manifest name `N` and optional
//! rename `R`, the searched identifier is `R` when present, else `N` with
//! `-` mapped to `_` (the standard Cargo lib-target normalization). The
//! dependency counts as used iff at least one source file contains one of:
//! `ident::` (path usage, covering `use` trees and qualified paths),
//! `use ident` (bare import), or `extern crate ident` (2015-edition linkage).
//! In strict mode, optional dependencies additionally count as used when a
//! `feature = "<dep>"` gate names them, capturing feature-gated activation.
//!
//! Scope rules. Development dependencies are unconditionally excluded: they
//! serve tests and examples whose reference patterns the heuristic cannot
//! judge, so including them would trade precision for coverage. Optional
//! dependencies are excluded by default for the analogous feature-gate
//! reason, and included under `--strict-unused` with the gate-aware rule
//! above. Build dependencies are included because `build.rs` participates in
//! the scanned corpus.
//!
//! Precision statement. The analysis is neither sound nor complete in the
//! formal sense: macro-generated references and build-script codegen escape
//! textual search (false positives), while coincidental identifier matches
//! in comments or strings suppress genuine dead dependencies (false
//! negatives). The wording of every finding (`possibly unused`) and the
//! `Warn` (not `Error`) severity encode exactly this epistemic status.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use cargo_metadata::{DependencyKind, Metadata};
use walkdir::WalkDir;

use crate::model::{CheckKind, Finding, FixAction, Severity};

/// Reads the full text of every `.rs` file under `pkg_dir` into memory.
/// Traversal prunes `target/` and `.git/` directories at the filter stage,
/// so generated artifacts and version-control objects never enter the corpus
/// nor pollute the analysis. Unreadable files and traversal errors are
/// skipped silently (`flatten` over the fallible iterator): a single
/// unreadable file must degrade coverage of that file only, never abort the
/// whole check. The returned vector preserves no ordering guarantees, which
/// is sufficient because all downstream predicates are existential.
fn read_rs_sources(pkg_dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let walker = WalkDir::new(pkg_dir).into_iter().filter_entry(|e| {
        // Skip target/ and .git/ entirely.
        if e.file_type().is_dir() {
            let name = e.file_name().to_string_lossy();
            if name == "target" || name == ".git" {
                return false;
            }
        }
        true
    });
    for entry in walker.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(p) {
            out.push(text);
        }
    }
    out
}

/// Existential reference predicate over the source corpus. Returns true iff
/// any file contains the identifier in one of the three syntactic reference
/// positions defined in the module doctrine. The empty identifier is defined
/// as used (vacuous truth), which protects against degenerate metadata
/// producing a universal false-positive. Substring matching is deliberate:
/// `ident::` as a contiguous token cannot arise from an unrelated longer
/// identifier (Rust identifiers admit no `:`), so the path pattern is
/// precise; the `use`/extern patterns are prefix-precise up to trailing
/// identifier characters, a residual imprecision accepted in favor of
/// zero-dependency simplicity.
fn appears_used(sources: &[String], ident: &str) -> bool {
    if ident.is_empty() {
        return true;
    }
    // Token search over the three reference positions: path usage
    // (`ident::`), import statements (`use ident`), and explicit linkage
    // (`extern crate ident`).
    let pat_path = format!("{ident}::");
    let pat_use = format!("use {ident}");
    let pat_extern = format!("extern crate {ident}");
    sources
        .iter()
        .any(|s| s.contains(&pat_path) || s.contains(&pat_use) || s.contains(&pat_extern))
}

/// Feature-gate reference predicate for optional dependencies in strict mode.
/// Returns true iff any source contains the exact attribute fragment
/// `feature = "<dep_name>"` with canonical double quotes and no interior
/// whitespace. The strict exactness is intentional: it recognizes the form
/// produced by `cargo add --optional` consumers and hand-written `cfg`
/// attributes alike, while refusing to guess at semantically equivalent but
/// textually distant formulations.
fn appears_feature_gated(sources: &[String], dep_name: &str) -> bool {
    let pat = format!("feature = \"{dep_name}\"");
    sources.iter().any(|s| s.contains(&pat))
}

/// Executes the unused analysis over all workspace members. For each member,
/// the corpus is read once and every in-scope dependency is tested against
/// it; dependencies appearing under several target tables are deduplicated
/// by (manifest name, is-build) so that one declaration yields at most one
/// finding. Each finding carries a `RemoveDep` fix action binding the exact
/// owning manifest and the exact `Cargo.toml` key, which makes `--fix`
/// a pure function of the findings. Ordering of the output is unspecified;
/// the orchestrator imposes canonical order downstream.
pub fn check_unused(metadata: &Metadata, strict: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Index of package id to package descriptor, projecting the flat
    // metadata package list onto workspace membership in O(1) per member.
    let pkgs: HashMap<&cargo_metadata::PackageId, &cargo_metadata::Package> =
        metadata.packages.iter().map(|p| (&p.id, p)).collect();

    for member_id in &metadata.workspace_members {
        let Some(pkg) = pkgs.get(member_id) else {
            continue;
        };
        let manifest_dir: PathBuf = pkg
            .manifest_path
            .parent()
            .map(|p| p.as_std_path().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let sources = read_rs_sources(&manifest_dir);
        let source_refs: &[String] = &sources;

        // Deduplicate dep names (same dep can appear for multiple targets).
        let mut seen: HashSet<(String, bool)> = HashSet::new();
        for dep in &pkg.dependencies {
            let is_dev = matches!(dep.kind, DependencyKind::Development);
            if is_dev {
                continue;
            }
            // Optional deps enabled via features are often referenced via
            // `#[cfg(feature = ...)]` instead of a direct import; skip them
            // unless strict mode is on.
            if dep.optional && !strict {
                continue;
            }
            // Dependencies renamed in the manifest (`package = "..."` or
            // `rename`) are searched under their effective identifier; all
            // others fall back to the hyphen-to-underscore normalization.
            let toml_name = dep.name.clone();
            let lib_ident = dep
                .rename
                .clone()
                .unwrap_or_else(|| toml_name.replace('-', "_"));
            // Development kind was excluded above, so the remaining kinds
            // (normal, build, unknown) are all treated as analyzable; build
            // dependencies are covered because build.rs is in the corpus.
            let key = (toml_name.clone(), matches!(dep.kind, DependencyKind::Build));
            if !seen.insert(key) {
                continue;
            }
            let used = appears_used(source_refs, &lib_ident)
                || (dep.optional && appears_feature_gated(source_refs, &toml_name));
            if !used {
                let kind_label = match dep.kind {
                    DependencyKind::Build => "build-",
                    _ => "",
                };
                let manifest = pkg
                    .manifest_path
                    .as_std_path()
                    .to_string_lossy()
                    .into_owned();
                findings.push(Finding {
                    check: CheckKind::Unused,
                    severity: Severity::Warn,
                    package: pkg.name.to_string(),
                    detail: format!("possibly unused {kind_label}dependency `{toml_name}`"),
                    hint: Some(format!(
                        "remove `{toml_name}` from [dependencies] in {} or run with --fix",
                        pkg.manifest_path
                    )),
                    manifest_path: Some(manifest.clone()),
                    dep_name: Some(toml_name.clone()),
                    fix: Some(FixAction::RemoveDep {
                        manifest,
                        dep: toml_name,
                    }),
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Axioms of the reference predicate: a qualified path counts as use,
    /// an absent identifier counts as disuse, and repeated evaluation is
    /// deterministic (idempotent observation).
    #[test]
    fn detects_used_and_unused_idents() {
        let sources = vec![
            "use serde_json::Value;".to_string(),
            "fn f() {}".to_string(),
        ];
        assert!(appears_used(&sources, "serde_json"));
        assert!(!appears_used(&sources, "tokio"));
        assert!(appears_used(&sources, "serde_json")); // idempotent
    }

    /// Axiom of the linkage position: an explicit `extern crate` declaration
    /// constitutes a reference under the predicate.
    #[test]
    fn extern_crate_counts_as_used() {
        let sources = vec!["extern crate openssl;".to_string()];
        assert!(appears_used(&sources, "openssl"));
    }

    /// Axioms of the gate predicate: exact canonical gates match, while
    /// interior whitespace breaks the fragment and therefore does not match.
    #[test]
    fn feature_gate_counts_for_optional() {
        let sources = vec!["#[cfg(feature = \" rayon \")]".to_string()];
        assert!(!appears_feature_gated(&sources, "rayon"));
        let sources = vec!["#[cfg(feature = \"rayon\")]".to_string()];
        assert!(appears_feature_gated(&sources, "rayon"));
    }
}
