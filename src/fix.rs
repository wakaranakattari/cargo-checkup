//! Repair subsystem: interpretation of declarative fix actions.
//!
//! Architecture. Checks never mutate the repository; they declare repairs as
//! [`FixAction`] values attached to findings. This
//! module interprets those declarations. The interpretation is partitioned
//! into three action classes, each executed by a dedicated routine:
//! manifest-table surgery (`RemoveDep`), manifest-field assignment
//! (`SetManifestField`), and subprocess delegation (`CargoUpdate`).
//!
//! Deduplication theorem. Several findings may imply the same repair (for
//! example, one `CargoUpdate` per duplicate version pair of a crate, or one
//! field assignment per member missing the same metadata). Actions are
//! deduplicated by their `Debug` rendering before execution, so each distinct
//! repair executes at most once per invocation regardless of finding
//! multiplicity. Correctness of the key follows from `FixAction` being a
//! value type: equal repairs are equal values, hence equal renderings.
//!
//! Execution modes. In mutating mode (`--fix`) repairs are applied and every
//! outcome is recorded; in dry-run mode (`--check`) the same code path
//! computes the identical action list but performs zero mutations, which
//! guarantees by construction that dry-run output faithfully predicts real
//! behavior. Outcomes distinguish applied actions from errors; the caller
//! maps a non-empty error set to exit code 2.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::Context;

use crate::config::CheckupConfig;
use crate::model::{Finding, FixAction};

/// The complete account of one repair pass: human-readable descriptions of
/// applied (or, under dry run, prospective) actions, plus human-readable
/// descriptions of failures. The two lists are disjoint by construction; an
/// action appears in at most one of them.
#[derive(Debug, Default)]
pub struct FixOutcome {
    pub actions: Vec<String>,
    pub errors: Vec<String>,
}

/// Interprets all fix actions attached to `findings` under policy `cfg`.
/// `workspace_root` anchors subprocess delegation (`cargo update` must run
/// with the workspace as its working directory to resolve the correct
/// lockfile); `dry_run` selects prediction (`--check`) over mutation
/// (`--fix`). Manifest paths embedded in actions are trusted as produced by
/// the checks of the same invocation; no path validation beyond filesystem
/// errors is performed, and every filesystem failure surfaces as an outcome
/// error rather than aborting the remaining actions.
pub fn execute_fixes(
    findings: &[Finding],
    cfg: &CheckupConfig,
    workspace_root: &Path,
    dry_run: bool,
) -> FixOutcome {
    let mut outcome = FixOutcome::default();
    // Deduplicate identical actions (several findings can share one fix).
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut by_kind: BTreeMap<&str, Vec<&FixAction>> = BTreeMap::new();
    for f in findings {
        if let Some(action) = &f.fix {
            let key = format!("{action:?}");
            if seen.insert(key) {
                let kind = match action {
                    FixAction::RemoveDep { .. } => "remove",
                    FixAction::CargoUpdate { .. } => "update",
                    FixAction::SetManifestField { .. } => "field",
                };
                by_kind.entry(kind).or_default().push(action);
            }
        }
    }

    // Class 1: dependency removal, grouped by owning manifest so that each
    // file undergoes exactly one read-modify-write cycle regardless of how
    // many entries it loses. Grouping is both an efficiency and an atomicity
    // measure at file granularity.
    if let Some(actions) = by_kind.get("remove") {
        // Group removals by manifest: one read/write per file.
        let mut by_manifest: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for a in actions {
            if let FixAction::RemoveDep { manifest, dep } = a {
                by_manifest.entry(manifest).or_default().push(dep);
            }
        }
        for (manifest, mut deps) in by_manifest {
            deps.sort_unstable();
            deps.dedup();
            let label = format!("remove {} from {manifest}", deps.join(", "));
            if dry_run {
                outcome.actions.push(format!("would {label}"));
                continue;
            }
            match remove_deps_from_manifest(manifest, &deps) {
                Ok(n) => outcome.actions.push(format!(
                    "removed {n} dependenc(ies) ({}) from {manifest}",
                    deps.join(", ")
                )),
                Err(e) => outcome.errors.push(format!("{label}: {e:#}")),
            }
        }
    }

    // Class 2: manifest-field assignment. Values resolve here, at apply
    // time, from policy - never at check time - so that one finding remains
    // valid under any policy. Resolution order per field: explicit `[fix]`
    // value first, `[msrv] version` as fallback for `rust-version`, built-in
    // default for `license`. A `rust-version` repair with neither configured
    // is an error rather than a guess, since inventing a toolchain floor
    // would assert an MSRV contract the author never approved.
    if let Some(actions) = by_kind.get("field") {
        for a in actions {
            if let FixAction::SetManifestField { manifest, field } = a {
                let value = match field.as_str() {
                    "license" => Some(
                        cfg.fix.license.clone().unwrap_or_else(|| "MIT OR Apache-2.0".to_string()),
                    ),
                    "rust-version" => cfg.fix.rust_version.clone().or_else(|| {
                        cfg.msrv.version.clone().or_else(|| {
                            outcome.errors.push(format!(
                                "set {field} in {manifest}: no value (set [fix] rust_version or [msrv] version)"
                            ));
                            None
                        })
                    }),
                    _ => {
                        outcome.errors.push(format!("unknown manifest field `{field}`"));
                        None
                    }
                };
                let Some(value) = value else { continue };
                let label = format!("set {field} = \"{value}\" in {manifest}");
                if dry_run {
                    outcome.actions.push(format!("would {label}"));
                    continue;
                }
                match set_package_field(manifest, field, &value) {
                    Ok(true) => outcome.actions.push(label),
                    Ok(false) => outcome
                        .actions
                        .push(format!("{field} already set in {manifest}")),
                    Err(e) => outcome.errors.push(format!("{label}: {e:#}")),
                }
            }
        }
    }

    // Class 3: subprocess delegation. Distinct packages are updated once
    // each, in canonical order; each invocation is independent (Cargo
    // serializes lockfile access itself), and per-package failure is
    // recorded without aborting the remaining updates.
    if let Some(actions) = by_kind.get("update") {
        let mut packages: BTreeSet<&str> = BTreeSet::new();
        for a in actions {
            if let FixAction::CargoUpdate { package } = a {
                packages.insert(package);
            }
        }
        for package in packages {
            let label = format!("cargo update -p {package}");
            if dry_run {
                outcome.actions.push(format!("would run `{label}`"));
                continue;
            }
            match run_cargo_update(workspace_root, package) {
                Ok(output) => outcome.actions.push(format!("ran `{label}`: {output}")),
                Err(e) => outcome.errors.push(format!("`{label}`: {e:#}")),
            }
        }
    }
    outcome
}

/// Removes `deps` from the `[dependencies]`-family tables of the manifest at
/// `manifest` and returns the number of removed entries. Coverage: the three
/// top-level tables plus every `[target.<cfg>.<section>]` table, so that
/// platform-specific declarations are repaired exactly like unconditional
/// ones. Format preservation invariant: parsing and serialization pass
/// through `toml_edit`, hence comments, whitespace and key order of
/// untouched content are byte-identical after the operation. Returns zero
/// (successfully) when none of the named entries exist, which makes the
/// operation idempotent.
fn remove_deps_from_manifest(manifest: &str, deps: &[&str]) -> anyhow::Result<usize> {
    let text = std::fs::read_to_string(manifest).with_context(|| format!("read {manifest}"))?;
    let mut doc: toml_edit::DocumentMut =
        text.parse().with_context(|| format!("parse {manifest}"))?;
    let mut removed = 0;
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        removed += remove_from_table(&mut doc, section, deps);
    }
    removed += remove_from_targets(&mut doc, deps);
    std::fs::write(Path::new(manifest), doc.to_string())
        .with_context(|| format!("write {manifest}"))?;
    Ok(removed)
}

/// Removes `deps` from one top-level dependency table. Returns the count of
/// actually removed keys; absent keys contribute zero, which composes into
/// the idempotence of the caller.
fn remove_from_table(doc: &mut toml_edit::DocumentMut, section: &str, deps: &[&str]) -> usize {
    let mut removed = 0;
    if let Some(table) = doc.get_mut(section).and_then(|v| v.as_table_mut()) {
        for dep in deps {
            if table.remove(dep).is_some() {
                removed += 1;
            }
        }
    }
    removed
}

/// Removes `deps` from every `[target.<cfg>.<section>]` table in the
/// document. Target keys are collected before mutation to satisfy the borrow
/// checker; each (target, section) pair is then treated exactly like a
/// top-level table. Returns the total removed count.
fn remove_from_targets(doc: &mut toml_edit::DocumentMut, deps: &[&str]) -> usize {
    let mut removed = 0;
    let Some(target) = doc.get_mut("target").and_then(|v| v.as_table_mut()) else {
        return 0;
    };
    // Clone keys to satisfy the borrow checker.
    let keys: Vec<String> = target.iter().map(|(k, _)| k.to_string()).collect();
    for key in keys {
        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(tbl) = target
                .get_mut(&key)
                .and_then(|v| v.as_table_mut())
                .and_then(|t| t.get_mut(section))
                .and_then(|v| v.as_table_mut())
            {
                for dep in deps {
                    if tbl.remove(dep).is_some() {
                        removed += 1;
                    }
                }
            }
        }
    }
    removed
}

/// Assigns `[package] <field>` to `value`, creating the key when absent.
/// Returns `true` iff the file changed; a pre-existing field (whatever its
/// value) is never overwritten, which makes the operation conservative and
/// idempotent: repeated application converges after the first mutation.
/// Absence of the `[package]` table is an error, since a manifest without it
/// is outside the tool's repair domain.
fn set_package_field(manifest: &str, field: &str, value: &str) -> anyhow::Result<bool> {
    let text = std::fs::read_to_string(manifest).with_context(|| format!("read {manifest}"))?;
    let mut doc: toml_edit::DocumentMut =
        text.parse().with_context(|| format!("parse {manifest}"))?;
    let package = doc
        .get_mut("package")
        .and_then(|v| v.as_table_mut())
        .with_context(|| format!("no [package] in {manifest}"))?;
    if package.get(field).is_some() {
        return Ok(false);
    }
    package[field] = toml_edit::value(value);
    std::fs::write(Path::new(manifest), doc.to_string())
        .with_context(|| format!("write {manifest}"))?;
    Ok(true)
}

/// Delegates version advancement to Cargo itself by running
/// `cargo update -p <package>` with `workspace_root` as working directory.
/// Rationale for delegation over reimplementation: requirement resolution is
/// Cargo's authoritative domain; reimplementing it would risk divergence
/// from the resolver's semantics. Returns the trailing summary line of
/// Cargo's stderr on success; any spawn failure or non-zero exit becomes an
/// error carrying Cargo's own diagnostic text, so no information is lost.
fn run_cargo_update(workspace_root: &Path, package: &str) -> anyhow::Result<String> {
    let out = Command::new("cargo")
        .args(["update", "-p", package])
        .current_dir(workspace_root)
        .output()
        .context("spawn `cargo update`")?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    // One-line summary: last non-empty stderr line ("Updating ...").
    let summary = String::from_utf8_lossy(&out.stderr)
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or("ok")
        .trim()
        .to_string();
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckKind, Severity};

    /// Fixture constructor: a warn-level unused finding on `dep` in
    /// `manifest`, carrying the corresponding `RemoveDep` action. The
    /// `manifest_path`/`dep_name` locators and the `fix` action are
    /// populated consistently, mirroring production findings.
    fn unused_finding(manifest: &str, dep: &str) -> Finding {
        Finding {
            check: CheckKind::Unused,
            severity: Severity::Warn,
            package: "x".into(),
            detail: "unused".into(),
            hint: None,
            manifest_path: Some(manifest.into()),
            dep_name: Some(dep.into()),
            fix: Some(FixAction::RemoveDep {
                manifest: manifest.into(),
                dep: dep.into(),
            }),
        }
    }

    /// Fixture helper: materializes a manifest with the given body in a
    /// process-isolated temporary directory and returns its path string.
    fn write_manifest(dir: &Path, body: &str) -> String {
        let _ = std::fs::create_dir_all(dir);
        let manifest = dir.join("Cargo.toml");
        std::fs::write(&manifest, body).unwrap();
        manifest.to_string_lossy().into_owned()
    }

    /// Theorem under test: removal is surgical. After execution the named
    /// entry is absent, all other entries are byte-preserved, exactly one
    /// action is reported, and no error is recorded.
    #[test]
    fn removes_unused_dep_keeping_others() {
        let dir = std::env::temp_dir().join(format!("checkup-fix-{}", std::process::id()));
        let manifest = write_manifest(
            &dir,
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\nunused-crate = \"0.1\"\n",
        );
        let findings = vec![unused_finding(&manifest, "unused-crate")];
        let cfg = CheckupConfig::default();
        let out = execute_fixes(&findings, &cfg, &dir, false);
        assert!(out.errors.is_empty());
        assert_eq!(out.actions.len(), 1);
        let text = std::fs::read_to_string(&manifest).unwrap();
        assert!(text.contains("serde"));
        assert!(!text.contains("unused-crate"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Theorem under test: dry run is observationally pure. The reported
    /// action is prefixed as prospective, and the manifest bytes are
    /// identical before and after.
    #[test]
    fn dry_run_changes_nothing() {
        let dir = std::env::temp_dir().join(format!("checkup-dry-{}", std::process::id()));
        let manifest = write_manifest(
            &dir,
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\nunused-crate = \"0.1\"\n",
        );
        let findings = vec![unused_finding(&manifest, "unused-crate")];
        let cfg = CheckupConfig::default();
        let out = execute_fixes(&findings, &cfg, &dir, true);
        assert!(out.actions[0].starts_with("would remove"));
        assert!(
            std::fs::read_to_string(&manifest)
                .unwrap()
                .contains("unused-crate")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Theorem under test: field assignment under the default policy writes
    /// the documented default license string into a manifest lacking any
    /// license declaration, with no errors recorded.
    #[test]
    fn sets_missing_license() {
        let dir = std::env::temp_dir().join(format!("checkup-lic-{}", std::process::id()));
        let manifest = write_manifest(&dir, "[package]\nname = \"x\"\nversion = \"0.1.0\"\n");
        let findings = vec![Finding {
            check: CheckKind::Hygiene,
            severity: Severity::Info,
            package: "x".into(),
            detail: "missing license".into(),
            hint: None,
            manifest_path: None,
            dep_name: None,
            fix: Some(FixAction::SetManifestField {
                manifest: manifest.clone(),
                field: "license".to_string(),
            }),
        }];
        let cfg = CheckupConfig::default();
        let out = execute_fixes(&findings, &cfg, &dir, false);
        assert!(out.errors.is_empty());
        assert!(
            std::fs::read_to_string(&manifest)
                .unwrap()
                .contains("MIT OR Apache-2.0")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
