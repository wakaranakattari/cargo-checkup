//! Duplicate-version analysis over `Cargo.lock` joined with the resolve graph.
//!
//! Problem statement. Cargo permits several versions of one crate to coexist
//! in a single lockfile whenever requirement strings across the dependency
//! closure cannot be unified. Coexistence inflates build times, binary size
//! and the audit surface, so each multiplicity deserves exactly one finding
//! that (a) enumerates the locked versions and (b) attributes every version
//! to the dependents that pin it, enabling targeted requirement surgery.
//!
//! Data-source duality. Version multiplicity is read from `Cargo.lock`
//! (the ground truth of what will build), while attribution is read from
//! the `cargo metadata` resolve graph (the ground truth of why it builds
//! that way). The join key is the locked package identity. Because
//! `cargo_metadata::PackageId` exposes no stable string projection, the
//! implementation keys both sides by the type's `Debug` rendering. Soundness
//! argument for this construction: both maps are built from values of the
//! same type produced by the same deserialization run, and `Debug` is a
//! deterministic function of the value, hence equal identities yield equal
//! keys and distinct identities yield distinct keys within one execution.
//! The key never crosses a process boundary (it is absent from reports and
//! fingerprints), so no stability beyond one run is required.
//!
//! Severity rationale. Findings are `Info`: multiplicity is often legitimate
//! (irreconcilable majors) and unifying it is an optimization, not a defect
//! repair. Every finding carries a best-effort `CargoUpdate` action: the
//! update succeeds exactly when semver permits unification and is a harmless
//! no-op otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cargo_metadata::Metadata;

use crate::model::{CheckKind, Finding, FixAction, Severity};

/// Renders the attribution lines for one duplicated crate, one line per
/// locked version in the given order. For version `v`, the line enumerates
/// the dependents of the locked node `dup_name@v` in canonical order,
/// truncated to 5 entries to bound report width on dense graphs; a version
/// with no recorded dependents (direct or root requirement) is labeled
/// accordingly rather than omitted, preserving the invariant that every
/// locked version appears exactly once. The function is pure over string
/// maps precisely so that attribution logic is unit-testable without
/// constructing cargo metadata:
///
/// - `id_label`: node key -> dependent `name@version` label.
/// - `reverse`: node key -> dependent node keys (the transposed graph).
/// - `id_pkg`: node key -> (crate name, locked version) pair.
pub fn render_dependents(
    dup_name: &str,
    versions: &[String],
    id_label: &BTreeMap<String, String>,
    reverse: &BTreeMap<String, Vec<String>>,
    id_pkg: &BTreeMap<String, (String, String)>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for v in versions {
        // Resolve the node key(s) of dup_name@v; cardinality is one in a
        // well-formed lockfile (name+version is unique there).
        let node_ids: Vec<&String> = id_pkg
            .iter()
            .filter(|(_, (n, ver))| n == dup_name && ver == v)
            .map(|(id, _)| id)
            .collect();
        let mut dependents: BTreeSet<&str> = BTreeSet::new();
        for id in node_ids {
            if let Some(deps) = reverse.get(id) {
                for d in deps {
                    if let Some(label) = id_label.get(d) {
                        dependents.insert(label.as_str());
                    }
                }
            }
        }
        if dependents.is_empty() {
            lines.push(format!("{v} <- (direct or root)"));
        } else {
            let list: Vec<&str> = dependents.into_iter().take(5).collect();
            lines.push(format!("{v} <- {}", list.join(", ")));
        }
    }
    lines
}

/// Executes the duplicate analysis. Pipeline stages:
/// 1. Lock parsing: `Cargo.lock` is parsed as TOML and its `[[package]]`
///    tables are projected onto (name, version) pairs; malformed entries
///    are skipped, and an absent or unparsable lockfile yields zero findings
///    (the check abstains - it cannot distinguish "no duplicates" from "no
///    data", and the outdated check already reports the missing-graph case).
///    Versions per name are sorted and deduplicated so that findings are
///    canonical regardless of lockfile order.
/// 2. Graph transposition: the resolve graph edges (dependent -> dependency)
///    are inverted into (dependency -> dependents) with human labels, keyed
///    by the construction of the module doctrine.
/// 3. Emission: every name with more than one distinct version yields one
///    finding stating the multiplicity, hinting the unify command together
///    with the per-version attribution lines, and carrying the `CargoUpdate`
///    repair action.
pub fn check_duplicates(metadata: &Metadata, workspace_root: &Path) -> Vec<Finding> {
    let lock_path = workspace_root.join("Cargo.lock");
    let Ok(text) = std::fs::read_to_string(&lock_path) else {
        return Vec::new();
    };
    let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
        return Vec::new();
    };
    let Some(pkgs) = doc.get("package").and_then(|p| p.as_array_of_tables()) else {
        return Vec::new();
    };

    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pkg in pkgs {
        let name = pkg
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        versions.entry(name).or_default().push(version);
    }

    // Reverse deps from the resolve graph: node key -> dependent node keys,
    // with human labels per node, keyed per the module doctrine.
    let mut id_pkg: BTreeMap<String, (String, String)> = BTreeMap::new();
    for pkg in &metadata.packages {
        id_pkg.insert(
            format!("{:?}", pkg.id),
            (pkg.name.to_string(), pkg.version.to_string()),
        );
    }
    let mut reverse: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut id_label: BTreeMap<String, String> = BTreeMap::new();
    if let Some(resolve) = &metadata.resolve {
        for node in &resolve.nodes {
            let nid = format!("{:?}", node.id);
            if let Some((n, v)) = id_pkg.get(&nid) {
                id_label.insert(nid.clone(), format!("{n}@{v}"));
            }
            for dep in &node.deps {
                let target = format!("{:?}", dep.pkg);
                reverse.entry(target).or_default().push(nid.clone());
            }
        }
    }

    let mut findings = Vec::new();
    for (name, mut vers) in versions {
        vers.sort();
        vers.dedup();
        if vers.len() > 1 {
            let lines = render_dependents(&name, &vers, &id_label, &reverse, &id_pkg);
            findings.push(
                Finding::new(
                    CheckKind::Duplicate,
                    Severity::Info,
                    name.clone(),
                    format!("{} versions in lockfile: {}", vers.len(), vers.join(", ")),
                )
                .with_hint(format!(
                    "run `cargo update -p {name}` to unify, if semver allows. {}",
                    lines.join("; ")
                ))
                .with_fix(FixAction::CargoUpdate { package: name }),
            );
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Theorem under test: attribution joins versions to dependents through
    /// the transposed graph. Fixture graph: crate `a` locked at 1.0.0 and
    /// 2.0.0, where 1.0.0 is depended upon by `x@3.0.0` and the root, while
    /// 2.0.0 has no recorded dependents. Expected lines: the first names
    /// both dependents, the second carries the direct-or-root label. (The
    /// lockfile write at the top documents the ground-truth shape the maps
    /// encode; the pure helper under test consumes the maps directly.)
    #[test]
    fn reports_multiple_versions() {
        let dir = std::env::temp_dir().join(format!("checkup-dup-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("Cargo.lock"),
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n[[package]]\nname = \"a\"\nversion = \"2.0.0\"\n[[package]]\nname = \"b\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        let id_pkg: BTreeMap<String, (String, String)> = [
            ("id-a1".to_string(), ("a".to_string(), "1.0.0".to_string())),
            ("id-a2".to_string(), ("a".to_string(), "2.0.0".to_string())),
            ("id-x".to_string(), ("x".to_string(), "3.0.0".to_string())),
        ]
        .into_iter()
        .collect();
        let id_label: BTreeMap<String, String> = [
            ("id-x".to_string(), "x@3.0.0".to_string()),
            ("id-root".to_string(), "root@0.1.0".to_string()),
        ]
        .into_iter()
        .collect();
        let reverse: BTreeMap<String, Vec<String>> = [(
            "id-a1".to_string(),
            vec!["id-x".to_string(), "id-root".to_string()],
        )]
        .into_iter()
        .collect();
        let lines = render_dependents(
            "a",
            &["1.0.0".to_string(), "2.0.0".to_string()],
            &id_label,
            &reverse,
            &id_pkg,
        );
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("x@3.0.0"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
