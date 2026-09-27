//! Duplicate-version analysis over `Cargo.lock`.
//!
//! Problem statement. Cargo permits several versions of one crate to coexist
//! in a single lockfile whenever requirement strings across the dependency
//! closure cannot be unified. Coexistence inflates build times, binary size
//! and the audit surface, so each multiplicity deserves exactly one finding
//! that enumerates the locked versions.
//!
//! Data source. Version multiplicity is read from `Cargo.lock` (the ground
//! truth of what will build). An absent or unparsable lockfile yields zero
//! findings: the check abstains rather than certifying an unknown state.
//!
//! Severity rationale. Findings are `Info`: multiplicity is often legitimate
//! (irreconcilable majors) and unifying it is an optimization, not a defect
//! repair.

use std::collections::BTreeMap;
use std::path::Path;

use crate::model::{CheckKind, Finding, Severity};

/// Parses `Cargo.lock` and reports crates present in more than one version.
/// The `[[package]]` tables are projected onto (name, version) pairs;
/// malformed entries are skipped. Versions per name are sorted and
/// deduplicated so that findings are canonical regardless of lockfile order.
pub fn check_duplicates(workspace_root: &Path) -> Vec<Finding> {
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
        let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string();
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

    let mut findings = Vec::new();
    for (name, mut vers) in versions {
        vers.sort();
        vers.dedup();
        if vers.len() > 1 {
            findings.push(
                Finding::new(
                    CheckKind::Duplicate,
                    Severity::Info,
                    name.clone(),
                    format!("{} versions in lockfile: {}", vers.len(), vers.join(", ")),
                )
                .with_hint(format!("run `cargo update -p {name}` to unify, if semver allows")),
            );
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Theorem under test: multiplicity is reported once per crate with the
    /// canonical sorted version list, while single-version crates are silent.
    #[test]
    fn reports_multiple_versions() {
        let dir = std::env::temp_dir().join(format!("checkup-dup-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("Cargo.lock"),
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n[[package]]\nname = \"a\"\nversion = \"2.0.0\"\n[[package]]\nname = \"b\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        let findings = check_duplicates(&dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].package, "a");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
