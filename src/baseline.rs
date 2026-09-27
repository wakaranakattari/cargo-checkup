//! Finding baselines: suppression of already-triaged results.
//!
//! Rationale. Repositories accumulate accepted findings (a pinned crate, a
//! tolerated duplicate) that a team has consciously approved. Re-reporting them on every run trains engineers to ignore the
//! tool. A baseline records the exact set of accepted findings; subsequent
//! runs suppress precisely that set and surface only novel findings. The
//! workflow is therefore: bless once with `--baseline-update`, then enforce
//! with `--baseline`.
//!
//! Identity semantics. A finding is identified by the quadruple
//! (check, package, dependency name, detail). The detail text embeds concrete
//! versions (for example `1.0.100 -> 1.0.229`), which yields the fundamental
//! soundness property of this scheme: any change in the underlying facts
//! alters the detail string and hence the fingerprint, so a mutated finding
//! correctly re-appears as novel rather than staying suppressed.
//!
//! Versioning. The file format carries a schema version. Readers reject
//! unknown versions with an explicit error instead of misinterpreting bytes,
//! which makes future format evolution safe by construction.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::Finding;

/// Schema version accepted by [`load_baseline`]. Files bearing any other
/// version are rejected; they are never partially interpreted.
const BASELINE_VERSION: u32 = 1;

/// On-disk representation: a version tag plus the ordered set of accepted
/// fingerprints. A `BTreeSet` (rather than a hash set) is used so that the
/// serialized file is canonical across runs, which keeps diffs of committed
/// baselines minimal and reviewable.
#[derive(Debug, Serialize, Deserialize)]
struct BaselineFile {
    version: u32,
    entries: BTreeSet<String>,
}

/// Computes the stable identity of one finding as
/// `check|package|dep_name|detail`, where an absent dependency name
/// contributes the empty string. Determinism argument: every component is
/// derived from the finding alone, so equal findings always yield equal
/// fingerprints within and across processes. Collision analysis: distinct
/// findings differ in at least one component by construction of the checks,
/// hence share a fingerprint only if all four components coincide, in which
/// case they are duplicates of the same fact and joint suppression is the
/// intended semantics.
pub fn fingerprint(f: &Finding) -> String {
    format!(
        "{}|{}|{}|{}",
        f.check.as_str(),
        f.package,
        f.dep_name.as_deref().unwrap_or(""),
        f.detail
    )
}

/// Reads and validates a baseline file. Contract: on success returns exactly
/// the accepted fingerprint set; on any failure (missing file, invalid JSON,
/// schema version mismatch) returns an error. The caller treats the error as
/// fatal, because proceeding without the accepted set would either drown the
/// user in blessed noise or, worse, silently bless everything.
pub fn load_baseline(path: &Path) -> anyhow::Result<BTreeSet<String>> {
    let text = std::fs::read_to_string(path)?;
    let file: BaselineFile = serde_json::from_str(&text)?;
    if file.version != BASELINE_VERSION {
        anyhow::bail!(
            "unsupported baseline version {} in {}",
            file.version,
            path.display()
        );
    }
    Ok(file.entries)
}

/// Serializes the given findings as a new baseline, creating missing parent
/// directories as needed, and returns the number of recorded entries. The
/// file is written in pretty-printed JSON so that it remains human-readable
/// and produces clean version-control diffs. Overwrites any prior baseline
/// atomically at the granularity of a single `write` call.
pub fn write_baseline(path: &Path, findings: &[Finding]) -> anyhow::Result<usize> {
    let entries: BTreeSet<String> = findings.iter().map(fingerprint).collect();
    let file = BaselineFile {
        version: BASELINE_VERSION,
        entries,
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, serde_json::to_string_pretty(&file)?)?;
    Ok(file.entries.len())
}

/// Partitions `findings` into novel findings (returned) and accepted ones
/// (counted). Formally: `kept = { f : fingerprint(f) not in entries }` and
/// `suppressed = |findings| - |kept|`. Complexity is linear in the number of
/// findings with logarithmic set membership. The input order is preserved in
/// `kept`, so downstream stable sorting is unaffected.
pub fn apply_baseline(findings: Vec<Finding>, entries: &BTreeSet<String>) -> (Vec<Finding>, usize) {
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = 0;
    for f in findings {
        if entries.contains(&fingerprint(&f)) {
            suppressed += 1;
        } else {
            kept.push(f);
        }
    }
    (kept, suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckKind, Severity};

    /// Test fixture constructor: a minimal warn-level finding carrying the
    /// given detail text. All other fields are fixed so that test assertions
    /// isolate exactly the property under examination.
    fn finding(detail: &str) -> Finding {
        Finding::new(CheckKind::Unused, Severity::Warn, "pkg", detail)
    }

    /// Theorem under test: bless-then-enforce is the identity on accepted
    /// findings and transparent to novel ones. After recording {a, b}, the
    /// input {a, c} must yield kept = [c] and suppressed = 1.
    #[test]
    fn roundtrip_suppresses() {
        let dir = std::env::temp_dir().join(format!("checkup-base-{}", std::process::id()));
        let path = dir.join("baseline.json");
        let findings = vec![finding("a"), finding("b")];
        write_baseline(&path, &findings).unwrap();
        let entries = load_baseline(&path).unwrap();
        let (kept, n) = apply_baseline(vec![finding("a"), finding("c")], &entries);
        assert_eq!(n, 1);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].detail, "c");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
