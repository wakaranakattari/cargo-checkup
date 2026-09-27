//! Policy configuration: the `checkup.toml` schema and its pure semantics.
//!
//! Doctrine. A dependency-health tool without a policy language can only
//! report universal facts (unused imports, known CVEs). Organizational
//! judgments - which licenses are acceptable, which crates are forbidden,
//! which toolchain floor is mandatory - vary per repository and therefore
//! belong in a checked-in policy file, not in flags. This module defines that
//! file's schema (`checkup.toml`), its discovery order, and the pure
//! decision procedures (license matching, partial-version comparison,
//! template generation) that the checks build upon. All procedures here are
//! total, deterministic functions of their inputs: configuration never
//! performs I/O except at the explicit load boundary.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Root of `checkup.toml`. Every field defaults (via `#[serde(default)]` on
/// each member) so that a minimal file containing a single table is valid.
/// `deny_unknown_fields` is enforced at every level: a misspelled table or
/// key is a hard parse error, because a policy tool that silently ignores
/// misconfiguration would certify repositories against a policy the author
/// did not write.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CheckupConfig {
    /// License allow/deny policy evaluated per locked crate.
    pub licenses: LicenseConfig,
    /// Forbidden crate names evaluated against the whole lockfile.
    pub banned: BannedConfig,
    /// Required toolchain floor evaluated per workspace member.
    pub msrv: MsrvConfig,
    /// Default values consumed by `--fix` manifest-field repairs.
    pub fix: FixConfig,
    /// Ordered suppression rules; first match suppresses.
    pub ignore: Vec<IgnoreRule>,
}

/// License policy. The two lists implement a deny-wins lattice (see
/// [`license_allowed`]): `deny` absolute-prohibits tokens, `allow`
/// close-world-restricts the remainder. An empty `allow` list denotes the
/// open world (everything not denied is accepted); a non-empty list denotes
/// the closed world (only listed expressions are accepted). Both lists empty
/// disables the license check entirely.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LicenseConfig {
    /// If non-empty, dependency licenses must match one of these (exact or token).
    pub allow: Vec<String>,
    /// License tokens that are never accepted.
    pub deny: Vec<String>,
}

/// Ban policy. Membership is by exact crate name, compared
/// case-insensitively, and evaluated against every locked package including
/// transitive dependencies: a banned crate pulled indirectly violates the
/// policy exactly as a direct one does, since the legal or technical
/// objection concerns the code shipped, not the edge that introduced it.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BannedConfig {
    /// Crate names that must not appear in the lockfile (incl. transitive).
    pub crates: Vec<String>,
}

/// Toolchain-floor policy. `version` accepts partial versions (`1.75`) as
/// well as full ones (`1.75.0`); comparison is performed on the triple
/// (major, minor, patch) by [`parse_partial_version`]. Absence disables the
/// requirement. Note the direction of the comparison: members declare their
/// own floor via `rust-version`, and the policy states the minimum of those
/// floors, so a member is compliant iff its declared floor is greater than
/// or equal to the required one.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MsrvConfig {
    /// Minimum `rust-version` required of every workspace member, e.g. "1.75".
    pub version: Option<String>,
}

/// Repair defaults for `--fix`. These values are declarative policy, not
/// guesses: `license` supplies the license string written for manifests
/// lacking one (falling back to `MIT OR Apache-2.0` when unset), and
/// `rust_version` supplies the toolchain floor written for manifests lacking
/// one (falling back to `[msrv] version`, and erroring when neither is
/// configured, since inventing a toolchain floor would be unsound).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FixConfig {
    /// Value written by `--fix` for a missing `license`. Default: MIT OR Apache-2.0.
    pub license: Option<String>,
    /// Value written by `--fix` for a missing `rust-version`. Unset by default.
    pub rust_version: Option<String>,
}

/// A single suppression rule from an `[[ignore]]` table. Semantics are
/// conjunctive over the specified fields: `check` (mandatory, matched
/// case-insensitively against the canonical check name) must match, and each
/// specified optional field must match (`package` by equality with the
/// finding subject, `dep` by equality with the finding's `dep_name`,
/// `detail_contains` by substring containment in the detail text). Omitted
/// fields impose no constraint. A rule whose `check` names no known analysis
/// matches nothing; the orchestrator additionally surfaces it under
/// `skipped:` so that the probable typo remains visible.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IgnoreRule {
    /// Check name, e.g. "unused", "outdated".
    pub check: String,
    /// Optional package the finding belongs to.
    pub package: Option<String>,
    /// Optional dependency name (`dep_name` of the finding).
    pub dep: Option<String>,
    /// Optional substring that must appear in `detail`.
    pub detail_contains: Option<String>,
}

impl CheckupConfig {
    /// Resolves the applicable policy file by the following total order:
    /// 1. the explicit `--config` path, which must exist (absence is an
    ///    error, since an explicitly requested policy that cannot be read
    ///    must never degrade to no policy);
    /// 2. `<workspace-root>/checkup.toml`, the canonical project location;
    /// 3. `<manifest-dir>/checkup.toml`, covering single-crate layouts where
    ///    the manifest directory differs from the workspace root.
    ///
    /// Returns `None` when no candidate exists; the caller then proceeds
    /// with the default (empty) policy.
    pub fn discover(
        explicit: Option<&Path>,
        workspace_root: &Path,
        manifest_dir: Option<&Path>,
    ) -> Option<PathBuf> {
        if let Some(p) = explicit {
            return p.exists().then(|| p.to_path_buf());
        }
        for dir in [Some(workspace_root), manifest_dir].into_iter().flatten() {
            let cand = dir.join("checkup.toml");
            if cand.exists() {
                return Some(cand);
            }
        }
        None
    }

    /// Loads and validates the policy file at `path`. I/O and TOML syntax
    /// errors are wrapped with the offending path for diagnosability. Schema
    /// violations (unknown fields, type mismatches) are rejected by serde,
    /// never coerced, per the strictness doctrine above.
    pub fn load(path: &Path) -> anyhow::Result<CheckupConfig> {
        let text = std::fs::read_to_string(path)?;
        let cfg: CheckupConfig =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("parse {}: {e}", path.display()))?;
        Ok(cfg)
    }
}

/// Tokenizes an SPDX-style license expression into comparable atoms.
/// Delimiters are the expression operators and grouping characters
/// (`/`, `(`, `)`, `|`, whitespace); the boolean connectives `OR`, `AND`
/// and the exception introducer `WITH` (case-insensitive) are discarded as
/// structural, not substantive. Each token is further normalized by stripping
/// surrounding quotes and a trailing `+` (the "or later" qualifier),
/// so that `"GPL-2.0+"` and `GPL-2.0` compare by their substantive core.
/// Examples: `MIT OR Apache-2.0` yields `[MIT, Apache-2.0]`; a lone
/// `GPL-3.0-only` yields itself.
pub fn license_tokens(expr: &str) -> Vec<String> {
    expr.split(|c: char| c == '/' || c == '(' || c == ')' || c == '|' || c.is_whitespace())
        .map(|t| t.trim().trim_matches('"').trim_end_matches('+').to_string())
        .filter(|t| {
            !t.is_empty()
                && !t.eq_ignore_ascii_case("OR")
                && !t.eq_ignore_ascii_case("AND")
                && !t.eq_ignore_ascii_case("WITH")
        })
        .collect()
}

/// Decides acceptance of a license expression under a policy. The decision
/// procedure, in order:
/// 1. Deny screening: if any token of the expression matches any `deny`
///    entry case-insensitively, the expression is rejected. Deny is
///    evaluated first and unconditionally, which establishes the deny-wins
///    theorem: no allow-list entry can rehabilitate a denied token, so
///    `MIT OR GPL-3.0-only` is rejected whenever `GPL-3.0-only` is denied,
///    regardless of `MIT` being allowed.
/// 2. Open world: with an empty `allow` list, every non-denied expression is
///    accepted.
/// 3. Closed world: with a non-empty `allow` list, acceptance requires
///    either verbatim equality of the whole expression (case-insensitive,
///    covering multi-license expressions the author enumerated exactly) or,
///    for single-token expressions, membership of that token in the list.
///    Multi-token expressions absent verbatim are rejected, erring toward
///    explicit enumeration over implicit decomposition.
pub fn license_allowed(expr: &str, cfg: &LicenseConfig) -> bool {
    let tokens = license_tokens(expr);
    if tokens
        .iter()
        .any(|t| cfg.deny.iter().any(|d| d.eq_ignore_ascii_case(t)))
    {
        return false;
    }
    if cfg.allow.is_empty() {
        return true;
    }
    if cfg
        .allow
        .iter()
        .any(|a| a.eq_ignore_ascii_case(expr.trim()))
    {
        return true;
    }
    // Single-token license covered by the allow-list.
    tokens.len() == 1 && cfg.allow.iter().any(|a| a.eq_ignore_ascii_case(&tokens[0]))
}

/// Parses a possibly partial version (`1`, `1.75`, `1.75.0`) into a
/// comparable triple, right-padding absent components with zero. Rationale:
/// `rust-version` in manifests is conventionally two-component, while
/// comparison requires three; padding is the unique order-preserving
/// embedding of partial versions into triples. Non-numeric components fail
/// to `None` rather than panic, and trailing components beyond the third are
/// ignored. Consequence: `1.75 == 1.75.0 < 1.85.0` under the derived
/// lexicographic order.
pub fn parse_partial_version(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().map(|p| p.parse().unwrap_or(0)).unwrap_or(0);
    let patch = parts.next().map(|p| p.parse().unwrap_or(0)).unwrap_or(0);
    Some((major, minor, patch))
}

/// Renders the starter `checkup.toml` for `cargo checkup init`, pre-filling
/// the `allow` list with the distinct license strings observed in the
/// current lockfile (sorted, deduplicated). Pre-filling encodes the status
/// quo as the initial policy: the first run after `init` is green by
/// construction, and every subsequent deviation is a deliberate, reviewable
/// policy decision rather than inherited noise. Sections without observed
/// data are emitted commented-out as documentation-by-example.
pub fn init_template(detected_licenses: &[String]) -> String {
    let mut allow = detected_licenses.to_vec();
    allow.sort();
    allow.dedup();
    let allow_block = if allow.is_empty() {
        "# allow = [\"MIT\", \"Apache-2.0\"]".to_string()
    } else {
        format!(
            "allow = [{}]",
            allow
                .iter()
                .map(|l| format!("\"{l}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!(
        r#"# cargo-checkup policy. See `cargo checkup --help`.
# Repo: https://github.com/wakaranakattari/cargo-checkup
# Docs: https://crates.io/crates/cargo-checkup

[licenses]
{allow_block}
# deny = ["GPL-3.0-only", "AGPL-3.0-only"]

[banned]
# crates = ["openssl"]

[msrv]
# version = "1.75"

[fix]
# license = "MIT OR Apache-2.0"
# rust_version = "1.75"

# Suppress one noisy finding:
# [[ignore]]
# check = "outdated"
# package = "serde"
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Axioms of tokenization: connectives vanish, grouping dissolves,
    /// substantive atoms survive verbatim.
    #[test]
    fn tokens_split_spdx() {
        assert_eq!(
            license_tokens("MIT OR Apache-2.0"),
            vec!["MIT", "Apache-2.0"]
        );
        assert_eq!(
            license_tokens("(MIT OR Apache-2.0) AND Unicode-DFS-2016"),
            vec!["MIT", "Apache-2.0", "Unicode-DFS-2016"]
        );
        assert_eq!(license_tokens("GPL-3.0-only"), vec!["GPL-3.0-only"]);
    }

    /// Axioms of the decision procedure: allow admits, deny preempts even
    /// across disjunction, closed world rejects the unlisted.
    #[test]
    fn deny_wins_over_allow() {
        let cfg = LicenseConfig {
            allow: vec!["MIT".into()],
            deny: vec!["GPL-3.0-only".into()],
        };
        assert!(license_allowed("MIT", &cfg));
        assert!(!license_allowed("MIT OR GPL-3.0-only", &cfg));
        assert!(!license_allowed("BSD-3-Clause", &cfg));
    }

    /// Axiom of the empty policy: the conjunction of no constraints accepts
    /// every expression, including proprietary ones.
    #[test]
    fn empty_policy_allows_all() {
        let cfg = LicenseConfig::default();
        assert!(license_allowed("MIT OR Apache-2.0", &cfg));
        assert!(license_allowed("Proprietary", &cfg));
    }

    /// Axioms of partial-version order: padding is transparent (`1.75` equals
    /// `1.75.0`) and minor dominates patch-level absence.
    #[test]
    fn partial_versions_compare() {
        assert!(parse_partial_version("1.75").unwrap() < parse_partial_version("1.85.0").unwrap());
        assert_eq!(
            parse_partial_version("1.75"),
            parse_partial_version("1.75.0")
        );
    }
}
