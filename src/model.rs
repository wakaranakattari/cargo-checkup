//! Core data model: finding taxonomy, severity lattice, fix actions, reports.
//!
//! Ontology. A scan of a Cargo workspace produces a finite multiset of
//! _findings_. Each finding is classified by exactly one _check kind_ (the
//! analysis that produced it) and one _severity_ (its gating significance).
//! Findings that a machine can repair carry a _fix action_: a declarative,
//! serializable repair program executed by the fix subsystem. A _report_ is
//! the ordered collection of findings of one scan plus scan metadata
//! (skipped-check notes and the suppression count). The model is
//! serialization-first: every type derives `Serialize`/`Deserialize` so that
//! the JSON report is a faithful projection of the in-memory report.

use serde::{Deserialize, Serialize};

/// The complete taxonomy of analyses. Each variant corresponds to one check
/// module under `crate::checks` and to one user-visible name in `--only`,
/// `--skip` and `--fail-on`. The set is closed: adding an analysis requires
/// extending this enum, its string mapping, and the scan orchestrator, which
/// keeps the CLI surface and the implementation in lockstep by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckKind {
    /// Dependencies that appear unused by textual analysis of package sources.
    Unused,
    /// Locked versions lagging behind the registry maximum stable version.
    Outdated,
    /// Multiple locked versions of a single crate in `Cargo.lock`.
    Duplicate,
    /// Known vulnerabilities affecting locked versions (OSV.dev).
    Advisory,
    /// Manifest-level hygiene: edition, version pins, metadata presence.
    Hygiene,
    /// Dependency license strings violating the configured policy.
    License,
    /// Crates present on the configured ban list.
    Banned,
}

impl CheckKind {
    /// Canonical machine name of the check. The mapping is bijective with
    /// [`CheckKind::parse_list`] inputs (modulo documented aliases), hence
    /// suitable as a stable key in reports, fingerprints and SARIF rule ids.
    pub fn as_str(self) -> &'static str {
        match self {
            CheckKind::Unused => "unused",
            CheckKind::Outdated => "outdated",
            CheckKind::Duplicate => "duplicate",
            CheckKind::Advisory => "advisory",
            CheckKind::Hygiene => "hygiene",
            CheckKind::License => "license",
            CheckKind::Banned => "banned",
        }
    }

    /// The exhaustive enumeration of checks, in canonical order. The scan
    /// orchestrator derives the enabled set from this list, so no check can
    /// be silently omitted from `--only`/`--skip` handling.
    pub fn all() -> &'static [CheckKind] {
        &[
            CheckKind::Unused,
            CheckKind::Outdated,
            CheckKind::Duplicate,
            CheckKind::Advisory,
            CheckKind::Hygiene,
            CheckKind::License,
            CheckKind::Banned,
        ]
    }

    /// Parses a comma-separated check list as accepted by `--only`,
    /// `--skip` and `--fail-on`. Grammar: case-insensitive tokens with
    /// surrounding whitespace ignored; empty tokens (from leading, trailing
    /// or doubled commas) are discarded. Documented aliases (`duplicates`,
    /// `audit`, `lint`, `ban`, `deny`) normalize to canonical variants.
    /// Any other token is a hard error naming the offender, which fails the
    /// invocation rather than silently narrowing the analysis.
    pub fn parse_list(s: &str) -> anyhow::Result<Vec<CheckKind>> {
        s.split(',')
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty())
            .map(|p| match p.as_str() {
                "unused" => Ok(CheckKind::Unused),
                "outdated" => Ok(CheckKind::Outdated),
                "duplicate" | "duplicates" => Ok(CheckKind::Duplicate),
                "advisory" | "advisories" | "audit" | "vuln" => Ok(CheckKind::Advisory),
                "hygiene" | "lint" => Ok(CheckKind::Hygiene),
                "license" | "licenses" => Ok(CheckKind::License),
                "banned" | "ban" | "deny" => Ok(CheckKind::Banned),
                other => Err(anyhow::anyhow!("unknown check: {other}")),
            })
            .collect()
    }
}

/// Gating significance of a finding. The order Info < Warn < Error is total:
/// `has_failures` treats Warn and Error as gate-failing, Info as advisory.
/// Rationale for the assignment: only severities that demand action fail a
/// build; purely informational observations (available upgrades, duplicate
/// inventories, missing optional metadata) never break a pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational observation; never fails the gate.
    Info,
    /// Actionable defect that fails the gate by default.
    Warn,
    /// Critical defect (vulnerability, policy violation) failing any gate.
    Error,
}

/// Declarative, serializable repair program attached to an auto-fixable
/// finding. The tagged-enum serialization keeps the JSON report
/// self-describing: each action carries its discriminant (`action`) and its
/// parameters. The fix subsystem interprets actions; checks only declare
/// them, which separates analysis from mutation and makes `--check` (dry
/// run) a pure projection of the same data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum FixAction {
    /// Delete dependency `dep` from the `[dependencies]`-family tables of
    /// the manifest at `manifest`. Idempotent: re-execution after success is
    /// a no-op reporting zero removals.
    RemoveDep { manifest: String, dep: String },
    /// Run `cargo update -p <package>` in the workspace root to advance the
    /// locked version within the declared requirements. Attached only when
    /// the lag is a minor or patch lag; major lags require requirement
    /// edits by a human and therefore carry no action.
    CargoUpdate { package: String },
    /// Set `[package] <field>` in the manifest at `manifest` (currently
    /// `license` or `rust-version`). The value is resolved at apply time
    /// from the `[fix]`/`[msrv]` configuration, not at check time, so that
    /// one finding stays valid under different policies. No-op when the
    /// field is already present.
    SetManifestField { manifest: String, field: String },
}

/// A single diagnosed fact.
///
/// - `check` classifies the producing analysis (see [`CheckKind`]).
/// - `severity` determines gate behavior (see [`Severity`]).
/// - `package` names the subject: a workspace member for manifest findings,
///   a locked crate for lockfile findings.
/// - `detail` states the fact in human terms and embeds the concrete values
///   (versions, names) that make the finding unique; it participates in the
///   baseline fingerprint, hence any change of the underlying facts yields a
///   textually distinct finding.
/// - `hint` is the recommended human remediation, omitted from
///   serialization when absent.
/// - `manifest_path`/`dep_name` locate the owning manifest entry for
///   consumers that address repairs by manifest; the authoritative machine
///   repair is `fix`.
/// - `fix` is `Some` iff the finding is machine-repairable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check: CheckKind,
    pub severity: Severity,
    /// Workspace member or locked package the finding belongs to.
    pub package: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Manifest that owns the dependency (for --fix). None for lock-only findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,
    /// Dependency name as written in Cargo.toml (for --fix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_name: Option<String>,
    /// Machine-readable fix, if the finding is auto-fixable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<FixAction>,
}

impl Finding {
    /// Constructor establishing the structural invariant: a fresh finding
    /// carries classification, subject and statement, with all optional
    /// channels (hint, locations, fix) unset. Callers extend via the
    /// builder combinators below.
    pub fn new(
        check: CheckKind,
        severity: Severity,
        package: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            check,
            severity,
            package: package.into(),
            detail: detail.into(),
            hint: None,
            manifest_path: None,
            dep_name: None,
            fix: None,
        }
    }

    /// Attaches the human remediation advisory. Pure builder combinator:
    /// consumes and returns `Self` with `hint` set.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Attaches the machine repair program. Pure builder combinator:
    /// consumes and returns `Self` with `fix` set, promoting the finding
    /// from observable to actionable.
    pub fn with_fix(mut self, fix: FixAction) -> Self {
        self.fix = Some(fix);
        self
    }
}

/// The complete result of one scan: findings plus scan metadata.
///
/// - `findings` is maintained in canonical (check, package, detail) order by
///   the orchestrator, which makes reports diff-stable across runs and
///   suitable for CI artifact comparison.
/// - `skipped` records analyses that could not run and why (offline mode,
///   missing lockfile, unreachable registry), so that absence of findings
///   is never ambiguous with absence of analysis.
/// - `suppressed` counts findings removed by `[[ignore]]` rules or the
///   baseline; it defaults to zero when the field is absent from the
///   serialized form.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub skipped: Vec<String>,
    #[serde(default)]
    pub suppressed: usize,
}

impl Report {
    /// Default gate predicate: true iff any finding has severity Warn or
    /// Error. Info findings are advisory by definition and cannot fail.
    pub fn has_failures(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f.severity, Severity::Warn | Severity::Error))
    }

    /// Restricted gate predicate for `--fail-on`: the default predicate
    /// applied to the subset of findings whose check belongs to `kinds`.
    /// An empty `kinds` set fails nothing, which is the correct vacuous
    /// reading of "fail on none of these".
    pub fn has_failures_in(&self, kinds: &[CheckKind]) -> bool {
        self.findings.iter().any(|f| {
            kinds.contains(&f.check) && matches!(f.severity, Severity::Warn | Severity::Error)
        })
    }

    /// Cardinality of findings of one check. Used by tests and by future
    /// summary renderers; linear in the finding count.
    pub fn count_by_check(&self, kind: CheckKind) -> usize {
        self.findings.iter().filter(|f| f.check == kind).count()
    }
}
