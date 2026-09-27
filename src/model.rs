//! Core data model: finding taxonomy, severity lattice and reports.
//!
//! Ontology. A scan of a Cargo workspace produces a finite multiset of
//! _findings_. Each finding is classified by exactly one _check kind_ (the
//! analysis that produced it) and one _severity_ (its gating significance).
//! A _report_ is the ordered collection of findings of one scan plus scan
//! metadata (skipped-check notes). The model is serialization-first: every
//! type derives `Serialize`/`Deserialize` so that the JSON report is a
//! faithful projection of the in-memory report.

use serde::{Deserialize, Serialize};

/// The complete taxonomy of analyses. Each variant corresponds to one check
/// module under `crate::checks` and to one user-visible name in `--only`
/// and `--skip`. The set is closed: adding an analysis requires extending
/// this enum, its string mapping, and the scan orchestrator, which keeps
/// the CLI surface and the implementation in lockstep by construction.
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
    /// suitable as a stable key in reports and fingerprints.
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

    /// Parses a comma-separated check list as accepted by `--only` and
    /// `--skip`. Grammar: case-insensitive tokens with surrounding
    /// whitespace ignored; empty tokens (from leading, trailing or doubled
    /// commas) are discarded. Documented aliases (`duplicates`, `audit`,
    /// `lint`, `ban`, `deny`) normalize to canonical variants. Any other
    /// token is a hard error naming the offender, which fails the
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

/// A single diagnosed fact.
///
/// - `check` classifies the producing analysis (see [`CheckKind`]).
/// - `severity` determines gate behavior (see [`Severity`]).
/// - `package` names the subject: a workspace member for manifest findings,
///   a locked crate for lockfile findings.
/// - `detail` states the fact in human terms and embeds the concrete values
///   (versions, names) that make the finding unique; it participates in
///   finding identity, hence any change of the underlying facts yields a
///   textually distinct finding.
/// - `hint` is the recommended human remediation, omitted from
///   serialization when absent.
/// - `manifest_path`/`dep_name` locate the owning manifest entry.
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
}

impl Finding {
    /// Constructor establishing the structural invariant: a fresh finding
    /// carries classification, subject and statement, with all optional
    /// channels (hint, locations) unset. Callers extend via the builder
    /// combinator below.
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
        }
    }

    /// Attaches the human remediation advisory. Pure builder combinator:
    /// consumes and returns `Self` with `hint` set.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
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
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub skipped: Vec<String>,
}

impl Report {
    /// Default gate predicate: true iff any finding has severity Warn or
    /// Error. Info findings are advisory by definition and cannot fail.
    pub fn has_failures(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f.severity, Severity::Warn | Severity::Error))
    }

    /// Cardinality of findings of one check. Used by tests and by future
    /// summary renderers; linear in the finding count.
    pub fn count_by_check(&self, kind: CheckKind) -> usize {
        self.findings.iter().filter(|f| f.check == kind).count()
    }
}
