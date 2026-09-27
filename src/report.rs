//! Report rendering: projections of a `Report` onto output formats.
//!
//! Doctrine. Analysis (`checks`), policy (`config`) and repair (`fix`) all
//! operate on the in-memory `Report`; this module is the sole boundary to
//! human and machine consumers. Three projections are defined, each total
//! over all reports:
//! - human: dense single-line findings with indented hints, optimized for
//!   terminal review and CI logs;
//! - json: the faithful serialization of the `Report` value itself,
//!   optimized for programmatic consumption and artifact archiving;
//! - sarif: the SARIF 2.1.0 static-analysis interchange format, optimized
//!   for ingestion by code-scanning platforms (notably GitHub code
//!   scanning).
//!
//! All renderers are pure functions: identical reports always render
//! identically, which makes golden-file testing of output well-defined.

use serde::Serialize;

use crate::model::{CheckKind, Report, Severity};

/// Terminal sigil per check kind. Uppercase marks the two prohibitive
/// severities' home checks (advisories and bans are never merely
/// informational), drawing the reviewer's eye to the gate-critical rows.
/// The mapping is display-only: machine formats use canonical `as_str`
/// names, never these labels.
fn label(kind: CheckKind) -> &'static str {
    match kind {
        CheckKind::Unused => "unused",
        CheckKind::Outdated => "outdated",
        CheckKind::Duplicate => "duplicate",
        CheckKind::Advisory => "ADVISORY",
        CheckKind::Hygiene => "hygiene",
        CheckKind::License => "license",
        CheckKind::Banned => "BANNED",
    }
}

/// Renders the human projection. Layout grammar: one severity-tagged row per
/// finding (`[level] <check> <subject> <statement>` in fixed-width columns),
/// each followed by its hint line when present; then the finding count (or
/// the clean bill `OK: no issues found` on the empty report); then the
/// suppression count when nonzero; then the skip ledger when non-empty. The
/// order of sections is fixed so that the verdict precedes the accounting,
/// matching how reviewers scan CI logs top-down.
pub fn render_human(report: &Report) -> String {
    let mut out = String::new();
    if report.findings.is_empty() {
        out.push_str("OK: no issues found\n");
    } else {
        for f in &report.findings {
            let sev = match f.severity {
                Severity::Info => "info",
                Severity::Warn => "warn",
                Severity::Error => "error",
            };
            out.push_str(&format!(
                "[{sev:5}] {:9} {:30} {}\n",
                label(f.check),
                f.package,
                f.detail
            ));
            if let Some(hint) = &f.hint {
                out.push_str(&format!("         hint: {hint}\n"));
            }
        }
        out.push_str(&format!("\n{} finding(s)\n", report.findings.len()));
    }
    if report.suppressed > 0 {
        out.push_str(&format!(
            "{} finding(s) suppressed by checkup.toml/baseline\n",
            report.suppressed
        ));
    }
    if !report.skipped.is_empty() {
        out.push_str("skipped:\n");
        for s in &report.skipped {
            out.push_str(&format!("  - {s}\n"));
        }
    }
    out
}

/// Renders the JSON projection: pretty-printed serialization of the report
/// value. Pretty-printing (rather than compact form) is chosen because these
/// artifacts are routinely inspected by humans in CI run archives; the size
/// overhead is linear and negligible at realistic finding counts.
pub fn render_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

/// SARIF log envelope. The `$schema` and `version` constants pin SARIF
/// 2.1.0, the version consumed by contemporary code-scanning ingesters;
/// `runs` carries exactly one run because one tool invocation is one
/// analysis run by definition.
#[derive(Debug, Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

/// One analysis run: the tool identity plus the ordered result list.
/// Result order follows report order, preserving the orchestrator's
/// canonical sorting through the interchange boundary.
#[derive(Debug, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

/// Tool identity wrapper, per the SARIF object model (run -> tool ->
/// driver). The indirection is schema-mandated, not designed.
#[derive(Debug, Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

/// Driver descriptor: tool name, crate version (injected at compile time so
/// that published artifacts self-identify their provenance), and the rule
/// catalog restricted to rules actually triggered in this run. Restriction
/// (rather than the full catalog) keeps small reports small while remaining
/// schema-valid, since every emitted `ruleId` resolves within `rules`.
#[derive(Debug, Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    rules: Vec<SarifRule>,
}

/// One rule descriptor: the stable identifier `checkup/<check>`, derived
/// from the canonical check name so that suppressions and dashboards keyed
/// on rule ids remain valid across tool versions.
#[derive(Debug, Serialize)]
struct SarifRule {
    id: String,
}

/// One result: the triggered rule, the SARIF severity level (the tool's
/// ternary severity maps onto SARIF's `error`/`warning`/`note` with `none`
/// deliberately unused, since every finding is at least noteworthy), and
/// the message combining subject, statement and remediation advisory.
#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
}

/// Message body. When a hint exists, subject and statement occupy the first
/// line and the remediation follows on the second; otherwise the single
/// line stands alone. The two-line shape mirrors the human renderer, giving
/// scanners and terminals a consistent reading experience.
#[derive(Debug, Serialize)]
struct SarifMessage {
    text: String,
}

/// Renders the SARIF 2.1.0 projection for code-scanning ingestion
/// (`--format sarif`). Rule catalog construction deduplicates triggered
/// checks in canonical order, so the catalog is deterministic for a given
/// finding multiset. Serialization is infallible by construction over
/// plain-data structs; the `{}` fallback is unreachable defensive code
/// satisfying the total-function contract of the module.
pub fn render_sarif(report: &Report) -> String {
    let mut kinds: Vec<CheckKind> = report.findings.iter().map(|f| f.check).collect();
    kinds.sort_by_key(|k| k.as_str());
    kinds.dedup();
    let rules = kinds
        .iter()
        .map(|k| SarifRule {
            id: format!("checkup/{}", k.as_str()),
        })
        .collect();
    let results = report
        .findings
        .iter()
        .map(|f| SarifResult {
            rule_id: format!("checkup/{}", f.check.as_str()),
            level: match f.severity {
                Severity::Error => "error",
                Severity::Warn => "warning",
                Severity::Info => "note",
            },
            message: SarifMessage {
                text: match &f.hint {
                    Some(hint) => format!("{}: {}\n{hint}", f.package, f.detail),
                    None => format!("{}: {}", f.package, f.detail),
                },
            },
        })
        .collect();
    let log = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "cargo-checkup",
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results,
        }],
    };
    serde_json::to_string_pretty(&log).unwrap_or_else(|_| "{}".to_string())
}
