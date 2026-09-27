//! Report rendering: projections of a `Report` onto output formats.
//!
//! Doctrine. Analysis (`checks`), policy (`config`) and repair (`fix`) all
//! operate on the in-memory `Report`; this module is the sole boundary to
//! human and machine consumers. Two projections are defined, each total
//! over all reports:
//! - human: dense single-line findings with indented hints, optimized for
//!   terminal review and CI logs;
//! - json: the faithful serialization of the `Report` value itself,
//!   optimized for programmatic consumption and artifact archiving.
//!
//! Both renderers are pure functions: identical reports always render
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
