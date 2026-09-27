//! Advisory analysis: known vulnerabilities in locked dependencies.
//!
//! Problem statement. A lockfile pins exact versions; some of those versions
//! may be subject to publicly disclosed vulnerabilities. The authoritative
//! question per locked `name@version` pair is therefore: does a vulnerability
//! database record an affected range containing this version?
//!
//! Protocol selection. Instead of vendoring a vulnerability database (the
//! `cargo-audit` approach, which requires cloning and updating the RustSec
//! advisory DB), this module queries the OSV.dev batch API over HTTPS. The
//! protocol is a single `POST /v1/querybatch` carrying up to hundreds of
//! (ecosystem, package, version) triples, with positional results: the i-th
//! response element corresponds to the i-th query. Positional correspondence
//! is the invariant on which finding attribution rests (see the zip loop).
//! Consequences of the choice: zero local state, zero subprocesses, and
//! coverage beyond Rust-specific advisories (OSV aggregates multi-ecosystem
//! records for crates.io), at the cost of mandatory network access - hence
//! the `--offline` skip path.
//!
//! Severity rationale. Every confirmed affected pair is an `Error`: a known
//! vulnerability in shipped code is the strongest possible gate signal, and
//! no auto-fix is attached because remediation (upgrade, patch, replacement)
//! requires version-range reasoning beyond version comparison.

use std::collections::BTreeMap;
use std::time::Duration;

use cargo_metadata::Metadata;
use serde::{Deserialize, Serialize};

use crate::model::{CheckKind, Finding, Severity};

/// Request envelope of the OSV batch API: an ordered list of queries.
/// Serialization shape follows the API schema exactly; field order is the
/// attribution contract with the positional response.
#[derive(Debug, Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

/// One vulnerability query: a package identity plus the exact locked version
/// under test. The server evaluates its recorded affected ranges against
/// this version; the client performs no range arithmetic of its own.
#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

/// Package identity in OSV coordinates: the crates.io name together with the
/// fixed ecosystem discriminator `crates.io`, which selects the registry
/// whose version ordering and advisory corpus apply.
#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

/// Response envelope: results in one-to-one positional correspondence with
/// the request queries. The client relies on equal length and order; a
/// length mismatch truncates attribution via `zip`, which is fail-closed
/// (unattributed results are dropped, never misattributed).
#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvResult>,
}

/// Per-query result: the (possibly empty) set of vulnerabilities affecting
/// the queried version. Defaults to empty so that schema evolution adding
/// optional fields cannot break deserialization of the mandatory core.
#[derive(Debug, Deserialize, Default)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

/// One vulnerability record: the canonical OSV/GHSA identifier plus an
/// optional human summary. Only these two fields are extracted; the full
/// record (severity vectors, references, ranges) is one hyperlink away via
/// the constructed `osv.dev/vulnerability/<id>` hint.
#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
}

/// Executes the advisory analysis. Pipeline stages:
/// 1. Corpus construction: the set of distinct locked third-party
///    `name@version` pairs, i.e. all metadata packages minus workspace
///    members, deduplicated by name (first locked version wins; duplicate
///    versions of one crate are reported by the `duplicate` check and share
///    the advisory fate of the sampled version).
/// 2. Chunked querying: the corpus is partitioned into chunks of 100, each
///    sent as one batch request. Chunking bounds request size within server
///    limits while keeping the request count logarithmic in practice.
/// 3. Attribution: each response element is zipped with its query; every
///    listed vulnerability becomes one `Error` finding on the queried pair,
///    with the summary truncated to 120 characters for report legibility.
///
/// Failure semantics are fail-open with full disclosure: transport errors,
/// non-success statuses and decode errors abort further chunks and record
/// the precise cause under `skipped:`, so a degraded run can never be
/// mistaken for a clean bill of health.
pub fn check_advisories(metadata: &Metadata, offline: bool) -> (Vec<Finding>, Vec<String>) {
    if offline {
        return (Vec::new(), vec!["advisory skipped (--offline)".to_string()]);
    }
    // Unique (name, version) of non-workspace packages.
    let mut locked: BTreeMap<String, String> = BTreeMap::new();
    for pkg in &metadata.packages {
        if metadata.workspace_members.contains(&pkg.id) {
            continue;
        }
        locked
            .entry(pkg.name.to_string())
            .or_insert(pkg.version.to_string());
    }
    // An empty corpus means no lockable third-party code exists; there is
    // nothing to query, which is reported rather than silently succeeding.
    if locked.is_empty() {
        return (Vec::new(), vec!["advisory: nothing locked".to_string()]);
    }
    let entries: Vec<(String, String)> = locked.into_iter().collect();

    let client = match reqwest::blocking::Client::builder()
        .user_agent(concat!("cargo-checkup/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (Vec::new(), vec!["advisory: http client failed".to_string()]),
    };

    let mut findings = Vec::new();
    let mut skipped = Vec::new();
    for chunk in entries.chunks(100) {
        let req = OsvBatchRequest {
            queries: chunk
                .iter()
                .map(|(name, version)| OsvQuery {
                    package: OsvPackage {
                        name: name.clone(),
                        ecosystem: "crates.io".to_string(),
                    },
                    version: version.clone(),
                })
                .collect(),
        };
        let resp = client
            .post("https://api.osv.dev/v1/querybatch")
            .json(&req)
            .send();
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                skipped.push(format!("advisory: osv request failed: {e}"));
                return (findings, skipped);
            }
        };
        if !resp.status().is_success() {
            skipped.push(format!("advisory: osv status {}", resp.status()));
            return (findings, skipped);
        }
        let body: OsvBatchResponse = match resp.json() {
            Ok(b) => b,
            Err(e) => {
                skipped.push(format!("advisory: osv decode failed: {e}"));
                return (findings, skipped);
            }
        };
        for ((name, version), result) in chunk.iter().zip(body.results.iter()) {
            for vuln in &result.vulns {
                let summary = if vuln.summary.is_empty() {
                    String::new()
                } else {
                    format!(" - {}", vuln.summary.chars().take(120).collect::<String>())
                };
                findings.push(
                    Finding::new(
                        CheckKind::Advisory,
                        Severity::Error,
                        name.clone(),
                        format!("{name}@{version} affected by {}{summary}", vuln.id),
                    )
                    .with_hint(format!("see https://osv.dev/vulnerability/{}", vuln.id)),
                );
            }
        }
    }
    (findings, skipped)
}
