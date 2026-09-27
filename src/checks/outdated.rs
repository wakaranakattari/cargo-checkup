//! Freshness analysis: locked versions versus registry maxima.
//!
//! Problem statement. A lockfile pins exact versions at the moment of
//! resolution; the registry moves on. For each direct workspace dependency,
//! the analysis asks whether the locked version strictly precedes the current
//! maximum stable version on crates.io, and if so, by which semver magnitude
//! (major, minor, or patch).
//!
//! Corpus restriction. Only direct dependencies of workspace members are
//! queried. Rationale: transitive versions are not actionable by the
//! repository owner (they move only via direct requirement changes), and
//! querying the full closure would multiply request volume by an order of
//! magnitude for unactionable data. Workspace-internal path dependencies are
//! excluded because they have no registry existence.
//!
//! Magnitude semantics. Lags classify as minor or patch when the newer
//! revision may still satisfy common caret requirements, and as major when
//! it definitionally violates every requirement pinning the current major;
//! the latter class always requires human requirement edits.
//!
//! Severity rationale. Findings are `Info`: an available upgrade is an
//! opportunity, not a defect, and must never fail a gate on its own. Gating
//! on freshness remains available explicitly via `--fail-on outdated`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use cargo_metadata::Metadata;
use serde::Deserialize;

use crate::cache::CratesCache;
use crate::model::{CheckKind, Finding, Severity};

/// Projection of the crates.io crate endpoint onto the single field the
/// analysis consumes. The `crate` key is renamed because `crate` is a Rust
/// keyword; all other response fields are ignored by construction, which
/// makes the client immune to additive API evolution.
#[derive(Debug, Deserialize)]
struct CratesIoResponse {
    #[serde(rename = "crate")]
    krate: CratesIoCrate,
}

/// Registry metadata fragment: the maximum stable version, if the registry
/// reports one. `None` covers yanked-only and pre-release-only crates, for
/// which "latest" is undefined and the analysis abstains.
#[derive(Debug, Deserialize)]
struct CratesIoCrate {
    max_stable_version: Option<String>,
}

/// Fetches the maximum stable version of one crate. Total function returning
/// `Option`: transport failure, non-success status and decode failure all
/// map to `None`, and the caller records each such case under `skipped:`
/// rather than treating absence of data as absence of lag (the two must
/// never be conflated).
fn fetch_max_stable(client: &reqwest::blocking::Client, name: &str) -> Option<String> {
    let url = format!("https://crates.io/api/v1/crates/{name}");
    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: CratesIoResponse = resp.json().ok()?;
    body.krate.max_stable_version
}

/// Classifies the semver distance between the locked (`current`) and
/// registry (`latest`) versions by the most significant differing component.
/// Precondition: `latest > current` (established by the caller); under it,
/// exactly one of the three arms holds, so the classification is total and
/// unambiguous on its domain.
fn bump_kind(current: &semver::Version, latest: &semver::Version) -> &'static str {
    if latest.major != current.major {
        "major"
    } else if latest.minor != current.minor {
        "minor"
    } else {
        "patch"
    }
}

/// Resolves maximum stable versions for all names with bounded parallelism.
/// The name list is partitioned into at most 8 chunks processed by scoped
/// threads sharing nothing but an immutable cache reference and cloned HTTP
/// clients (cloning a `reqwest` client shares the connection pool, so no
/// pool is duplicated). Cache hits never touch the network. Design
/// parameters: 8 workers bound registry load and avoid rate-limiting while
/// keeping wall-clock time near the slowest single lookup; scoped threads
/// guarantee all workers join before return, so the function has no
/// background effects. Result order across chunks is unspecified; the
/// orchestrator imposes canonical order downstream.
fn fetch_all(
    client: &reqwest::blocking::Client,
    cache: &CratesCache,
    names: &[String],
) -> Vec<(String, Option<String>)> {
    if names.is_empty() {
        return Vec::new();
    }
    let workers = names.len().clamp(1, 8);
    let chunk_size = names.len().div_ceil(workers);
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for chunk in names.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            let client = client.clone();
            handles.push(s.spawn(move || {
                let mut out = Vec::with_capacity(chunk.len());
                for name in chunk {
                    let latest = cache
                        .get(&name)
                        .or_else(|| fetch_max_stable(&client, &name));
                    out.push((name, latest));
                }
                out
            }));
        }
        let mut results = Vec::with_capacity(names.len());
        for h in handles {
            results.extend(h.join().unwrap_or_default());
        }
        results
    })
}

/// Executes the freshness analysis. Pipeline stages:
/// 1. Locked-version extraction: distinct crate names mapped to a
///    representative locked version from the resolve graph, excluding
///    workspace members (which are versioned by the repository itself).
///    An empty map means no resolvable third-party code exists, which is
///    reported as a skip condition rather than a vacuous success.
/// 2. Direct-dependency projection: the queried set is the intersection of
///    locked names with declared direct dependencies (minus path-internal
///    ones), per the corpus restriction above.
/// 3. Resolution and comparison: each name resolves via cache-then-network;
///    unresolvable names are recorded under `skipped:`; unparsable versions
///    on either side abstain silently (a registry or lockfile anomaly, not
///    a repository defect); strict precedence (`latest > current`) emits a
///    finding with magnitude classification, human hint, and - for
///    minor/patch lags - the `CargoUpdate` repair action.
///
/// Cache discipline: observations are stored after successful fetch unless
/// `--no-cache` is set; persistence itself happens once per scan in the
/// orchestrator via `CratesCache::save`.
pub fn check_outdated(
    metadata: &Metadata,
    offline: bool,
    no_cache: bool,
    cache: &mut CratesCache,
) -> (Vec<Finding>, Vec<String>) {
    if offline {
        return (Vec::new(), vec!["outdated skipped (--offline)".to_string()]);
    }
    // Unique crate names with a representative locked version.
    let mut locked: BTreeMap<String, String> = BTreeMap::new();
    if let Some(resolve) = &metadata.resolve {
        let pkg_version: BTreeMap<&cargo_metadata::PackageId, String> = metadata
            .packages
            .iter()
            .map(|p| (&p.id, p.version.to_string()))
            .collect();
        for node in &resolve.nodes {
            // Each resolve node denotes one locked package; its version is
            // recovered through the package index keyed by node identity.
            if let Some(v) = pkg_version.get(&node.id) {
                // Find package name for this id.
                if let Some(pkg) = metadata.packages.iter().find(|p| p.id == node.id) {
                    // Skip workspace members themselves.
                    if metadata.workspace_members.contains(&node.id) {
                        continue;
                    }
                    locked.entry(pkg.name.to_string()).or_insert(v.clone());
                }
            }
        }
    }
    if locked.is_empty() {
        // No resolvable third-party code exists (for example, metadata was
        // produced without a lockfile); the check abstains explicitly.
        return (
            Vec::new(),
            vec![
                "outdated: no resolve graph, run `cargo metadata` in a workspace with Cargo.lock"
                    .to_string(),
            ],
        );
    }
    // Only check direct workspace deps to keep request count reasonable.
    let mut direct: BTreeSet<String> = BTreeSet::new();
    for member in &metadata.workspace_members {
        if let Some(pkg) = metadata.packages.iter().find(|p| &p.id == member) {
            for dep in &pkg.dependencies {
                // Skip workspace-internal path deps.
                if metadata
                    .packages
                    .iter()
                    .any(|p| p.name == dep.name && metadata.workspace_members.contains(&p.id))
                {
                    continue;
                }
                direct.insert(dep.name.clone());
            }
        }
    }

    let client = match reqwest::blocking::Client::builder()
        .user_agent(concat!("cargo-checkup/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            return (Vec::new(), vec!["outdated: http client failed".to_string()]);
        }
    };

    let names: Vec<String> = direct.into_iter().collect();
    let mut findings = Vec::new();
    let mut skipped = Vec::new();
    for (name, latest_opt) in fetch_all(&client, cache, &names) {
        let Some(current_str) = locked.get(&name) else {
            continue;
        };
        let Ok(current) = current_str.parse::<semver::Version>() else {
            continue;
        };
        let Some(latest_str) = latest_opt else {
            skipped.push(format!("outdated: no crates.io data for `{name}`"));
            continue;
        };
        if !no_cache {
            cache.put(&name, latest_str.clone());
        }
        let Ok(latest) = latest_str.parse::<semver::Version>() else {
            continue;
        };
        if latest > current {
            let kind = bump_kind(&current, &latest);
            let finding = Finding::new(
                CheckKind::Outdated,
                Severity::Info,
                name.clone(),
                format!("{current_str} -> {latest_str} ({kind} behind)"),
            )
            .with_hint(format!("run `cargo update -p {name}`"));
            findings.push(finding);
        }
    }
    (findings, skipped)
}
