//! Scan orchestrator: from CLI options to a suppressed, ordered report.
//!
//! Pipeline architecture. A scan is the sequential composition of six
//! stages, each with a single responsibility:
//! 1. Metadata acquisition: one `cargo metadata` invocation materializes
//!    the workspace graph (packages, resolve nodes, manifests).
//! 2. Policy resolution: the `checkup.toml` file is discovered and parsed,
//!    or the empty default policy is adopted; ignore rules are validated.
//! 3. Analysis: every enabled check executes over the metadata, each
//!    contributing findings and skip notes independently (checks share no
//!    mutable state, so their relative order is semantically irrelevant).
//! 4. Cache persistence: the crates.io memoization table is flushed once,
//!    after all readers have run.
//! 5. Suppression: `[[ignore]]` rules filter first (repository-declared
//!    exceptions), then the baseline filters (triage-accepted findings).
//!    The order matters: the baseline blesses post-ignore findings, so
//!    removing an ignore rule correctly resurrects the finding rather than
//!    hiding it behind a stale blessing.
//! 6. Canonicalization: findings are sorted by (check, package, detail),
//!    making every report diff-stable across runs and machines.
//!
//! Error doctrine. Metadata failure, unreadable policy, and unreadable
//! baseline are fatal (a report computed from partial inputs would be a
//! false certificate). Per-check degradations (offline mode, unreachable
//! registry) are non-fatal by design and surface as skip notes, so that
//! absence of findings is never ambiguous with absence of analysis.

pub mod baseline;
pub mod cache;
pub mod checks;
pub mod config;
pub mod fix;
pub mod model;
pub mod report;

use std::collections::HashSet;
use std::path::PathBuf;

pub use config::CheckupConfig;
pub use model::{CheckKind, Finding, FixAction, Report, Severity};

/// The complete parameterization of one scan, mirroring the CLI surface.
/// Each field maps to exactly one flag or subcommand-less option; `None`
/// denotes the flag's absence (defaults apply), never an error. The struct
/// is consumed by value semantics at use sites but held by reference here,
/// since a scan borrows its options for its entire duration.
pub struct ScanOptions {
    /// Manifest anchoring the `cargo metadata` invocation, i.e. `--manifest-path`.
    pub manifest_path: Option<PathBuf>,
    /// Skip the network-dependent checks, i.e. `--offline`.
    pub offline: bool,
    /// Bypass the crates.io disk cache, i.e. `--no-cache`.
    pub no_cache: bool,
    /// Extend unused analysis to optional dependencies, i.e. `--strict-unused`.
    pub strict_unused: bool,
    /// Restrict execution to these checks, i.e. `--only` (absence runs all).
    pub only: Option<Vec<CheckKind>>,
    /// Exclude these checks from execution, i.e. `--skip`.
    pub skip: Option<Vec<CheckKind>>,
    /// Explicit policy file, i.e. `--config` (absence triggers discovery).
    pub config_path: Option<PathBuf>,
    /// Baseline for suppression-by-triage, i.e. `--baseline`.
    pub baseline: Option<PathBuf>,
    /// Destination for bless-mode baseline writing, i.e. `--baseline-update`.
    pub baseline_update: Option<PathBuf>,
}

/// Conjunctive ignore predicate over one finding and the policy rule set.
/// A rule matches iff its check equals the finding's canonical check name
/// and every specified optional field matches (package by subject equality,
/// dep by `dep_name` equality, detail fragment by substring containment).
/// Omitted fields are unconstrained. The predicate is monotone in rule
/// specificity: adding constraints can only narrow the match set, never
/// widen it, so rules compose safely.
fn finding_ignored(f: &Finding, rules: &[config::IgnoreRule]) -> bool {
    rules.iter().any(|r| {
        if r.check.to_lowercase() != f.check.as_str() {
            return false;
        }
        if let Some(p) = &r.package {
            if p != &f.package {
                return false;
            }
        }
        if let Some(d) = &r.dep {
            if f.dep_name.as_deref() != Some(d.as_str()) {
                return false;
            }
        }
        if let Some(sub) = &r.detail_contains {
            if !f.detail.contains(sub) {
                return false;
            }
        }
        true
    })
}

/// Executes the six-stage pipeline and returns the canonical report together
/// with the loaded policy (which `--fix` requires for value resolution).
/// Postconditions: findings are canonically ordered; `suppressed` equals the
/// exact number of findings removed by ignore rules and baseline combined;
/// every executed-but-degraded check contributed its cause to `skipped`.
/// In bless mode (`baseline_update` set), the post-ignore findings are
/// written as the new baseline and the returned report carries zero
/// findings with the write recorded under `skipped:`, so the invocation
/// both records and reports success in one artifact.
pub fn scan(opts: &ScanOptions) -> anyhow::Result<(Report, CheckupConfig)> {
    let mut cmd = cargo_metadata::MetadataCommand::new();
    if let Some(manifest) = &opts.manifest_path {
        cmd.manifest_path(manifest);
    }
    let metadata = cmd.exec()?;
    let workspace_root = metadata.workspace_root.as_std_path().to_path_buf();
    let manifest_dir = opts
        .manifest_path
        .as_ref()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    // Stage 2: policy resolution with early rule validation. Unknown check
    // names in rules are reported, not fatal: a typo must be visible, but
    // must not veto an otherwise valid scan.
    let mut skipped_notes: Vec<String> = Vec::new();
    let cfg_path = match &opts.config_path {
        Some(p) => {
            if !p.exists() {
                anyhow::bail!("config file not found: {}", p.display());
            }
            Some(p.clone())
        }
        None => CheckupConfig::discover(None, &workspace_root, manifest_dir.as_deref()),
    };
    let cfg = match &cfg_path {
        Some(p) => CheckupConfig::load(p)?,
        None => CheckupConfig::default(),
    };
    // Validate ignore rules early so typos don't silently do nothing.
    for rule in &cfg.ignore {
        if CheckKind::parse_list(&rule.check).is_err() {
            skipped_notes.push(format!("ignore rule with unknown check `{}`", rule.check));
        }
    }

    // Check selection: `--only` is a whitelist, `--skip` a blacklist,
    // absence of both is the full taxonomy. `--only` dominates `--skip`
    // when both are given (a check must be listed to run at all).
    let enabled: HashSet<CheckKind> = CheckKind::all()
        .iter()
        .copied()
        .filter(|k| {
            if let Some(only) = &opts.only {
                return only.contains(k);
            }
            if let Some(skip) = &opts.skip {
                return !skip.contains(k);
            }
            true
        })
        .collect();

    // Stage 3: independent analyses over shared immutable metadata.
    let mut report = Report::default();
    let mut cache = cache::CratesCache::load(opts.no_cache || opts.offline);

    if enabled.contains(&CheckKind::Unused) {
        report
            .findings
            .extend(checks::unused::check_unused(&metadata, opts.strict_unused));
    }
    if enabled.contains(&CheckKind::Hygiene) {
        report
            .findings
            .extend(checks::hygiene::check_hygiene(&metadata));
    }
    if enabled.contains(&CheckKind::License) || enabled.contains(&CheckKind::Banned) {
        let mut policy = checks::policy::check_policy(&metadata, &cfg);
        policy.retain(|f| enabled.contains(&f.check));
        report.findings.extend(policy);
    }
    if enabled.contains(&CheckKind::Duplicate) {
        report.findings.extend(checks::duplicates::check_duplicates(
            &metadata,
            &workspace_root,
        ));
    }
    if enabled.contains(&CheckKind::Outdated) {
        let (findings, skipped) =
            checks::outdated::check_outdated(&metadata, opts.offline, opts.no_cache, &mut cache);
        report.findings.extend(findings);
        report.skipped.extend(skipped);
    }
    if enabled.contains(&CheckKind::Advisory) {
        let (findings, skipped) = checks::advisory::check_advisories(&metadata, opts.offline);
        report.findings.extend(findings);
        report.skipped.extend(skipped);
    }
    // Stage 4: single cache flush after all readers completed.
    cache.save();

    // Stage 5a: repository-declared exceptions. The suppressed count is
    // exact: pre-filter cardinality minus post-filter cardinality.
    let before = report.findings.len();
    report.findings.retain(|f| !finding_ignored(f, &cfg.ignore));
    report.suppressed += before - report.findings.len();

    // Stage 5b: triage-accepted findings. Baseline load failure is fatal
    // (proceeding without the accepted set would misreport blessed noise
    // as novel defects).
    if let Some(path) = &opts.baseline {
        match baseline::load_baseline(path) {
            Ok(entries) => {
                let findings = std::mem::take(&mut report.findings);
                let (kept, n) = baseline::apply_baseline(findings, &entries);
                report.findings = kept;
                report.suppressed += n;
            }
            Err(e) => anyhow::bail!("baseline {}: {e:#}", path.display()),
        }
    }

    // Bless mode: persist post-ignore findings as the new accepted set and
    // return an empty finding list, so the invocation reports the blessing
    // itself rather than the blessed findings.
    if let Some(path) = &opts.baseline_update {
        let n = baseline::write_baseline(path, &report.findings)?;
        report.findings.clear();
        report
            .skipped
            .push(format!("wrote {n} baseline entries to {}", path.display()));
    }

    // Stage 6: canonical order for CI diff-stability.
    report.findings.sort_by(|a, b| {
        (a.check.as_str(), &a.package, &a.detail).cmp(&(b.check.as_str(), &b.package, &b.detail))
    });
    report.skipped.extend(skipped_notes);
    Ok((report, cfg))
}

/// Implements `cargo checkup init`: materializes a starter `checkup.toml` in
/// the workspace root. Refuses to overwrite an existing file unless `force`
/// is set, since silent overwrite would destroy curated policy. The template
/// is pre-filled with the distinct license strings of the current lockfile
/// (see `config::init_template`), encoding the status quo as the initial
/// policy. Returns the written path on success.
pub fn init_config(manifest_path: Option<&PathBuf>, force: bool) -> anyhow::Result<PathBuf> {
    let mut cmd = cargo_metadata::MetadataCommand::new();
    if let Some(manifest) = manifest_path {
        cmd.manifest_path(manifest);
    }
    let metadata = cmd.exec()?;
    let workspace_root = metadata.workspace_root.as_std_path().to_path_buf();
    let path = workspace_root.join("checkup.toml");
    if path.exists() && !force {
        anyhow::bail!("{} exists (use --force to overwrite)", path.display());
    }
    let mut licenses: Vec<String> = metadata
        .packages
        .iter()
        .filter(|p| !metadata.workspace_members.contains(&p.id))
        .filter_map(|p| p.license.clone())
        .collect();
    licenses.sort();
    licenses.dedup();
    std::fs::write(&path, config::init_template(&licenses))?;
    Ok(path)
}
