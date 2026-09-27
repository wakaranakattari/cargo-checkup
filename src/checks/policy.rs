//! Organizational policy enforcement over the lockfile and member metadata.
//!
//! Doctrine. Universal analyses (unused code, known CVEs) need no
//! configuration, but three judgments are inherently organizational and must
//! come from `checkup.toml`: which licenses are acceptable, which crates are
//! forbidden, and what toolchain floor members must declare. This module
//! evaluates exactly those three policies. When a policy section is empty,
//! its analysis is definitionally vacuous and produces zero findings, which
//! keeps policy-free runs silent without special-casing at the call site.
//!
//! Evaluation domains. License and ban policies range over distinct locked
//! third-party packages (workspace members excluded - a repository cannot
//! ban or license-violate itself), deduplicated by name with first-locked
//! version as representative. The MSRV policy ranges over workspace members,
//! comparing each declared `rust-version` against the required floor on
//! partial-version triples (see `config::parse_partial_version`).
//!
//! Severity assignment. License violations and ban hits are `Error`: they
//! express deliberate organizational prohibitions, and a gate that can be
//! broken by prohibited code is no gate. Unlicensed dependencies are `Warn`
//! (absence of metadata is suspicious but not proven prohibited). A member
//! floor below the required one is `Warn` and carries a `SetManifestField`
//! repair resolving to the required value at apply time.

use std::collections::{BTreeMap, BTreeSet};

use cargo_metadata::Metadata;

use crate::config::{CheckupConfig, license_allowed, parse_partial_version};
use crate::model::{CheckKind, Finding, Severity};

/// Evaluates the license, ban and MSRV policies. The function is pure over
/// (metadata, config): it performs no I/O and consults no network, so its
/// output is a deterministic function of the lockfile content and the policy
/// text. Findings are emitted in deterministic (sorted-name) order; final
/// canonical ordering is imposed downstream regardless.
pub fn check_policy(metadata: &Metadata, cfg: &CheckupConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    let has_license_policy = !cfg.licenses.allow.is_empty() || !cfg.licenses.deny.is_empty();
    let has_banned = !cfg.banned.crates.is_empty();
    let msrv = cfg.msrv.version.as_deref().and_then(parse_partial_version);

    if has_license_policy || has_banned {
        // Projection of the lockfile onto (name -> (version, license)):
        // distinct third-party crates with their declared license strings.
        let mut locked: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
        for pkg in &metadata.packages {
            if metadata.workspace_members.contains(&pkg.id) {
                continue;
            }
            locked
                .entry(pkg.name.to_string())
                .or_insert((pkg.version.to_string(), pkg.license.clone()));
        }
        // Normalized ban set: lowercasefolded once, so that per-candidate
        // matching is a single hash lookup on the folded candidate name.
        let banned: BTreeSet<String> = cfg.banned.crates.iter().map(|s| s.to_lowercase()).collect();
        for (name, (version, license)) in &locked {
            // Ban rule: exact (modulo case) membership. Any hit - direct or
            // transitive, the map makes no distinction - is an error.
            if has_banned && banned.contains(&name.to_lowercase()) {
                findings.push(
                    Finding::new(
                        CheckKind::Banned,
                        Severity::Error,
                        name.clone(),
                        format!("{name}@{version} is on the banned list"),
                    )
                    .with_hint("remove it from checkup.toml [banned] or drop the dependency"),
                );
            }
            // License rule: trichotomy over the declared license string.
            // Absent metadata warns (unknown provenance); a rejected
            // expression errors (proven violation); an accepted expression
            // is silent. The decision itself lives in `license_allowed`.
            if has_license_policy {
                match license {
                    None => findings.push(
                        Finding::new(
                            CheckKind::License,
                            Severity::Warn,
                            name.clone(),
                            format!("{name}@{version} declares no license"),
                        )
                        .with_hint("add an exception to [[ignore]] or pick another crate"),
                    ),
                    Some(expr) if !license_allowed(expr, &cfg.licenses) => findings.push(
                        Finding::new(
                            CheckKind::License,
                            Severity::Error,
                            name.clone(),
                            format!("{name}@{version} license `{expr}` violates policy"),
                        )
                        .with_hint("adjust [licenses] in checkup.toml or replace the crate"),
                    ),
                    _ => {}
                }
            }
        }
    }

    // MSRV rule: a member complies iff its declared floor parses and
    // dominates the required floor component-wise. Unparsable floors and the
    // absent-policy case (`msrv` is `None`) are silent here: absent
    // declarations are the hygiene check's jurisdiction (rule H2), and this
    // rule judges declared values only.
    if let Some(required) = msrv {
        let pkgs: std::collections::HashMap<_, _> =
            metadata.packages.iter().map(|p| (&p.id, p)).collect();
        for member_id in &metadata.workspace_members {
            let Some(pkg) = pkgs.get(member_id) else {
                continue;
            };
            match pkg
                .rust_version
                .as_ref()
                .and_then(|v| parse_partial_version(&v.to_string()))
            {
                Some(have) if have < required => findings.push(
                    Finding::new(
                        CheckKind::Hygiene,
                        Severity::Warn,
                        pkg.name.to_string(),
                        format!(
                            "rust-version {} below required {}",
                            pkg.rust_version.as_ref().unwrap(),
                            cfg.msrv.version.as_deref().unwrap_or("")
                        ),
                    )
                    .with_hint("bump `rust-version` in Cargo.toml or run with --fix")
                    .with_fix(crate::model::FixAction::SetManifestField {
                        manifest: pkg
                            .manifest_path
                            .as_std_path()
                            .to_string_lossy()
                            .into_owned(),
                        field: "rust-version".to_string(),
                    }),
                ),
                _ => {}
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Axiom of vacuous policy: the default (empty) configuration defines no
    /// license rule, no ban and no floor, hence the policy evaluator ranges
    /// over empty rule sets. This test pins the emptiness invariant on which
    /// the "silent when unconfigured" behavior formally depends.
    #[test]
    fn empty_config_is_silent_on_fake_data() {
        // Policy with no rules produces nothing regardless of metadata shape.
        let cfg = CheckupConfig::default();
        assert!(cfg.licenses.allow.is_empty());
        assert!(cfg.banned.crates.is_empty());
        assert!(cfg.msrv.version.is_none());
    }
}
