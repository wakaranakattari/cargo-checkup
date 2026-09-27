//! Check registry: the exhaustive index of analyses.
//!
//! Each submodule implements exactly one [`crate::model::CheckKind`] variant
//! as a pure function over cargo metadata (plus, where unavoidable,
//! registry I/O): `unused` (textual reference analysis), `outdated`
//! (registry freshness), `duplicates` (lockfile multiplicity with resolve
//! attribution), `advisory` (OSV vulnerability matching), `hygiene`
//! (manifest well-formedness), `policy` (organizational license/ban/MSRV
//! rules from `checkup.toml`). The orchestrator in `crate::scan` is the sole
//! consumer; no check is reachable except through it, which guarantees that
//! global concerns (check selection, ignore rules, baselines, ordering) apply
//! uniformly to every analysis.

pub mod advisory;
pub mod duplicates;
pub mod hygiene;
pub mod outdated;
pub mod policy;
pub mod unused;
