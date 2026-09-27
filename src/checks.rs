//! Check registry: the exhaustive index of analyses.
//!
//! Each submodule implements exactly one [`crate::model::CheckKind`] variant
//! as a pure function over cargo metadata. The orchestrator in `crate::scan`
//! is the sole consumer; no check is reachable except through it, which
//! guarantees that global concerns (check selection, ordering) apply
//! uniformly to every analysis.

pub mod duplicates;
pub mod hygiene;
pub mod unused;
