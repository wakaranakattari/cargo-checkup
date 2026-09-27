//! Persistent disk cache for crates.io `max_stable_version` lookups.
//!
//! Rationale. The `outdated` check resolves one HTTP request per direct
//! dependency. Without memoization, repeated invocations (local iterations,
//! CI matrices) pay the full network latency on every run and risk
//! rate-limiting by the registry. This module implements a minimal
//! time-bounded memoization table: each entry maps a crate name to the
//! observed maximum stable version together with the observation timestamp.
//! Entries older than the time-to-live constant are treated as absent, which
//! bounds the staleness of every reported version by construction.
//!
//! Failure model. The cache is strictly best-effort and purely advisory: any
//! I/O or deserialization failure degrades to an empty table, and a missing
//! or unwritable cache directory disables persistence without affecting the
//! correctness of the scan. No cache error ever propagates to the caller.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Maximum age of a cached observation. Invariant: for every entry returned
/// by [`CratesCache::get`], `now - fetched_at <= TTL` holds.
const TTL: Duration = Duration::from_secs(24 * 3600);

/// On-disk representation of the cache. The `entries` field defaults to an
/// empty map so that truncated or partially written files still deserialize
/// into a usable (empty) table rather than aborting the scan.
#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default)]
    entries: HashMap<String, CachedEntry>,
}

/// A single memoized observation.
///
/// - `max_stable`: the `max_stable_version` string reported by crates.io.
/// - `fetched_at`: Unix timestamp (seconds) of the observation. A value of
///   zero denotes the epoch and therefore always fails the freshness test.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedEntry {
    max_stable: String,
    fetched_at: u64,
}

/// Current Unix time in seconds. Definition: seconds elapsed since
/// `UNIX_EPOCH` according to the system clock; falls back to zero when the
/// clock precedes the epoch (a configuration no freshness test can satisfy,
/// hence fail-safe).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Memoization table for crates.io version lookups.
///
/// State consists of the optional persistence path (`None` denotes a disabled
/// cache that accepts no writes), the in-memory entry map, and a dirty flag
/// recording whether the map changed since load. The dirty flag guarantees
/// that [`CratesCache::save`] performs zero filesystem operations on runs
/// that only performed reads, which keeps read-only invocations side-effect
/// free.
pub struct CratesCache {
    path: Option<PathBuf>,
    entries: HashMap<String, CachedEntry>,
    dirty: bool,
}

impl CratesCache {
    /// Constructs the table. When `disabled` is true, the table is inert:
    /// [`CratesCache::put`] discards all writes and [`CratesCache::save`] is
    /// a no-op. Otherwise the table attempts to load the file at the
    /// resolved cache path; any failure (absent file, unreadable content,
    /// schema mismatch) yields an empty table. Postcondition: the returned
    /// instance is always usable regardless of filesystem state.
    pub fn load(disabled: bool) -> Self {
        let path = cache_path();
        if disabled {
            return Self {
                path: None,
                entries: HashMap::new(),
                dirty: false,
            };
        }
        let entries = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str::<CacheFile>(&t).ok())
            .map(|f| f.entries)
            .unwrap_or_default();
        Self {
            path,
            entries,
            dirty: false,
        }
    }

    /// Returns the memoized maximum stable version for `name` iff a fresh
    /// observation exists. Freshness predicate: the entry exists and
    /// `now - fetched_at <= TTL`, evaluated with saturating subtraction so
    /// that clock skew toward the past cannot underflow. Stale entries are
    /// indistinguishable from absent ones; they remain stored until
    /// overwritten but are never returned.
    pub fn get(&self, name: &str) -> Option<String> {
        let e = self.entries.get(name)?;
        if now_unix().saturating_sub(e.fetched_at) > TTL.as_secs() {
            return None;
        }
        Some(e.max_stable.clone())
    }

    /// Records an observation for `name` with the current timestamp and marks
    /// the table dirty. On a disabled table (`path` is `None`) the write is
    /// discarded, preserving the invariant that a disabled cache performs no
    /// observable state change.
    pub fn put(&mut self, name: &str, max_stable: String) {
        if self.path.is_none() {
            return;
        }
        self.entries.insert(
            name.to_string(),
            CachedEntry {
                max_stable,
                fetched_at: now_unix(),
            },
        );
        self.dirty = true;
    }

    /// Persists the table iff it changed since load. Creates missing parent
    /// directories on demand. Every failure mode (uncreatable directory,
    /// serialization error, unwritable file) is silently absorbed: the cache
    /// is an optimization, and its loss must not alter scan results.
    pub fn save(&self) {
        let Some(path) = &self.path else { return };
        if !self.dirty {
            return;
        }
        if let Some(parent) = path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return;
            }
        }
        let file = CacheFile {
            entries: self.entries.clone(),
        };
        if let Ok(text) = serde_json::to_string(&file) {
            let _ = std::fs::write(path, text);
        }
    }
}

/// Resolves the persistence path by the following total order:
/// 1. `$XDG_CACHE_HOME/cargo-checkup/crates-io.json` when `XDG_CACHE_HOME`
///    is set and non-empty (XDG Base Directory specification);
/// 2. `$HOME/.cache/cargo-checkup/crates-io.json` otherwise.
///
/// Returns `None` when neither variable yields a path, in which case the
/// cache operates in memory only for the duration of the process.
fn cache_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Some(
                PathBuf::from(xdg)
                    .join("cargo-checkup")
                    .join("crates-io.json"),
            );
        }
    }
    std::env::var("HOME").ok().map(|h| {
        PathBuf::from(h)
            .join(".cache")
            .join("cargo-checkup")
            .join("crates-io.json")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Axiom under test: a disabled table is observationally inert.
    /// A `put` followed by `get` must behave as if the `put` never happened.
    #[test]
    fn put_get_roundtrip() {
        let mut c = CratesCache {
            path: None,
            entries: HashMap::new(),
            dirty: false,
        };
        // Disabled cache stores nothing.
        c.put("serde", "1.0.0".into());
        assert_eq!(c.get("serde"), None);
    }

    /// Axiom under test: freshness is decided solely by entry age.
    /// An epoch-dated entry misses; a just-written entry hits.
    #[test]
    fn stale_entry_misses() {
        let mut c = CratesCache {
            path: Some(PathBuf::from("/nonexistent")),
            entries: HashMap::new(),
            dirty: false,
        };
        c.entries.insert(
            "old".into(),
            CachedEntry {
                max_stable: "1.0.0".into(),
                fetched_at: 0,
            },
        );
        assert_eq!(c.get("old"), None);
        c.put("fresh", "2.0.0".into());
        assert_eq!(c.get("fresh").as_deref(), Some("2.0.0"));
    }
}
