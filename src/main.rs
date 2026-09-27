//! Command-line boundary: argument grammar and exit-code algebra.
//!
//! Invocation model. The binary serves two call shapes: direct
//! (`cargo-checkup [FLAGS]`) and cargo-subcommand (`cargo checkup [FLAGS]`),
//! where cargo injects its own name as the first argument. The subcommand
//! shim strips that injected token, unifying both shapes into one grammar
//! before parsing. Lexical detail: only the exact first-position token
//! `checkup` is stripped, so a user flag or value coincidentally spelling
//! `checkup` elsewhere is never disturbed.
//!
//! Exit-code algebra. The process terminates with exactly one of:
//! - 0: the report is clean or info-only;
//! - 1: a gate-relevant finding exists (any Warn/Error);
//! - 2: the tool itself failed (unparseable flags or check lists,
//!   metadata I/O errors).
//!
//! The algebra is total: every control path returns one of the three codes.

use std::path::PathBuf;
use std::process::ExitCode;

use cargo_checkup::{report, scan, CheckKind, ScanOptions};
use clap::{Parser, ValueEnum};

/// Report projection selector. The two variants correspond bijectively to
/// the renderers of the report module: terminal review and archival
/// interchange (JSON). The default is the human projection, matching
/// interactive use as the common case.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
}

/// Unified cargo health check: unused, outdated, duplicates, advisories,
/// hygiene - one report.
#[derive(Debug, Parser)]
#[command(name = "cargo-checkup", version, about)]
struct Cli {
    /// Path to Cargo.toml (defaults to current dir).
    #[arg(long)]
    manifest_path: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "human")]
    format: Format,
    /// Skip network checks (outdated, advisory).
    #[arg(long)]
    offline: bool,
    /// Ignore the disk cache for crates.io lookups.
    #[arg(long)]
    no_cache: bool,
    /// Also flag optional dependencies that look unused.
    #[arg(long)]
    strict_unused: bool,
    /// Only run these checks (comma-separated).
    #[arg(long)]
    only: Option<String>,
    /// Skip these checks (comma-separated).
    #[arg(long)]
    skip: Option<String>,
}

fn cargo_subcommand_args() -> Vec<String> {
    let mut args: Vec<String> = std::env::args().collect();
    // `cargo checkup ...` passes `checkup` as the first arg.
    if args.get(1).map(|s| s.as_str()) == Some("checkup") {
        args.remove(1);
    }
    args
}

/// Parses one comma-separated check-list flag into canonical variants.
/// Returns `Ok(None)` for an absent flag (no restriction) and `Err(2)` -
/// the tool-error exit code - naming the offending flag on parse failure.
/// Failure is immediate and total: no scan runs on malformed selection,
/// since a narrowed analysis masquerading as a full one would be a false
/// certificate.
fn parse_kinds(s: &Option<String>, flag: &str) -> Result<Option<Vec<CheckKind>>, ExitCode> {
    match s {
        None => Ok(None),
        Some(v) => match CheckKind::parse_list(v) {
            Ok(k) => Ok(Some(k)),
            Err(e) => {
                eprintln!("error: --{flag}: {e}");
                Err(ExitCode::from(2))
            }
        },
    }
}

/// Main control flow: parse, scan, render, gate. Every leaf returns a
/// member of the exit-code algebra documented in the module header; no path
/// falls through and no path panics on user input (clap owns argument
/// validation, and all fallible operations below it are `match`ed
/// explicitly).
fn main() -> ExitCode {
    let cli = Cli::parse_from(cargo_subcommand_args());

    let Ok(only) = parse_kinds(&cli.only, "only") else {
        return ExitCode::from(2);
    };
    let Ok(skip) = parse_kinds(&cli.skip, "skip") else {
        return ExitCode::from(2);
    };

    let opts = ScanOptions {
        manifest_path: cli.manifest_path.clone(),
        offline: cli.offline,
        no_cache: cli.no_cache,
        strict_unused: cli.strict_unused,
        only,
        skip,
    };
    let rep = match scan(&opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to run checkup: {e:#}");
            return ExitCode::from(2);
        }
    };

    match cli.format {
        Format::Human => print!("{}", report::render_human(&rep)),
        Format::Json => println!("{}", report::render_json(&rep)),
    }
    exit_for(&rep)
}

/// Evaluates the default gate predicate over the report. The mapping onto
/// exit codes is bijective: failure becomes 1, passage becomes 0, and no
/// other code originates here.
fn exit_for(rep: &cargo_checkup::Report) -> ExitCode {
    if rep.has_failures() { ExitCode::from(1) } else { ExitCode::from(0) }
}
