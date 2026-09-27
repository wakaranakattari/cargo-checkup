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
//! - 0: the report is clean or info-only; a requested `--fix` applied
//!   without errors;
//! - 1: a gate-relevant finding exists (any Warn/Error); `--check`
//!   preserves this semantics because it changes nothing;
//! - 2: the tool itself failed (unparseable flags or check lists,
//!   metadata I/O errors, failed fix actions).
//!
//! The algebra is total: every control path returns one of the three codes.

use std::path::PathBuf;
use std::process::ExitCode;

use cargo_checkup::{fix, report, scan, CheckKind, ScanOptions};
use clap::{Parser, ValueEnum};

/// Report projection selector. The two variants correspond bijectively to
/// the renderers of the report module: terminal review and archival
/// interchange (JSON). The default is the human projection, matching
/// interactive use as the common case.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
}

/// Unified cargo health check: unused, outdated, duplicates, advisories,
/// license policy, hygiene - one report, optional --fix.
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
    /// Apply all auto-fixes (unused removal, manifest fields, cargo update).
    #[arg(long)]
    fix: bool,
    /// Print what --fix would do without changing anything.
    #[arg(long)]
    check: bool,
    /// Only run these checks (comma-separated).
    #[arg(long)]
    only: Option<String>,
    /// Skip these checks (comma-separated).
    #[arg(long)]
    skip: Option<String>,
    /// Fail only on these checks (comma-separated, default: any warn/error).
    #[arg(long)]
    fail_on: Option<String>,
    /// Suppress findings recorded in the baseline file.
    #[arg(long)]
    baseline: Option<PathBuf>,
    /// Write current findings as the new baseline file.
    #[arg(long)]
    baseline_update: Option<PathBuf>,
    /// Path to checkup.toml policy file (auto-discovered by default).
    #[arg(long)]
    config: Option<PathBuf>,
}

/// Normalizes the process argument vector into the tool grammar by excising
/// the cargo-injected `checkup` token when present at position one. Pure
/// function of the argument vector; performs no parsing itself, only the
/// lexical normalization on which parsing depends.
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

/// Main control flow, structured as a decision tree over mode: the scan
/// runs, then exactly one of the fix pipeline (`--fix`/`--check`) or the
/// render-and-gate path executes. Every leaf returns a member of the
/// exit-code algebra documented in the module header; no path falls through
/// and no path panics on user input (clap owns argument validation, and all
/// fallible operations below it are `match`ed explicitly).
fn main() -> ExitCode {
    let cli = Cli::parse_from(cargo_subcommand_args());

    let Ok(only) = parse_kinds(&cli.only, "only") else {
        return ExitCode::from(2);
    };
    let Ok(skip) = parse_kinds(&cli.skip, "skip") else {
        return ExitCode::from(2);
    };
    let Ok(fail_on) = parse_kinds(&cli.fail_on, "fail-on") else {
        return ExitCode::from(2);
    };

    let opts = ScanOptions {
        manifest_path: cli.manifest_path.clone(),
        offline: cli.offline,
        no_cache: cli.no_cache,
        strict_unused: cli.strict_unused,
        only,
        skip,
        config_path: cli.config.clone(),
        baseline: cli.baseline.clone(),
        baseline_update: cli.baseline_update.clone(),
    };
    let (rep, cfg) = match scan(&opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to run checkup: {e:#}");
            return ExitCode::from(2);
        }
    };

    // Repair branch. `--check` (dry run) prints the prospective actions to
    // stdout and preserves gate semantics onward; `--fix` applies them,
    // narrates to stderr (stdout stays machine-clean for potential piping),
    // and returns 0 unless an action errored (2). The `cargo update`
    // working directory is the scanned manifest's directory when known,
    // else the process working directory, else the current directory
    // sentinel - a total fallback chain with no failure mode.
    if cli.fix || cli.check {
        // Workspace root for `cargo update`: prefer the scanned manifest dir.
        let root = cli
            .manifest_path
            .as_ref()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let outcome = fix::execute_fixes(&rep.findings, &cfg, &root, cli.check);
        for a in &outcome.actions {
            if cli.check {
                println!("{a}");
            } else {
                eprintln!("fix: {a}");
            }
        }
        for e in &outcome.errors {
            eprintln!("fix error: {e}");
        }
        if cli.check {
            // --check changes nothing; exit per findings.
            return exit_for(&rep, fail_on.as_deref());
        }
        if !outcome.errors.is_empty() {
            return ExitCode::from(2);
        }
        return ExitCode::from(0);
    }

    // Render-and-gate branch: project the report onto the selected format,
    // then evaluate the gate predicate over it.
    match cli.format {
        Format::Human => print!("{}", report::render_human(&rep)),
        Format::Json => println!("{}", report::render_json(&rep)),
        Format::Sarif => println!("{}", report::render_sarif(&rep)),
    }
    exit_for(&rep, fail_on.as_deref())
}

/// Evaluates the gate predicate: the restricted predicate over `fail_on`
/// when the flag is present, the default predicate otherwise. The mapping
/// onto exit codes is bijective with the algebra: failure becomes 1,
/// passage becomes 0, and no other code originates here.
fn exit_for(rep: &cargo_checkup::Report, fail_on: Option<&[CheckKind]>) -> ExitCode {
    let failed = match fail_on {
        Some(kinds) => rep.has_failures_in(kinds),
        None => rep.has_failures(),
    };
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}
