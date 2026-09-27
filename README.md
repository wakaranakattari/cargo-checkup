# cargo-checkup

`cargo-checkup` is a single binary that audits the dependency health of a Rust
workspace in one pass. It replaces a shelf of single-purpose plugins with one
unified report, one policy file, and optional automatic fixes.

Checks performed:

- **unused** - dependencies that look unused (stable Rust, no nightly needed)
- **outdated** - locked versions behind crates.io max stable
- **duplicate** - several versions of one crate in `Cargo.lock`, with
  who-pulls-what chains from the resolve graph
- **advisory** - known vulnerabilities via the OSV.dev API, no database clone
- **license** - dependency licenses against an allow/deny policy
- **banned** - forbidden crates anywhere in the lockfile, including transitive
- **hygiene** - missing `license`/`rust-version`, stale edition, wildcard reqs

## Installation

From crates.io:

```sh
cargo install cargo-checkup
```

From source:

```sh
git clone https://github.com/wakaranakattari/cargo-checkup
cd cargo-checkup
cargo install --path .
```

Requirements: stable Rust 1.85 or newer. No nightly toolchain, no extra
binaries. The `outdated` and `advisory` checks need network access; everything
else works fully offline, and `--offline` skips the network checks entirely.

Shell completions:

```sh
cargo checkup completions bash >> ~/.bashrc
cargo checkup completions zsh >> ~/.zshrc
cargo checkup completions fish > ~/.config/fish/completions/cargo-checkup.fish
```

A man page is included at `doc/cargo-checkup.1`:

```sh
man doc/cargo-checkup.1
```

## Quick start

```sh
cd your-workspace
cargo checkup init      # write a starter checkup.toml
cargo checkup           # full check, as a cargo subcommand
```

Typical output:

```text
[warn ] unused    myapp     possibly unused dependency `itoa`
         hint: remove `itoa` from [dependencies] in /repo/Cargo.toml or run with --fix
[error] advisory  time      time@0.3.20 affected by GHSA-...
         hint: see https://osv.dev/vulnerability/GHSA-...
[error] license   old-dep   old-dep@2.1.0 license `GPL-3.0-only` violates policy
         hint: adjust [licenses] in checkup.toml or replace the crate
[info ] outdated  serde     1.0.100 -> 1.0.229 (patch behind)
         hint: run `cargo update -p serde`
[info ] duplicate syn       2 versions in lockfile: 2.0.119, 3.0.6
         hint: run `cargo update -p syn` to unify. 2.0.119 <- jni-macros@0.22.4; 3.0.6 <- clap_derive@4.6.7, serde_derive@1.0.229

5 finding(s)
```

## CLI reference

```text
cargo checkup [OPTIONS]
cargo-checkup init [--force]
cargo-checkup completions <bash|zsh|fish|powershell|elvish>
```

| Flag                            | Meaning                                               |
| ------------------------------- | ----------------------------------------------------- |
| `--manifest-path <PATH>`        | Path to `Cargo.toml` (default: current directory)     |
| `--format <human\|json\|sarif>` | Output format (default: `human`)                      |
| `--offline`                     | Skip network checks (`outdated`, `advisory`)          |
| `--no-cache`                    | Ignore the disk cache for crates.io lookups           |
| `--strict-unused`               | Also flag optional dependencies that look unused      |
| `--fix`                         | Apply all auto-fixes, exit 0 on success               |
| `--check`                       | Print what `--fix` would do, change nothing           |
| `--only <list>`                 | Run only these checks, comma-separated                |
| `--skip <list>`                 | Skip these checks, comma-separated                    |
| `--fail-on <list>`              | Exit 1 only on these checks, comma-separated          |
| `--config <PATH>`               | Policy file (default: auto-discovered `checkup.toml`) |
| `--baseline <PATH>`             | Suppress findings recorded in the baseline            |
| `--baseline-update <PATH>`      | Write current findings as the new baseline            |

Check names accepted by `--only`, `--skip`, `--fail-on`: `unused`,
`outdated`, `duplicate`, `advisory`, `hygiene`, `license`, `banned`.

When invoked as `cargo checkup`, the extra `checkup` argument that cargo
inserts is stripped automatically, so both `cargo checkup --offline` and
`cargo-checkup --offline` work.

## Checks in detail

### unused (warn, fixable)

For every non-dev dependency of each workspace member, the crate identifier
(`my-crate` becomes `my_crate`, renames honored) is searched in all `.rs`
files of that package, including `build.rs`, tests, examples and benches. A
dependency that never appears as `ident::`, `use ident` or
`extern crate ident` is reported.

- Dev-dependencies are always skipped: they are only used under `cfg(test)`
  and a text scan cannot judge them reliably.
- Optional dependencies are skipped by default because they are often
  referenced through `#[cfg(feature = "...")]` gates rather than imports.
  `--strict-unused` enables checking them; a `feature = "<dep>"` gate then
  counts as usage.
- Severity is `warn`, so any hit fails the default CI gate. Suppress single
  hits with `[[ignore]]` (see below) rather than disabling the whole check.

### outdated (info, minor/patch fixable)

Locked versions of direct workspace dependencies are compared against
`max_stable_version` from the crates.io API. Results are cached on disk for
24 hours (`$XDG_CACHE_HOME/cargo-checkup/crates-io.json`, falling back to
`~/.cache/...`) and fetched with 8 parallel workers.

Minor and patch lags carry an auto-fix (`cargo update -p <crate>`). Major
lags are reported for a human because the requirement string usually blocks
the upgrade and semver allows breaking changes.

### duplicate (info, fixable)

Parses `Cargo.lock` and reports crates present in more than one version. For
each version the report names up to 5 dependents (`name@version`) taken from
the `cargo metadata` resolve graph, so you can see which requirement chain
pins the old copy. The attached fix runs `cargo update -p <crate>` to attempt
unification where semver permits.

### advisory (error, not fixable)

Every locked third-party `name@version` is sent to `api.osv.dev/v1/querybatch`
in batches of 100. No rustsec database clone, no extra tools. Each returned
vulnerability is an `error` finding with a link to `osv.dev/vulnerability/<id>`.
Upgrading the affected crate (manually or via the `outdated` fix) is the
remedy, so no auto-fix is attached.

### license (error/warn, not fixable)

Every locked third-party crate's license string is matched against
`[licenses]` in `checkup.toml`:

- `deny` wins: any denied token inside the expression (for example
  `GPL-3.0-only` inside `MIT OR GPL-3.0-only`) is an `error`.
- If `allow` is non-empty, expressions outside it are `error`s. A bare
  single-token license matching the list, or the whole expression matching
  verbatim, is accepted.
- A crate declaring no license at all is a `warn`.

Matching is token-based over SPDX-style `OR`/`AND` expressions, not a full
SPDX parser; parenthesized forms like `(MIT OR Apache-2.0) AND Unicode-3.0`
are handled at the token level.

### banned (error, not fixable)

Crate names from `[banned] crates` are matched case-insensitively against the
whole lockfile, including transitive dependencies. Any hit is an `error`.

### hygiene (info/warn, partly fixable)

Manifest-level checks needing no network:

- missing `license` (or `license-file`) - info, fixable via `[fix] license`
- missing `rust-version` - info, fixable via `[fix] rust_version`
- `rust-version` below `[msrv] version` - warn, fixable (takes the required value)
- stale `edition` (`2015`/`2018`) - info, manual
- wildcard requirement `*` - warn, manual (pin a semver range)

## Policy file (`checkup.toml`)

`cargo checkup init` writes a starter file into the workspace root with the
`allow` list pre-filled from licenses currently in the lockfile. Lookup order
for a run: `--config <PATH>`, then `<workspace-root>/checkup.toml`, then
`<manifest-dir>/checkup.toml`. A missing file means "no policy": license and
banned checks stay silent. An unreadable or mistyped file is a hard error
(exit 2) - a policy tool must never silently ignore its own config
(`deny_unknown_fields` is enforced, so typos in table names fail loudly).

Full example:

```toml
[licenses]
allow = ["MIT", "Apache-2.0", "MIT OR Apache-2.0"]
deny = ["GPL-3.0-only", "AGPL-3.0-only"]

[banned]
crates = ["openssl"]

[msrv]
version = "1.75"

[fix]
license = "MIT OR Apache-2.0"
rust_version = "1.75"

[[ignore]]
check = "outdated"
package = "serde"

[[ignore]]
check = "unused"
dep = "itoa"
detail_contains = "build-"
```

An `[[ignore]]` rule suppresses a finding when all specified fields match:
`check` (required), plus optional `package`, `dep` (the `Cargo.toml` name),
and `detail_contains` (substring of the detail line). Rules with unknown check
names do not fail the run but are listed under `skipped:` so typos stay
visible.

## Baselines for legacy repos

A large existing repo will produce noise on the first run. Bless it once,
then gate only on new findings:

```sh
cargo checkup --baseline-update .checkup-baseline.json
cargo checkup --baseline .checkup-baseline.json
```

The baseline stores stable fingerprints of post-ignore findings and reports
`N finding(s) suppressed by checkup.toml/baseline`. Version bumps change the
detail text, so an updated crate correctly re-appears as a new finding.
Commit the baseline file and refresh it deliberately when dependencies change.

## CI integration

Minimal gate - fails only on what matters, info-level findings stay green:

```yaml
- run: cargo install cargo-checkup
- run: cargo checkup --fail-on unused,advisory,license,banned
```

SARIF upload for GitHub code scanning:

```yaml
- run: cargo checkup --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Air-gapped runners:

```sh
cargo checkup --offline
```

A ready-made workflow (fmt, clippy, tests, offline dogfood on itself,
publish dry-run) ships at `.github/workflows/ci.yml`.

## Fixes (`--fix` vs `--check`)

`--check` prints the planned actions and changes nothing; the exit code still
follows the findings. `--fix` applies them and exits 0 unless an action
errors (exit 2).

| Finding                                                      | `--fix` action                                                                                                    |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| unused                                                       | removes the entry from `[dependencies]` (also target-specific tables), one read/write per manifest                |
| missing `license`                                            | sets `[package] license` from `[fix] license` (default `MIT OR Apache-2.0`)                                       |
| missing/low `rust-version`                                   | sets `[package] rust-version` from `[fix] rust_version`, else `[msrv] version`; errors when neither is configured |
| outdated minor/patch                                         | runs `cargo update -p <crate>` in the workspace root                                                              |
| duplicate                                                    | runs `cargo update -p <crate>` (best-effort unify)                                                                |
| major outdated, advisory, license, banned, wildcard, edition | manual - printed as hints                                                                                         |

Identical actions implied by several findings are deduplicated and executed
once.

## Exit codes

| Code | Meaning                                                              |
| ---- | -------------------------------------------------------------------- |
| 0    | clean, info-only, or `--fix` applied successfully                    |
| 1    | a warn/error finding exists (or matches `--fail-on`)                 |
| 2    | tool error: bad flags, unreadable config/baseline, failed fix action |

## Cache

`outdated` caches crates.io answers for 24 hours. `--no-cache` bypasses
load and store, `--offline` skips the check (and the advisory check)
entirely. Delete `$XDG_CACHE_HOME/cargo-checkup/crates-io.json` (or
`~/.cache/cargo-checkup/crates-io.json`) to force a refresh.

## Comparison with alternatives

`cargo-audit` needs a rustsec checkout and covers only advisories.
`cargo-deny` covers licenses/bans but not unused/outdated/duplicates and uses
its own config language. `cargo-udeps` needs nightly and flags only unused
deps. `cargo-outdated` only lists versions. `cargo-msrv` only bisects the
toolchain. `cargo-shear`/`machete` only trim manifests. `cargo-checkup` runs
all of these concerns in one pass with one config file and one report format,
at the cost of heuristic (not compiler-precise) unused detection.

The name `cargo-doctor` was already taken on crates.io by an unrelated
abandoned crate, hence `cargo-checkup`.

## Limitations

- `unused` is a text scan. Re-exports through macros, build-script codegen,
  and feature-unification edge cases can produce false positives or miss
  real dead deps. When in doubt, verify with a full build after `--fix`.
- `outdated` checks direct workspace dependencies only, to keep request
  counts reasonable.
- License matching is token-based, not a certified SPDX evaluator. Dual
  licensing with `WITH` exceptions on non-standard texts may need an
  explicit `[[ignore]]` rule.
