<p align="center">
  <img src="docs/images/logo-wordmark.svg" alt="brew-ports" width="520">
</p>

# brew-ports-untangle

`brew-ports` untangles a Mac that has both Homebrew and MacPorts, or more than
one Homebrew prefix.

Do you have both Homebrew and MacPorts packages installed, and find that things
don't work? Maybe you don't know you have both, because you ran commands from
the internet, and now some things don't work?

Using two package managers on a Mac (`brew` and `port`) causes lots of issues.
They install libraries and packages in different locations, and both try to put
theirs first on the PATH. Homebrew packages can then build or link against MacPorts
libraries, and the other way round - this causes issues when updating packages.

You also usually end up with two copies of the same packages, half of them never used.

`brew-ports` inventories every installation and checks each package manager's
database. It recommends a manager to keep and migrates your packages to it,
asking before each phase.

`--remove-manager` also removes the other manager entirely.

> **Status:** every command exists, and unit tests run each one against
> simulated hosts, but the tool has not yet migrated a real Mac. Until it has,
> use the read-only commands listed under Safety and the `--dry-run` form of
> the others.

## Why

Package managers that share one Mac interfere with each other:

- Each manager installs a separate set of shared libraries and interpreters,
  so `openssl`, `python`, and `glib` exist twice and drift apart.
- Both put their `bin` directories first on `PATH`, so the order of the lines
  in your shell files decides which `python3` or `git` runs.
- Builds find headers and libraries in the other prefix. Neither manager's
  health tools can see the other's packages.

## Requirements

brew-ports needs:

- macOS 13 or newer, on Apple Silicon or Intel.
- The Command Line Tools (`xcode-select --install`), which both managers need.
  brew-ports runs without them, so `doctor` can report them missing.
- An administrator account for the commands that change the system. They ask
  for your password once per run, through `sudo`.

A release bundles CPython 3.15, so brew-ports needs neither manager nor the
Command Line Tools, even while removing a manager or python.

## Getting started

Download your Mac's release with `curl` and unpack it:

```sh
arch=$(uname -m)        # arm64 on Apple Silicon, x86_64 on Intel
curl -LO "https://github.com/andylemin/brew-ports-untangle/releases/download/v0.1.0/brew-ports-0.1.0-macos-$arch.tar.gz"
mkdir -p ~/.local
tar -xzf "brew-ports-0.1.0-macos-$arch.tar.gz" -C ~/.local
~/.local/brew-ports-0.1.0/bin/brew-ports scan
```

- Use `curl`. A browser marks the download as quarantined, and
  Gatekeeper refuses to run Python inside it.
- Unpack it outside every Homebrew and MacPorts prefix. If brew-ports runs from
  inside one, `doctor` reports `system-running-inside-prefix`, and `plan`
  refuses to start.
- `SHA256SUMS` lists each release's tarball sums.

From a checkout, fetch the same Python first:

```sh
git clone https://github.com/andylemin/brew-ports-untangle.git
cd brew-ports-untangle
tools/fetch-python.sh "$(uname -m)" build/python
./brew-ports scan
```

A typical session migrates MacPorts packages to Homebrew, with the release's
`bin` on `PATH`:

```sh
brew-ports doctor                                   # health of both managers
brew-ports recommend                                # which manager to keep
brew-ports plan --target brew --out plan.json       # what will be installed, kept and removed
brew-ports apply plan.json --dry-run                # every command, nothing run
brew-ports apply plan.json                          # confirm each phase as it runs
brew-ports verify plan.json
```

## Commands

brew-ports has nine commands:

| Command | What it does |
| --- | --- |
| `scan` | Inventory every prefix: packages, services, taps, shell setup, cross-prefix linkage, language packages. |
| `doctor [--fix]` | Health checks for both managers. `--fix` offers each remedy for confirmation. |
| `recommend` | Score both directions by package coverage, casks, bottles, services, and work, and recommend one. |
| `bootstrap-ports` | Install MacPorts from its signed installer package on a Mac without it. |
| `plan --target brew\|ports` | Map each package you installed on purpose to a replacement, with its confidence and evidence, and write `plan.json`. |
| `apply PLAN` | Run a plan. |
| `verify [PLAN]` | Check a run's result against the current state of the Mac. |
| `env-cleanup [--apply]` | Show the PATH lines, exports, and sourced files of a removed prefix in your shell files. `--apply` removes them. |
| `rollback RUN-ID` | Reinstall what a run removed, from its snapshot. |

Every command takes `--state-dir DIR`, `--verbose`, `--quiet`, `--no-color`, and `--redact`.
Commands that change the system take `--yes` and `--dry-run`.

On a terminal, a status line shows the step a command is in and how long it has run. It also names the
program the step waits for, or counts the files it reads. `--quiet` turns it off.

The main `plan` options:

| Option | Meaning |
| --- | --- |
| `--only NAME,…` | Migrate only these packages. The source manager stays. |
| `--keep NAME,…` | Leave these packages installed in the source. |
| `--drop NAME,…` | Remove these packages without a replacement. |
| `--map SOURCE=TARGET` | Choose the target package yourself. |
| `--accept-medium` | Accept medium-confidence mappings without asking. |
| `--casks keep\|drop\|map` | What to do with Homebrew casks when the target is MacPorts. |
| `--lang-packages report\|pipx` | Report Python, Node, Ruby, and Perl packages, or reinstall Python tools with `pipx`. |
| `--remove-manager[=PREFIX,…]` | Also remove the old manager itself once its packages are gone. |
| `--start-services` | Start the replacements of the services that were running. |
| `--repology` | Ask repology.org about packages the offline catalogs cannot match. |
| `--refresh` | Update the target's catalog (`brew update`, `port sync`) first. |

## How a migration runs

`apply` runs a plan in phases, and asks before each phase unless you give
`--yes`.

| Phase | Step |
| --- | --- |
| 0 | Preflight: the blocking health findings, the tool checks, the disk check, and `sudo`. |
| 1 | Snapshot both managers: package lists, `Brewfile`, registry backup, services, shell files. |
| 2 | Repair the target manager where the packages it installs need repair. |
| 3 | Install every replacement, then rebuild target packages that link into the old prefix. |
| 4 | Gate: each replacement must exist, provide its commands, and link cleanly. |
| 5 | Remove the source packages, after stopping their services. |
| 6 | Remove the old manager itself, only with `--remove-manager`, after archiving its data directories. |
| 7 | Clean the shell environment and `/etc/paths`. |
| 8 | Run the `verify` checks, and write `report.md`. |

`--stop-after N` ends a run after phase N. `apply --resume RUN-ID` continues a
run: phases 1 to 3 skip the work that succeeded, and the later phases recompute
the remaining work from the host. After phase 6,
`rollback` prints how to reinstall the removed manager, and restores its
packages when run again.

## Safety

Five rules protect the Mac:

- `scan`, `recommend`, `plan`, `verify`, and `doctor` without `--fix` change
  nothing on the system, and write only to the state directory and to
  `plan --out`.
- A run removes nothing before phase 4 checks the replacement, and touches
  nothing outside the plan's removal set. That set never holds packages you
  keep, the surviving manager's packages, or services you wrote yourself.
- brew-ports runs as you. `sudo` runs per command, only where needed. `brew`
  never runs under `sudo`. Ctrl-C lets the running command finish its cleanup
  before the run stops.
- Every run records a journal, a snapshot of both managers, and a backup of
  every file it edits, which `rollback` restores from.
- Only installs, `--refresh`, `bootstrap-ports`, `--repology`, and the PyPI
  lookups of `--lang-packages pipx` use the network. brew-ports checks the
  MacPorts installer package against a pinned Apple Developer ID signature
  before running it.

## Exit codes

brew-ports exits with one of six codes:

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Findings present (`doctor`, `recommend`), or a refused plan. |
| 2 | Usage error. |
| 3 | A precondition failed: running as root, the Command Line Tools missing, a blocking finding, a stale plan, or no `sudo`. |
| 4 | An action or a service stop failed, or an interrupt stopped the run. The output names the resume command. |
| 5 | A `verify` check failed. |

## Findings

`doctor` reports each finding by name, with its evidence and remedy. The name's
first word gives its area:

| Prefix | Area | Example |
| --- | --- | --- |
| `system-` | Toolchain and system | `system-clt-missing` |
| `brew-` | Homebrew | `brew-keg-without-receipt` |
| `ports-` | MacPorts | `ports-missing-file` |
| `env-` | Both managers and the shell environment | `env-shadowed-commands` |

`verify` checks the replacements, their services, the login shell's PATH, and
the language packages, and that nothing of the removal set remains.

## State

The state directory, `~/Library/Application Support/brew-ports/` unless
`--state-dir` names another, keeps each run under `runs/<run-id>/`: its scan,
plan, journal, snapshot, backups, archives, and `report.md`. The report redacts
your home directory and login name, and `--redact` also redacts the terminal
output.

## Development

The code uses Python 3.15 and its standard library only. Run the unit tests in
a container, or on the fetched Python:

```sh
docker run --rm -v "$PWD:/src:ro" -w /src python:3.15-slim \
  python3 -B -m unittest discover -s tests/unit -t .
build/python/bin/python3 -B -m unittest discover -s tests/unit -t .
```

The tests never run `brew`, `port`, or `sudo`: commands go through a fake
runner. CI runs the quality gates and unit tests, and migrates a disposable
runner with both managers in each direction.

[CONTRIBUTING.md](CONTRIBUTING.md) describes the gates, the conventions, and
the releases. [docs/architecture.md](docs/architecture.md) shows how the modules
fit together.

## License

MIT, see [LICENSE](LICENSE).
