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

A full move also uninstalls each old Homebrew or MacPorts that it leaves empty.
`--keep-managers` leaves them installed.

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
curl -LO "https://github.com/andylemin/brew-ports-untangle/releases/download/v0.2.0/brew-ports-0.2.0-macos-$arch.tar.gz"
mkdir -p ~/.local
tar -xzf "brew-ports-0.2.0-macos-$arch.tar.gz" -C ~/.local
~/.local/brew-ports-0.2.0/bin/brew-ports scan
```

- Use `curl`. A browser marks the download as quarantined, and
  Gatekeeper refuses to run Python inside it.
- Unpack it outside every Homebrew and MacPorts prefix. If brew-ports runs from
  inside one, `doctor` says so, and `plan` refuses to start.
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
brew-ports doctor --fix --target brew               # repair the one you keep
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
| `doctor [--fix] [--target brew\|ports]` | Health checks for both managers. `--fix` offers the fixes it can make and asks before each. On a Mac with more than one installation, `--fix` needs `--target` and repairs only the installation you keep. |
| `recommend` | Score both directions by package coverage, casks, bottles, services, and work, and recommend one. |
| `bootstrap-ports` | Install MacPorts from its signed installer package on a Mac without it. |
| `plan --target brew\|ports` | Find a replacement for each package you installed yourself, ask about the uncertain ones, and write `plan.json`. |
| `apply PLAN` | Run a plan. |
| `verify [PLAN]` | Check a run's result against the current state of the Mac. |
| `env-cleanup [--apply]` | Show the PATH lines, exports, and sourced files of a removed prefix in your shell files. `--apply` removes them. |
| `rollback RUN-ID` | Reinstall what a run removed, from its snapshot. |

Every command takes `--state-dir DIR`, `--verbose`, `--quiet`, and `--redact`.
Commands that change the system take `--yes` and `--dry-run`.

On a terminal, a status line shows the step a command is in and how long it has run. It also names the
program the step waits for, or counts the files it reads. `--quiet` turns it off.

The main `plan` options:

| Option | Meaning |
| --- | --- |
| `--only NAME,…` | Move only these packages. No manager is uninstalled. |
| `--leave NAME,…` | Leave these packages, and what they need, in the old installation. |
| `--uninstall NAME,…` | Uninstall these packages without a replacement. For packages that have none. |
| `--replace OLD=NEW` | Choose the replacement of a package yourself. |
| `--accept-closest` | Where a package has no exact replacement, take the closest match without asking. |
| `--casks keep\|uninstall\|replace` | What becomes of Homebrew's apps (casks) when the packages move into MacPorts. |
| `--pipx` | Reinstall Python tools without a replacement with `pipx`. By default they are only listed. |
| `--keep-managers` | Do not uninstall the old Homebrew or MacPorts that the move leaves empty. |
| `--delete PATH,…` | After the move, delete an old installation whole, although its command cannot run. |
| `--start-services` | Start the replacements of the services that were running. |
| `--upgrade-all` | Upgrade every package that has a newer version in the installation the packages move into, not only those the replacements need. The plan lists what stays as it is, such as an app whose upgrade asks for your password, with the command that upgrades it. A package that the move does not need and that one of these upgrades breaks does not stop the move: `apply` lists it for you to repair. `rollback` does not undo these upgrades. |
| `--repology` | Ask repology.org about packages the offline catalogs cannot match. |
| `--refresh` | Update the target's catalog (`brew update`, `port sync`) first. |

`plan` asks whether the move may remove a pin (`brew pin`) from a package of
the installation the packages move into. It asks about a pin that is in the
way of the move, and with `--upgrade-all` about each pinned package that the
option would upgrade or that keeps other packages from an upgrade. After a
yes, `apply` removes the pin in phase 3 and upgrades the package; `rollback`
does not put the pin back. `--yes` does not answer these questions: a pin
stays until you say otherwise, and a pin that is in the way of the move then
refuses the plan.

## How a migration runs

`apply` runs a plan in phases. It asks before each phase that installs,
uninstalls, or edits something, unless you give `--yes`.

| Phase | Step |
| --- | --- |
| 0 | Checks before starting: the blocking health findings, the tool checks, the disk check, and `sudo`. |
| 1 | Save a record for undo: package lists, `Brewfile`, registry backup, services, shell files, and a local snapshot of the disk (see below). |
| 2 | Repair the installation that stays, where the packages it installs need repair. |
| 3 | Remove the pins you agreed to, install the replacements, and upgrade what `--upgrade-all` adds; then rebuild packages that link into the old installation. |
| 4 | Check the replacements: each must exist, provide its commands, and link cleanly. A package that the move does not need and that an upgrade of `--upgrade-all` broke is listed for you to repair, and the run goes on. The run stops if phase 3 tried to install a package again that uses such an upgrade, and that package is gone. |
| 5 | Uninstall the old packages, after stopping their services. |
| 6 | Uninstall each old manager that is now empty, after archiving its data directories. Answering no leaves it installed, and the run goes on. A move with `--only` or `--keep-managers` has no phase 6. |
| 7 | Clean up the shell files and `/etc/paths`. |
| 8 | Final check: run the `verify` checks, and write `report.md`. |

In phases 2 and 3, Homebrew upgrades only what the plan lists. brew-ports
turns off Homebrew's own upgrade of the packages that use an upgraded one,
checks those packages itself, and installs again one that lost a library.

`--stop-after N` ends a run after phase N. `apply --resume RUN-ID` continues a
run: phases 1 to 3 skip the work that succeeded, and the later phases recompute
the remaining work from the host. After phase 6,
`rollback` prints how to reinstall the removed manager, and restores its
packages when run again.

### The disk snapshot of phase 1

Besides its own record in the run folder, phase 1 asks macOS for a local
snapshot of the disk (`tmutil localsnapshot`). It is the kind of snapshot Time
Machine takes every hour, and it is a second safety net:

- It holds the files of the Mac's APFS volumes as they were before the run
  changed anything, not only the packages.
- `brew-ports rollback` does not use it. Rollback reinstalls from the record
  in the run folder.
- macOS keeps a local snapshot for about 24 hours, and deletes it sooner when
  it needs the space. Until then the space of what the run uninstalled is
  still in use, although macOS already counts it as available.
- `tmutil listlocalsnapshots /` lists the snapshots by date, and
  `tmutil deletelocalsnapshots DATE` deletes one.
- To get a file back from it, open Time Machine and go back to the time of
  the run. Apple describes both:
  [About Time Machine local snapshots](https://support.apple.com/en-us/102154)
  and
  [Restore items backed up with Time Machine on Mac](https://support.apple.com/guide/mac-help/restore-files-mh11422/mac).

When macOS cannot take the snapshot, the run goes on: phase 1 says so, and
`snapshot/notes.txt` in the run folder says why.

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
  lookups of `--pipx` use the network. brew-ports checks the
  MacPorts installer package against a pinned Apple Developer ID signature
  before running it.

## Exit codes

brew-ports exits with one of six codes:

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | `doctor` found something that stops a move or is broken, `recommend` has findings, or a plan was refused. |
| 2 | Usage error. |
| 3 | A precondition failed: running as root, the Command Line Tools missing, a blocking finding, a stale plan, or no `sudo`. |
| 4 | An action or a service stop failed, or an interrupt stopped the run. The output names the resume command. |
| 5 | A `verify` check failed. |

## Findings

`doctor` says what it checked, then whether anything stops a move. Its
findings follow in groups:

| Group | What is in it |
| --- | --- |
| To fix before a move | What stops a move, or a part of one. Each finding says which. |
| Broken or at risk | What fails today, or will fail once an installation is gone. |
| Worth cleaning up | Smaller things: leftovers, old versions, PATH entries that lead nowhere. |
| Only if you keep … | The upkeep of one installation, on a Mac with several. Skip it for an installation you move out of. |
| For information | Nothing that has to be done. Some have a fix you may want all the same. |

Each finding is one sentence, up to three lines of what was found, and what
to do: a line that starts with `Fix:`, one that says there is nothing to do,
or one that says why brew-ports offers no fix. `Fix: brew-ports doctor --fix`
marks a fix that `doctor --fix` makes for you, after it asks. Checks that
could not run come last.

On a Mac with more than one installation, `doctor --fix` repairs only the one
you keep. Name it with `--target brew` or `--target ports`, and with
`--target-prefix PATH` where the Mac has two of that manager; without
`--target`, `doctor --fix` stops and names the options. Until you choose, the
line of such a fix says which installation it is for: `Fix, if you keep
MacPorts at /opt/local: brew-ports doctor --fix --target ports`. In another
installation `doctor --fix` repairs nothing; it counts the fixes it leaves out
and names what there stops the move.

With `--target`, each finding says what it stops for the move into that
installation, and a finding about another installation says that no fix is
offered. The report also lists, under `Broken or at risk`, the packages of the
other installations that the one you keep has too. While a package is
installed twice, one copy is broken: typing its command or building with it
finds only one of the two. `plan --target` plans the move that uninstalls the
other copies, except those that a package staying there still needs. Where a
copy can go alone, the finding gives the command for one of them. When
`doctor --fix` offers to repair such a package, it says where the other copy
is and how to uninstall it once the repair has worked. A fix that only removes
something says nothing of the kind.

`doctor` exits 1 only when a finding is in one of the first two groups.

`--verbose` prints the lines that the short report leaves out, each finding's
name, and what the scan noted. A long list ends with how many more entries
there are. `doctor.json` in the run folder holds the findings under the same
names. A name's first word gives its area:

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
runner. CI runs the quality gates and unit tests, migrates a disposable
runner with both managers in each direction, and moves all of MacPorts into
Homebrew on a third, which must end without MacPorts.

[CONTRIBUTING.md](CONTRIBUTING.md) describes the gates, the conventions, and
the releases. [docs/architecture.md](docs/architecture.md) shows how the modules
fit together.

## License

MIT, see [LICENSE](LICENSE).
