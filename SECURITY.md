# Security

brew-ports runs some commands with `sudo` and removes package-manager files, so
report a vulnerability privately.

## Report a vulnerability

Use Report a vulnerability on the Security tab to open a private advisory. Say
what you ran and what brew-ports did. Attach the run's `report.md` from
`~/Library/Application Support/brew-ports/runs/`, if there is one: it alone
redacts your home directory and login name.

Only the latest release receives fixes.

## What brew-ports does with privilege

brew-ports keeps these limits on every run of a plan, the `plan.json` that
`brew-ports plan` writes:

- It runs as you, and refuses to start as root or under `sudo`. Each command
  that needs root runs through `sudo -n`, after one `sudo -v`. `brew` never
  runs under `sudo`.
- It installs only the plan's replacements. It removes only the packages in the
  plan's removal set, their services, and each old Homebrew or MacPorts that
  the move leaves empty. `--keep-managers` leaves those installed.
- It edits your shell files, `/etc/paths`, `/etc/paths.d`, and `/etc/shells`.
  When the plan removes your login shell's package, brew-ports switches the
  shell with `chsh`. It snapshots each manager first, and backs up each file it
  edits.
- It uses the network only for installs, `--refresh`, `bootstrap-ports`,
  `--repology`, and PyPI lookups of `--pipx`. It first checks the
  MacPorts installer against a pinned Apple Developer ID signature.

The release bundles a python-build-standalone CPython, pinned by SHA-256 in
`tools/fetch-python.sh`. Each release's `SHA256SUMS` lists its tarballs' sums.

## In scope

In scope are reports that show:

- brew-ports removes or overwrites anything the plan does not list.
- A crafted package name, plist, or plan makes brew-ports run a command.
- brew-ports runs as root anything the plan does not list.
- A plan, or a file in the state directory, makes brew-ports act on the wrong
  path.
