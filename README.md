# Cenziadah ( 摻假的 )

Cenziadah is a runtime-integrity checker for Linux processes. It detects in-memory tampering
in running programs (injected code, inline hooks) and the usual signs after a break-in
(unexpected child processes, unexpected network destinations). It works from the host through
`/proc`, opens no listening sockets, and is a single static Go binary.

- **[PRODUCT.md](PRODUCT.md)**: plain-language product description (public).
- **[PLAN.md](PLAN.md)**: internal design, product decisions and roadmap (private, never exported).
- **[CHANGELOG.md](CHANGELOG.md)**: release history (SemVer).

## Commands

| Command | What it does |
|---|---|
| `cenziadah snapshot --pid N \| --name NAME -o base.json` | Record one process's known-good state. |
| `cenziadah check --pid N \| --name NAME [--baseline base.json] [--json]` | Check one process; exit 0 clean, 1 findings, 2 operational error. |
| `cenziadah watch [--tui] [--interval 10s]` | Continuously monitor **every** process (see below). |
| `cenziadah version` | Version and build identifiers. |

### `watch`: all-process monitoring

```bash
sudo cenziadah watch                    # log mode: one line per new/resolved finding
sudo cenziadah watch --json             # the same as JSON Lines (for journald / log shipping)
sudo cenziadah watch --tui              # interactive list: SAFE / ALERT per process
```

1. The first sweep **learns a baseline** of every process, assuming the host is clean at that
   moment. Legitimate JIT memory (browsers, Electron, gjs, Android apps) is learned and stays
   quiet afterwards.
2. `--interval` after each sweep ends it sweeps again and reports only what **changed**: new
   findings and resolved ones. A quiet host prints nothing. Parsed libraries and in-memory
   `.text` digests are reused across sweeps while the file is unchanged, so a steady sweep
   mostly stats files.

Flags:
- `--pace D`: pause D after each process within a sweep (default 1ms; 0 = none).
- `--min-age D`: skip processes younger than D (default: one interval).
- `--no-mem`: don't read process memory (no root needed; module integrity is not checked).
- `--no-auto-learn`: by default a program first seen after start is learned on first sight if
  its binary is package-installed (root-owned, in a root-only directory), so upgraded apps
  don't alert; each one is announced. This flag turns that off.
- `--skip-exe PATH=REASON`: skip an executable (repeatable). Every skip is recorded with its
  reason; there is no built-in trust list.

TUI keys: `↑/↓` move, `enter` details, `esc` back, `h` history (every event with full
details), `c` / `C` acknowledge the selected / all earlier alerts, `a` alerts only, `s` show
skipped processes (with the reason), `r` rescan now, `q` quit.

ALERT means MEDIUM or worse. A process starting a program it did not start at learn time is
HIGH when that program is a shell, interpreter or network tool, or is not package-installed
(e.g. from /tmp or a web root); an ordinary package-installed program is LOW: recorded in the
log and history, not an alert.

An alert that resolves on its own (e.g. a short-lived child exited) is not lost: the row shows
`WAS!` until acknowledged, and its details keep which child it was and when.
A `~` after the findings count means the process was checked without memory access.

The `BASE` column says how much a SAFE/ALERT verdict is worth:

| BASE | Meaning |
|---|---|
| `checked` | Compared with a baseline learned in an earlier sweep: a real verdict. |
| `new` (cyan) | Baseline learned in this sweep (at start, or a new package-installed program): SAFE means nothing yet; the first real check is the next sweep. |
| `none` (yellow) | No baseline (not running at start, not package-installed): only the checks that need no reference ran. |
| `known` (with `s`, status `WAIT`) | Too young to inspect yet; its program already has a baseline. |

**Privileges:** run as root, or grant `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH`. Without them,
other users' processes are skipped and module integrity is not checked; `watch` warns about this.

### Running on a server (package + systemd + e-mail)

Build the packages (`make packages`, see Development) and install one:

```bash
sudo apt install ./dist/cenziadah_<version>-1_amd64.deb      # Debian / Ubuntu
sudo dnf install ./dist/cenziadah-<version>-1.x86_64.rpm     # Fedora / RHEL
```

The package installs `/usr/bin/cenziadah`, the `cenziadah-watch` systemd service and its
configuration file `/etc/default/cenziadah`. The service is **not** started automatically: it
learns its baseline from the host's state when it starts, so you choose the moment.

1. Edit `/etc/default/cenziadah`, e.g. `CENZIADAH_ARGS="--interval 10s --mail-to ops@example.com"`.
2. `sudo systemctl enable --now cenziadah-watch`
3. Events (JSON lines) are in the journal: `journalctl -u cenziadah-watch -o cat`.

With `--mail-to`, cenziadah mails a startup summary (what it learned and accepted) and, per sweep,
every new alert at `--mail-min` or above (default `medium`), with full details. Mail goes through
the local MTA's `sendmail` (`--sendmail`, default `/usr/sbin/sendmail`: postfix, exim, msmtp-mta,
...), which must be root-owned and not writable by others. At most `--mail-max-per-hour` alert
mails are sent (default 20); the journal keeps everything. `--mail-from` sets the sender
(default: the MTA's configured sender).

Note: the service runs as root for now, and every (re)start re-learns the baseline from the
current state of the host.

## Development

Requires Go (see `go.mod`) and, for some tests, a C compiler (`cc`).

```bash
make all               # fmt check + vet + build + unit tests (each command is printed)
make build             # bin/cenziadah, version-stamped
make test              # unit tests only
make compromise-test   # the one integration test: vulnerable victim + real exploit (needs sudo)
make packages          # .deb + .rpm into dist/ (nfpm; ARCH=amd64|arm64)
make help              # list targets
```

Layout (each package is a black box with its own tests):

```
cmd/cenziadah/      CLI (thin: flags -> packages)
internal/procfs/    the only package that reads /proc
internal/elfref/    on-disk ELF modelling (.text, build-id, relocation mask)
internal/container/ container runtime state (Docker healthchecks), read-only from the host
internal/cron/      root-owned crontab jobs (so cron's own jobs are recognised)
internal/systemd/   root-owned systemd unit files (so units' configured commands are recognised)
internal/notify/    e-mail alerts through the local sendmail (opt-in)
internal/detector/  detectors (maps, module integrity, process tree, fd/socket) + .text digest cache
internal/engine/    collect a process, build snapshots, run detectors
internal/baseline/  snapshot save/load; per-identity baseline sets for all-process mode
internal/scan/      all-process sweep engine + sweep-to-sweep diff
internal/watch/     continuous loop (learn, sweep, emit deltas) + log output
internal/tui/       interactive display (the only package using bubbletea/lipgloss)
internal/report/    text / JSON rendering of reports and events
testharness/        deliberately vulnerable victim + exploits (validation only, never linked)
scripts/            baseline/check every Docker container on a host
```

## Versioning

SemVer. The version lives in `internal/version`; `CHANGELOG.md` is updated on every release.

## Releasing to GitHub

Development happens on gitlab; public releases go to github.com/paulborile/Cenziadah, cloned at
`../../git/Cenziadah` (override with `PROD_REPO=`).

1. Commit everything for the release on gitlab (only **committed** files are released), with the
   version bumped and a `## [vX.Y.Z]` CHANGELOG section.
2. `make production DRY_RUN=1`: preview what the sync would change in the clone.
3. `make production`: tests, builds the .deb/.rpm, syncs the tree into the clone (minus
   `packaging/production-exclude`), writes the release notes and checksums, and prints the git
   commands for step 4. It changes no git state.
4. In the clone: review `git status`, then commit, tag `vX.Y.Z` and push the branch and tag.
5. `make github-release`: creates the GitHub release with the packages, checksums and notes.

## License

Cenziadah is free software, licensed under the **GNU Affero General Public License v3.0 or
later** ([LICENSE](LICENSE)). Contributions are welcome under the
[Contributor License Agreement](CLA.md); see [CONTRIBUTING.md](CONTRIBUTING.md).

Third-party Go modules keep their own licenses (bubbletea and lipgloss: MIT).
