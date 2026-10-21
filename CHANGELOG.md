# Changelog

All notable changes to Cenziadah are recorded here.

## [v0.8.2] - 2026-10-21

First public release (github.com/paulborile/Cenziadah).

### Fixed
- The redaction tests used a real WakaTime API key (from the command line
  that motivated redaction in v0.5.6) as test data. GitHub push protection
  rejected the first public push. The tests now use a made-up key, split in
  the source so secret scanners do not match it. The real key must be
  rotated: it is also in this repo's earlier history.

## [v0.8.1] - 2026-10-21

Prepared as the first public release but never published (its push was
rejected, see v0.8.2).

### Added
- `make production`: publishes the COMMITTED tree to the public GitHub clone
  (`PROD_REPO`, default `../../git/Cenziadah`). It refuses uncommitted
  changes, a missing CHANGELOG section or an existing tag; runs `make all
  packages`; syncs the tree minus `packaging/production-exclude` (our
  production baselines in `data/`, prebuilt test exploit/victim binaries);
  writes the release notes (this CHANGELOG section) and SHA256SUMS; and
  prints the git commit/tag/push commands, which are run by hand. It changes
  no git state. `DRY_RUN=1` only lists what the sync would change.
- `make github-release`: after the tag is pushed, creates the GitHub release
  with the .deb, .rpm, checksums and notes (`gh release create --verify-tag`).
- PRODUCT.md: "How it compares" capability table (K-Scanner, Volatility 3,
  Falco/Tracee/Tetragon).

## [v0.8.0] - 2026-10-21

A quoting mistake in `/etc/default/cenziadah`
(`CENZIADAH_ARGS="--interval 10s" --mail-to ...`, which reached cenziadah as
`--interval 10s--mail-to`) left the service in a silent restart loop for
about 3 hours (1071 restarts): the host was unmonitored and, since the mail
options were part of the broken line, nobody was told.

### Added
- `watch --check-config`: validates every option, including the mail setup
  (addresses, severity, rate limit, a root-owned sendmail), then exits 0 with
  "configuration OK" or non-zero with the reason. Nothing is scanned or sent.
- `watch` rejects stray positional arguments with a hint to check the quoting.

### Changed
- systemd unit: `ExecStartPre=cenziadah watch --check-config $CENZIADAH_ARGS`,
  and `StartLimitIntervalSec=300` / `StartLimitBurst=5`, so a broken
  configuration ends in `failed` (visible in `systemctl --failed`) instead of
  restarting forever.
- postinstall: on upgrade, if the running service fails to come back, prints
  a WARNING that the host is not monitored, with the commands to diagnose it.
- `/etc/default/cenziadah` comments: all options inside ONE pair of quotes,
  and how to check them first.

## [v0.7.0] - 2026-10-16

CPU load: `watch` held more than one core continuously on a desktop with ~500
processes (39 min of CPU in 36 min of uptime, I/O wait under swap pressure).

### Changed
- `watch` waits `--interval` after each sweep ENDS instead of on a fixed
  ticker. A 10.7s sweep with `--interval 10s` used to chain straight into the
  next one; now cenziadah is idle at least as long as it works. A sweep slower
  than the interval logs a warning (at most once an hour).
- Parsed ELF modules and in-memory `.text` digests are kept ACROSS sweeps
  (`engine.SweepCache`, `detector.TextCache`), keyed by the file version:
  device, inode, size, mtime and ctime from stat(2). A file written in place
  gets a new mtime/ctime (ctime cannot be set back without root) and is
  parsed and digested again; a mapping with anonymous (copied-on-write) pages,
  i.e. a patched process, is still always read from memory. Entries no sweep
  used are dropped. A steady sweep now mostly stats files instead of reading
  and hashing ~1GB of browser/Electron code.
- The module cache used to be keyed by the resolved path, which is
  `/proc/<pid>/root/...` and so differed for every process: each library was
  parsed (ELF + relocation mask) once per process per sweep, not once per
  sweep. It is now keyed by the file itself.
- systemd unit: `Nice=10`, `CPUWeight=20`, `IOSchedulingClass=idle`, so the
  monitor always yields to the work on the host.

### Added
- `watch --pace D` (default 1ms): a pause after each inspected process, so a
  sweep never holds a CPU at 100% for its whole duration.

## [v0.6.2] - 2026-10-16

### Fixed
- False CRITICAL `module.build_id_diff` after an unattended package upgrade
  (seen live: systemd 255.4-1ubuntu8.17 -> .18 replaced `libsystemd.so.0.38.0`
  and `libudev.so.1.7.8` in place, same file names; every program started
  afterwards, e.g. `gjs` and `fprintd`, alerted against the old build-ids).
  A build-id change is now accepted as an upgrade when the library on disk is
  root-owned in a root-only directory and its ctime is at or after the
  baseline's learn time (`procfs.ReplacedSince`): the finding is suppressed,
  reported as LEARNED, and the module's baseline entry is REPLACED with the
  new version (`baseline.Set.ReplaceModules`), so later sweeps keep checking
  its in-memory `.text`. A merge would have dropped the digest for good.
  Only root can replace such a file; a changed user-writable library, or one
  whose ctime predates the baseline, still alerts CRITICAL.

## [v0.6.1] - 2026-10-15

### Fixed
- False CRITICAL `maps.rwx` for Electron/V8 apps whose baseline already held
  their JIT region (seen live: an Obsidian renderer, `rwx [heap]`, against a
  baseline with `rwx [anon:v8]`). V8 sometimes places its 512MB rwx code
  range over the unused brk start, and the kernel then labels it `[heap]`.
  `procfs.AnnotateBrk` marks a `[heap]` region that does not begin at
  `start_brk` (stat field 47) as plain anonymous memory (`Region.NotBrkHeap`),
  and baseline matching now treats every anonymous region as one class
  (`[anon]`, `[anon:<name>]`, NotBrkHeap): `[anon:<name>]` names are set by
  the process itself, so they never carried trust. The real brk heap, the
  stack and file-backed mappings are still matched by their own labels, so an
  rwx brk heap is not excused by a JIT region.

## [v0.6.0] - 2026-10-15

### Added
- Every alert names the cenziadah version that produced it: JSON events (the
  journal with `--json`) carry `"version"`, and each alert block in an e-mail
  has a `version  cenziadah vX.Y.Z` line. An alert copied out of context now
  shows which detection logic raised it (e.g. one from a host still running an
  older build). The mail signature, TUI title and startup line already had it.

## [v0.5.6] - 2026-10-15

### Fixed
- Secrets in command lines were copied verbatim into findings, the journal and
  alert e-mails (seen live: VS Code starting `wakatime-cli ... --key waka_...`).
  New package `internal/redact` masks them with `***`: values of flags whose
  name ends in key/token/secret/password/passwd/pwd/passphrase/auth/credential
  (`--key V`, `--password=V`; `--key-file` and `--auth-type` are kept),
  `*_KEY=`/`*_TOKEN=`/`*_PASSWORD=`-style environment assignments,
  `scheme://user:PASSWORD@host`, and well-known token shapes (GitHub, GitLab,
  Slack, AWS key ids, `sk-...`, WakaTime, JWTs). Applied once in `engine.Run`
  to everything that leaves cenziadah (target cmdline, finding details,
  string evidence) and to snapshot targets; detection rules still match the
  raw command line. Redaction can only hide text, never change a finding.

### Changed
- A child's command line in a `proctree` finding detail is capped at 512 bytes
  (`… (N more bytes)`), after redaction so no half secret is left; the
  evidence keeps the whole (redacted) command line.

## [v0.5.5] - 2026-10-15

### Fixed
- False HIGH `proctree.unexpected_child` ("non-package location") for VS Code's
  `vsce-sign` (run when an extension is installed or updated). The `code` deb
  ships it as `0775 root:root`, and the program-trust check
  (`procfs.TrustedExe`/`TrustedPath`/`TrustedPathUnder`) rejected any
  group-writable file. Group-write is now accepted when the group is root
  (gid 0): only root's own group can write, so no unprivileged account gains
  anything. Other groups, world-write and non-root owners are still rejected.
  The config-file checks (crontabs, systemd units, sendmail) are unchanged.

## [v0.5.4] - 2026-10-14

### Fixed
- False CRITICAL `module.build_id_diff` for every library of an Android app
  after a Play Store update (seen on waydroid: 27 alerts for `com.whatsapp`,
  all of `files/decompressed/libs.spo/*.so`, 29s after the update installed).
  An app update does not change `app_process64`, so the updated app kept its
  identity and was checked against the old version's libraries. An Android
  app's install directory (`/data/app/~~<rand>/<pkg>-<rand>`, new for every
  install and update) is now part of its identity (`TargetDesc.AppInstall`,
  `procfs.AppInstall`): an updated app is a new program, auto-learned and
  reported like a new native version (not with `--no-auto-learn`). The
  directory is used only when it is the process's OWN `base.apk`, and it,
  everything up to `/data/app`, and `base.apk` are owned by root or Android's
  system user and not world-writable, and the app does not itself run as root
  or system. So a compromised app cannot fake an update of itself, and
  tampered libraries in its writable data dir still alert on the same version.
  Residual risk: libraries tampered between a real update and the new
  process's first sight are learned as normal (as with native auto-learn).

## [v0.5.3] - 2026-10-14

### Fixed
- False HIGH `proctree.unexpected_child` every 30s on a desktop running VS Code:
  its Node service runs `/bin/sh -c "/usr/share/code/resources/app/out/vs/base/node/cpuUsage.sh" <pids>`.
  A shell child is now accepted (suppressed, reason "packaged script ...")
  when it only runs a script shipped with the parent's own program: command
  line exactly `<shell> [-c] ["]<script>["] [plain-word args]` (no shell
  syntax), the shell is root-owned, and the script and every directory up to
  the parent binary's dedicated (non-shared) directory are root-owned and not
  group/world-writable (`procfs.TrustedPathUnder`). A compromised non-root
  parent cannot plant such a script or append commands; it can still run the
  package's own scripts with plain arguments.

## [v0.5.2] - 2026-10-14

### Changed
- `make clean` no longer deletes built packages: it removes `bin/` and
  `dist/build/` only. `.deb`/`.rpm` files in `dist/` carry their version in the
  file name and accumulate across releases.

## [v0.5.1] - 2026-10-14

### Fixed
- False CRITICAL `module.build_id_diff` in production on a containerised Apache
  worker: libc and ld-linux "differed from baseline" because they were compared
  with the HOST's libc. The worker was retiring (Apache recycles workers after
  `MaxConnectionsPerChild`); its `/proc/<pid>/root` was no longer readable, and
  `procfs.ResolveBackingPath` fell back to the same path on the host, a
  different file for a process in a container. Verified on fender: container
  libc fce446c9…/ld 433b9dde… (= baseline), host libc a4a7992a…/ld 0d77dbd4…
  (= the reported "loaded"). The bare host path is now used only when the
  process verifiably shares cenziadah's mount namespace
  (`procfs.SameMountNamespace`); otherwise the module gets no opinion. The same
  unsafe fallback is removed from `procfs.TrustedPath` and from the directory
  check in `procfs.TrustedExe`.

## [v0.5.0] - 2026-10-13

For leaving cenziadah running unattended on a server for days and being told
about every case as it happens.

### Added
- E-mail alerts from `watch`: `--mail-to ADDR` mails a startup summary (what
  was learned and accepted as normal) and, once per sweep, every new alert at
  `--mail-min` or above (default `medium`) with full details (process, exe,
  cmdline, finding). Delivered through the local MTA's sendmail interface
  (`--sendmail`, default /usr/sbin/sendmail; `--mail-from` optional).
  Rate-limited (`--mail-max-per-hour`, default 20; skipped mails are counted
  and reported in the next one). Delivery runs on a background queue with a
  timeout, so a slow or broken MTA never delays a sweep. Security: the sendmail
  program and its directory must be root-owned and not writable by others
  (cenziadah runs as root and executes it); no shell is used; addresses are
  validated; process names, paths and command lines are sanitized so they can
  add neither mail headers nor lines. (`internal/notify`, `watch.Tee`.)
- systemd service `cenziadah-watch` (`packaging/cenziadah-watch.service`):
  runs `cenziadah watch --json $CENZIADAH_ARGS` from `/etc/default/cenziadah`,
  restarts on failure, events in the journal. Runs as root for now.
- `.deb` and `.rpm` packages (`make packages` / `make deb` / `make rpm`, built
  with nfpm, `ARCH=amd64|arm64`): static `/usr/bin/cenziadah`, the service,
  `/etc/default/cenziadah` (config file, kept on upgrade), docs and license.
  The service is not enabled or started on install (it learns from the host's
  state at start, so the admin picks the moment); on upgrade it is restarted
  only if it was running; on removal it is stopped and disabled.
- `.gitignore` (`bin/`, `dist/`).

## [v0.4.4] - 2026-10-13

### Fixed
- systemd services alerted HIGH as PID 1 starting a shell (seen in production:
  `/bin/sh /usr/lib/apt/apt.systemd.daily update`, the timer-started
  apt-daily.service). A child of systemd is now recorded as suppressed
  ("systemd unit apt-daily.service") when its command line is one of the
  Exec*= lines of the unit named by its cgroup (set by systemd; a non-root
  process cannot move itself into another service's cgroup), or the same
  script started through its interpreter. Only root-owned unit files and
  drop-ins are read; user units are not trusted. An orphan re-parented to
  PID 1 keeps its original cgroup and does not match that unit's commands.
- Everything running inside a `Type=oneshot` system unit (a batch job such as
  apt-daily) is treated as that job's own work, like a cron job's tree.
  Long-running services get no such allowance: a webshell's children inside
  apache2.service still alert.
- TUI process detail said "ALERT: 1 active finding(s)" for a process with only
  a LOW finding (since v0.4.0 LOW is not an alert); it now says "SAFE: 1
  low-severity finding(s) recorded".

### Added
- `internal/systemd` (unit-file parser: search paths, drop-ins with `ExecStart=`
  reset, templates `foo@bar.service`, continuation lines, Exec prefixes),
  `procfs.SystemUnit` (unit from /proc/<pid>/cgroup, v2 and v1),
  `engine.OneshotUnit`.

## [v0.4.3] - 2026-10-13

### Changed
- Makefiles are no longer quiet: the `run_quiet` wrapper (which hid commands and
  showed output only on failure) and the `@` prefixes are removed, so make
  prints every command it runs and its output. Only `make help` stays silent.
  `make clean` no longer hides testharness errors.

## [v0.4.2] - 2026-10-13

### Fixed
- Cron jobs alerted HIGH as a daemon starting a shell (seen in production: the
  daily `/bin/sh -c test -x /usr/sbin/anacron || { cd / && run-parts --report
  /etc/cron.daily; }`, 06:25–06:41). A shell started by cron whose command line
  exactly matches a job in a ROOT-OWNED crontab (`/etc/crontab`,
  `/etc/cron.d/*`, root's crontab; read in cron's own mount namespace) is now
  recorded as suppressed ("cron job from /etc/crontab"), and everything that job
  starts (run-parts, the cron.daily scripts, their tools) is treated as the
  job's own work. Other users' crontabs are deliberately not trusted: a job a
  compromised `www-data` adds to its own crontab keeps alerting.
- Docker healthcheck children that exited before their command line could be
  read (seen in production on the nostr-relay container: `exe=/usr/bin/wget
  cmd=""`) were not matched. For an exited child with no command line the
  healthcheck now matches by program: the healthcheck's program name (CMD form)
  or a shell (CMD-SHELL form). A live child must still match exactly.

### Added
- `internal/cron`: parser for root-owned crontabs (SHELL=, @keywords, user
  field, `%` lines skipped, run-parts file-name rules for /etc/cron.d).
  `engine.IsCron`, `engine.CronJob`, `container.HealthcheckOf`,
  `detector.Target.ScheduledJob`.

## [v0.4.1] - 2026-10-12

### Changed
- **License: the whole agent is open source under AGPL-3.0-or-later** (`LICENSE`,
  the official FSF text). Every source file carries an SPDX header
  (`SPDX-License-Identifier: AGPL-3.0-or-later`). This replaces the earlier
  plan to keep the detectors closed (see PLAN.md, "Product, licensing &
  distribution"): no private detectors, no private/public repo split, no
  export script. The data portal stays a separate private project.

### Added
- `CLA.md` (Individual Contributor License Agreement, modelled on the Apache
  ICLA; contributors keep copyright and allow additional license terms),
  `CLA-SIGNATURES.md`, `CONTRIBUTING.md`; License sections in README and
  PRODUCT.md. No code changes.

## [v0.4.0] - 2026-10-12

Unexpected children are graded by WHAT they are, not only by "never seen at
learn time". Production showed that a single learning sweep cannot have seen
every program a service starts on demand (postfix workers, healthchecks,
script helpers, mail delivery), and adding exceptions case by case does not
converge. The post-exploitation shape is constant: a service starting a shell,
interpreter, network tool or dropped binary.

### Changed
- An unexpected child that no rule explains is now:
  - HIGH if it is a shell, interpreter or network tool (`sh`, `python*`,
    `perl`, `curl`, `wget`, `nc`, `ssh`, ...), if its program is not
    package-installed (not root-owned or in a writable directory: /tmp, web
    root, home), or if it is alive with a hidden executable;
  - LOW if it is an ordinary package-installed program (root-owned, root-only
    directory) the parent had not started at learn time. LOW is recorded (log
    mode, TUI history, FINDINGS count) but is not an alert.
  - For a parent without a baseline: MEDIUM for the risky shapes, INFO
    otherwise.
- TUI: ALERT and sticky `WAS!` now require MEDIUM or worse; rows with only
  LOW/INFO findings are SAFE with their finding count.
- Unchanged: memory findings (rwx, anonymous exec, module integrity), and the
  structural rules (learned allow-list, pre-existing children, sibling
  programs, terminal shells, Docker healthchecks).

### Added
- `procfs.Child.Trusted` (child program package-installed, set by the engine),
  `procfs.IsNetworkTool`, `procfs.IsRiskyProgram`.

## [v0.3.4] - 2026-10-12

### Fixed
- Docker healthchecks alerted as unexpected children of `containerd-shim`
  (seen in production: `/bin/sh -c dms-healthcheck` of docker-mailserver).
  Docker runs a container's HEALTHCHECK through its shim periodically. For a
  shim, the container ID is taken from its command line (`-id`) and the
  configured healthcheck from Docker's root-owned state
  (`<data-root>/containers/<id>/config.v2.json`; data-root from
  /etc/docker/daemon.json, default /var/lib/docker). A child whose command line
  matches it exactly is recorded as suppressed ("Docker healthcheck of
  container <id>"). Any other child of a shim, e.g. `docker exec`, still alerts.
  Nothing inside a container can write that state.

### Added
- `internal/container`: reads runtime configuration from Docker's on-disk
  state (bounded reads, IDs validated as 64 hex chars). `procfs.Child.Expected`.

## [v0.3.3] - 2026-10-12

### Fixed
- Regression in v0.3.2: an exploit's one-shot shell (`sh -c id`) that exited
  and stayed a zombie has no readable exe, so it was downgraded to INFO
  ("exited before it could be identified") and the rogue-child alert was lost
  (caught by re-running the victim/exploit test). A child that exited without a
  readable exe now stays HIGH when its process name is a shell or interpreter
  (`sh`, `bash`, `python*`, `perl`, ...); the finding detail shows `comm=` and
  `(exited)`. Other unidentifiable exited children (postfix workers) stay INFO.
  Limitation: a process can rename itself, so a renamed shell would be INFO.
- Shell/interpreter name lists moved to `procfs` (`IsShell`, `IsInterpreter`)
  so the detector can use them.

## [v0.3.2] - 2026-10-12

### Fixed
- Unexpected-child alerts with an empty exe and cmdline (seen in production on
  postfix `master`, HIGH, nothing to act on): short-lived children exited
  between the sweep's process-table read and their parent's inspection, so
  their details were read too late. The exe and cmdline captured in the process
  table are now used as a fallback; an exited child's sibling check uses the
  file at its path in the parent's mount namespace (same root-only rule,
  `procfs.TrustedPath`), so postfix's short-lived workers are recognised. A
  child that was already gone or a zombie even at table time is reported as
  INFO "child exited before it could be identified"; a live child with a
  hidden exe still alerts HIGH. (`procfs.Child.Exited`, `ProcEntry.Cmdline`,
  `ProcEntry.Zombie`, `Status.Zombie`.)

## [v0.3.1] - 2026-10-12

### Changed
- `watch --tui` shows the cenziadah version in its header; log mode prints the
  version and build date once at startup, so production logs say which build
  produced them.

## [v0.3.0] - 2026-10-12

No alert can vanish unseen in the TUI any more: in production an `apache2`
unexpected-child alert resolved on its own (the child exited) before anyone
could see which child it was.

### Added
- Sticky alerts: a process that alerted (above INFO) keeps a `WAS!` row
  (magenta, sorted right after current alerts) after the finding resolves,
  until acknowledged with `c` (selected row) or `C` (all). The process detail
  lists each earlier alert with first-seen / resolved times and the full detail
  (which child, which command line). A process that exited keeps an
  `(exited)` row. Header counts unacknowledged alerts. Acknowledging only
  clears the marker; it changes nothing about detection or trust.
- History view (`h`): every event since start (NEW, RESOLVED, LEARNED, new
  programs), newest first, with full details; bounded to the last 2000 events.
- The recent-changes footer now shows each finding's detail (e.g. the child's
  exe and cmdline), not only its technique.

### Changed
- In the process detail view, `h` no longer means "back" (it opens the history
  from the list); use `esc`, `←` or backspace.

### Known limitations
- History and sticky alerts live in the TUI process only: they are lost when it
  exits. A durable record (log mode under systemd/journald) is planned with
  step 2; the incident database and portal reporter later.

## [v0.2.0] - 2026-10-12

All-process monitoring: `cenziadah watch` (log or interactive TUI), built on a
new all-process scan engine, plus false-positive work driven by live desktop
and production (fender) testing.

### Added
- `internal/scan`: all-process scan engine. One sweep inspects every eligible
  process through the existing detectors and returns one report per process;
  kernel threads, cenziadah itself, processes younger than `MinAge` and
  operator-listed executables are skipped with a recorded reason; a process that
  exits or is unreadable mid-sweep is skipped, never fatal. Baselines are looked up
  per process identity (exe path + build-id + process name, see Changed).
- `detector.TextCache`: reuses in-memory `.text` digests across processes in one
  sweep, only for mappings whose smaps `Anonymous` size is 0 (provably the shared
  page cache), so a hooked process is always digested fresh.
- `procfs.ProcTable` (one `/proc` walk per sweep, direct children lookup),
  `procfs.ReadSmapsAnon`, `Status.Kthread`, `elfref.BuildID` (build-id without
  building the relocation mask), `engine.CollectInScan`, `engine.ScanDetectors`,
  `model.Report.Degraded`.
- `cenziadah watch`: continuous all-process monitoring. The first sweep learns a
  per-process-identity baseline in memory; later sweeps report only new and
  resolved findings, as text or JSON Lines (`--json`), or in an interactive
  SAFE/ALERT process list (`--tui`, bubbletea + lipgloss, confined to
  `internal/tui`). Flags: `--interval`, `--min-age`, `--no-mem`,
  `--skip-exe PATH=REASON`. Sweeps stop promptly on SIGINT/SIGTERM.
- `internal/watch` (the loop, output-agnostic), `baseline.Set` (per-identity
  merged baselines), `scan.Learn`, `scan.Diff`, `model.Event`,
  `report.EventText` / `report.EventJSON`, `engine.SweepCache` (each library is
  parsed once per sweep), `elfref.Module.MaskChunk`.
- `watch` no longer absorbs a pre-existing compromise silently: findings already
  present during the learn sweep (judged without a baseline, above INFO) are
  reported once as `LEARNED` (one line per process in text, one event per
  finding in JSON) and shown in the TUI header and process detail.
- `watch` auto-learns programs first seen after start when their binary is
  package-installed (running image and its directory root-owned and not
  group/world-writable), e.g. a new version after an upgrade. Each one is
  announced ("learned new program" / TUI recent changes and header) and any
  findings it already carried are reported as `LEARNED`. Binaries from /tmp,
  home or other writable directories keep the strict check. `--no-auto-learn`
  turns it off. (`scan.Options.AutoLearn`, `scan.Learner`,
  `procfs.TrustedExe`, `Result.NewPrograms`.)
- Sibling-program rule for service suites: a child running a program installed
  next to the parent's own binary (same directory; binary and directory
  root-owned and not group/world-writable) is recorded as suppressed instead of
  alerting. Fixes on-demand children such as postfix `master` -> `tlsmgr`
  (seen in production), `smtpd`, `cleanup`. Never applies in shared system
  directories (/usr/bin, /usr/sbin, /usr/libexec, ...) or to shells and
  interpreters (python*, perl, node, env, busybox, ...), so a venv's python or
  /usr/bin/sh cannot pass as a sibling. (`procfs.Child.Sibling`,
  `engine.siblingCandidate`.)
- Interactive terminal shells: commands typed into a user's terminal no longer
  alert as unexpected children of the shell; they are recorded as suppressed
  ("a command someone typed"). The shape (a shell with a controlling terminal)
  is not enough, because an attacker's pty-upgraded reverse shell has it too.
  The shell must also be legitimate: running when the baseline was learned, or
  started by a parent whose baseline expects that shell (terminal emulator,
  sshd, tmux), or nested in a legitimate shell. A pty shell under an exploited
  service fails that, so what is typed into it keeps alerting (verified live
  with `python3 -c 'import pty; pty.spawn(...)'`). Decided by the all-process
  scanner only; `check` never suppresses. (`detector.Target.InteractiveShell`,
  `engine.TerminalShell`, `procfs.HasControllingTTY`, `ProcTable.Entry`.)
- TUI `BASE` column: what each verdict was measured against. `checked`
  (baseline from an earlier sweep: a real verdict), `new` (cyan: learned this
  sweep, first real check next sweep), `none` (yellow: no baseline, only the
  baseline-less checks ran). Waiting (too young) processes show `WAIT` with
  `known` / `none`. Header splits the scanned count by state; the detail view
  explains it. `model.Report.Baseline`, `model.BaselineState`,
  `scan.Skipped.Baseline`.
- `watch` explains skipped processes: log mode prints a skip-reason breakdown
  at learn; the TUI lists them with `s` (status SKIP, reason, hint in detail).
  TUI header shows how long the last sweep took.
- README rewritten (was the GitLab template): commands, `watch` usage,
  development and layout. PRODUCT.md describes `watch`.
- `cenziadah-data-webapp-plan.md`: plan for the separate data portal (Go +
  htmx, email-code login, runs/incidents dashboard, ingest API, deployment on
  the cloud-server infrastructure). To be moved to its own repo.
- First external dependencies: `github.com/charmbracelet/bubbletea` v1.3.10 and
  `github.com/charmbracelet/lipgloss` v1.1.0, used only by `internal/tui`.

### Changed
- Process identity is now exe + build-id + process name: Android apps all run
  as `app_process64` and were otherwise merged into one baseline.
- Relocation masking zeroes only the masked offsets per chunk instead of a map
  lookup per byte, and in-memory baselines skip on-disk .text digests (no
  detector reads them; `scan.Options.DiskDigests` opts in). Together: the learn
  sweep on a desktop went from 38s to 4s.
- PLAN.md: recorded product decisions — AGPLv3 + CLA for the open part, closed
  detectors compiled into a static binary (not Go plugins), private repo with a
  generated public export, opt-in outbound reporting to a separate data portal
  (start records + incidents) via a new `internal/reporter` module.

### Fixed
- `watch`: a package upgrade of a running program (e.g. VS Code, Brave) made
  all its processes lose their baseline and flood the TUI with CRITICAL JIT and
  INFO child alerts: the exe path gains " (deleted)" and the build-id was read
  from the path. Identity now ignores the suffix and the build-id is read from
  the running image via /proc/<pid>/exe.
- `watch`: children whose exe is hidden (setuid/setgid helpers such as
  ssh-agent, fusermount3, chrome-sandbox) alerted HIGH on every sweep after the
  empty-exe fix below. Children already running when the baseline was learned
  are now accepted by pid + start time; new unreadable children still alert.
- Deleted-backing false positives after package upgrades (planned, never
  implemented): an executable mapping whose file was replaced after the process
  started by a root-owned, non-writable file is reported suppressed with the
  reason. A dropped-and-unlinked library still alerts. ~660 false findings on a
  desktop up for two weeks.
- A child process with an unreadable exe (zombie, another user's) was learned
  into the baseline as an allowed child with an empty path, which then allowed
  every later child with an unreadable exe, including an exploit's shell.
- Building a snapshot without memory access dereferenced a nil memory handle
  (typed-nil interface); reachable via `watch --no-mem` or without
  `CAP_SYS_PTRACE`.

### Known limitations
- `watch` learns its baseline from the running host when it starts (in memory
  only): it trusts whatever state the host is in at that moment. Persisted
  baselines (`snapshot --all`, `watch --baseline`) are not implemented yet.
- Programs that legitimately start new kinds of children on demand and are not
  covered by the sibling rule (e.g. VS Code's extension host starting a
  `python3` language server) alert HIGH; a launcher policy file is planned.
- A process that forks a copy of itself, having had no children at learn time,
  alerts HIGH when its binary is in a shared directory (/usr/bin, /usr/sbin).
- INFO-only findings (children of a process without a baseline) still mark the
  TUI row as ALERT.
- Running with only `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH` instead of root is
  untested, and no systemd unit is shipped yet.
- `incidents` and the portal reporter are not implemented.

## [v0.1.0] - 2026-10-09

### Added
- Project scaffold: Go module `github.com/paulborile/cenziadah`, Makefile-driven
  toolchain (`make build|test|vet|fmt|all`), package layout per PLAN.md.
- `internal/model`: core primitives — Finding (with first-class Suppressed),
  Snapshot (shapes + digests, ASLR-proof), Incident.
- `internal/procfs`: the sole `/proc` access layer — maps, status, stat (start
  time), mem (bounded pread), fd, net (tcp/udp v4+v6 with inode), proctree.
- `internal/elfref`: disk-only ELF modeling — `.text` range, GNU build-id,
  relocation mask for the memory-vs-disk comparison.
- Detectors: maps anomalies (rwx / anon-exec / deleted-backing, with ART-JIT and
  kernel-mapping suppression + baseline-diff), module integrity (build-id check +
  streamed masked `.text` comparison), process-tree, fd/socket (owned-socket
  attribution via fd-inode join, allow-list based).
- `internal/baseline`: Snapshot save/load with schema versioning.
- `internal/engine`: target resolution (pid/name), one-pass procfs collection,
  snapshot builder, detector runner; degraded mode when `/proc/<pid>/mem` is
  unavailable (no CAP_SYS_PTRACE) so maps/fd/socket/proctree still run.
- `internal/report`: text + JSON rendering, severity-ordered, suppressed-count.
- CLI: `cenziadah snapshot` and `cenziadah check` (exit codes 0/1/2; clear
  "needs sudo / CAP_SYS_PTRACE" message on EPERM).

- Test harness: a deliberately-vulnerable, "unaware" `victim` (C, NX-enforced) with
  two real memory-corruption bugs reachable over its control socket — a stack
  buffer overflow (LOGIN) and a heap/struct overflow that clobbers an adjacent
  function pointer (SETNAME) — plus a `LEAK` info-leak primitive returning a stack
  and a libc address. A separate Go `exploit` performs a faithful modern exploit:
  leak to defeat ASLR, overflow to hijack control, then a return-oriented (ROP)
  chain that calls `mprotect` to make the stack executable (defeating NX) and
  returns into benign shellcode that runs `id > /tmp/cenziadah_pwned` via /bin/sh.
  The marker file (which the victim's own code never creates) is independent ground
  truth that the injected shell actually executed. Every address is resolved from
  the leak — nothing is hardcoded to a libc base. cenziadah detects the resulting
  rwx page (the mprotect W^X violation) and the rogue child. The `scenarios`
  integration test (build tag `harness`) launches the victim under `setarch -R`,
  runs each exploit, and asserts the `maps.rwx` IoC against a baseline — with a
  clean-control false-positive gate. Built -no-pie (an intentionally exploitable
  target, not production settings). Run via `make compromise-test`.
- Detector hardening found by running against live processes: suppress kernel
  `[vdso]`/`[vsyscall]` exec mappings; attribute sockets to the target via
  fd-inode join (so a shared network namespace doesn't surface host-wide
  connections); treat an absent/empty fd or socket allow-list as 'no policy' (do
  not deny-all); degraded check when `/proc/<pid>/mem` is unavailable.

- Scripts (`scripts/`): `baseline-all-containers.sh` snapshots the main process of
  every running Docker container into `<container>-czd.json` in the cwd (run on the
  HOST after a stack restart); `check-all-containers.sh` checks each against its
  baseline for cron. Both warn-and-continue, exit non-zero on any failure/finding;
  a 0-module baseline (unresolved paths => module integrity unarmed) is treated as a
  failure rather than passing silently.

- Fix: exploit shellcode's parent path now blocks on `pause()` (zero CPU) instead of
  an infinite `jmp` spin. A leftover exploited victim previously pegged a core
  indefinitely (observed running ~100%% CPU for 28h after a manual run).

- Versioning (SemVer): `cenziadah version` / `--version` / `-v` reports the semantic
  version (`v0.1.0`, the single source of truth in internal/version) plus build
  identifiers (git commit + build date, injected via -ldflags; Go VCS-info fallback
  for plain `go build`). Baselines embed `tool_version`, and `check` prints which
  cenziadah build created the baseline it loads.

- Red-team validation (`testharness/redteam/`): `validate-samba-cve-2007-2447.sh` validates
  cenziadah against a REAL third-party exploit — Metasploit `samba/usermap_script` (CVE-2007-2447)
  vs the genuine Samba 3.0.20 in `tleemcjr/metasploitable2`, run disposably on loopback. Asserts
  cenziadah catches the post-exploit rogue shell child + reverse-shell socket. Not part of
  `make test` (needs docker/network/root). No exploit code authored; uses a published module +
  published training image, with an honesty guard (confirms the exploit landed before judging
  cenziadah) and guaranteed teardown.
- Detection: collection is now **subtree-aware** (`procfs.Descendants`) — proctree/socket/fd
  gathering walks the target's whole descendant tree and unions their sockets+fds, so a
  post-exploitation shell in a forked worker (nginx/Apache-prefork/smbd handle requests in
  workers) is detected when inspecting the master. Surfaced by the live Samba test.

### Notes
- `watch`, `incidents` (SQLite), and the `capture`/`triage`/`conntrack` packages
  are not yet implemented.
- The compromise test runs in degraded mode without `CAP_SYS_PTRACE`, proving the
  maps/proctree/socket detectors; module integrity is covered by its own unit test
  (inline-hook + build-id) and the full live path needs sudo.
