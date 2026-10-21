# Cenziadah — Plan

## Context

**Cenziadah** ("adultered") is a defensive runtime-integrity checker for Linux processes. Its
job: decide whether a *running* process has been tampered with in memory by code that arrived
via a memory-corruption exploit (RCE through buffer overflow, image-parsing bug, etc.) — i.e.
detect in-memory code injection, inline hooking, and the usual post-exploitation IoCs.

The tool is **generic**: it targets any Linux process by pid or name. Nothing in the design is
WhatsApp- or waydroid-specific except the choice of example target.

- **Reference target #1 (hardest):** `com.whatsapp` on waydroid. Hardest because Android's ART
  runtime legitimately uses RWX / anon-exec pages (JIT) — the worst-case false-positive source.
  Proving the detectors here means they generalize.
- **Reference target #2 (common, low-noise):** a native Linux daemon such as **Apache (`httpd`)**
  or **Traefik**. A native C binary or a static Go binary under W^X should have *zero* legitimate
  RWX pages, so the absolute detectors are high-signal with no baseline needed; module-integrity is
  the clean native case (compare loaded `.so` / the static binary against its on-disk ELF); a web
  server spawning `/bin/sh` is a textbook webshell/RCE IoC; odd outbound sockets = reverse
  shell / C2. Same four detectors, no code change — just `--name httpd` / `--pid <n>`.

The initial, deliberately narrow *acceptance* question remains: **does the `com.whatsapp` instance
running on waydroid on this host show signs of compromise?** — but it is answered by a general tool.

### The architectural fact that makes this feasible

Waydroid shares the **host PID namespace**. `com.whatsapp` runs as an ordinary host Linux
process (observed PID 2566717, UID 10147, parent is the zygote-equivalent). Therefore **all
inspection happens from the host through `/proc/<pid>/...`** — no Android device, no ADB, no
on-device root, no Mach-O, none of the iOS/`/data/data` machinery the original TODO mixed in.
This collapses the problem to classic Linux `/proc` forensics.

### Non-functional requirement: Cenziadah must not itself be exploitable
A forensic monitor is a high-value target — if it is more attackable than what it watches, it becomes
the soft spot. Cenziadah is therefore designed with a **minimal attack surface**:
- **No listening sockets. Ever.** The tool opens no inbound ports, no control socket, no RPC. `watch`
  is a self-driven poll loop, not a server. (The v2 eBPF layer is kernel-side telemetry, still no
  inbound socket.) The only network traffic is the opt-in, outbound-only HTTPS reporting to the
  data portal, confined to `internal/reporter`.
- **No untrusted input channels.** It takes no stdin, no network input, no attacker-controllable
  config at runtime. Configuration is CLI flags + an operator-owned policy/baseline file written by a
  trusted admin; these are trust boundaries, not attacker channels.
- **Adversarial data is parsed defensively, never trusted.** The tool unavoidably *reads* two hostile
  things: the target's `/proc/<pid>/mem` (attacker-influenced bytes) and on-disk ELF backing files.
  These are treated as **opaque, bounded, read-only data**: fixed-size bounded reads (never size-from-
  the-data allocations), no `exec`/`eval`/deserialization of anything read from the target, captured
  payloads stored as inert blobs (never executed or loaded), and `debug/elf` fed only the *trusted
  on-disk* file — never a memory dump (stdlib ELF parser isn't hardened against adversarial input).
- **Minimal privilege, minimal deps, memory-safe.** Pure Go (memory-safe), no cgo in the detector
  (the only C is the *test victim*, isolated in `testharness/` and never linked into the tool), the
  smallest dependency set possible, and only `CAP_SYS_PTRACE`+`CAP_DAC_READ_SEARCH` — never full root
  as a daemon. Output (reports, DB) is write-only to operator-owned paths; the tool never reads back
  and acts on attacker-reachable files.
- **Fail safe, not open.** Malformed/oversized/racing input → bounded error + operational exit, never
  a crash that could be steered or an unbounded allocation (ties into the memory budget).

### Development conventions
- **Unit tests for every major component.** Each package ships `_test.go` coverage of its core logic,
  written against fixtures so it runs with no root and no live process (as `procfs` already does).
- **No integration tests except the real compromise test.** The *only* integration-level test is the
  end-to-end `testharness/scenarios/` run (victim + exploit + `cenziadah check`). No other
  cross-package or live-process integration tests are maintained.
- **The whole dev toolchain runs from the Makefile.** `make build|test|vet|fmt|lint|harness|
  compromise-test|all`. Targets are not quiet: make prints each command and its output.

### Non-functional requirement: memory budget
The tool must run on **small Linux servers — peak RSS well under 1 GB** for a `check`, regardless of
how large the *target* process is (a busy Apache or WhatsApp's ART heap can map GBs). This is a
design constraint, not an afterthought — see **Memory budget** under Architecture. In short: never
load a whole process image or a whole mapping into memory; stream `/proc/<pid>/mem` in a small
fixed-size chunk buffer, compare `.text` incrementally, and keep only compact digests/shapes in the
Snapshot. Target working set: a few MB for the tool itself + one bounded read buffer (default ~1 MB).

### Decisions locked with the user
- **False positives:** ART (WhatsApp's Android runtime) legitimately uses RWX / anonymous
  executable pages for its JIT. v1 handles this with a **baseline-diff model**: snapshot a
  known-clean target, then on check only flag what is *new vs baseline*. No deep ART modeling
  in v1.
- **Privilege:** tool **requires elevated privilege** (root, or `CAP_SYS_PTRACE` +
  `CAP_DAC_READ_SEARCH`) to read another UID's `maps`/`mem`. Documented, not worked around.
- **Test harness:** a **classic memory-corruption vulnerable app** (real stack/heap overflow)
  plus a matching exploit that lands shellcode — end-to-end, mimicking the WhatsApp RCE path —
  so Cenziadah is validated against a genuine compromise, never against WhatsApp itself.

---

## Product, licensing & distribution (decided 2026-10-11, revised 2026-10-12)

### Licensing (revised 2026-10-12: fully open agent)
- **The whole agent is open source under AGPL-3.0-or-later** (`LICENSE`; every source file carries
  an SPDX header). This replaces the 2026-10-11 decision to keep the detectors closed.
- **Why the change:** the detection techniques are well known (memory forensics, EDRs); the hard,
  valuable work turned out to be false-positive engineering against real systems, which a closed
  binary protects only for weeks. Meanwhile a closed binary running as root on production servers
  is a trust problem for exactly the users who need it, and false positives are best fixed by
  many users on many distributions. The private/public split, export script and plugin interface
  would have been a large ongoing cost for a one-person project.
- **Why AGPL (not Apache 2.0):** anyone who distributes a modified build, or offers one as a network
  service, must publish their source. Apache 2.0 never obliges changes to come back.
- **CLA required** for outside contributions (`CLA.md`, signatures in `CLA-SIGNATURES.md`):
  contributors keep their copyright and grant the maintainer the right to license contributions
  under other terms too (dual licensing remains possible). Modelled on the Apache ICLA.
- No license can force changes to flow back *to this repo*; reporting obligations, if any, live in
  the **data portal's terms of service**.
- **Get a legal review** of the CLA (and of copyright ownership, see below) before the first
  public release.

### Where the value is protected
- **The data portal stays private** (separate repo): exploit reports, payload hashes, attack
  patterns across installations, fleet dashboard and alerting. It grows with every install and
  cannot be copied by forking the agent; it can become a paid service.
- The agent's edge is its quality (low false positives, verified detection) and speed of release.

### Repositories (revised)
- **This repo will be the single public agent repo.** No private detectors, no export script, no
  generated public copy.
- **The data portal** lives in its own private repo (`cenziadah-data-webapp-plan.md` moves there).
- Before making this repo public: review history and docs for private infrastructure details
  (production host names, mail provider, personal paths in examples) and move or scrub them.

### Exploit reporting & run records (data portal)
- The **data portal** is a separate project: an HTTPS API backed by MySQL. Its API is still to be
  defined; the endpoints Cenziadah needs are listed below.
- All network reporting lives in one new module, **`internal/reporter`**. It consumes
  `model.Report` / `model.Incident` and nothing else. The detection core stays network-free, and the
  tool still opens **no listening sockets**: reporting is outbound HTTPS only.
- **Opt-in.** Reporting is off by default and enabled by explicit config or flag. IP addresses and
  host info are personal data under GDPR, and captured memory can contain customer secrets.
- **Run record:** every execution sends a **start record** (version, subcommand, host info).
- **Exploit report:** each confirmed incident uploads findings, target path + build-id, and payload
  **hashes plus triage**. Raw payload bytes are sent only with an additional explicit flag. Payloads
  are redacted by default.
- **(Revised 2026-10-13)** For an operator's own server, `watch --mail-to` sends mail through the host's local MTA (opt-in, root-owned sendmail only, rate-limited). For fleets: **email is sent by the portal, not by each host.** Hosts upload to the portal only; the portal
  emails a project mailbox (to be defined, not a personal address). Most servers have no `sendmail`,
  and unauthenticated mail from arbitrary hosts gets spam-filtered.
- **External IP:** the portal records the source IP it observes on every request, which the client
  cannot fake, and returns it in the response for local logging. Behind NAT or a proxy, that is the
  gateway's address. Client-side fallback, for display only:
  `dig +short myip.opendns.com @resolver1.opendns.com`.
- **Host info collected:** hostname, a SHA-256 of `/etc/machine-id` (never the raw ID), kernel
  release, distro (`/etc/os-release`), architecture, Cenziadah version + build, and the observed
  external IP (set by the portal).
- **Fail-open, bounded:** reporting runs asynchronously with a short timeout. An unreachable portal
  never blocks, slows, or fails a scan. Undelivered reports are queued locally with a bounded queue.
- **Missing heartbeats raise an alert:** an attacker on the host can block outbound reporting, so
  the portal alerts when a host that normally sends start records goes silent.
- **Portal API needed by the client (draft):**
  ```
  POST /v1/runs        start record          -> { run_id, observed_ip }
  POST /v1/incidents   findings + incident   -> { incident_id, observed_ip }
  ```
  Requests are authenticated with a per-install token. The client never parses anything from the
  response beyond these fields, which preserves the no-untrusted-input requirement.

---

## Assessment of the original TODO (do these requirements make sense?)

**Keep — sound and cheap/high-signal:**
- RWX / anonymous-executable mapping scan (`/proc/<pid>/maps`). ✔
- Module integrity: in-memory `.text` vs on-disk `.text` of loaded `.so`s. ✔ (gold standard)
- Process-tree anomalies (unexpected children of the target). ✔
- FD / socket inspection (`/proc/<pid>/fd`, `/proc/<pid>/net/*`). ✔

**Correct / re-scope:**
- Drop all **iOS / Mach-O / `/var/mobile`** content — out of scope (Linux/waydroid only).
- Drop **`/data/data` Android-path** assumptions; on waydroid these are host paths under
  `/var/lib/waydroid/data/` and need sudo — treat as on-disk artifacts, not Android APIs.
- **CFI / stack-pivot / ROP stack-unwind detection** — genuinely hard, low-signal for v1. Defer.
- **Network C2 / ASN (AS32934/AS63293) attribution + traffic-volume-vs-activity correlation**
  — a whole subsystem. v1 ships only a thin **destination allow-list** socket check; defer the rest.
- **SQLite WAL / msgstore.db / axolotl.db forensics & "unregistered linked devices"** — encrypted
  at rest, separate discipline, partly not observable from outside. Defer entirely.

**Add (the TODO's key omission):**
- **Baseline + check model.** "Anomalous" is meaningless without a known-good reference. This is
  the backbone of the tool and the chosen defense against ART JIT false positives.

**Net v1 scope:** four detectors (maps, module-integrity, process-tree, fd/socket), driven by a
snapshot/baseline → check pipeline, incident capture into a local DB, proven against a real
vulnerable test app.

---

## Architecture

### Core primitives
A **`Finding`** is the unit that flows out: `{Technique, Severity, PID, Title, Detail,
Evidence map[string]any, Suppressed bool, SuppressReason string}`. `Suppressed` is **first-class** —
a detector never silently drops a flag; it records *why* it was suppressed (e.g. matched the ART
allow-list). This keeps the ART false-positive handling auditable.

A **`Snapshot`** (baseline) is the serialized known-good state a check diffs against. Crucially it
stores **shapes + digests, not absolute addresses** — ASLR/PIE make raw virtual addresses
meaningless across runs. Regions are keyed by *backing file + permission class*; modules are keyed
by path + **GNU build-id** + on-disk `.text` digest. It also holds the allow-lists (expected libs,
socket CIDRs, fd path prefixes, allowed child exes) and the ART suppression profile.

### Package layout (black-box boundaries, each independently testable)
```
cmd/cenziadah/            CLI entrypoint (thin: parse flags -> dispatch subcommand)
internal/model/           Finding, Snapshot, Report, Technique/Severity enums. ZERO deps on other
                          internal packages — the lingua franca everything shares.
internal/procfs/          the ONLY package that touches /proc: maps, mem (pread per region), fd,
                          net/{tcp,tcp6,udp,udp6}, proctree (walk for PPID==target), status(uid/ns)
internal/elfref/          pure, DISK-ONLY ELF modeling: .text range, build-id, reloc mask (see below)
internal/detector/        a Detector interface { Name(); Inspect(ctx,*Target) ([]Finding,error) }
                            maps_anomaly.go   RWX + anon-exec + deleted-backing scan
                            module_integrity.go  in-mem .text vs on-disk .text (uses elfref)
                            proctree.go       unexpected-child detection
                            fdsocket.go       fd + socket allow-list checks
internal/baseline/        Snapshot save/load (JSON), diff, allow-list policy, ART suppression profile
internal/capture/         INCIDENT capture: on a confirmed finding, collect evidence (payload bytes,
                            triage, proc context, live+recent sockets) -> Incident record
internal/triage/          cheap static analysis of captured payload: strings, short disasm of entry,
                            syscall-stub detection -> classification hints ("is this interesting?")
internal/conntrack/       lightweight connection-history sampler (ring buffer of recent remote
                            IP:port for the target), feeds delivery/C2 context into an Incident
internal/incidentdb/      local SQLite store (pure-Go modernc.org/sqlite), dedup by payload hash
internal/engine/          orchestrate: resolve target -> run detectors -> capture -> assemble Report
internal/report/          render Report as text now, JSON later
internal/reporter/        opt-in outbound HTTPS to the data portal (start records, incidents);
                            async, bounded, fail-open. The ONLY package that touches the network.
```
All detector implementations are open source (AGPL-3.0-or-later); see *Product, licensing &
distribution*.
Detectors receive **already-parsed structs** from `procfs`, so each is unit-testable with synthetic
maps/mem fixtures and **no root**. `elfref` is pure and disk-only → testable against checked-in `.so`
fixtures. New deferred techniques (CFI, C2, WAL) slot in later as new `Detector`s without touching
existing ones. `procfs` is the platform layer (wraps the one thing we don't control — the kernel's
/proc format). Detectors depend only on `procfs` structs + `snapshot`, never on each other → any
detector can be rewritten or dropped in isolation.

**Dependencies:** the open part of this project is **published** in the public repo, so it uses only the Go
standard library and well-known public modules — **no internal/private company repos**. Standard
library covers nearly everything: `debug/elf` (ELF parsing for the `.text` comparison), `os`/`bufio`
(reading `/proc`), `encoding/json` (snapshots), `crypto/sha256` (payload hashing). The one external
module v1 needs is **`modernc.org/sqlite`** (pure-Go, no cgo) for the incident DB — chosen precisely
because it avoids cgo and stays portable on small servers. `golang.org/x/arch` is an optional,
well-known public module for the triage disassembly hint. Keep the dependency set minimal; reach
further only if the stdlib genuinely falls short.

### CLI surface
```
cenziadah snapshot --pid <n> | --name com.whatsapp  -o baseline.json   # capture known-good
cenziadah check    --pid <n> | --name com.whatsapp  [--baseline baseline.json]
cenziadah watch    [--tui] [--interval 10s] [--json] [--no-mem]          # all processes: learn, then deltas
cenziadah incidents list|show <id>|export                              # query the compromise DB
```
- `check` without a baseline runs only the **absolute** detectors (RWX, deleted-backing,
  disk-vs-mem mismatch, rogue child) — these don't need a reference.
- `check` with a baseline additionally runs **differential** detectors (new anon-exec region,
  new child, new socket destination) — this is what tames ART JIT noise.

**Exit codes:** `0` clean · `1` findings at/above the severity threshold · `2` operational error
(e.g. `EPERM` reading `/proc` → print a clear "run with sudo / CAP_SYS_PTRACE" message, never a
silent empty report).

### Deployment / triggering
**v1 operational default: `watch` daemon under a hardened systemd unit** — *not* cron. Rationale:
integrity checking is a point-in-time sample, and plain cron is blind between ticks (a transient
in-memory implant can `mmap` RWX, run, and free it inside one window) and has no memory of prior
state. The `watch` daemon instead:
- keeps the **baseline in memory**, polls on a short interval (`--interval`), and emits **only
  new/changed findings** (deltas) — far better signal, and cheap thanks to buffer reuse + cached
  digests, so a short interval doesn't cost much.
- ships as a `cenziadah.service` systemd unit granting **only** `CAP_SYS_PTRACE` +
  `CAP_DAC_READ_SEARCH` (via `AmbientCapabilities`/`CapabilityBoundingSet`), `NoNewPrivileges`,
  `ProtectSystem`/`ProtectHome`, a `DynamicUser` or dedicated user — never full root from a crontab.
  Findings go to journald (and optionally a webhook/log sink later).

A lightweight **systemd timer** (periodic stateless `check`) can be added later for operators who
don't want a resident process; still preferred over cron (journald logging, scoped caps). v1 focuses
on the daemon.

**v2 roadmap — event-triggered detection** (closes the sampling-window gap entirely; out of v1 scope):
- **eBPF tracepoints** on `mmap`/`mprotect` (fire the instant a target page gains `PROT_EXEC`),
  `ptrace`, `fork/exec` under the target, and `connect()` to non-allow-listed destinations — turns
  "was there an RWX page at sample time?" into "a page just became executable → check now." Kernel-
  side, so it fits the memory budget. Needs an eBPF toolchain (e.g. `cilium/ebpf`) + kernel support.
- **fanotify/inotify** on the target's on-disk ELF/`.so` paths → re-check on modification (on-disk
  tamper, `(deleted)` backings) without an eBPF toolchain.

### Memory budget (peak RSS < 1 GB, independent of target size)
The tool's footprint must not scale with the target process's mapped size. Rules baked into the
design:
- **Stream, never slurp.** `procfs.mem` reads via `pread` into **one reusable fixed-size buffer**
  (default 1 MB, `--read-buf`). `.text` comparison in `module_integrity` runs chunk-by-chunk against
  the on-disk `.text` read through the same sized window — mismatches are detected incrementally, so
  a 200 MB `.so` costs one 1 MB buffer, not 200 MB.
- **Digests, not bytes, in the Snapshot.** Baseline stores a rolling SHA-256 of masked `.text`
  (and build-id), plus region *shapes* — never raw page contents. A snapshot of a multi-GB process is
  kilobytes on disk and in RAM.
- **Maps/fd/net parsing is line-streamed** (`bufio.Scanner`), producing compact structs; we don't
  hold the whole `/proc/<pid>/maps` text or every region's bytes.
- **Bounded concurrency.** `watch` reuses buffers across cycles; no per-cycle large allocations.
- **Verification includes a memory assertion** (below): measure the tool's peak RSS while checking a
  deliberately large target and assert it stays under the budget.

### Hardest correctness problem: in-memory `.text` vs on-disk `.text`
Naively diffing bytes false-positives on every relocated symbol (GOT/PLT, R_X86_64_RELATIVE,
IFUNC resolution). Pragmatic v1 approach, lowest-FP first:
0. **Identity first (cheap, catches the easy case).** Read the **GNU build-id**
   (`.note.gnu.build-id`) from both the in-memory module and the on-disk backing file. If they
   differ, that *itself* is a finding (wrong / swapped / patched library loaded) — report it and
   **skip** the byte diff. Only diff when identities match.
1. For each file-backed executable mapping (scoped to the baseline's allow-list of real native
   `.so`s), use `debug/elf` on the on-disk backing to locate the `.text` section (offset, VA, size).
2. Read the same virtual range from `/proc/<pid>/mem` using the maps load bias
   (`region.start - region.file_offset + section.offset`).
3. **Compare only `.text`** (pure code), which relocations largely don't touch — GOT/PLT live in
   `.got`/`.plt`/`.data.rel.ro`, which we *exclude* by never comparing whole segments.
4. **Build a relocation mask:** enumerate `.rela.dyn` / `.rela.plt`; for any relocation whose target
   falls *inside* `.text` (rare on modern PIC `.so` — mostly IFUNC/textrel), mark those 4–8 bytes
   "don't-care". Well-formed PIC libs usually yield an empty mask, but the machinery prevents
   false-positives on the rare textrel library.
5. Non-masked `.text` bytes must match disk exactly — compared **chunk-by-chunk** through the shared
   fixed-size read buffer (never the whole section in RAM; see Memory budget). Mismatch ⇒ **inline
   hook / patch** (Critical): report offset + before/after bytes (a hook's first bytes are usually a
   `jmp`/`push;ret` trampoline — include a short disassembly hint if cheap).
6. Validate on the test app's own libs first (clean = zero findings), then ART-loaded libs.

**`debug/elf` on trusted input only:** feed it the on-disk backing files (trusted), never an
attacker-controllable memory dump — the stdlib ELF parser is not hardened against adversarial input.

**`/proc/<pid>/mem` is live — handle races:** pages can change/unmap mid-read (`pread` may `EIO` or
short-read). Read per-region with retry (best-effort, non-intrusive) for v1. Document the alternative
(`PTRACE_SEIZE`+`INTERRUPT` to freeze for a consistent read) as a later, more intrusive option.

### False-positive sources to handle explicitly
- **ART JIT (dominant FP source)** — RWX / anon-exec from the Android runtime, backed by
  `memfd:jit-cache`, `/dev/ashmem/dalvik-*`, `[anon:dalvik-*]`, `*.oat`/`*.art`/`*.vdex`/`*.odex`.
  Defense: baseline-diff (primary) **plus** an allow-list that *suppresses* (not drops — sets
  `Suppressed=true` with a reason) regions whose backing matches these ART patterns. Never attempt
  the `.text` byte-diff on JIT/oat regions — they have no stable disk `.text`.
- **Legitimate JITs / `memfd:`** generally → baseline-diff + record backing name.
- **Lazy PLT binding / CoW** in `.text` comparison → `.text`-only + reloc-mask (above).
- **Benign `(deleted)` mappings** from package upgrades (`apt`) → scope the deleted-backing rule to
  *executable* mappings and cross-check build-id, so a post-upgrade library isn't flagged.
- **Socket allow-list drift** — legit destinations change; keep CIDRs in versioned policy, treat
  `net.unexpected_dest` as Medium (investigative), not Critical, to avoid alert fatigue.
- **Disk file may also be tampered** — the diff trusts the backing file; pair with a trusted
  build-id / hash list in policy, else an attacker patching both memory and disk evades detection.

---

## Test harness (validation that Cenziadah actually works)

A real, self-contained compromise — never WhatsApp — under `testharness/`:
- **`victim/`** — a small C (or cgo) server with a genuine, bounded **stack/heap buffer overflow**
  reachable via a local input (stdin/socket). Built intentionally without the mitigations that
  would stop the PoC (its own CFLAGS; nothing system-wide touched).
- **`exploit/`** — a matching local exploit that overflows the buffer and lands **shellcode into an
  RWX/anon-exec region**, producing the exact IoCs Cenziadah looks for (new anon-exec page,
  optionally an inline hook, optionally a spawned `/bin/sh` child, optionally an odd socket).
- **`scenarios/`** — scripts that: (1) start victim, (2) `cenziadah snapshot` the clean process,
  (3) run exploit, (4) `cenziadah check` → assert the expected Findings appear; and a clean-run
  control that must yield **zero** Findings (false-positive gate).

The victim app loads a small native `libvictim.so` exporting a hookable function (e.g.
`victim_checksum()`) and exposes a control socket so each compromise is deterministic. The real
overflow path (cgo `memcpy` into a fixed buffer from a length-prefixed message) drives the
end-to-end RCE case; the per-detector table gives one positive observable per detector so each is
independently proven:

| Detector | Compromise action |
|---|---|
| `maps.rwx` | `mmap(PROT_READ\|WRITE\|EXEC)`, copy benign shellcode (a `ret`), jump to it |
| `maps.anon_exec` | `mmap` anon `PROT_EXEC` (not file-backed) + execute from it |
| `maps.deleted_backing` | load a `.so` from a temp path, `unlink` while mapped → `(deleted)` exec mapping |
| `module.text_mismatch` | injector overwrites first bytes of `victim_checksum` in-memory with a `jmp` trampoline (classic inline hook) |
| `proctree.unexpected_child` | victim `fork/exec`s `/bin/sh -c id` (post-exploit shell) |
| `fd.sensitive_path` | victim opens an fd to a sensitive-path fixture |
| `net.unexpected_dest` | victim opens TCP to a non-allow-listed loopback port (C2 stand-in) |

Each scenario also asserts **zero** findings against the un-compromised victim (FP regression guard).
The `module.text_mismatch` and overflow cases use ptrace/self-inject, so the test env must account
for **Yama `ptrace_scope`** (`/proc/sys/kernel/yama/ptrace_scope`) — run as root or set the scope in
the test env only. These scenarios are the acceptance tests for v1.

---

## Incident capture & compromise DB

When a finding is **confirmed** (not suppressed), the engine captures a durable `Incident` so you
keep a queryable record of *when, from/to where, and with what code*.

### What's collectable (and the honest limits)
- **Times:** detection time + process start time (`/proc/<pid>/stat` starttime → wall clock) to bound
  the compromise window.
- **Target identity:** pid, exe, build-id, cmdline, uid/gid.
- **The injected code ("is it interesting?") — yes.** For `maps.rwx`/`maps.anon_exec`, dump the
  offending region from `/proc/<pid>/mem` (**bounded** — capped, streamed, respects the memory
  budget). For `module.text_mismatch`, capture the patched bytes + trampoline target. Store: a
  **SHA-256** (correlation/dedup), the **raw bytes (bounded blob)**, and **static triage** from
  `internal/triage`: embedded strings, a short disassembly of the entry, and syscall-stub detection
  (`execve`/`connect`/`socket` ⇒ reverse-shell/loader/dropper classification hints).
- **IP — important caveat, handled by design:** a post-hoc memory scanner **cannot** recover the IP
  the exploit *arrived from* (the delivery packet is gone; WhatsApp delivery is TLS-to-Meta).
  Therefore v1 captures two things: (1) **remote IP:port of sockets open at detection time**
  (`/proc/<pid>/net/tcp{,6}` joined to fd inodes) — catches live C2/reverse-shell/exfil; and (2) a
  **recent-connection ring buffer** from `internal/conntrack`: the `watch` daemon periodically
  samples the target's socket table and retains recent remote endpoints, so an Incident still gets
  network context even if the socket closed before detection. True *delivery-IP* capture needs the
  v2 eBPF `connect()`/`accept()` layer — noted, not promised for v1.
- **Behavioral IoCs:** rogue child processes (exe/cmdline), suspicious fds (paths).

### DB
Local **SQLite** via pure-Go `modernc.org/sqlite` (single file, no cgo, portable on small servers),
deduped by `payload_sha256` + target so repeat detections correlate instead of duplicating:
```
incidents(id, detected_at, proc_start, pid, exe, build_id, technique, severity,
          payload_sha256, payload_size, payload_blob,
          live_remote_ips(json), recent_remote_ips(json),
          child_procs(json), suspicious_fds(json), triage(json), raw_report(json))
```
CLI: `cenziadah incidents list|show <id>|export` to query/triage after the fact. DB path is
configurable (`--db`); writes are bounded and streamed to respect the memory budget.

---

## Verification (end-to-end)

All toolchain steps run from the Makefile, which prints each command and its output:
```
make fmt      # gofmt -l .
make vet      # go vet ./...
make build    # go build ./cmd/...
make test     # go test ./...   (unit tests only)
make compromise-test   # the ONE integration test: build harness, run exploit, assert findings
make all      # fmt + vet + build + test
```
Unit tests (`make test`) cover every major component. The compromise test is the only integration
test. Acceptance (via `testharness/scenarios/`):
1. **Clean control:** snapshot + check a freshly-started victim → **0 findings** (FP gate).
2. **Exploit detected:** run the overflow exploit → `check` reports the injected anon-exec region
   (and any inline hook / rogue child / odd socket the exploit triggers), each as a `Finding`.
3. **Module integrity unit test:** a lib with a deliberately patched `.text` byte → exactly one
   mismatch finding; unpatched → zero.
4. **Incident capture:** after the RWX-shellcode exploit, assert an `Incident` row is written with
   a non-empty `payload_sha256`, a bounded `payload_blob`, triage that flags the planted syscall
   stub, and the exploit's reverse-shell destination present in `live_remote_ips` or
   `recent_remote_ips`. Re-running the same exploit dedups to the same payload hash.
5. **Memory budget:** run `check` against a deliberately large target (e.g. WhatsApp under ART, or a
   test process that maps a multi-hundred-MB region) while sampling the *tool's* peak RSS
   (`/usr/bin/time -v`, or read `VmHWM` from the tool's own `/proc/self/status`). Assert peak RSS
   stays **well under 1 GB** and does not scale with target size. Add a unit/integration check that
   fails if a single read allocation exceeds `--read-buf`.
6. **Live sanity (manual, sudo):** `cenziadah snapshot --name com.whatsapp` then `check` on the
   real process → confirm baseline-diff suppresses ART JIT noise (clean WhatsApp ⇒ ~0 diff
   findings). This step requires `sudo`/`CAP_SYS_PTRACE` and is run by the user.

---

## Out of scope for v1 (future phases)
Event-triggered detection (eBPF `mmap`/`mprotect`/`exec`/`connect` hooks, fanotify-on-binary) ·
true delivery-IP capture (needs the eBPF connect/accept layer) ·
CFI/stack-pivot/ROP detection · network C2/ASN attribution + traffic-volume correlation ·
SQLite WAL/msgstore forensics & linked-device checks · iOS/Mach-O · structural ART-region modeling ·
standalone systemd timer unit.

## Maintenance & visibility
- The agent repo is **AGPL-3.0-or-later and will be public**; contributions need the CLA (see
  *Licensing*). Code, docs and test harness must contain no private infrastructure, credentials or
  customer data. The portal URL and per-install tokens come from config, never hardcoded.
- `PRODUCT.md` is the user-facing product description; `PLAN.md` is the design/decision record.
- Maintain `CHANGELOG.md`: every fix or feature bumps the SemVer version and adds an entry.
