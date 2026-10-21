# Cenziadah — Product Overview

> **Cenziadah** (摻假的, roughly "adulterated" in Chinese) is a tool that checks whether a
> running program on a Linux computer has been secretly tampered with by an attacker — while it
> is still running.

This document explains, in plain language, what Cenziadah is for and what kinds of attacks it
can catch. A [Glossary](#glossary) at the end explains every technical term and acronym, so you
do not need to be a security expert to follow along.

---

## The problem it solves

Most security tools look for bad files sitting on a disk, or watch network traffic. But some of
the most dangerous attacks never touch the disk at all: the attacker breaks into a program
*while it is running* and quietly changes the program's **memory** — the live working copy of the
code and data the program is using right now. The program keeps looking normal from the outside,
but it is now doing the attacker's bidding.

This is exactly how high-end attacks against messaging apps, web servers, and other services
often work: a booby-trapped message, image, or network request triggers a bug that lets the
attacker run their own code *inside* the victim program. Nothing new appears on disk, so
traditional antivirus and file scanners miss it.

**Cenziadah answers one question: "Is this running program still the program it is supposed to
be, or has something been injected or altered inside it?"**

---

## How it works, in one picture

Cenziadah uses a simple, reliable idea: **take a fingerprint of a program when you know it is
clean, then compare against that fingerprint later.**

1. **Snapshot (baseline).** When you trust that a program is clean — for example, right after a
   fresh, verified deployment — Cenziadah records a compact "known-good" fingerprint of it: what
   its code looks like in memory, which libraries it loaded, what child programs and network
   connections are normal.
2. **Check.** Later (on a schedule, or on demand), Cenziadah inspects the *same running program*
   again and compares it to the baseline. Anything that does not match the known-good state is
   reported as a **finding**.

Because it compares against a known-good baseline, Cenziadah can stay quiet about the normal,
noisy behavior of a healthy program and speak up only when something genuinely new and
suspicious appears.

It runs **on the host machine** and inspects programs through the operating system's own
read-only view of running processes. It reads; it does not modify the programs it watches. It
works on ordinary Linux services (web servers, databases) and on apps running inside containers
(such as Docker) or Android-compatibility layers (such as Waydroid).

---

## What it can detect

Cenziadah looks for the tell-tale signs that a running program has been compromised in memory.
Each finding below is something an attacker typically *cannot avoid* leaving behind when they
inject or alter code at runtime.

### 1. Injected executable code
When attackers run their own code inside a victim program, they have to put that code somewhere
the processor is allowed to execute. That leaves footprints:

- **Writable-and-executable memory (`maps.rwx`).** Healthy programs almost never have a chunk of
  memory that is *both* writable and executable at the same time — modern systems deliberately
  forbid it (see **W^X** in the glossary). A region that is both is a classic sign of injected
  code. **Severity: critical.**
- **Executable memory with no file behind it (`maps.anon_exec`).** Legitimate program code comes
  from a file on disk. Executable memory that is backed by *no file* is often attacker code that
  was written straight into memory. **Severity: high.**
- **Executable code from a deleted file (`maps.deleted_backing`).** Code running from a file that
  has since been deleted is a common way attackers hide what they loaded. **Severity: high.**

### 2. Tampered program code (hooking / patching)
Attackers often change a few bytes inside an existing, trusted library to silently redirect it —
for example, to intercept encryption or steal data. Cenziadah catches this by comparing the
program's code **as it runs in memory** against the trusted baseline:

- **In-memory code changed (`module.text_mismatch`).** The live code of a library no longer
  matches its known-good fingerprint — a strong sign of an **inline hook** or patch.
  **Severity: critical.**
- **A different build of a library was loaded (`module.build_id_diff`).** The program loaded a
  library whose unique build identifier does not match the baseline — it could be a swapped-in,
  malicious replacement. (Note: this also fires legitimately when you *update* software, which is
  why the recommended practice is to re-baseline after every deployment.) **Severity: critical.**

### 3. Suspicious new behavior after a break-in
A successful break-in usually leads to follow-on activity. Cenziadah watches for the classic
post-compromise moves:

- **Unexpected child programs (`proctree.unexpected_child`).** A web server or messaging app
  suddenly launching a command shell (for example `/bin/sh`) is a textbook sign that an attacker
  is now running commands. **Severity: high.**
- **Connections to unexpected places (`net.unexpected_dest`).** The program opens a network
  connection to a destination that is not on its known-good list — a possible sign of data being
  stolen or the attacker "phoning home" to a control server. **Severity: medium (investigate).**
- **Access to sensitive files (`fd.sensitive_path`).** The program has opened files it has no
  business touching, which can indicate an attacker has broken out of the program's normal
  boundaries. **Severity: medium.**

---

## What it is **not**

To set expectations honestly:

- **It is not antivirus.** It does not scan files on disk for known malware signatures.
- **It does not block attacks.** It *detects* tampering after the fact; it is a tripwire and a
  forensic aid, not a firewall.
- **It does not catch every kind of bug.** Many web vulnerabilities (for example, tricking an app
  into revealing data, or logic flaws) leave no trace in a program's memory and are outside what
  Cenziadah looks at. Cenziadah focuses specifically on **memory tampering and the injection or
  alteration of running code.**
- **It relies on a trustworthy baseline.** If you fingerprint a program that is *already*
  compromised, Cenziadah will treat that compromised state as "normal." Baselines should be taken
  when you are confident the program is clean.

---

## How it compares

No single technique in Cenziadah is new: RWX scanning, in-memory code inspection, hook detection
and process/socket anomaly checks all exist in mature tools. What is uncommon is the
**combination**: a dependency-free, baseline-diff, state-sampling integrity checker that also
understands containers and Android/ART. It sits between offline memory forensics (Volatility:
powerful, but you analyze a dump after the fact) and eBPF runtime platforms (Falco, Tracee,
Tetragon: powerful, but privileged kernel-level daemons).

Legend: ● yes · ◐ partial · ○ no. The rows are Cenziadah's distinguishing capabilities, not a
full feature census of each tool.

| Capability | **Cenziadah** | K-Scanner | Volatility 3 | Falco / Tracee / Tetragon |
|---|---|---|---|---|
| License | **AGPL-3.0-or-later** (+ CLA) | MIT | VSL v1.0 (custom, not OSI) | Apache 2.0 |
| Commercial backer | none (independent) | none | Volatility Foundation (non-profit) | Sysdig / Aqua / Cisco (CNAPP upsell) |
| RWX / injected-code detection | ● | ● | ● (`malfind`) | ◐ (via mmap/mprotect events) |
| In-memory `.text` vs baseline (inline hooks) | ● (digest diff) | ○ | ◐ (no v3 Linux inline-hook plugin) | ○ |
| Known-good baseline / drift model | ● | ○ | ○ | ○ (rule-based, not baseline) |
| Container-aware | ● (mount-namespace paths) | ◐ (cgroup id only) | ◐ (from dump) | ● |
| Android / ART awareness | ● (JIT suppression) | ○ | ◐ (Android dumps, research) | ○ |
| Kernel / syscall-table / rootkit | ○ | ○ | ● (`check_syscall`) | ● |
| Event-driven (catches the act) | ○ (samples state) | ○ | ○ | ● |
| No eBPF / kernel module | ● (single Go binary; `watch` can run as a systemd service) | ● | ● (but needs a dump + Python) | ○ |

Every tool here, Cenziadah included, covers only a narrow band of the attack lifecycle (mainly
execution, defense evasion by code injection, partly persistence and command-and-control). None
of them replaces a WAF, patching, identity controls or data-loss prevention; Cenziadah is one
layer of defense in depth.

Source: competitive analysis of 2026-10-10 (claims checked against each project's documentation
and license files at that date).

---

## How it is used

Cenziadah is a single command-line program. The core actions are:

- `cenziadah snapshot` — record a known-good baseline of a running program.
- `cenziadah check` — compare a running program against its baseline and report findings.
- `cenziadah watch` — keep watching **every** running program. It first learns what normal looks
  like on the machine, then reports only changes: a program that suddenly starts a shell, opens
  an unusual connection, or has its code altered. It can write one log line per change, or show
  a live, interactive list of all programs marked SAFE or ALERT (`--tui`).
- `cenziadah version` — show the version.

Findings are reported with a severity (critical / high / medium) and the evidence behind them, in
human-readable text or machine-readable JSON. An exit code signals the result so it can plug into
alerting: **0** = clean, **1** = findings worth attention, **2** = could not run (for example,
insufficient permissions).

Helper scripts can baseline and check **every container in a stack** at once, which is how it is
typically run in production: baseline right after each deployment, then check periodically.

### Practical notes
- Cenziadah needs elevated permission to read another program's live memory (see
  **CAP_SYS_PTRACE** in the glossary). In practice it runs as an administrator (root) or is
  granted just that one capability.
- Because software updates legitimately change program code, the recommended routine is to
  **re-take the baseline after every deployment or update.** After that, any code change that
  appears *without* a deployment is a genuine alert.

---

## Glossary

Terms and acronyms, in plain language.

- **Process / running program** — a program that is currently executing on the computer (as
  opposed to just a file sitting on disk).
- **Memory (process memory)** — the live, in-use copy of a program's code and data while it runs.
  Attacks that tamper here leave nothing on disk.
- **Baseline / snapshot** — a recorded "known-good" fingerprint of a program, used for later
  comparison.
- **Finding** — something Cenziadah flagged as not matching the known-good baseline.
- **Shellcode / injected code** — the attacker's own code, placed inside a victim program so the
  computer runs it.
- **Inline hook / patch** — quietly changing a few bytes inside existing, trusted code to
  redirect what it does (for example, to spy on it), without replacing the whole file.
- **RWX / W^X** — memory permissions. Memory can be **R**eadable, **W**ritable, and/or
  e**X**ecutable. **W^X** ("write XOR execute") is the modern safety rule that memory should be
  writable *or* executable but **not both at once**. **RWX** memory (all three) breaks that rule
  and is a classic sign of injected code.
- **Module / shared library (`.so` file)** — a reusable chunk of code (for example, an encryption
  library) that many programs load and run. A frequent target for tampering.
- **`.text` section** — the part of a program or library that contains its actual executable
  instructions (its "code"). Cenziadah fingerprints this to detect code tampering.
- **Build ID** — a unique identifier baked into a compiled program or library, like a serial
  number for that exact build. A mismatch means a *different build* was loaded.
- **IoC (Indicator of Compromise)** — an observable sign that a system may have been breached
  (for example, an unexpected command shell or an RWX memory region).
- **RCE (Remote Code Execution)** — an attack in which someone who is *not* on the machine manages
  to run their own code on it, typically by exploiting a bug — the kind of break-in Cenziadah is
  designed to catch the aftermath of.
- **Memory-corruption vulnerability** — a class of software bug (such as a *buffer overflow*)
  where malformed input corrupts a program's memory in a way that can hand control to an attacker.
- **Buffer overflow** — a common memory-corruption bug: a program writes more data into a
  storage area than it can hold, spilling over and corrupting adjacent memory.
- **ASLR (Address Space Layout Randomization)** — a defense that randomly shuffles where things
  sit in a program's memory, making attacks harder. Real attacks often work around it; Cenziadah
  accounts for it by fingerprinting *what* code is present rather than *where* it sits.
- **NX (No-eXecute) / DEP** — a protection that marks data areas as non-executable so planted data
  cannot be run as code. (Attackers try to defeat it; the attempt itself leaves detectable traces.)
- **Process tree (parent / child process)** — programs can launch other programs; the launcher is
  the "parent" and the launched one is the "child." An attacker-spawned shell shows up as an
  unexpected child.
- **File descriptor (fd)** — a handle a program holds to an open file, socket, or device.
  Unexpected ones can reveal an attacker reaching into places the program shouldn't go.
- **Socket** — a network connection endpoint. An unexpected outbound socket can indicate data
  theft or communication with an attacker's server.
- **CAP_SYS_PTRACE** — a specific Linux permission that allows one program to inspect another's
  memory. Cenziadah needs it (or administrator/root access) to do its job, and nothing more.
- **Container (Docker) / Waydroid** — technologies that run programs in isolated environments.
  Docker packages services (web servers, databases) into self-contained units; Waydroid runs
  Android apps on Linux. Cenziadah can inspect programs inside both, from the host.
- **ART (Android Runtime)** — the system that runs Android apps. It legitimately does some things
  (like generating executable code on the fly) that would look suspicious elsewhere; Cenziadah
  knows to treat those as normal so it doesn't raise false alarms on Android apps.
- **False positive** — a harmless thing mistakenly flagged as a problem. Cenziadah's baseline
  comparison and its knowledge of runtimes like ART are designed to keep these low.

---

## License

Cenziadah is open source under the GNU Affero General Public License v3.0 or later: you can read,
audit, run and modify every line of what runs on your servers. Contributions are accepted under a
Contributor License Agreement (see CONTRIBUTING.md).
