# testharness/redteam — live third-party exploit validation

**Everything related to validating cenziadah against a real, third-party exploit lives in this
folder.** It is self-contained and disposable.

## What this does

Proves cenziadah detects a **real** compromise in software we did **not** write, using a published
exploit against a published vulnerable-training target:

- **Target:** `tleemcjr/metasploitable2` — the canonical pentest-training image, which ships the
  genuine **Samba 3.0.20** vulnerable to **CVE-2007-2447** (the "username map script" command
  injection). Run disposably, with SMB bound to **host loopback only**.
- **Exploit:** Metasploit's maintained `exploit/multi/samba/usermap_script` module (rank
  Excellent), run from the official `metasploitframework/metasploit-framework` Docker image.
  **No exploit code is written here** — we run a standard, widely-distributed security-testing tool.
- **Why it validates cenziadah:** a successful exploit makes `smbd` fork a worker that runs an
  attacker command, opening a reverse shell. That leaves the exact IoCs cenziadah detects:
  a **rogue shell/`nc` child under the smbd process tree** (`proctree.unexpected_child`) and a
  **reverse-shell socket** to the attacker's handler (`net.unexpected_dest`).

> Note on `maps.rwx`: this Samba bug is *command injection*, not memory-corruption, so it does not
> produce a writable+executable memory region. The `maps.rwx` / inline-hook detectors are validated
> separately, against our **own** memory-corruption victim, by `make compromise-test`. This folder
> complements that by proving detection of a real third-party RCE's post-exploitation behavior.

## How it relates to the rest of the harness

- `testharness/victim` + `testharness/exploit` + `testharness/scenarios` validate cenziadah against
  **our own** deliberately-vulnerable server (a controlled memory-corruption bug we wrote): proves
  `maps.rwx`, inline hooks, rogue child. Run by `make compromise-test`.
- **This folder** validates against **third-party** software with a real CVE and a real, published
  exploit. It is **not** part of `make test` — it needs Docker, network, and root.

## Run it

```bash
sudo ./testharness/redteam/validate-samba-cve-2007-2447.sh
```

It: starts the vulnerable container and Samba → resolves the host PID of the `smbd` master →
baselines the clean smbd with cenziadah → confirms a CLEAN pre-exploit check (false-positive gate)
→ runs the real Metasploit exploit to get a reverse shell → confirms the shell landed (ground
truth) → runs `cenziadah check` while the shell is live → asserts cenziadah reports
`proctree.unexpected_child` and/or `net.unexpected_dest`. It also prints the OS-level ground truth
(the injected `nc`/`sh` chain under smbd and the socket) independently of cenziadah.

Exit codes: `0` PASS, `1` exploit landed but cenziadah missed it (a real bug — investigate),
`2` operational error, `3` inconclusive (exploit did not land — **not** a cenziadah failure).

## Why cenziadah has to walk the process subtree

The exploit does not compromise the smbd **master**; it makes the master fork a **worker** to
handle the malicious request, and the shell is a child of that worker (a *grandchild* of the
master). Detecting this required cenziadah to inspect the target's whole **subtree** (descendants),
not just direct children, and to union the descendants' sockets/fds — so a post-exploit shell in a
forked worker is visible when inspecting the master. This is a general improvement: most servers
(nginx, Apache prefork, smbd) handle requests in workers.

## Safety

- Nothing is exposed off-box: SMB is published only on `127.0.0.1`, and the reverse shell connects
  back to the host over the container's own docker bridge gateway.
- `trap cleanup EXIT INT TERM` force-removes the container and live scratch on every exit path.
- We author no exploit; if the published module/image stop working, the script reports that and
  stops — it does not substitute hand-written exploit code.
- Never point this at a non-disposable or production container.

## Files

- `validate-samba-cve-2007-2447.sh` — the single orchestration script.
- `work/` — git-ignored scratch (baseline JSON, msf logs, check output). Safe to delete.
