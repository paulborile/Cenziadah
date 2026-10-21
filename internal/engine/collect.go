// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paulborile/cenziadah/internal/container"
	"github.com/paulborile/cenziadah/internal/cron"
	"github.com/paulborile/cenziadah/internal/detector"
	"github.com/paulborile/cenziadah/internal/elfref"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
	"github.com/paulborile/cenziadah/internal/redact"
	"github.com/paulborile/cenziadah/internal/systemd"
	"github.com/paulborile/cenziadah/internal/version"
)

var errSkip = errors.New("engine: module skipped")

// Collect reads a process's procfs state once and assembles a detector.Target.
// withMem controls whether /proc/<pid>/mem is opened (needed for module
// integrity, not for a plain snapshot). The caller must close Target.Mem.
func Collect(pid int, withMem bool, baseline *model.Snapshot) (*detector.Target, error) {
	st, err := procfs.ReadStatus(pid)
	if err != nil {
		return nil, err
	}
	regions, err := procfs.ReadMaps(pid)
	if err != nil {
		return nil, err
	}
	// Walk the whole subtree, not just direct children: forking servers (nginx,
	// Apache prefork, smbd) handle requests in worker processes, so a post-exploit
	// shell is usually a grandchild of the master, and its C2 socket/fds belong to the
	// worker. Gather descendants and union their sockets+fds so such a compromise is
	// visible when inspecting the master. (Socket ownership is established by joining
	// socket inodes to fds, so the worker's fds must be present for its socket to be
	// attributed and flagged.)
	kids, _ := procfs.Descendants(pid) // best-effort
	fds, _ := procfs.ReadFDs(pid)
	socks, _ := procfs.ReadSockets(pid)
	for _, k := range kids {
		if kf, err := procfs.ReadFDs(k.PID); err == nil {
			fds = append(fds, kf...)
		}
		if ks, err := procfs.ReadSockets(k.PID); err == nil {
			socks = append(socks, ks...)
		}
	}

	return assemble(pid, st, regions, kids, fds, socks, withMem, baseline)
}

// CollectInScan is Collect for an all-process scan. Each process in the sweep is
// inspected on its own, so it takes only DIRECT children (from the cycle's
// ProcTable, no extra /proc walk) and only its own fds/sockets; a worker's rogue
// shell is caught when the worker itself is scanned. Subtree union here would
// make every ancestor (up to pid 1) report every descendant. It also annotates
// regions with smaps Anonymous sizes so detector.TextCache can reuse digests.
func CollectInScan(pid int, tab *procfs.ProcTable, withMem bool) (*detector.Target, error) {
	st, err := procfs.ReadStatus(pid)
	if err != nil {
		return nil, err
	}
	regions, err := procfs.ReadMaps(pid)
	if err != nil {
		return nil, err
	}
	if withMem {
		// smaps is only needed for the .text digest cache, i.e. when memory is read.
		if anon, err := procfs.ReadSmapsAnon(pid); err == nil {
			procfs.AnnotateAnon(regions, anon) // on error regions stay "unknown": no cache reuse
		}
	}
	fds, _ := procfs.ReadFDs(pid)
	socks, _ := procfs.ReadSockets(pid)
	return assemble(pid, st, regions, tab.ChildrenOf(pid), fds, socks, withMem, nil)
}

// assemble builds the Target from already-read procfs state and, when withMem is
// set, opens /proc/<pid>/mem (see Collect for the error contract).
func assemble(pid int, st procfs.Status, regions []procfs.Region, kids []procfs.Child,
	fds []procfs.FD, socks []procfs.Socket, withMem bool, baseline *model.Snapshot) (*detector.Target, error) {
	desc := model.TargetDesc{
		PID:  pid,
		Name: st.Name,
		UID:  st.UID,
		GID:  st.GID,
	}
	desc.Exe, _ = procfs.Exe(pid)
	desc.Cmdline, _ = procfs.Cmdline(pid)
	if procfs.IsAppProcess(desc.Exe) {
		desc.AppInstall = procfs.AppInstall(pid, st.UID, desc.Cmdline, regions)
	}
	if hc := shimHealthcheck(desc); hc.Cmdline != "" {
		for i := range kids {
			if healthcheckChild(hc, kids[i]) {
				kids[i].Expected = "Docker healthcheck of container " + container.ShimContainerID(desc.Cmdline)[:12]
			}
		}
	}
	if IsCron(desc.Exe) {
		for i := range kids {
			if src := CronJob(pid, kids[i].Cmdline); src != "" {
				kids[i].Expected = "cron job from " + src
			}
		}
	}
	if isSystemd(pid, desc.Exe) {
		for i := range kids {
			if unit := systemdUnitChild(pid, kids[i]); unit != "" {
				kids[i].Expected = "systemd unit " + unit
			}
		}
	}
	for i := range kids {
		k := &kids[i]
		if k.Exe != "" {
			// A running child is judged by its running image; otherwise (exited,
			// or not readable without root) by the file at its path in the
			// parent's mount namespace. Both require root-owned, root-only.
			k.Trusted = procfs.TrustedExe(k.PID) || procfs.TrustedPath(pid, k.Exe)
		}
		k.Sibling = k.Trusted && siblingCandidate(desc.Exe, k.Exe)
		if k.Trusted && k.Expected == "" {
			if script := packagedScript(pid, desc.Exe, *k); script != "" {
				k.Expected = "packaged script " + script + " (root-only, under the parent's program directory)"
			}
		}
	}
	if start, err := procfs.StartTime(pid); err == nil {
		desc.StartsAt = start.Unix()
		procfs.AnnotateReplaced(pid, regions, start)
	}
	procfs.AnnotateBrk(pid, regions)
	if desc.Exe != "" {
		// Read the build-id of the binary the process is actually running, via
		// /proc/<pid>/exe: it opens the mapped inode even after a package upgrade
		// has deleted or replaced the file at the path (the path would give the
		// NEW version's build-id, or nothing). Fall back to the path.
		var err error
		desc.BuildID, err = elfref.BuildID(procfs.ExeLink(pid))
		if err != nil {
			exePath := procfs.TrimDeleted(desc.Exe)
			if hp, ok := procfs.ResolveBackingPath(pid, exePath); ok {
				exePath = hp
			}
			desc.BuildID, _ = elfref.BuildID(exePath)
		}
	}

	tgt := &detector.Target{
		Desc:     desc,
		Regions:  regions,
		FDs:      fds,
		Sockets:  socks,
		Children: kids,
		Baseline: baseline,
	}
	if withMem {
		// Opening /proc/<pid>/mem needs CAP_SYS_PTRACE (Yama). If it fails we
		// return the target WITHOUT a mem handle plus the error, so the caller can
		// decide: run the memory-free detectors in a degraded check, or treat it as
		// fatal for snapshot (which must digest module .text).
		mem, err := procfs.OpenMem(pid)
		if err != nil {
			return tgt, err
		}
		tgt.Mem = mem
	}
	return tgt, nil
}

// BuildSnapshot distills a known-good Snapshot from a collected Target: region
// shapes, module digests (with on-disk masked .text sha256), and allow-lists
// derived from the current (assumed-clean) state.
func BuildSnapshot(t *detector.Target) (*model.Snapshot, error) {
	return BuildSnapshotCached(t, nil)
}

// BuildSnapshotCached is BuildSnapshot sharing one sweep's caches across processes
// (see SweepCache); a nil cache opens, digests and reads every module afresh.
func BuildSnapshotCached(t *detector.Target, cache *SweepCache) (*model.Snapshot, error) {
	s := &model.Snapshot{
		SchemaVersion: model.CurrentSchemaVersion,
		ToolVersion:   version.Full(),
		CreatedAt:     time.Now(),
		Target:        t.Desc,
	}
	s.Target.Cmdline = redact.Text(s.Target.Cmdline) // a snapshot file is shown and shared too

	// A nil *procfs.Mem stored in the MemReader interface would NOT compare equal
	// to nil (typed-nil interface) and would be read through; convert explicitly.
	var mem detector.MemReader
	if t.Mem != nil {
		mem = t.Mem
	}
	seen := map[string]bool{}
	for _, r := range t.Regions {
		s.Regions = append(s.Regions, model.RegionShape{
			Perm:       model.PermClass(r.Perms()),
			Backing:    backingLabel(r),
			Exec:       r.Exec,
			FileBacked: r.FileBacked(),
		})
		if r.Exec && r.FileBacked() && !seen[r.Path] {
			seen[r.Path] = true
			if md, err := moduleDigest(t.Desc.PID, r, mem, cache); err == nil {
				s.Modules = append(s.Modules, md)
			}
		}
	}
	for _, c := range t.Children {
		// A child whose exe could not be read (exited/zombie, or another user's)
		// says nothing about what is expected; an empty rule would allow every
		// future child with an unreadable exe, e.g. an exploit's shell.
		if c.Exe == "" {
			continue
		}
		s.Children = append(s.Children, model.ChildRule{Exe: c.Exe})
	}
	// Sockets/FDs allow-lists are intentionally left for the operator to curate in
	// policy; capturing the live set as "allowed" risks baking in an active C2.
	return s, nil
}

// ModuleDigests digests the modules at paths as t maps them now (the same
// record BuildSnapshot keeps), e.g. to replace a baseline's entry after a
// package upgrade. Paths t does not map, or that cannot be read, are left out.
func ModuleDigests(t *detector.Target, paths []string, cache *SweepCache) []model.ModuleDigest {
	var mem detector.MemReader
	if t.Mem != nil {
		mem = t.Mem // see BuildSnapshotCached: no typed-nil interface
	}
	want := map[string]bool{}
	for _, p := range paths {
		want[p] = true
	}
	var out []model.ModuleDigest
	for _, r := range t.Regions {
		if !r.Exec || !r.FileBacked() || !want[r.Path] {
			continue
		}
		delete(want, r.Path)
		if md, err := moduleDigest(t.Desc.PID, r, mem, cache); err == nil {
			out = append(out, md)
		}
	}
	return out
}

// moduleDigest records a module's identity and TWO masked .text digests: the
// on-disk bytes and the in-memory bytes in this (known-good) process. It resolves
// the maps backing path (target's mount namespace) to a host path and skips non-ELF
// Android artifacts (.oat/.apk/...). The in-memory digest requires a mem handle;
// without one only the disk digest + build-id are recorded.
func moduleDigest(pid int, r procfs.Region, mem detector.MemReader, cache *SweepCache) (model.ModuleDigest, error) {
	if !procfs.IsELFCodeLib(r.Path) {
		return model.ModuleDigest{}, errSkip
	}
	hostPath, ok := procfs.ResolveBackingPath(pid, r.Path)
	if !ok {
		return model.ModuleDigest{}, errSkip
	}
	mod, err := cache.OpenModule(hostPath, r)
	if err != nil {
		return model.ModuleDigest{}, err
	}
	md := model.ModuleDigest{
		Path:     r.Path,
		BuildID:  mod.BuildID,
		TextSize: int64(mod.TextSize),
	}
	if cache == nil || cache.DiskDigests {
		md.DiskTextSHA = cache.diskDigest(hostPath, r, mod)
	}
	if mem != nil && cache != nil {
		md.MemTextSHA, _ = cache.textCache().Digest(mem, r, mod, nil)
	} else if mem != nil {
		sum, reason, ok := detector.MemTextDigestDebug(mem, r, mod, nil)
		if ok {
			md.MemTextSHA = sum
		} else if debugEnabled() {
			fmt.Fprintf(os.Stderr, "cenziadah: no mem digest for %s (.text %d): %s\n", r.Path, mod.TextSize, reason)
		}
	}
	return md, nil
}

// debugEnabled reports whether CENZIADAH_DEBUG is set to a truthy value, enabling
// per-module diagnostic output on stderr.
func debugEnabled() bool {
	v := os.Getenv("CENZIADAH_DEBUG")
	return v != "" && v != "0" && v != "false"
}

// diskTextDigest computes the masked on-disk .text sha256 for a module.
func diskTextDigest(mod *elfref.Module) string {
	f, err := mod.RawReaderAt()
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	var done uint64
	for done < mod.TextSize {
		n := uint64(len(buf))
		if rem := mod.TextSize - done; rem < n {
			n = rem
		}
		if _, err := f.ReadAt(buf[:n], int64(mod.TextOff+done)); err != nil && err != io.EOF {
			return ""
		}
		mod.MaskChunk(buf[:n], done)
		h.Write(buf[:n])
		done += n
	}
	return hex.EncodeToString(h.Sum(nil))
}

// backingLabel mirrors detector.backingLabel for snapshot shape keys.
func backingLabel(r procfs.Region) string {
	if r.NotBrkHeap {
		return "[anon]" // see procfs.AnnotateBrk
	}
	if r.Deleted {
		if r.Path != "" {
			return r.Path + " (deleted)"
		}
		return "(deleted)"
	}
	if r.Path == "" {
		return "[anon]"
	}
	return r.Path
}

// TerminalShell reports whether pid has the SHAPE of an interactive terminal
// shell: a shell executable with a controlling terminal. Shape alone proves
// nothing (an attacker's pty-upgraded reverse shell has it too); the
// all-process scanner additionally requires the shell to be legitimate before
// setting detector.Target.InteractiveShell.
func TerminalShell(pid int, exe string) bool {
	return isShell(exe) && procfs.HasControllingTTY(pid)
}

func isShell(exe string) bool { return procfs.IsShell(exe) }

// dockerRoot is Docker's data root, read once from /etc/docker/daemon.json.
var dockerRoot = sync.OnceValue(func() string { return container.DockerRoot("/etc/docker/daemon.json") })

// shimHealthcheck returns, for a containerd shim, the exact command line of the
// healthcheck Docker runs in its container ("" otherwise). Docker execs the
// healthcheck through the shim periodically, so it is the shim's child; it is
// read from Docker's root-owned state, which nothing inside a container can
// write. Any other child of a shim (e.g. `docker exec`) is not covered.
func shimHealthcheck(desc model.TargetDesc) container.Healthcheck {
	if !strings.HasPrefix(path.Base(procfs.TrimDeleted(desc.Exe)), "containerd-shim") {
		return container.Healthcheck{}
	}
	id := container.ShimContainerID(desc.Cmdline)
	if id == "" {
		return container.Healthcheck{}
	}
	hc, _ := container.HealthcheckOf(dockerRoot(), id)
	return hc
}

// healthcheckChild matches a shim's child against its container's healthcheck:
// by exact command line, or, for a child that already exited and whose command
// line could no longer be read (seen in production: `wget ... cmd=""`), by its
// program: the healthcheck's program name (CMD form) or a shell (CMD-SHELL).
func healthcheckChild(hc container.Healthcheck, c procfs.Child) bool {
	if c.Cmdline != "" {
		return c.Cmdline == hc.Cmdline
	}
	if !c.Exited || c.Exe == "" {
		return false
	}
	if hc.Program == "" {
		return procfs.IsShell(c.Exe)
	}
	return path.Base(procfs.TrimDeleted(c.Exe)) == hc.Program
}

func isSystemd(pid int, exe string) bool {
	return pid == 1 || path.Base(procfs.TrimDeleted(exe)) == "systemd"
}

// loadUnit reads a system unit as systemd process sysPID sees its filesystem.
var loadUnit = func(sysPID int, name string) (systemd.Unit, bool) {
	root := "/proc/" + strconv.Itoa(sysPID) + "/root"
	if _, err := os.Stat(root + "/etc"); err != nil {
		root = "/"
	}
	return systemd.Load(root, name, nil)
}

// unitOf is the system service a process belongs to (procfs.SystemUnit).
var unitOf = procfs.SystemUnit

// systemdUnitChild returns the unit name if child c of systemd is one of the
// commands its unit (from the child's cgroup, set by systemd) is configured to
// run, e.g. apt-daily.service's `/bin/sh /usr/lib/apt/apt.systemd.daily update`.
// An orphan re-parented to PID 1 keeps its original cgroup and will not match
// that unit's Exec lines.
func systemdUnitChild(sysPID int, c procfs.Child) string {
	if c.Exited || c.Cmdline == "" {
		return ""
	}
	name := unitOf(c.PID)
	if name == "" {
		return ""
	}
	u, ok := loadUnit(sysPID, name)
	if !ok || !u.Matches(c.Cmdline, procfs.IsShell(c.Exe) || procfs.IsInterpreter(c.Exe)) {
		return ""
	}
	return name
}

// OneshotUnit returns the system unit pid runs in if that unit is Type=oneshot
// (a batch job such as apt-daily.service), else "". Everything in a one-shot
// unit's cgroup is that job's work; long-running services do not qualify, so a
// webshell's children inside apache2.service still alert.
func OneshotUnit(pid int) string {
	name := unitOf(pid)
	if name == "" {
		return ""
	}
	if u, ok := loadUnit(1, name); ok && u.Oneshot {
		return name
	}
	return ""
}

// IsCron reports whether exe is the cron daemon (Debian cron, cronie crond).
func IsCron(exe string) bool {
	switch path.Base(procfs.TrimDeleted(exe)) {
	case "cron", "crond":
		return true
	}
	return false
}

// cronJobs reads the root-owned cron jobs as the cron process cronPID sees its
// filesystem (its own mount namespace: cron may run in a container).
var cronJobs = func(cronPID int) map[string]cron.Job {
	root := "/proc/" + strconv.Itoa(cronPID) + "/root"
	if _, err := os.Stat(root + "/etc"); err != nil {
		root = "/" // its root is not readable (unprivileged run): host files
	}
	return cron.Jobs(root, nil)
}

// CronJob returns the crontab file that configures the shell command line
// childCmdline as a job of cron process cronPID, or "" if no root-owned
// crontab does. Only exact command lines match.
func CronJob(cronPID int, childCmdline string) string {
	if childCmdline == "" {
		return ""
	}
	if j, ok := cronJobs(cronPID)[childCmdline]; ok {
		return j.Source
	}
	return ""
}

// siblingCandidate is the path part of the sibling-program rule: the child's
// program sits in the same directory as the parent's, that directory is a
// DEDICATED one (not a shared system bin/lib dir, where "same directory" means
// nothing: /usr/bin holds every shell), and the child is not a shell or an
// interpreter (a venv puts python next to gunicorn; `python -c` is a reverse
// shell). The caller also requires the child's binary and directory to be
// root-only (procfs.TrustedExe), so a compromised service account cannot plant
// a "sibling".
func siblingCandidate(parentExe, childExe string) bool {
	if parentExe == "" || childExe == "" {
		return false
	}
	pdir := path.Dir(procfs.TrimDeleted(parentExe))
	cexe := procfs.TrimDeleted(childExe)
	if path.Dir(cexe) != pdir || sharedDirs[pdir] {
		return false
	}
	return !isShell(cexe) && !isInterpreter(cexe)
}

// packagedScript returns the script a shell child of parentPID runs when that
// script ships with the parent's own program: the command line is exactly
// `<shell> [-c] ["]<script>["] [args]`, the args are plain words (no shell
// syntax: no ; | & $ ` > < quotes or spaces inside), and the script lies in a
// root-only tree under the parent binary's DEDICATED directory (not a shared one
// like /usr/bin). Electron apps do this (VS Code runs
// resources/app/out/vs/base/node/cpuUsage.sh every 30s). Returns "" otherwise.
//
// The caller also requires the shell itself to be root-only (Child.Trusted),
// so a dropped binary merely named "sh" does not qualify. A compromised
// non-root parent cannot plant such a script, nor smuggle extra
// commands into the line; it can only run the package's own scripts with plain
// arguments.
func packagedScript(parentPID int, parentExe string, c procfs.Child) string {
	if parentExe == "" || c.Exe == "" || !isShell(c.Exe) {
		return ""
	}
	m := packagedScriptRE.FindStringSubmatch(c.Cmdline)
	if m == nil || m[1] != m[3] {
		return ""
	}
	pdir := path.Dir(procfs.TrimDeleted(parentExe))
	if sharedDirs[pdir] || !procfs.TrustedPathUnder(parentPID, pdir, m[2]) {
		return ""
	}
	return m[2]
}

// packagedScriptRE: shell, optional -c, optionally double-quoted absolute
// script path, plain-word arguments. Groups: open quote, path, close quote.
var packagedScriptRE = regexp.MustCompile(`^\S+ (?:-c )?("?)(/[A-Za-z0-9._/+-]+)("?)(?: [A-Za-z0-9._,=:+-]+)*$`)

// sharedDirs hold programs from many unrelated packages; the sibling rule never
// applies there.
var sharedDirs = map[string]bool{
	"/bin": true, "/sbin": true, "/usr/bin": true, "/usr/sbin": true,
	"/usr/local/bin": true, "/usr/local/sbin": true, "/usr/libexec": true,
	"/usr/lib": true, "/lib": true, "/usr/games": true, "/snap/bin": true,
	"/system/bin": true, "/system/xbin": true, "/vendor/bin": true, // Android/waydroid
}

func isInterpreter(exe string) bool { return procfs.IsInterpreter(exe) }
