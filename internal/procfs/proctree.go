// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"strconv"
	"time"
)

// Child is a process whose parent is the target.
type Child struct {
	PID       int
	Name      string // comm; still readable for a zombie whose exe is gone
	Exe       string
	Cmdline   string
	StartedAt time.Time // zero if unknown
	// PreExisting: this exact process (pid + start time) was already running
	// when the baseline was learned. Set by the all-process scanner.
	PreExisting bool
	// Sibling: the child runs a program installed next to the parent's own
	// binary, in a dedicated root-only directory (a service suite such as
	// postfix: master -> tlsmgr, smtpd, cleanup). Set by the engine.
	Sibling bool
	// Exited: the child had exited (or was a zombie) when inspected; its exe and
	// cmdline may come from the sweep's process table, or be unknown.
	Exited bool
	// Expected, when set, says which runtime configuration starts exactly this
	// child (e.g. a container's Docker healthcheck). Set by the engine.
	Expected string
	// Trusted: the child's program is package-installed (binary and directory
	// root-owned, not group/world-writable; see TrustedExe / TrustedPath). Set
	// by the engine. A compromised service account cannot create such a file.
	Trusted bool
}

// Children returns the direct child processes of parentPID by scanning /proc for
// any process whose PPid matches. Best-effort: processes that vanish or are
// unreadable during the scan are skipped.
func Children(parentPID int) ([]Child, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var kids []Child
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid dir
		}
		st, err := ReadStatus(pid)
		if err != nil {
			continue // race: process exited
		}
		if st.PPID != parentPID {
			continue
		}
		c := Child{PID: pid}
		c.Exe, _ = Exe(pid)         // may fail for kernel/zombie; leave empty
		c.Cmdline, _ = Cmdline(pid) // best-effort
		kids = append(kids, c)
	}
	return kids, nil
}

// Descendants returns every process in the subtree rooted at parentPID (children,
// grandchildren, ...), excluding parentPID itself. Forking servers (nginx, Apache
// prefork, smbd) handle requests in child workers, so a post-exploitation shell is
// typically a grandchild of the master; subtree walking is required to see it.
func Descendants(parentPID int) ([]Child, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	// Build pid -> ppid and pid set in one pass.
	ppidOf := make(map[int]int)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		st, err := ReadStatus(pid)
		if err != nil {
			continue // race: exited
		}
		ppidOf[pid] = st.PPID
	}
	// A pid is in the subtree if walking up ppids reaches parentPID.
	inSubtree := func(pid int) bool {
		for steps := 0; steps < 1024; steps++ { // bound against cycles
			pp, ok := ppidOf[pid]
			if !ok || pp == 0 {
				return false
			}
			if pp == parentPID {
				return true
			}
			pid = pp
		}
		return false
	}
	var out []Child
	for pid := range ppidOf {
		if pid == parentPID || !inSubtree(pid) {
			continue
		}
		c := Child{PID: pid}
		c.Exe, _ = Exe(pid)
		c.Cmdline, _ = Cmdline(pid)
		out = append(out, c)
	}
	return out, nil
}
