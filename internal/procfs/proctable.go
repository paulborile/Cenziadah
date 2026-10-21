// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"sort"
	"strconv"
	"time"
)

// ProcEntry is one process in a ProcTable: the cheap identity facts needed to
// decide whether (and how) to scan it, read once per scan cycle.
type ProcEntry struct {
	PID       int
	PPID      int
	Name      string
	Exe       string // resolved /proc/<pid>/exe; empty for kernel threads or when unreadable
	Cmdline   string
	UID       int
	Zombie    bool      // already exited when the table was read
	StartedAt time.Time // zero if unknown
	Kernel    bool      // kernel thread: no user memory, nothing to inspect
}

// ProcTable is a point-in-time listing of every process, read in one /proc walk.
// An all-process scan builds it once per cycle and answers parent/child questions
// from it, instead of re-walking /proc for every process (which is O(N^2)).
type ProcTable struct {
	Entries  []ProcEntry // sorted by PID
	children map[int][]int
	byPID    map[int]int // pid -> index in Entries
}

// ReadProcTable walks /proc once. Best-effort: processes that exit or are
// unreadable mid-walk are left out, never fatal.
func ReadProcTable() (*ProcTable, error) {
	dirents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var entries []ProcEntry
	for _, d := range dirents {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue // not a pid dir
		}
		st, err := ReadStatus(pid)
		if err != nil {
			continue // race: exited
		}
		e := ProcEntry{
			PID:    pid,
			PPID:   st.PPID,
			Name:   st.Name,
			UID:    st.UID,
			Kernel: st.Kthread || pid == kthreaddPID || st.PPID == kthreaddPID,
		}
		if !e.Kernel {
			e.Exe, _ = Exe(pid) // may fail (permissions, zombie); leave empty
		}
		e.StartedAt, _ = StartTime(pid)
		e.Zombie = st.Zombie
		if !e.Kernel {
			e.Cmdline, _ = Cmdline(pid)
		}
		entries = append(entries, e)
	}
	return NewProcTable(entries), nil
}

// kthreaddPID is the kernel thread daemon; every kernel thread is its child.
const kthreaddPID = 2

// NewProcTable indexes entries. It is exported so tests (and callers holding a
// synthetic listing) can build a table without /proc.
func NewProcTable(entries []ProcEntry) *ProcTable {
	sort.Slice(entries, func(i, j int) bool { return entries[i].PID < entries[j].PID })
	t := &ProcTable{Entries: entries, children: make(map[int][]int), byPID: make(map[int]int)}
	for i, e := range entries {
		t.children[e.PPID] = append(t.children[e.PPID], e.PID)
		t.byPID[e.PID] = i
	}
	return t
}

// Entry returns the table entry for pid.
func (t *ProcTable) Entry(pid int) (ProcEntry, bool) {
	i, ok := t.byPID[pid]
	if !ok {
		return ProcEntry{}, false
	}
	return t.Entries[i], true
}

// ChildrenOf returns the direct children of pid. Exe and cmdline are read live;
// a short-lived child (a postfix worker, a one-shot command) has often exited
// by the time its parent is inspected later in the sweep, so the values captured
// when the table was read are used instead. Exited is set when the child is gone
// or a zombie: then even an empty exe is "could not be identified", not "hidden".
func (t *ProcTable) ChildrenOf(pid int) []Child {
	var kids []Child
	for _, cpid := range t.children[pid] {
		e := t.Entries[t.byPID[cpid]]
		c := Child{PID: cpid, Name: e.Name, StartedAt: e.StartedAt}
		var err error
		c.Exe, err = Exe(cpid)
		gone := err != nil && os.IsNotExist(err)
		if c.Exe == "" {
			c.Exe = e.Exe
		}
		if c.Cmdline, _ = Cmdline(cpid); c.Cmdline == "" {
			c.Cmdline = e.Cmdline
		}
		if !gone {
			if st, err := ReadStatus(cpid); err != nil {
				gone = os.IsNotExist(err)
			} else if st.Zombie {
				gone = true
			}
		}
		c.Exited = gone || e.Zombie
		kids = append(kids, c)
	}
	return kids
}
