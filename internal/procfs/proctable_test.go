// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const smapsFixture = `55d0c0a00000-55d0c0a28000 r--p 00000000 08:01 1234   /usr/bin/bash
Size:                160 kB
Anonymous:             0 kB
VmFlags: rd mr mw me sd
55d0c0a28000-55d0c0b07000 r-xp 00028000 08:01 1234   /usr/bin/bash
Size:                892 kB
Anonymous:             4 kB
VmFlags: rd ex mr mw me sd
7f0000000000-7f0000021000 rw-p 00000000 00:00 0
Size:                132 kB
Anonymous:           132 kB
`

func TestParseSmapsAnon(t *testing.T) {
	got, err := parseSmapsAnon(strings.NewReader(smapsFixture))
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint64]uint64{0x55d0c0a00000: 0, 0x55d0c0a28000: 4, 0x7f0000000000: 132}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(got), len(want), got)
	}
	for start, kb := range want {
		if got[start] != kb {
			t.Errorf("start %#x: anon %d kB, want %d", start, got[start], kb)
		}
	}
}

func TestAnnotateAnonUnknownStaysUnknown(t *testing.T) {
	regions := []Region{{Start: 0x1000}, {Start: 0x2000}}
	AnnotateAnon(regions, map[uint64]uint64{0x1000: 0})
	if !regions[0].AnonKnown || regions[0].AnonKB != 0 {
		t.Errorf("region 0 should be known-clean: %+v", regions[0])
	}
	if regions[1].AnonKnown {
		t.Errorf("region without smaps entry must stay unknown: %+v", regions[1])
	}
}

func TestProcTableChildrenOf(t *testing.T) {
	tab := NewProcTable([]ProcEntry{
		{PID: 30, PPID: 10},
		{PID: 10, PPID: 1},
		{PID: 20, PPID: 10},
		{PID: 40, PPID: 30}, // grandchild of 10: must NOT be a direct child
	})
	if tab.Entries[0].PID != 10 {
		t.Errorf("entries not sorted by pid: %+v", tab.Entries)
	}
	kids := tab.ChildrenOf(10)
	if len(kids) != 2 {
		t.Fatalf("ChildrenOf(10) = %+v, want pids 20 and 30", kids)
	}
	for _, k := range kids {
		if k.PID != 20 && k.PID != 30 {
			t.Errorf("unexpected child %d", k.PID)
		}
	}
}

func TestReadProcTableContainsSelf(t *testing.T) {
	tab, err := ReadProcTable()
	if err != nil {
		t.Fatal(err)
	}
	self := os.Getpid()
	for _, e := range tab.Entries {
		if e.PID == self {
			if e.Kernel || e.Exe == "" || e.StartedAt.IsZero() {
				t.Errorf("self entry incomplete: %+v", e)
			}
			return
		}
	}
	t.Fatalf("pid %d not in process table", self)
}

func TestParseHasTTY(t *testing.T) {
	const terminal = "1104757 (bash) S 982957 1104757 1104757 34829 1104757 4194560 0 0"
	const script = "3825565 (bash) S 3600671 3825565 3825565 0 -1 4194560 0 0"
	const odd = "42 (a ) b) S 1 42 42 34829 42 0" // comm with spaces and ')'
	if !parseHasTTY(terminal) || !parseHasTTY(odd) {
		t.Error("terminal shell not recognised")
	}
	if parseHasTTY(script) {
		t.Error("process without a terminal must not count")
	}
}

func TestProcTableEntry(t *testing.T) {
	tab := NewProcTable([]ProcEntry{{PID: 7, PPID: 1, Name: "x"}})
	if e, ok := tab.Entry(7); !ok || e.Name != "x" {
		t.Errorf("Entry(7) = %+v, %v", e, ok)
	}
	if _, ok := tab.Entry(8); ok {
		t.Error("Entry(8) should be missing")
	}
}

// A short-lived child exits between the table read and its parent's inspection:
// the exe/cmdline captured in the table are used, and it is marked Exited.
func TestChildrenOfFallsBackToTable(t *testing.T) {
	const gone = 4194000 // above the default pid_max range in use: never a live pid here
	if _, err := os.Stat("/proc/" + strconv.Itoa(gone)); err == nil {
		t.Skip("pid unexpectedly exists")
	}
	tab := NewProcTable([]ProcEntry{
		{PID: 10, PPID: 1},
		{PID: gone, PPID: 10, Exe: "/usr/lib/postfix/sbin/smtpd", Cmdline: "smtpd -n smtp -t inet"},
	})
	kids := tab.ChildrenOf(10)
	if len(kids) != 1 || kids[0].Exe != "/usr/lib/postfix/sbin/smtpd" || kids[0].Cmdline == "" || !kids[0].Exited {
		t.Fatalf("child = %+v, want table exe/cmdline and Exited", kids)
	}
}

func TestChildrenOfMarksZombie(t *testing.T) {
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Wait() // reap at the end: until then it is a zombie
	time.Sleep(200 * time.Millisecond)
	tab, err := ReadProcTable()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tab.ChildrenOf(os.Getpid()) {
		if c.PID == cmd.Process.Pid {
			if !c.Exited {
				t.Errorf("zombie child not marked Exited: %+v", c)
			}
			return
		}
	}
	t.Fatal("zombie child not listed")
}

func TestIsShellAndInterpreter(t *testing.T) {
	for name, want := range map[string]bool{"sh": true, "/usr/bin/bash (deleted)": true, "python3.12": true,
		"perl": true, "smtpd": false, "nodeworker": false, "": false} {
		if got := IsShell(name) || IsInterpreter(name); got != want {
			t.Errorf("%q: %v, want %v", name, got, want)
		}
	}
}

func TestIsRiskyProgram(t *testing.T) {
	for name, want := range map[string]bool{"/usr/bin/curl": true, "wget": true, "/usr/bin/dash": true,
		"python3": true, "/usr/bin/ssh": true, "/usr/lib/postfix/sbin/tlsmgr": false, "sha512sum": false} {
		if got := IsRiskyProgram(name); got != want {
			t.Errorf("IsRiskyProgram(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParseSystemUnit(t *testing.T) {
	for in, want := range map[string]string{
		"0::/system.slice/apt-daily.service\n":                               "apt-daily.service",
		"0::/system.slice/docker.service/payload\n":                          "docker.service",
		"0::/init.scope\n":                                                   "",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope": "",
		"12:pids:/\n1:name=systemd:/system.slice/cron.service\n0::/\n":       "",
		"12:pids:/\n1:name=systemd:/system.slice/cron.service\n":             "cron.service",
	} {
		if got := parseSystemUnit(strings.NewReader(in)); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
