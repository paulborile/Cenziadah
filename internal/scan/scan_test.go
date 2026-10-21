// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package scan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/paulborile/cenziadah/internal/detector"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

var now = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// jitRegion is an anonymous rwx mapping, the classic JIT (and injection) shape.
var jitRegion = procfs.Region{Start: 0x7f0000000000, End: 0x7f0000010000, Read: true, Write: true, Exec: true, Private: true}

// fakeHost is a synthetic process table plus per-pid collect behaviour.
type fakeHost struct {
	shells   map[int]bool      // pids with the terminal-shell shape
	cronJobs map[string]string // root-owned cron job command lines -> source
	oneshot  map[int]string    // pid -> its Type=oneshot systemd unit
	apps     map[int]string    // pid -> Android app install dir
	entries  []procfs.ProcEntry
	targets  map[int]*detector.Target
	errs     map[int]error
	collects []int
}

func (h *fakeHost) scanner(opts Options) *Scanner {
	s := New(opts)
	s.readTable = func() (*procfs.ProcTable, error) { return procfs.NewProcTable(h.entries), nil }
	s.collect = func(pid int, _ *procfs.ProcTable, _ bool) (*detector.Target, error) {
		h.collects = append(h.collects, pid)
		return h.targets[pid], h.errs[pid]
	}
	s.now = func() time.Time { return now }
	s.selfPID = 999
	s.buildID = func(int) string { return "b1" }
	s.terminalShell = func(pid int, _ string) bool { return h.shells[pid] }
	s.cronJob = func(_ int, cmd string) string { return h.cronJobs[cmd] }
	s.oneshotUnit = func(pid int) string { return h.oneshot[pid] }
	s.appInstall = func(pid int) string { return h.apps[pid] }
	return s
}

func proc(pid int, exe string) procfs.ProcEntry {
	return procfs.ProcEntry{PID: pid, PPID: 1, Name: fmt.Sprintf("p%d", pid), Exe: exe, StartedAt: now.Add(-time.Hour)}
}

func target(pid int, exe string, regions ...procfs.Region) *detector.Target {
	return &detector.Target{Desc: model.TargetDesc{PID: pid, Name: fmt.Sprintf("p%d", pid), Exe: exe, BuildID: "b1"}, Regions: regions}
}

func skippedReason(res Result, pid int) string {
	for _, s := range res.Skipped {
		if s.PID == pid {
			return s.Reason
		}
	}
	return ""
}

func TestScanFiltersBeforeCollecting(t *testing.T) {
	young := proc(30, "/usr/bin/new")
	young.StartedAt = now.Add(-time.Second)
	h := &fakeHost{
		entries: []procfs.ProcEntry{
			{PID: 2, Name: "kthreadd", Kernel: true},
			proc(999, "/usr/bin/cenziadah"),
			young,
			proc(40, "/opt/noisy-jit"),
			proc(50, "/usr/bin/bash"),
		},
		targets: map[int]*detector.Target{50: target(50, "/usr/bin/bash")},
	}
	res, err := h.scanner(Options{MinAge: 10 * time.Second, SkipExe: map[string]string{"/opt/noisy-jit": "accepted JIT"}}).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]string{2: ReasonKernel, 999: ReasonSelf, 30: ReasonTooYoung, 40: ReasonPolicy + "accepted JIT"}
	for pid, reason := range want {
		if got := skippedReason(res, pid); got != reason {
			t.Errorf("pid %d skip reason = %q, want %q", pid, got, reason)
		}
	}
	if len(h.collects) != 1 || h.collects[0] != 50 {
		t.Errorf("only pid 50 should be collected, collected %v", h.collects)
	}
	if res.Stats.Candidates != 5 || res.Stats.Scanned != 1 {
		t.Errorf("stats = %+v", res.Stats)
	}
}

func TestScanSurvivesVanishedAndUnreadableProcesses(t *testing.T) {
	h := &fakeHost{
		entries: []procfs.ProcEntry{proc(10, "/a"), proc(20, "/b"), proc(30, "/c"), proc(40, "/d")},
		targets: map[int]*detector.Target{10: target(10, "/a"), 40: target(40, "/d")},
		errs: map[int]error{
			20: fmt.Errorf("read maps: %w", fs.ErrNotExist),
			30: &os.PathError{Op: "open", Path: "/proc/30/maps", Err: fs.ErrPermission},
		},
	}
	res, err := h.scanner(Options{}).Scan(context.Background())
	if err != nil {
		t.Fatalf("one bad pid must not fail the sweep: %v", err)
	}
	if got := skippedReason(res, 20); got != ReasonExited {
		t.Errorf("vanished pid reason = %q", got)
	}
	if got := skippedReason(res, 30); got != ReasonPermission {
		t.Errorf("unreadable pid reason = %q", got)
	}
	if len(res.Reports) != 2 || res.Reports[0].Target.PID != 10 || res.Reports[1].Target.PID != 40 {
		t.Errorf("reports should be pids 10 and 40 in order, got %+v", res.Reports)
	}
}

func TestScanDegradedWithoutMemAccess(t *testing.T) {
	h := &fakeHost{
		entries: []procfs.ProcEntry{proc(10, "/a")},
		targets: map[int]*detector.Target{10: target(10, "/a")}, // Mem nil
		errs:    map[int]error{10: &os.PathError{Op: "open", Path: "/proc/10/mem", Err: fs.ErrPermission}},
	}
	res, _ := h.scanner(Options{WithMem: true}).Scan(context.Background())
	if len(res.Reports) != 1 || res.Reports[0].Degraded == "" {
		t.Fatalf("expected one degraded report, got %+v skipped=%+v", res.Reports, res.Skipped)
	}
}

type mapBaselines map[string]*model.Snapshot

func (m mapBaselines) Lookup(id string) *model.Snapshot { return m[id] }

// The point of baseline-diff over K-Scanner-style RWX flagging: a JIT region that
// was present in the known-good baseline is suppressed; the same region in a
// process WITHOUT a baseline stays active.
func TestScanBaselineSuppressesKnownJIT(t *testing.T) {
	h := &fakeHost{
		entries: []procfs.ProcEntry{proc(10, "/usr/bin/gjs"), proc(20, "/usr/bin/unknown")},
		targets: map[int]*detector.Target{
			10: target(10, "/usr/bin/gjs", jitRegion),
			20: target(20, "/usr/bin/unknown", jitRegion),
		},
	}
	base := mapBaselines{
		"/usr/bin/gjs@b1#p10": {Regions: []model.RegionShape{{Perm: model.PermRWX, Backing: "[anon]", Exec: true}}},
	}
	res, _ := h.scanner(Options{Baselines: base}).Scan(context.Background())
	if len(res.Reports) != 2 {
		t.Fatalf("want 2 reports, got %d", len(res.Reports))
	}
	if n := len(res.Reports[0].Active()); n != 0 {
		t.Errorf("baselined JIT should be suppressed, got %d active: %+v", n, res.Reports[0].Findings)
	}
	if res.Reports[1].MaxSeverity() != model.SevCritical {
		t.Errorf("un-baselined rwx should be CRITICAL, got %v", res.Reports[1].MaxSeverity())
	}
}

func TestIdentity(t *testing.T) {
	if got := Identity(model.TargetDesc{Exe: "/usr/bin/bash", BuildID: "abc", Name: "bash"}); got != "/usr/bin/bash@abc#bash" {
		t.Errorf("Identity = %q", got)
	}
	if got := Identity(model.TargetDesc{Exe: "/usr/bin/bash", Name: "bash"}); got != "/usr/bin/bash#bash" {
		t.Errorf("Identity without build-id = %q", got)
	}
	app := model.TargetDesc{Exe: "/system/bin/app_process64", BuildID: "x"}
	wa, other := app, app
	wa.Name, other.Name = "com.whatsapp", "com.android.chrome"
	if Identity(wa) == Identity(other) {
		t.Error("Android apps sharing app_process64 must get distinct identities")
	}
	v1, v2 := wa, wa
	v1.AppInstall, v2.AppInstall = "/data/app/~~a==/com.whatsapp-1==", "/data/app/~~b==/com.whatsapp-2=="
	if Identity(v1) == Identity(v2) || Identity(v1) == Identity(wa) {
		t.Error("an app update (new install dir) must be a new identity")
	}
}

func TestScanTableErrorFailsSweep(t *testing.T) {
	s := New(Options{})
	s.readTable = func() (*procfs.ProcTable, error) { return nil, errors.New("no /proc") }
	if _, err := s.Scan(context.Background()); err == nil {
		t.Error("unreadable /proc must fail the sweep")
	}
}

// TestScanLiveHost runs a real sweep over this machine's /proc, as an
// unprivileged user: it must complete, scan at least this test's own process
// family, and never error just because other users' processes are unreadable.
func TestScanLiveHost(t *testing.T) {
	res, err := New(Options{IncludeSelf: true}).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Scanned == 0 {
		t.Fatalf("live sweep scanned nothing: %+v", res.Stats)
	}
	if res.FinishedAt.Before(res.StartedAt) {
		t.Error("finish before start")
	}
}

func TestScanStopsWhenCancelled(t *testing.T) {
	h := &fakeHost{
		entries: []procfs.ProcEntry{proc(10, "/a"), proc(20, "/b")},
		targets: map[int]*detector.Target{10: target(10, "/a"), 20: target(20, "/b")},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.scanner(Options{}).Scan(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(h.collects) != 0 {
		t.Errorf("cancelled sweep still collected %v", h.collects)
	}
}

func TestSkipSummary(t *testing.T) {
	r := Result{Skipped: []Skipped{
		{Reason: ReasonKernel}, {Reason: ReasonPermission}, {Reason: ReasonPermission},
		{Reason: ReasonPolicy + "noisy"}, {Reason: ReasonPolicy + "other"},
	}}
	want := "2 permission denied, 2 policy, 1 kernel thread"
	if got := r.SkipSummary(); got != want {
		t.Errorf("SkipSummary = %q, want %q", got, want)
	}
}
