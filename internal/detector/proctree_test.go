// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"strings"
	"testing"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

func TestProcTreeUnexpectedChild(t *testing.T) {
	base := &model.Snapshot{Children: []model.ChildRule{{Exe: "/usr/bin/helper"}}}
	target := &Target{
		Desc:     model.TargetDesc{PID: 100},
		Baseline: base,
		Children: []procfs.Child{
			{PID: 101, Exe: "/usr/bin/helper", Cmdline: "helper"}, // allowed
			{PID: 102, Exe: "/bin/sh", Cmdline: "/bin/sh -c id"},  // unexpected
		},
	}
	fs, _ := ProcTree{}.Inspect(target)
	act := activeByTech(fs)
	f, ok := act[model.TechUnexpectedChild]
	if !ok {
		t.Fatal("expected unexpected-child finding")
	}
	if f.Evidence["exe"] != "/bin/sh" {
		t.Errorf("flagged wrong child: %v", f.Evidence["exe"])
	}
	// The allow-listed child must be suppressed, not active.
	suppressed := 0
	for _, x := range fs {
		if x.Suppressed {
			suppressed++
		}
	}
	if suppressed != 1 {
		t.Errorf("expected 1 suppressed child, got %d", suppressed)
	}
}

func TestInteractiveShellChildrenSuppressed(t *testing.T) {
	tgt := &Target{
		InteractiveShell: true,
		Baseline:         &model.Snapshot{},
		Children:         []procfs.Child{{PID: 9, Exe: "/usr/bin/top"}},
	}
	fs, _ := ProcTree{}.Inspect(tgt)
	if len(fs) != 1 || !fs[0].Suppressed || fs[0].SuppressReason == "" {
		t.Fatalf("a typed command must be recorded as suppressed with a reason: %+v", fs)
	}
	tgt.InteractiveShell = false // the same child under a non-interactive process alerts
	fs, _ = ProcTree{}.Inspect(tgt)
	if fs[0].Suppressed || fs[0].Severity != model.SevHigh {
		t.Errorf("non-interactive parent must alert HIGH: %+v", fs[0])
	}
}

func TestSiblingChildSuppressed(t *testing.T) {
	tgt := &Target{
		Baseline: &model.Snapshot{},
		Children: []procfs.Child{
			{PID: 9, Exe: "/usr/lib/postfix/sbin/tlsmgr", Sibling: true},
			{PID: 10, Exe: "/bin/sh"},
		},
	}
	fs, _ := ProcTree{}.Inspect(tgt)
	if len(fs) != 2 || !fs[0].Suppressed || fs[1].Suppressed || fs[1].Severity != model.SevHigh {
		t.Fatalf("sibling must be suppressed and the shell must alert HIGH: %+v", fs)
	}
}

// An exited child whose exe could not be read at all carries no evidence: INFO.
// An ALIVE child with a hidden exe still alerts HIGH.
func TestUnidentifiableExitedChildIsInfo(t *testing.T) {
	tgt := &Target{Baseline: &model.Snapshot{}, Children: []procfs.Child{{PID: 9, Exited: true}, {PID: 10}}}
	fs, _ := ProcTree{}.Inspect(tgt)
	if len(fs) != 2 || fs[0].Severity != model.SevInfo || fs[0].Suppressed || fs[1].Severity != model.SevHigh {
		t.Fatalf("exited unknown child should be INFO, alive hidden child HIGH: %+v", fs)
	}
}

// Regression (v0.3.2): the exploit's one-shot shell exits and stays a zombie with
// no readable exe; its name still says "sh", so it must keep alerting HIGH.
func TestExitedShellChildStillHigh(t *testing.T) {
	tgt := &Target{Baseline: &model.Snapshot{}, Children: []procfs.Child{
		{PID: 9, Name: "sh", Exited: true},
		{PID: 10, Name: "smtpd", Exited: true},
	}}
	fs, _ := ProcTree{}.Inspect(tgt)
	if fs[0].Severity != model.SevHigh || !strings.Contains(fs[0].Detail, "comm=sh") {
		t.Errorf("exited shell child must stay HIGH with its name: %+v", fs[0])
	}
	if fs[1].Severity != model.SevInfo {
		t.Errorf("exited non-shell child without exe should be INFO: %+v", fs[1])
	}
}

func TestExpectedChildSuppressed(t *testing.T) {
	tgt := &Target{Baseline: &model.Snapshot{}, Children: []procfs.Child{
		{PID: 9, Exe: "/usr/bin/dash", Cmdline: "/bin/sh -c dms-healthcheck", Expected: "Docker healthcheck of container 88180067883c"},
		{PID: 10, Exe: "/usr/bin/dash", Cmdline: "/bin/sh -c id"},
	}}
	fs, _ := ProcTree{}.Inspect(tgt)
	if !fs[0].Suppressed || fs[0].SuppressReason != "Docker healthcheck of container 88180067883c" {
		t.Errorf("healthcheck child should be suppressed with its reason: %+v", fs[0])
	}
	if fs[1].Suppressed || fs[1].Severity != model.SevHigh {
		t.Errorf("any other shell under the shim must alert: %+v", fs[1])
	}
}

func TestChildRiskMatrix(t *testing.T) {
	for _, c := range []struct {
		child procfs.Child
		base  bool
		want  model.Severity
		why   string
	}{
		{procfs.Child{Exe: "/usr/lib/postfix/sbin/tlsmgr", Trusted: true}, true, model.SevLow, "ordinary package program"},
		{procfs.Child{Exe: "/usr/bin/sha512sum", Trusted: true}, true, model.SevLow, "script helper"},
		{procfs.Child{Exe: "/usr/bin/dash", Trusted: true}, true, model.SevHigh, "shell under a service (webshell shape)"},
		{procfs.Child{Exe: "/usr/bin/python3.12", Trusted: true}, true, model.SevHigh, "interpreter"},
		{procfs.Child{Exe: "/usr/bin/curl", Trusted: true}, true, model.SevHigh, "downloader"},
		{procfs.Child{Exe: "/var/www/html/up.bin"}, true, model.SevHigh, "binary from a writable location"},
		{procfs.Child{}, true, model.SevHigh, "alive with a hidden exe"},
		{procfs.Child{Exe: "/usr/bin/dash", Trusted: true}, false, model.SevMedium, "shell, parent without baseline"},
		{procfs.Child{Exe: "/usr/bin/ls", Trusted: true}, false, model.SevInfo, "ordinary, parent without baseline"},
	} {
		if got, _ := childRisk(c.child, c.base); got != c.want {
			t.Errorf("%s: %v, want %v", c.why, got, c.want)
		}
	}
}
