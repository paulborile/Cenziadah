// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package notify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/scan"
	"github.com/paulborile/cenziadah/internal/version"
)

// fakeMailer records messages; block makes Send wait until released.
type fakeMailer struct {
	mu    sync.Mutex
	msgs  []string
	block chan struct{}
}

func (f *fakeMailer) Send(_ context.Context, msg []byte) error {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	f.msgs = append(f.msgs, string(msg))
	f.mu.Unlock()
	return nil
}

func (f *fakeMailer) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.msgs...)
}

func sink(f *fakeMailer) *MailSink {
	return NewMailSink(Config{To: "ops@example.com", Min: model.SevMedium, Mailer: f, Host: "fender"})
}

func event(kind model.EventKind, sev model.Severity, name string) model.Event {
	return model.Event{Kind: kind, At: time.Now(), Target: model.TargetDesc{PID: 1384, Name: name, Exe: "/usr/sbin/apache2", Cmdline: "apache2 -DFOREGROUND", UID: 33},
		Finding: model.Finding{Technique: model.TechUnexpectedChild, Severity: sev, Title: "unexpected shell/interpreter/network-tool child",
			Detail: `pid=999 exe=/usr/bin/dash cmd="sh -c id"`}}
}

func TestOnlyNewAlertsAtThresholdAreMailedOncePerSweep(t *testing.T) {
	f := &fakeMailer{}
	m := sink(f)
	m.Sweep(1, scan.Result{}, []model.Event{
		event(model.EventNew, model.SevHigh, "apache2"),
		event(model.EventNew, model.SevCritical, "victim"),
		event(model.EventNew, model.SevLow, "master"),
		event(model.EventResolved, model.SevHigh, "apache2"),
	})
	m.Sweep(2, scan.Result{}, []model.Event{event(model.EventNew, model.SevLow, "x"), event(model.EventResolved, model.SevHigh, "y")})
	m.Close()
	msgs := f.all()
	if len(msgs) != 1 {
		t.Fatalf("want one mail (sweep 2 has nothing to mail), got %d", len(msgs))
	}
	body := msgs[0]
	for _, want := range []string{"To: ops@example.com", "Subject: cenziadah: 2 alert(s) on fender: HIGH proctree.unexpected_child apache2",
		"[CRITICAL]", "cmdline  apache2 -DFOREGROUND", "version  cenziadah " + version.Version, `detail   pid=999 exe=/usr/bin/dash cmd="sh -c id"`} {
		if !strings.Contains(body, want) {
			t.Errorf("mail missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "master") {
		t.Error("LOW finding must not be mailed")
	}
}

func TestRateLimitCountsAndReports(t *testing.T) {
	f := &fakeMailer{}
	m := NewMailSink(Config{To: "ops@example.com", Min: model.SevMedium, MaxPerHour: 2, Mailer: f, Host: "h"})
	clock := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }
	for i := 0; i < 4; i++ { // 2 sent, 2 skipped
		m.Sweep(i, scan.Result{}, []model.Event{event(model.EventNew, model.SevHigh, "a")})
	}
	clock = clock.Add(61 * time.Minute) // window expired
	m.Sweep(5, scan.Result{}, []model.Event{event(model.EventNew, model.SevHigh, "a")})
	m.Close()
	msgs := f.all()
	if len(msgs) != 3 || !strings.Contains(msgs[2], "2 earlier alert mail(s) were not sent (rate limit 2/hour)") {
		t.Fatalf("want 3 mails, the last reporting 2 skipped; got %d:\n%s", len(msgs), strings.Join(msgs, "\n====\n"))
	}
}

// Process names and command lines are attacker-controlled: they must never be
// able to add a mail header (e.g. a Bcc to the attacker).
func TestNoHeaderInjection(t *testing.T) {
	f := &fakeMailer{}
	m := sink(f)
	evil := event(model.EventNew, model.SevHigh, "x\r\nBcc: attacker@evil.example")
	evil.Target.Cmdline = "a\nBcc: attacker@evil.example"
	m.Sweep(1, scan.Result{}, []model.Event{evil})
	m.Close()
	msg := f.all()[0]
	head := msg[:strings.Index(msg, "\n\n")]
	if strings.Contains(head, "\nBcc:") || strings.Count(msg, "\nBcc:") > 0 {
		t.Fatalf("header injected:\n%s", msg)
	}
}

func TestStartupMail(t *testing.T) {
	f := &fakeMailer{}
	m := sink(f)
	res := scan.Result{Stats: scan.Stats{Scanned: 58}, FinishedAt: time.Now(),
		Skipped:  []scan.Skipped{{PID: 2, Reason: scan.ReasonKernel}},
		Accepted: []model.Event{{Kind: model.EventLearned, At: time.Now(), Target: model.TargetDesc{PID: 50, Name: "victim"}, Finding: model.Finding{Technique: model.TechMapsRWX, Severity: model.SevCritical}}}}
	m.Learned(baseline.NewSet(), res)
	m.Close()
	msg := f.all()[0]
	for _, want := range []string{"Subject: cenziadah started on fender: watching 58 processes", "skipped 1: 1 kernel thread",
		"LEARNED CRITICAL pid=50 victim", "will be mailed to ops@example.com"} {
		if !strings.Contains(msg, want) {
			t.Errorf("startup mail missing %q:\n%s", want, msg)
		}
	}
}

func TestFullQueueDropsInsteadOfBlocking(t *testing.T) {
	f := &fakeMailer{block: make(chan struct{})}
	m := NewMailSink(Config{To: "ops@example.com", Min: model.SevMedium, MaxPerHour: 1000, Mailer: f, Host: "h"})
	done := make(chan struct{})
	go func() {
		for i := 0; i < queueSize+5; i++ { // worker holds 1, queue holds 16, the rest drop
			m.Sweep(i, scan.Result{}, []model.Event{event(model.EventNew, model.SevHigh, "a")})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a stuck MTA blocked the sweep loop")
	}
	if m.queueFull == 0 {
		t.Error("drops should be counted")
	}
	close(f.block)
	m.Close()
}

// The real Sendmail runs `<path> -t -i` with the message on stdin.
func TestSendmailExec(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	stub := filepath.Join(dir, "sendmail")
	os.WriteFile(stub, []byte("#!/bin/sh\necho \"$@\" > "+out+".args\ncat > "+out+"\n"), 0o755)
	msg := compose("ops@example.com", "", "s", "hello", time.Now(), "t")
	if err := (Sendmail{Path: stub}).Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(out + ".args")
	got, _ := os.ReadFile(out)
	if strings.TrimSpace(string(args)) != "-t -i" || string(got) != string(msg) {
		t.Errorf("args=%q stdin=%q", args, got)
	}
}

func TestTrustedProgram(t *testing.T) {
	if _, err := TrustedProgram("/usr/bin/ls"); err != nil {
		t.Errorf("/usr/bin/ls should be trusted: %v", err)
	}
	if os.Getuid() != 0 {
		p := filepath.Join(t.TempDir(), "sendmail")
		os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755)
		if _, err := TrustedProgram(p); err == nil {
			t.Error("a user-owned sendmail must be refused")
		}
	}
	if _, err := TrustedProgram("/nonexistent/sendmail"); err == nil {
		t.Error("missing program must be refused")
	}
}

func TestValidAddress(t *testing.T) {
	for a, ok := range map[string]bool{"ops@example.com": true, "a.b+c@sub.example.org": true,
		"no-at": false, "x@y": false, "a b@example.com": false, "a@example.com\nBcc: x@y.z": false, "Name <a@example.com>": false} {
		if (ValidAddress(a) == nil) != ok {
			t.Errorf("ValidAddress(%q) ok=%v", a, !ok)
		}
	}
}
