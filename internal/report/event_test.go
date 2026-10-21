// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/version"
)

func sampleEvent() model.Event {
	return model.Event{
		Kind:   model.EventNew,
		At:     time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC),
		Target: model.TargetDesc{PID: 42, Name: "victim", Exe: "/opt/victim"},
		Finding: model.Finding{Technique: model.TechUnexpectedChild, Severity: model.SevHigh,
			Title: "unexpected child process", Detail: "cmd=\"sh -c id\nFAKE LINE\""},
	}
}

func TestEventTextIsOneLine(t *testing.T) {
	var b bytes.Buffer
	EventText(&b, sampleEvent())
	out := b.String()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("attacker newline must not split the event: %q", out)
	}
	for _, want := range []string{"2026-10-11T12:00:00Z NEW HIGH pid=42 victim", "proctree.unexpected_child"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

func TestEventJSONRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := EventJSON(&b, sampleEvent()); err != nil {
		t.Fatal(err)
	}
	var got model.Event
	if err := json.Unmarshal(b.Bytes(), &got); err != nil || got.Target.PID != 42 || got.Kind != model.EventNew {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if got.Version != version.Version {
		t.Errorf("event version = %q, want %q", got.Version, version.Version)
	}
}

func TestLearnedTextOneLinePerProcess(t *testing.T) {
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	ev := func(pid int, tech model.Technique, sev model.Severity) model.Event {
		return model.Event{Kind: model.EventLearned, At: at, Target: model.TargetDesc{PID: pid, Name: "p"}, Finding: model.Finding{Technique: tech, Severity: sev}}
	}
	var b bytes.Buffer
	LearnedText(&b, []model.Event{
		ev(1, model.TechMapsRWX, model.SevCritical), ev(1, model.TechMapsRWX, model.SevCritical), ev(1, model.TechMapsAnonExec, model.SevHigh),
		ev(2, model.TechMapsAnonExec, model.SevHigh),
	})
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %q", b.String())
	}
	if !strings.Contains(lines[0], "LEARNED CRITICAL pid=1 p () 3 finding(s): maps.rwx x2, maps.anon_exec x1") {
		t.Errorf("line 1 = %q", lines[0])
	}
}
