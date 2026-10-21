// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package report

import (
	"strings"
	"testing"

	"github.com/paulborile/cenziadah/internal/model"
)

func TestTextOrdersBySeverityAndCountsSuppressed(t *testing.T) {
	r := model.Report{
		Target: model.TargetDesc{PID: 1, Name: "demo"},
		Findings: []model.Finding{
			{Technique: model.TechUnexpectedDest, Severity: model.SevMedium, Title: "sock"},
			{Technique: model.TechMapsRWX, Severity: model.SevCritical, Title: "rwx"},
			{Technique: model.TechMapsAnonExec, Severity: model.SevHigh, Title: "art", Suppressed: true, SuppressReason: "x"},
		},
	}
	var sb strings.Builder
	Text(&sb, r)
	out := sb.String()
	// Critical must appear before Medium.
	if strings.Index(out, "rwx") > strings.Index(out, "sock") {
		t.Error("expected CRITICAL before MEDIUM")
	}
	if !strings.Contains(out, "1 finding(s) suppressed") {
		t.Errorf("expected suppressed count, got:\n%s", out)
	}
}

func TestTextCleanWhenNoActive(t *testing.T) {
	var sb strings.Builder
	Text(&sb, model.Report{Target: model.TargetDesc{PID: 1}})
	if !strings.Contains(sb.String(), "CLEAN") {
		t.Error("expected CLEAN for empty report")
	}
}
