// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package watch

import (
	"bytes"
	"strings"
	"testing"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/scan"
)

func TestLogSinkReportsLearnedAndSkips(t *testing.T) {
	var out, status bytes.Buffer
	res := scan.Result{
		Skipped:  []scan.Skipped{{PID: 9, Reason: scan.ReasonPermission}},
		Accepted: []model.Event{{Kind: model.EventLearned, Target: model.TargetDesc{PID: 50, Name: "victim"}, Finding: model.Finding{Technique: model.TechMapsRWX, Severity: model.SevCritical, Title: "rwx"}}},
	}
	LogSink{Out: &out, Status: &status}.Learned(baseline.NewSet(), res)
	if !strings.Contains(out.String(), "LEARNED CRITICAL pid=50 victim () 1 finding(s): maps.rwx x1") {
		t.Errorf("accepted finding not printed: %q", out.String())
	}
	if !strings.Contains(status.String(), "skipped 1: 1 permission denied") || !strings.Contains(status.String(), "accepted as normal") {
		t.Errorf("status missing skip summary or learned warning: %q", status.String())
	}
}
