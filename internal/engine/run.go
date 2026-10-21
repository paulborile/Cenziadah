// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package engine

import (
	"time"

	"github.com/paulborile/cenziadah/internal/detector"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/redact"
)

// AllDetectors returns the default detector set in a stable order.
func AllDetectors() []detector.Detector {
	return []detector.Detector{
		detector.MapsAnomaly{},
		detector.ModuleIntegrity{},
		detector.ProcTree{},
		detector.FDSocket{},
	}
}

// ScanDetectors is AllDetectors for an all-process sweep: module integrity shares
// the sweep's module and .text digest caches across every process.
func ScanDetectors(cache *SweepCache) []detector.Detector {
	ds := AllDetectors()
	for i, d := range ds {
		if mi, ok := d.(detector.ModuleIntegrity); ok {
			mi.Cache = cache.textCache()
			mi.OpenModule = cache.OpenModule
			ds[i] = mi
		}
	}
	return ds
}

// Run executes the given detectors against the target and assembles a Report.
// A detector's operational error is not fatal to the whole run; it is skipped so
// one failing check never blinds the others. (Fail safe, not open.)
//
// The Report is what leaves cenziadah (journal, mail, TUI, reports), so its
// command lines and finding texts are redacted here (see package redact); the
// detectors themselves saw the raw target.
func Run(t *detector.Target, dets []detector.Detector) model.Report {
	rep := model.Report{
		Target:    t.Desc,
		CheckedAt: time.Now(),
	}
	rep.Target.Cmdline = redact.Text(rep.Target.Cmdline)
	for _, d := range dets {
		fs, err := d.Inspect(t)
		if err != nil {
			continue
		}
		for i := range fs {
			redactFinding(&fs[i])
		}
		rep.Findings = append(rep.Findings, fs...)
	}
	return rep
}

// redactFinding removes secrets from a finding's texts: its detail and every
// string in its evidence (e.g. a child's cmdline).
func redactFinding(f *model.Finding) {
	f.Detail = redact.Text(f.Detail)
	for k, v := range f.Evidence {
		if s, ok := v.(string); ok {
			f.Evidence[k] = redact.Text(s)
		}
	}
}

// SelectDetectors filters AllDetectors by name; an empty or nil selection returns all.
func SelectDetectors(names []string) []detector.Detector {
	if len(names) == 0 {
		return AllDetectors()
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []detector.Detector
	for _, d := range AllDetectors() {
		if want[d.Name()] {
			out = append(out, d)
		}
	}
	return out
}
