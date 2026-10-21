// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"testing"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

func activeByTech(fs []model.Finding) map[model.Technique]model.Finding {
	m := map[model.Technique]model.Finding{}
	for _, f := range fs {
		if !f.Suppressed {
			m[f.Technique] = f
		}
	}
	return m
}

func TestMapsAnomalyDetectsRWXAndAnonExec(t *testing.T) {
	target := &Target{
		Desc: model.TargetDesc{PID: 42},
		Regions: []procfs.Region{
			{Start: 0x1000, End: 0x2000, Read: true, Exec: true, Path: "/usr/bin/app"},             // normal r-x, ok
			{Start: 0x3000, End: 0x4000, Read: true, Write: true, Exec: true},                      // rwx -> critical
			{Start: 0x5000, End: 0x6000, Read: true, Exec: true},                                   // anon-exec -> high
			{Start: 0x7000, End: 0x8000, Read: true, Exec: true, Path: "/tmp/x.so", Deleted: true}, // deleted-backing
		},
	}
	fs, err := MapsAnomaly{}.Inspect(target)
	if err != nil {
		t.Fatal(err)
	}
	act := activeByTech(fs)
	if _, ok := act[model.TechMapsRWX]; !ok {
		t.Error("expected rwx finding")
	}
	if f := act[model.TechMapsRWX]; f.Severity != model.SevCritical {
		t.Errorf("rwx severity = %v, want CRITICAL", f.Severity)
	}
	if _, ok := act[model.TechMapsAnonExec]; !ok {
		t.Error("expected anon-exec finding")
	}
	if _, ok := act[model.TechMapsDeletedBacking]; !ok {
		t.Error("expected deleted-backing finding")
	}
	// The normal r-x file-backed region must NOT produce a finding.
	for _, f := range fs {
		if f.Technique == model.TechMapsAnonExec && f.Evidence["start"] == "0x1000" {
			t.Error("normal r-x region should not be flagged")
		}
	}
}

func TestMapsAnomalySuppressesART(t *testing.T) {
	target := &Target{
		Desc: model.TargetDesc{PID: 7},
		Regions: []procfs.Region{
			{Start: 0x1000, End: 0x2000, Read: true, Write: true, Exec: true, Path: "memfd:jit-cache"},
		},
	}
	fs, _ := MapsAnomaly{}.Inspect(target)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if !fs[0].Suppressed || fs[0].SuppressReason == "" {
		t.Errorf("ART jit-cache rwx should be suppressed with a reason, got %+v", fs[0])
	}
}

func TestMapsAnomalyBaselineSuppression(t *testing.T) {
	base := &model.Snapshot{
		Regions: []model.RegionShape{
			{Perm: "rwx", Backing: "[anon]", Exec: true},
		},
	}
	target := &Target{
		Desc:     model.TargetDesc{PID: 9},
		Baseline: base,
		Regions: []procfs.Region{
			{Start: 0x1000, End: 0x2000, Read: true, Write: true, Exec: true}, // anon rwx, but in baseline
		},
	}
	fs, _ := MapsAnomaly{}.Inspect(target)
	if len(fs) != 1 || !fs[0].Suppressed {
		t.Errorf("baseline-known rwx should be suppressed, got %+v", fs)
	}
}

func TestDeletedBackingReplacedByUpgradeIsSuppressed(t *testing.T) {
	upgraded := procfs.Region{Start: 0x1000, End: 0x2000, Read: true, Exec: true, Path: "/usr/lib/libfoo.so.1", Deleted: true, ReplacedOnDisk: true}
	dropped := procfs.Region{Start: 0x3000, End: 0x4000, Read: true, Exec: true, Path: "/tmp/x.so", Deleted: true}
	fs, _ := MapsAnomaly{}.Inspect(&Target{Regions: []procfs.Region{upgraded, dropped}})
	var active, suppressed int
	for _, f := range fs {
		if f.Technique != model.TechMapsDeletedBacking {
			continue
		}
		if f.Suppressed {
			suppressed++
		} else {
			active++
		}
	}
	if active != 1 || suppressed != 1 {
		t.Fatalf("want the dropped lib active and the upgraded one suppressed, got active=%d suppressed=%d", active, suppressed)
	}
}

// Anonymous regions match the baseline as one class: V8's JIT code range is
// "[anon:v8]" in one run and, placed over the unused brk start, "[heap]" in the
// next (Obsidian renderer, 2026-10-15). The real brk heap stays its own class:
// an rwx brk heap is not excused by a JIT region.
func TestMapsAnomalyAnonymousClass(t *testing.T) {
	base := &model.Snapshot{Regions: []model.RegionShape{{Perm: "rwx", Backing: "[anon:v8]", Exec: true}}}
	rwx := func(path string, notBrk bool) procfs.Region {
		return procfs.Region{Start: 0x1000, End: 0x2000, Read: true, Write: true, Exec: true, Private: true, Path: path, NotBrkHeap: notBrk}
	}
	for _, c := range []struct {
		r          procfs.Region
		suppressed bool
		why        string
	}{
		{rwx("[heap]", true), true, "JIT range labelled [heap] by placement"},
		{rwx("", false), true, "unnamed anonymous"},
		{rwx("[anon:other]", false), true, "another self-chosen name"},
		{rwx("[heap]", false), false, "the real brk heap made rwx"},
		{rwx("[stack]", false), false, "rwx stack"},
	} {
		fs, _ := MapsAnomaly{}.Inspect(&Target{Desc: model.TargetDesc{PID: 9}, Baseline: base, Regions: []procfs.Region{c.r}})
		if len(fs) != 1 || fs[0].Suppressed != c.suppressed {
			t.Errorf("%s: findings %+v, want suppressed=%v", c.why, fs, c.suppressed)
		}
	}
}
