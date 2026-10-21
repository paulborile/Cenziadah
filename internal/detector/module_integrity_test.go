// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/paulborile/cenziadah/internal/elfref"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// fakeMem serves bytes from a flat image indexed by virtual address, so the
// detector can be exercised without a live process.
type fakeMem struct {
	base uint64
	data []byte
}

func (f *fakeMem) ReadAt(buf []byte, addr uint64) (int, error) {
	off := int(addr - f.base)
	if off < 0 || off >= len(f.data) {
		return 0, os.ErrInvalid
	}
	n := copy(buf, f.data[off:])
	return n, nil
}

func buildSO(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "m.c")
	os.WriteFile(src, []byte("int f(int x){return x*3+1;}\nint g(int x){return f(x)+f(x);}\n"), 0o644)
	out := filepath.Join(dir, "m.so")
	if b, err := exec.Command(cc, "-shared", "-fPIC", "-Wl,--build-id", "-o", out, src).CombinedOutput(); err != nil {
		t.Skipf("cc failed: %s", b)
	}
	return out
}

// setup builds a target whose single region maps the .so's .text, with fakeMem
// seeded from the real on-disk .text. Returns the detector, target, mem, module.
func setup(t *testing.T, so string) (ModuleIntegrity, *Target, *fakeMem, *elfref.Module) {
	mod, err := elfref.Open(so)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	// Region maps file offset 0 at virtual base 0x400000 (offset 0, so load bias is base).
	const base = 0x400000
	textVA := uint64(base) + mod.TextOff
	// fakeMem holds the real on-disk .text at textVA (clean == identical to disk).
	textBytes := make([]byte, mod.TextSize)
	copy(textBytes, raw[mod.TextOff:mod.TextOff+mod.TextSize])
	fm := &fakeMem{base: textVA, data: textBytes}

	target := &Target{
		Desc: model.TargetDesc{PID: os.Getpid()}, // a process whose view of the filesystem contains the .so
		Regions: []procfs.Region{
			{Start: base, End: base + uint64(len(raw)) + 0x1000, Read: true, Exec: true, Offset: 0, Path: so},
		},
	}
	return ModuleIntegrity{ReadBuf: 4096}, target, fm, mod
}

// baselineWithMemText builds a baseline whose module entry records the CURRENT
// (clean) in-memory .text digest for the region — i.e. the known-good state.
func baselineWithMemText(target *Target, fm *fakeMem, mod *elfref.Module, path string) *model.Snapshot {
	region := target.Regions[0]
	sum, _ := MemTextDigest(fm, region, mod, nil)
	return &model.Snapshot{
		Modules: []model.ModuleDigest{{Path: path, BuildID: mod.BuildID, MemTextSHA: sum, TextSize: int64(mod.TextSize)}},
	}
}

func TestModuleIntegrityCleanNoFinding(t *testing.T) {
	so := buildSO(t)
	det, target, fm, mod := setup(t, so)
	target.Baseline = baselineWithMemText(target, fm, mod, so)
	fs, err := det.inspect(target, fm)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if !f.Suppressed {
			t.Errorf("clean module (mem == baseline) should yield no active findings, got %+v", f)
		}
	}
}

func TestModuleIntegrityDetectsInlineHook(t *testing.T) {
	so := buildSO(t)
	det, target, fm, mod := setup(t, so)
	// Record the clean in-memory .text as the baseline.
	target.Baseline = baselineWithMemText(target, fm, mod, so)
	// Now simulate an inline hook applied AFTER the baseline: patch a .text byte in
	// live memory.
	fm.data[0] ^= 0xFF
	fs, err := det.inspect(target, fm)
	if err != nil {
		t.Fatal(err)
	}
	var hooks int
	for _, f := range fs {
		if f.Technique == model.TechModuleTextMismatch && !f.Suppressed {
			hooks++
		}
	}
	if hooks != 1 {
		t.Fatalf("expected exactly 1 text-mismatch finding, got %d (%+v)", hooks, fs)
	}
}

func TestModuleIntegrityBuildIDMismatch(t *testing.T) {
	so := buildSO(t)
	det, target, fm, mod := setup(t, so)
	// Baseline claims a different build-id for this path.
	target.Baseline = &model.Snapshot{
		Modules: []model.ModuleDigest{{Path: so, BuildID: "deadbeef", TextSize: int64(mod.TextSize)}},
	}
	fs, _ := det.inspect(target, fm)
	var bidDiff int
	for _, f := range fs {
		if f.Technique == model.TechModuleBuildIDDiff {
			bidDiff++
		}
	}
	if bidDiff != 1 {
		t.Fatalf("expected build-id mismatch finding, got %d (%+v)", bidDiff, fs)
	}
}

// A library replaced in place by a package upgrade after the baseline (root-only
// file, ctime after the baseline) is accepted and marked for re-learning; any
// other build-id change still alerts.
func TestModuleIntegrityUpgradedLibrary(t *testing.T) {
	so := buildSO(t)
	learned := time.Date(2026, 10, 15, 13, 4, 0, 0, time.UTC)
	for _, replaced := range []bool{true, false} {
		det, target, fm, mod := setup(t, so)
		target.Baseline = &model.Snapshot{
			CreatedAt: learned,
			Modules:   []model.ModuleDigest{{Path: so, BuildID: "deadbeef", TextSize: int64(mod.TextSize)}},
		}
		var gotSince time.Time
		det.ReplacedSince = func(_ int, path string, since time.Time) bool { gotSince = since; return replaced && path == so }
		fs, _ := det.inspect(target, fm)
		if len(fs) != 1 || fs[0].Technique != model.TechModuleBuildIDDiff {
			t.Fatalf("replaced=%v: want one build-id finding, got %+v", replaced, fs)
		}
		f := fs[0]
		up, _ := f.Evidence[EvidenceUpgraded].(bool)
		if f.Suppressed != replaced || up != replaced {
			t.Errorf("replaced=%v: suppressed=%v upgraded=%v", replaced, f.Suppressed, up)
		}
		if !gotSince.Equal(learned) {
			t.Errorf("checked against %v, want the baseline's learn time %v", gotSince, learned)
		}
	}
}
