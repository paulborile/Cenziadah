// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package elfref

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildFixtureSO compiles a tiny shared object with a GNU build-id so the test
// exercises the real debug/elf path rather than a hand-rolled blob.
func buildFixtureSO(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available; skipping ELF fixture test")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "fix.c")
	if err := os.WriteFile(src, []byte("int add(int a,int b){return a+b;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "fix.so")
	cmd := exec.Command(cc, "-shared", "-fPIC", "-Wl,--build-id", "-o", out, src)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cc failed (%v): %s", err, b)
	}
	return out
}

func TestOpenExtractsTextAndBuildID(t *testing.T) {
	so := buildFixtureSO(t)
	m, err := Open(so)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if m.TextSize == 0 {
		t.Error("TextSize should be non-zero")
	}
	if m.BuildID == "" {
		t.Error("BuildID should be present (compiled with --build-id)")
	}
	// A trivial leaf function on modern PIC should have no text relocations.
	if len(m.RelocMask) != 0 {
		t.Logf("note: %d reloc sites inside .text (acceptable, textrel/IFUNC)", len(m.RelocMask))
	}
}

func TestOpenMissingFile(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nope.so")); err == nil {
		t.Error("expected error opening nonexistent file")
	}
}

func TestBuildIDStableAcrossOpens(t *testing.T) {
	so := buildFixtureSO(t)
	a, err := Open(so)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(so)
	if err != nil {
		t.Fatal(err)
	}
	if a.BuildID != b.BuildID {
		t.Errorf("build-id not stable: %q vs %q", a.BuildID, b.BuildID)
	}
}

func TestBuildIDMatchesOpen(t *testing.T) {
	so := buildFixtureSO(t)
	m, err := Open(so)
	if err != nil {
		t.Fatal(err)
	}
	bid, err := BuildID(so)
	if err != nil || bid == "" || bid != m.BuildID {
		t.Fatalf("BuildID = %q (%v), Open says %q", bid, err, m.BuildID)
	}
}

func TestMaskChunkZeroesOnlyMaskedBytes(t *testing.T) {
	m := &Module{RelocMask: map[uint64]struct{}{3: {}, 10: {}, 11: {}}} // filled by hand
	buf := []byte{1, 1, 1, 1, 1, 1, 1, 1}                               // .text offsets 8..15
	m.MaskChunk(buf, 8)
	want := []byte{1, 1, 0, 0, 1, 1, 1, 1} // offsets 10 and 11 masked; 3 is outside the chunk
	for i := range want {
		if buf[i] != want[i] {
			t.Fatalf("buf = %v, want %v", buf, want)
		}
	}
}
