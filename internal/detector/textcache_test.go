// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"testing"

	"github.com/paulborile/cenziadah/internal/elfref"
)

// countingMem wraps fakeMem and counts reads, to prove a cache hit skips memory.
type countingMem struct {
	*fakeMem
	reads int
}

func (c *countingMem) ReadAt(buf []byte, addr uint64) (int, error) {
	c.reads++
	return c.fakeMem.ReadAt(buf, addr)
}

// twoProcesses returns two "processes" mapping the same file (same dev+inode),
// each with its own copy of the clean .text.
func twoProcesses(t *testing.T) (det ModuleIntegrity, a, b *countingMem, tgt *Target, mod *elfref.Module) {
	so := buildSO(t)
	det, tgt, fm, mod := setup(t, so)
	tgt.Regions[0].Dev, tgt.Regions[0].Inode = "08:01", 4242
	mod.Stamp = "2049:4242:100:1.0:1.0" // as engine.SweepCache sets it
	clone := func() *countingMem {
		data := make([]byte, len(fm.data))
		copy(data, fm.data)
		return &countingMem{fakeMem: &fakeMem{base: fm.base, data: data}}
	}
	return det, clone(), clone(), tgt, mod
}

func TestTextCacheReusesUnwrittenMapping(t *testing.T) {
	det, a, b, tgt, mod := twoProcesses(t)
	r := tgt.Regions[0]
	r.AnonKnown, r.AnonKB = true, 0

	c := NewTextCache()
	sumA, okA := c.Digest(a, r, mod, make([]byte, det.ReadBuf))
	sumB, okB := c.Digest(b, r, mod, make([]byte, det.ReadBuf))
	if !okA || !okB || sumA != sumB {
		t.Fatalf("digests: a=%q(%v) b=%q(%v)", sumA, okA, sumB, okB)
	}
	if b.reads != 0 {
		t.Errorf("second identical unwritten mapping should be a cache hit, read mem %d times", b.reads)
	}
	if hits, misses := c.Stats(); hits != 1 || misses != 1 {
		t.Errorf("stats hits=%d misses=%d, want 1/1", hits, misses)
	}
}

// The security property: a hooked process must never get the clean digest from
// the cache. A real hook leaves CoW pages (Anonymous > 0), so it is read fresh.
func TestTextCacheNeverMasksHookedProcess(t *testing.T) {
	det, a, b, tgt, mod := twoProcesses(t)
	clean := tgt.Regions[0]
	clean.AnonKnown, clean.AnonKB = true, 0
	hooked := clean
	hooked.AnonKB = 4 // the patched page was copied-on-write
	b.data[0] ^= 0xFF // inline hook in process b

	c := NewTextCache()
	sumA, _ := c.Digest(a, clean, mod, make([]byte, det.ReadBuf))
	sumB, ok := c.Digest(b, hooked, mod, make([]byte, det.ReadBuf))
	if !ok || b.reads == 0 {
		t.Fatalf("hooked mapping must be read from memory (reads=%d ok=%v)", b.reads, ok)
	}
	if sumA == sumB {
		t.Fatal("hooked process got the clean digest: cache masked the hook")
	}
}

func TestTextCacheUnknownSmapsReadsMemory(t *testing.T) {
	det, a, b, tgt, mod := twoProcesses(t)
	r := tgt.Regions[0] // AnonKnown=false: smaps not read

	c := NewTextCache()
	c.Digest(a, r, mod, make([]byte, det.ReadBuf))
	c.Digest(b, r, mod, make([]byte, det.ReadBuf))
	if b.reads == 0 {
		t.Error("mapping with unknown smaps state must not be served from cache")
	}
}

func TestNilTextCacheReadsMemory(t *testing.T) {
	det, a, _, tgt, mod := twoProcesses(t)
	var c *TextCache
	if _, ok := c.Digest(a, tgt.Regions[0], mod, make([]byte, det.ReadBuf)); !ok || a.reads == 0 {
		t.Errorf("nil cache should read memory (reads=%d ok=%v)", a.reads, ok)
	}
}

// A module without a Stamp (file version unknown) is never cached: across
// sweeps the file could have changed under the same inode.
func TestTextCacheNeedsStamp(t *testing.T) {
	det, a, b, tgt, mod := twoProcesses(t)
	r := tgt.Regions[0]
	r.AnonKnown, r.AnonKB = true, 0
	mod.Stamp = ""
	c := NewTextCache()
	c.Digest(a, r, mod, make([]byte, det.ReadBuf))
	c.Digest(b, r, mod, make([]byte, det.ReadBuf))
	if b.reads == 0 || c.Len() != 0 {
		t.Errorf("stamp-less module was cached (reads=%d len=%d)", b.reads, c.Len())
	}
}

// Across sweeps: the same file version is a hit; a file written in place (new
// mtime/ctime, so a new Stamp) is read again; digests no sweep used are dropped.
func TestTextCacheAcrossSweeps(t *testing.T) {
	det, a, b, tgt, mod := twoProcesses(t)
	r := tgt.Regions[0]
	r.AnonKnown, r.AnonKB = true, 0
	buf := make([]byte, det.ReadBuf)
	c := NewTextCache()

	c.BeginSweep()
	c.Digest(a, r, mod, buf)
	c.EndSweep()

	c.BeginSweep()
	c.Digest(b, r, mod, buf)
	if b.reads != 0 {
		t.Errorf("same file version in the next sweep should be a hit, read %d times", b.reads)
	}
	changed := *mod
	changed.Stamp = "2049:4242:100:2.0:2.0"
	b.data[0] ^= 0xFF // the file was written in place
	sum2, _ := c.Digest(b, r, &changed, buf)
	if b.reads == 0 {
		t.Fatal("a changed file version must be read from memory")
	}
	c.EndSweep()

	c.BeginSweep() // a sweep where only the new version is mapped
	c.Digest(b, r, &changed, buf)
	c.EndSweep()
	if c.Len() != 1 {
		t.Errorf("cache holds %d digests, want only the version still mapped", c.Len())
	}
	if got, _ := c.Digest(b, r, &changed, buf); got != sum2 {
		t.Error("digest of the current version changed")
	}
}
