// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"os"
	"strings"
	"testing"

	"github.com/paulborile/cenziadah/internal/elfref"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// fakeMemFlat serves bytes from a flat image based at base; reads past the image end
// error (modelling an unmapped page), so we can exercise the failure diagnostics.
type fakeMemFlat struct {
	base uint64
	data []byte
}

func (f *fakeMemFlat) ReadAt(buf []byte, addr uint64) (int, error) {
	off := int(addr - f.base)
	if off < 0 || off+len(buf) > len(f.data) {
		return 0, os.ErrInvalid
	}
	return copy(buf, f.data[off:]), nil
}

func TestMemTextDigestDebugRejectsTextPastMapping(t *testing.T) {
	// .text claims to be larger than the executable mapping => must be rejected with
	// a clear reason, NOT silently read into unmapped memory. This is the production
	// failure mode (container mapping shorter than the ELF .text).
	mod := &elfref.Module{
		TextOff:   0x1000,
		TextSize:  0x5000, // 20 KiB
		RelocMask: map[uint64]struct{}{},
	}
	region := procfs.Region{
		Start:  0x400000,
		End:    0x402000, // only 8 KiB mapped — smaller than .text
		Offset: 0x1000,
	}
	_, reason, ok := MemTextDigestDebug(&fakeMemFlat{}, region, mod, nil)
	if ok {
		t.Fatal("expected failure when .text exceeds the exec mapping")
	}
	if !strings.Contains(reason, "not within exec mapping") {
		t.Errorf("reason = %q, want it to mention the mapping bound", reason)
	}
}

func TestMemTextDigestDebugReadError(t *testing.T) {
	mod := &elfref.Module{TextOff: 0, TextSize: 0x100, RelocMask: map[uint64]struct{}{}}
	region := procfs.Region{Start: 0x400000, End: 0x401000, Offset: 0}
	// fakeMem has no data, so the read fails -> reason mentions the read.
	_, reason, ok := MemTextDigestDebug(&fakeMemFlat{base: 0x400000, data: nil}, region, mod, nil)
	if ok || !strings.Contains(reason, "read failed") {
		t.Errorf("expected read-failed reason, got ok=%v reason=%q", ok, reason)
	}
}

func TestMemTextDigestDebugSuccess(t *testing.T) {
	data := make([]byte, 0x200)
	for i := range data {
		data[i] = byte(i)
	}
	mod := &elfref.Module{TextOff: 0, TextSize: 0x200, RelocMask: map[uint64]struct{}{}}
	region := procfs.Region{Start: 0x400000, End: 0x401000, Offset: 0}
	sum, reason, ok := MemTextDigestDebug(&fakeMemFlat{base: 0x400000, data: data}, region, mod, nil)
	if !ok || reason != "" || sum == "" {
		t.Errorf("expected success, got ok=%v reason=%q sum=%q", ok, reason, sum)
	}
}
