// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/paulborile/cenziadah/internal/elfref"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// MemReader is the minimal read capability needed to digest in-memory .text.
// *procfs.Mem satisfies it; tests supply a fake.
type MemReader interface {
	ReadAt(buf []byte, addr uint64) (int, error)
}

// MemTextDigest computes the sha256 of a module's in-memory .text for a live
// process, with relocation sites masked (zeroed) so legitimate linker fixups do
// not change the digest. It uses the standard load-bias arithmetic:
//
//	vaddr(.text) = region.Start + (mod.TextOff - region.Offset)
//
// Returns ("", false) if the .text is not covered by the mapping or memory could
// not be read (a live-memory race), so the caller treats it as "no opinion"
// rather than a false mismatch.
func MemTextDigest(mem MemReader, region procfs.Region, mod *elfref.Module, buf []byte) (string, bool) {
	sum, _, ok := MemTextDigestDebug(mem, region, mod, buf)
	return sum, ok
}

// MemTextDigestDebug is MemTextDigest but also returns a human-readable reason when
// it cannot produce a digest, so callers can log WHY a module was not integrity-
// checked (e.g. the read offset that failed). reason is "" on success.
func MemTextDigestDebug(mem MemReader, region procfs.Region, mod *elfref.Module, buf []byte) (sum string, reason string, ok bool) {
	if mod.TextSize == 0 {
		return "", "zero .text size", false
	}
	if mod.TextOff < region.Offset {
		return "", fmt.Sprintf(".text file offset %#x precedes mapping offset %#x", mod.TextOff, region.Offset), false
	}
	textVA := region.Start + (mod.TextOff - region.Offset)
	// Sanity: the .text range must lie within this executable mapping, else the
	// bias/region pairing is wrong and reads would run into unmapped memory.
	if textVA < region.Start || textVA+mod.TextSize > region.End {
		return "", fmt.Sprintf(".text [%#x,%#x) not within exec mapping [%#x,%#x)",
			textVA, textVA+mod.TextSize, region.Start, region.End), false
	}
	if len(buf) == 0 {
		buf = make([]byte, 1<<20)
	}
	h := sha256.New()
	var done uint64
	for done < mod.TextSize {
		n := uint64(len(buf))
		if rem := mod.TextSize - done; rem < n {
			n = rem
		}
		w := buf[:n]
		if _, err := mem.ReadAt(w, textVA+done); err != nil && err != io.EOF {
			return "", fmt.Sprintf("read failed at %#x (+%#x into .text): %v", textVA+done, done, err), false
		}
		mod.MaskChunk(w, done)
		h.Write(w)
		done += n
	}
	return hex.EncodeToString(h.Sum(nil)), "", true
}
