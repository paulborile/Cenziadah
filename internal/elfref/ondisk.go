// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package elfref models an on-disk ELF object enough to compare its executable
// .text against the same code mapped in a live process. It is PURE and DISK-ONLY:
// it opens trusted on-disk backing files with the stdlib debug/elf parser and
// never parses attacker-controlled memory (the stdlib ELF reader is explicitly
// not hardened against adversarial input).
package elfref

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
)

// Module is the subset of an ELF file cenziadah reasons about.
type Module struct {
	Path     string
	BuildID  string // GNU build-id (hex), "" if absent
	TextAddr uint64 // virtual address of .text as laid out in the file
	TextOff  uint64 // file offset of .text
	TextSize uint64
	// RelocMask marks byte offsets WITHIN .text (relative to TextAddr) that a
	// runtime relocation legitimately changes, so they are excluded from the
	// memory-vs-disk comparison. On modern PIC objects this is usually empty.
	RelocMask map[uint64]struct{}
	// maskSorted holds the RelocMask offsets in ascending order, so MaskChunk can
	// zero a chunk's masked bytes without a lookup per byte.
	maskSorted []uint64
	// Stamp identifies the exact file version this was parsed from (device,
	// inode, size, mtime, ctime), set by a caller that caches modules across
	// sweeps (engine.SweepCache); "" when unknown.
	Stamp string
}

// Open parses the ELF at path and extracts the .text layout, build-id, and the
// set of relocation sites that fall inside .text.
func Open(path string) (*Module, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elfref: open %s: %w", path, err)
	}
	defer f.Close()

	text := f.Section(".text")
	if text == nil {
		return nil, errors.New("elfref: no .text section")
	}
	m := &Module{
		Path:      path,
		TextAddr:  text.Addr,
		TextOff:   text.Offset,
		TextSize:  text.Size,
		RelocMask: map[uint64]struct{}{},
		BuildID:   readBuildID(f),
	}
	buildRelocMask(f, m)
	m.sortMask()
	return m, nil
}

// RawReaderAt opens the backing file for raw byte reads at file offsets (used to
// stream the on-disk .text for comparison). The caller must Close it.
func (m *Module) RawReaderAt() (*os.File, error) {
	return os.Open(m.Path)
}
