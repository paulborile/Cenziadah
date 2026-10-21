// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package elfref

import (
	"debug/elf"
	"sort"
)

// buildRelocMask records byte offsets within .text (relative to TextAddr) that a
// dynamic relocation legitimately patches at load time, so the memory-vs-disk
// comparison can treat them as "don't-care". On well-formed position-independent
// objects almost no relocations land inside .text (they target .got/.plt/.data),
// so this mask is usually empty — but handling it prevents false positives on the
// rare text-relocation (textrel) or IFUNC case.
func buildRelocMask(f *elf.File, m *Module) {
	textStart := m.TextAddr
	textEnd := m.TextAddr + m.TextSize

	mark := func(off uint64, width uint64) {
		if off < textStart || off >= textEnd {
			return
		}
		rel := off - textStart
		for i := uint64(0); i < width && rel+i < m.TextSize; i++ {
			m.RelocMask[rel+i] = struct{}{}
		}
	}

	for _, sec := range f.Sections {
		switch sec.Type {
		case elf.SHT_RELA:
			rels, err := f.Section(sec.Name).Data()
			if err != nil {
				continue
			}
			// Each Elf64_Rela is 24 bytes: r_offset(8) r_info(8) r_addend(8).
			for off := 0; off+24 <= len(rels); off += 24 {
				rOffset := f.ByteOrder.Uint64(rels[off : off+8])
				mark(rOffset, 8)
			}
		case elf.SHT_REL:
			rels, err := f.Section(sec.Name).Data()
			if err != nil {
				continue
			}
			// Each Elf64_Rel is 16 bytes: r_offset(8) r_info(8).
			for off := 0; off+16 <= len(rels); off += 16 {
				rOffset := f.ByteOrder.Uint64(rels[off : off+8])
				mark(rOffset, 8)
			}
		}
	}
}

// sortMask builds the sorted offset list used by MaskChunk.
func (m *Module) sortMask() {
	m.maskSorted = m.maskSorted[:0]
	for off := range m.RelocMask {
		m.maskSorted = append(m.maskSorted, off)
	}
	sort.Slice(m.maskSorted, func(i, j int) bool { return m.maskSorted[i] < m.maskSorted[j] })
}

// MaskChunk zeroes the relocation-masked bytes in buf, which holds .text bytes
// starting at offset off (relative to TextAddr). The usual empty mask costs
// nothing; otherwise only the masked offsets inside the chunk are visited.
func (m *Module) MaskChunk(buf []byte, off uint64) {
	if len(m.maskSorted) != len(m.RelocMask) {
		m.sortMask() // RelocMask was filled by hand, not by Open
	}
	if len(m.maskSorted) == 0 {
		return
	}
	end := off + uint64(len(buf))
	i := sort.Search(len(m.maskSorted), func(i int) bool { return m.maskSorted[i] >= off })
	for ; i < len(m.maskSorted) && m.maskSorted[i] < end; i++ {
		buf[m.maskSorted[i]-off] = 0
	}
}
