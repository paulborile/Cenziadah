// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package elfref

import (
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
)

// BuildID returns the GNU build-id of the ELF file at path ("" if it has none).
// It parses only the section headers and the note, unlike Open, which also builds
// the .text relocation mask; use it when identity is all that is needed.
func BuildID(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return readBuildID(f), nil
}

// readBuildID extracts the GNU build-id from the .note.gnu.build-id section.
// Returns "" if the note is missing or malformed.
func readBuildID(f *elf.File) string {
	sec := f.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil || len(data) < 12 {
		return ""
	}
	// ELF note: namesz(4) descsz(4) type(4) name(namesz, padded) desc(descsz)
	order := f.ByteOrder
	namesz := order.Uint32(data[0:4])
	descsz := order.Uint32(data[4:8])
	// name is 4-byte aligned
	nameEnd := 12 + align4(namesz)
	descEnd := nameEnd + descsz
	if uint32(len(data)) < descEnd {
		return ""
	}
	return hex.EncodeToString(data[nameEnd:descEnd])
}

func align4(n uint32) uint32 { return (n + 3) &^ 3 }

var _ = binary.LittleEndian // keep binary imported for symmetry with other files
