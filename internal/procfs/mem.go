// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"errors"
	"os"
	"strconv"
)

// Mem is a read-only handle to /proc/<pid>/mem. The target's memory is hostile,
// attacker-influenced data: this type only ever READS fixed, caller-bounded
// lengths into caller-provided buffers. It never allocates a size taken from the
// data itself, never executes or interprets what it reads.
type Mem struct {
	f *os.File
}

// OpenMem opens /proc/<pid>/mem for reading. Requires CAP_SYS_PTRACE (or being
// the same uid and ptrace-allowed) for another process.
func OpenMem(pid int) (*Mem, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/mem")
	if err != nil {
		return nil, err
	}
	return &Mem{f: f}, nil
}

// Close releases the handle.
func (m *Mem) Close() error { return m.f.Close() }

// ReadAt reads len(buf) bytes starting at virtual address addr into buf, using
// pread so no seek state is shared. The length read is exactly len(buf) — the
// caller owns the bound. /proc/<pid>/mem is live, so a page may be unmapped or
// changed mid-read; such reads return an error (often EIO) or a short read,
// which the caller handles as a race rather than a crash.
func (m *Mem) ReadAt(buf []byte, addr uint64) (int, error) {
	if addr > uint64(1)<<63 {
		// Guard against absurd offsets that would overflow the int64 pread offset.
		return 0, errors.New("procfs: address out of range")
	}
	return m.f.ReadAt(buf, int64(addr))
}
