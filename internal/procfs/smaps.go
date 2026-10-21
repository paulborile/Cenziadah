// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// ReadSmapsAnon parses /proc/<pid>/smaps and returns, for each mapping (keyed by
// its start address), the "Anonymous:" size in kB.
//
// For a file-backed mapping, Anonymous > 0 means some of its pages were written
// and copied-on-write into private memory. Code is never written legitimately
// after load (except relocations/instrumentation), so a .text mapping with
// Anonymous == 0 is byte-for-byte the file's shared page cache. That is what
// makes it safe to reuse one process's .text digest for another (see
// detector.TextCache).
func ReadSmapsAnon(pid int) (map[uint64]uint64, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/smaps")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseSmapsAnon(f)
}

// parseSmapsAnon is separated from ReadSmapsAnon so tests can feed a fixture.
func parseSmapsAnon(r io.Reader) (map[uint64]uint64, error) {
	out := make(map[uint64]uint64)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var cur uint64
	haveCur := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Anonymous:") {
			if haveCur {
				out[cur] = firstUint(strings.TrimPrefix(line, "Anonymous:"))
			}
			continue
		}
		// A mapping header looks like a maps line ("start-end perms ...");
		// attribute lines ("Size:", "VmFlags:") never parse as one.
		if reg, ok := parseMapLine(line); ok {
			cur, haveCur = reg.Start, true
		}
	}
	return out, sc.Err()
}

// AnnotateAnon copies smaps Anonymous sizes onto regions. Regions with no smaps
// entry keep AnonKnown=false, which callers must treat as "possibly written".
func AnnotateAnon(regions []Region, anon map[uint64]uint64) {
	for i := range regions {
		if kb, ok := anon[regions[i].Start]; ok {
			regions[i].AnonKB = kb
			regions[i].AnonKnown = true
		}
	}
}

func firstUint(s string) uint64 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.ParseUint(fields[0], 10, 64)
	return n
}
