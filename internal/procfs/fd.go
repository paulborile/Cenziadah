// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"strconv"
)

// FD describes one open file descriptor of a process.
type FD struct {
	Num    int
	Target string // what /proc/<pid>/fd/<n> points to
}

// ReadFDs lists the open file descriptors of pid and resolves each symlink
// target. Unreadable individual fds are skipped (best-effort).
func ReadFDs(pid int) ([]FD, error) {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var fds []FD
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		tgt, err := os.Readlink(dir + "/" + e.Name())
		if err != nil {
			continue
		}
		fds = append(fds, FD{Num: n, Target: tgt})
	}
	return fds, nil
}
