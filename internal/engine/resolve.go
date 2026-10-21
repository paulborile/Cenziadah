// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package engine orchestrates a run: resolve the target process, collect its
// procfs state once, build a Target for the detectors, and (for snapshot) distill
// a known-good Snapshot. It is the only place the pieces are wired together.
package engine

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// ErrNotFound is returned when no process matches a name selector.
var ErrNotFound = errors.New("engine: no matching process")

// ErrMultiple is returned when a name selector matches more than one process.
var ErrMultiple = errors.New("engine: multiple matching processes")

// ResolvePID returns the pid for a selector. Exactly one of pid/name is used:
// pid>0 is returned as-is; otherwise name is matched against /proc/*/comm and
// /proc/*/cmdline.
func ResolvePID(pid int, name string) (int, error) {
	if pid > 0 {
		if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err != nil {
			return 0, fmt.Errorf("engine: pid %d: %w", pid, err)
		}
		return pid, nil
	}
	if name == "" {
		return 0, errors.New("engine: need --pid or --name")
	}
	matches, err := matchByName(name)
	if err != nil {
		return 0, err
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("%w: %q", ErrNotFound, name)
	case 1:
		return matches[0], nil
	default:
		return 0, fmt.Errorf("%w: %q matches pids %v", ErrMultiple, name, matches)
	}
}

func matchByName(name string) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		st, err := procfs.ReadStatus(pid)
		if err != nil {
			continue
		}
		if st.Name == name {
			out = append(out, pid)
			continue
		}
		if cmd, err := procfs.Cmdline(pid); err == nil && cmd != "" {
			// match on the leading token of cmdline (argv[0]) as well
			if cmd == name || hasArg0(cmd, name) {
				out = append(out, pid)
			}
		}
	}
	return out, nil
}

func hasArg0(cmdline, name string) bool {
	// cmdline is space-joined; compare the first token.
	for i := 0; i < len(cmdline); i++ {
		if cmdline[i] == ' ' {
			return cmdline[:i] == name
		}
	}
	return cmdline == name
}

// IsPermission reports whether err is a permission failure reading /proc, so the
// CLI can tell the user to run with sudo / CAP_SYS_PTRACE (operational exit 2).
func IsPermission(err error) bool {
	return errors.Is(err, os.ErrPermission)
}

var _ = model.CurrentSchemaVersion // engine references model in collect.go too
