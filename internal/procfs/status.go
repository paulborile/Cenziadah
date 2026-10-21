// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Status is the subset of /proc/<pid>/status that cenziadah needs.
type Status struct {
	PID  int
	PPID int
	Name string
	UID  int // real uid
	GID  int // real gid
	// Kthread is true for kernel threads ("Kthread: 1", Linux 6.x+). Older kernels
	// omit the line; callers also treat pid 2 (kthreadd) and its children as kernel.
	Kthread bool
	// Zombie: the process has exited and waits to be reaped ("State: Z").
	Zombie bool
}

// ReadStatus parses /proc/<pid>/status.
func ReadStatus(pid int) (Status, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return Status{}, err
	}
	defer f.Close()

	st := Status{PID: pid}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			st.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "PPid:"):
			st.PPID, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
		case strings.HasPrefix(line, "Uid:"):
			st.UID = firstInt(strings.TrimPrefix(line, "Uid:"))
		case strings.HasPrefix(line, "Gid:"):
			st.GID = firstInt(strings.TrimPrefix(line, "Gid:"))
		case strings.HasPrefix(line, "State:"):
			st.Zombie = strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(line, "State:")), "Z")
		case strings.HasPrefix(line, "Kthread:"):
			st.Kthread = firstInt(strings.TrimPrefix(line, "Kthread:")) == 1
		}
	}
	return st, sc.Err()
}

// firstInt returns the first whitespace-separated integer in s (the "real" id
// column in Uid:/Gid: lines).
func firstInt(s string) int {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(fields[0])
	return n
}

// Exe resolves /proc/<pid>/exe to the on-disk path of the running binary.
func Exe(pid int) (string, error) {
	return os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
}

// ExeLink returns the /proc/<pid>/exe path itself. Opening it yields the binary
// the process is running even if that file was since deleted or replaced.
func ExeLink(pid int) string {
	return "/proc/" + strconv.Itoa(pid) + "/exe"
}

// TrimDeleted removes the " (deleted)" suffix the kernel appends to the exe link
// of a process whose binary was unlinked (typically by a package upgrade).
func TrimDeleted(path string) string {
	return strings.TrimSuffix(path, " (deleted)")
}

// Cmdline reads /proc/<pid>/cmdline and renders it with spaces between args.
func Cmdline(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return "", err
	}
	// Arguments are NUL-separated; drop a trailing NUL and join with spaces.
	s := strings.TrimRight(string(b), "\x00")
	return strings.ReplaceAll(s, "\x00", " "), nil
}
