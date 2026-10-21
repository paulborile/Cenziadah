// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// bootTime caches the system boot time derived from /proc/stat btime.
var cachedBootTime time.Time

// StartTime returns the wall-clock time the process started, derived from the
// 22nd field of /proc/<pid>/stat (starttime, in clock ticks since boot) plus the
// system boot time. This bounds the compromise window.
func StartTime(pid int) (time.Time, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return time.Time{}, err
	}
	// comm (field 2) may contain spaces/parens; split on the last ')'.
	s := string(data)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 {
		return time.Time{}, err
	}
	rest := strings.Fields(s[rparen+1:])
	// After comm, field 3 is state; starttime is field 22 overall => index 19 here
	// (rest[0] is state == field 3). field 22 -> rest[19].
	if len(rest) < 20 {
		return time.Time{}, err
	}
	ticks, err := strconv.ParseInt(rest[19], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	bt, err := bootTime()
	if err != nil {
		return time.Time{}, err
	}
	const clkTck = 100 // USER_HZ; standard on Linux/amd64
	secs := ticks / clkTck
	nsec := (ticks % clkTck) * (int64(time.Second) / clkTck)
	return bt.Add(time.Duration(secs)*time.Second + time.Duration(nsec)), nil
}

func bootTime() (time.Time, error) {
	if !cachedBootTime.IsZero() {
		return cachedBootTime, nil
	}
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			sec, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			cachedBootTime = time.Unix(sec, 0)
			return cachedBootTime, nil
		}
	}
	return time.Time{}, err
}

// HasControllingTTY reports whether pid has a controlling terminal (tty_nr,
// field 7 of /proc/<pid>/stat, is non-zero): a shell in a terminal or an ssh
// session has one; a reverse shell over a plain socket or a script shell does not.
func HasControllingTTY(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	return parseHasTTY(string(data))
}

func parseHasTTY(stat string) bool {
	rparen := strings.LastIndexByte(stat, ')')
	if rparen < 0 {
		return false
	}
	rest := strings.Fields(stat[rparen+1:]) // rest[0] = state (field 3)
	if len(rest) < 5 {
		return false
	}
	tty, err := strconv.Atoi(rest[4])
	return err == nil && tty != 0
}

// AnnotateBrk marks regions the kernel labels "[heap]" that are NOT the brk
// heap. The kernel gives that label to any mapping overlapping the brk range,
// and when the brk heap is unused (start_brk == brk) a large anonymous mmap
// placed over start_brk gets it too: V8 puts its 512MB rwx code range there in
// some runs and in others not, so the same JIT region shows up as "[anon:v8]"
// one day and "[heap]" the next. The real brk heap always begins exactly at
// start_brk; a "[heap]" region starting anywhere else is plain anonymous memory.
func AnnotateBrk(pid int, regions []Region) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return
	}
	startBrk, ok := parseStartBrk(string(data))
	if !ok {
		return
	}
	for i := range regions {
		if regions[i].Path == "[heap]" && regions[i].Start != startBrk {
			regions[i].NotBrkHeap = true
		}
	}
}

// parseStartBrk returns field 47 (start_brk) of /proc/<pid>/stat.
func parseStartBrk(stat string) (uint64, bool) {
	rparen := strings.LastIndexByte(stat, ')')
	if rparen < 0 {
		return 0, false
	}
	rest := strings.Fields(stat[rparen+1:]) // rest[0] = state (field 3)
	if len(rest) < 45 {
		return 0, false
	}
	v, err := strconv.ParseUint(rest[44], 10, 64)
	return v, err == nil && v != 0
}
