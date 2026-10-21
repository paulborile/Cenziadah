// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// TrustedExe reports whether the binary process pid is running looks
// package-installed: the running image (/proc/<pid>/exe, the actual inode, even
// if since deleted) is a regular file owned by root and not group/world-
// writable, and so is the directory it lives in. A compromised non-root account
// cannot create such a file, so it is a reasonable bar for accepting a program
// that was not running when a baseline was learned (e.g. a new version after an
// upgrade). Binaries in /tmp, home directories or any writable directory fail.
func TrustedExe(pid int) bool {
	var st syscall.Stat_t
	if err := syscall.Stat(ExeLink(pid), &st); err != nil || !rootOnly(st) || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return false
	}
	link, err := os.Readlink(ExeLink(pid))
	if err != nil {
		return false
	}
	dir := "/proc/" + strconv.Itoa(pid) + "/root" + path.Dir(TrimDeleted(link))
	var dst syscall.Stat_t
	if err := syscall.Stat(dir, &dst); err != nil {
		// the host directory of that name is the same one only in our own
		// mount namespace (see ResolveBackingPath)
		if !SameMountNamespace(pid) {
			return false
		}
		if err := syscall.Stat(path.Dir(TrimDeleted(link)), &dst); err != nil {
			return false
		}
	}
	return rootOnly(dst)
}

// TrustedPath is TrustedExe for a program that is no longer running (a child
// that exited before it could be inspected): the file at exe, as seen in the
// mount namespace of process nsPID (its parent), must be a regular file owned by
// root and not group/world-writable, in a directory with the same properties.
func TrustedPath(nsPID int, exe string) bool {
	exe = TrimDeleted(exe)
	if exe == "" || !strings.HasPrefix(exe, "/") {
		return false
	}
	root := "/proc/" + strconv.Itoa(nsPID) + "/root"
	var st, dst syscall.Stat_t
	if err := syscall.Stat(root+exe, &st); err != nil {
		// never judge another namespace's program by the host file of that name
		if !SameMountNamespace(nsPID) {
			return false
		}
		if err := syscall.Stat(exe, &st); err != nil {
			return false
		}
		root = ""
	}
	if !rootOnly(st) || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return false
	}
	if err := syscall.Stat(root+path.Dir(exe), &dst); err != nil {
		return false
	}
	return rootOnly(dst)
}

// TrustedPathUnder is TrustedPath for a file somewhere below directory top: the
// file and EVERY directory from its own up to top must be root-owned and not
// group/world-writable, so no non-root account can have placed or swapped in
// any part of the path. file must be a clean absolute path strictly below top.
func TrustedPathUnder(nsPID int, top, file string) bool {
	if file != path.Clean(file) || !strings.HasPrefix(file, top+"/") || !TrustedPath(nsPID, file) {
		return false
	}
	root := "/proc/" + strconv.Itoa(nsPID) + "/root"
	if _, err := os.Lstat(root + "/"); err != nil {
		if !SameMountNamespace(nsPID) {
			return false
		}
		root = ""
	}
	for dir := path.Dir(file); ; dir = path.Dir(dir) {
		var st syscall.Stat_t
		if err := syscall.Stat(root+dir, &st); err != nil || !rootOnly(st) {
			return false
		}
		if dir == top {
			return true
		}
	}
}

// rootOnly: owned by root and writable by no one else. Group-write is allowed
// only for root's own group (gid 0): some packages ship 0775 root:root files
// (VS Code's vsce-sign), and gid 0 grants no unprivileged account anything.
func rootOnly(st syscall.Stat_t) bool {
	if st.Uid != 0 || st.Mode&syscall.S_IWOTH != 0 {
		return false
	}
	return st.Mode&syscall.S_IWGRP == 0 || st.Gid == 0
}

// ReplacedSince reports whether the file at path (in process nsPID's mount
// namespace) is package-installed (TrustedPath) and was put in place at or
// after since: its ctime, which only the kernel sets (changing it needs root to
// change the clock), is not before since. A package upgrade that replaced a
// library after a baseline was learned satisfies it; a non-root account cannot.
func ReplacedSince(nsPID int, path string, since time.Time) bool {
	if since.IsZero() || !TrustedPath(nsPID, path) {
		return false
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/"+strconv.Itoa(nsPID)+"/root"+path, &st); err != nil {
		if !SameMountNamespace(nsPID) || syscall.Stat(path, &st) != nil {
			return false
		}
	}
	return !time.Unix(st.Ctim.Sec, st.Ctim.Nsec).Before(since)
}
