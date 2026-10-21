// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"syscall"
	"time"
)

// AnnotateReplaced marks executable mappings whose backing file was deleted
// because it was REPLACED, the signature of a package upgrade: a package
// manager writes the new library and renames it over the old one, so a process
// that was already running keeps mapping the old, now-deleted inode.
//
// A mapping is marked ReplacedOnDisk only when all of these hold, so an
// attacker's dropped-and-unlinked library (the case the deleted-backing check
// exists for) is not excused:
//   - a regular file now exists at the same path, with a different inode;
//   - it is owned by root and not group/world-writable (package-managed; a
//     compromised service account cannot plant such a file);
//   - it was created (ctime) after the process started.
func AnnotateReplaced(pid int, regions []Region, procStart time.Time) {
	if procStart.IsZero() {
		return
	}
	for i := range regions {
		r := &regions[i]
		if !r.Deleted || !r.Exec || r.Path == "" {
			continue
		}
		host, ok := ResolveBackingPath(pid, r.Path)
		if !ok {
			continue // nothing at that path any more: not an upgrade
		}
		var st syscall.Stat_t
		if err := syscall.Stat(host, &st); err != nil {
			continue
		}
		created := time.Unix(st.Ctim.Sec, st.Ctim.Nsec)
		r.ReplacedOnDisk = st.Ino != r.Inode &&
			st.Uid == 0 &&
			st.Mode&(syscall.S_IWGRP|syscall.S_IWOTH) == 0 &&
			!created.Before(procStart)
	}
}
