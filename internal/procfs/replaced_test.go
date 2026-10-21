// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAnnotateReplacedPackageManagedFile(t *testing.T) {
	// /usr/bin/ls is root-owned and not group/world-writable, like any packaged
	// library. A process "started" at the epoch predates its installation.
	if _, err := os.Stat("/usr/bin/ls"); err != nil {
		t.Skip("/usr/bin/ls not present")
	}
	r := []Region{{Exec: true, Deleted: true, Path: "/usr/bin/ls", Inode: 1}}
	AnnotateReplaced(os.Getpid(), r, time.Unix(1, 0))
	if !r[0].ReplacedOnDisk {
		t.Error("root-owned file installed after process start should count as an upgrade")
	}
}

// The security property: a file the attacker could have written themselves
// (not root-owned) never excuses a deleted executable mapping.
func TestAnnotateReplacedIgnoresUserOwnedFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: temp files are root-owned")
	}
	p := filepath.Join(t.TempDir(), "evil.so")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := []Region{{Exec: true, Deleted: true, Path: p, Inode: 1}}
	AnnotateReplaced(os.Getpid(), r, time.Unix(1, 0))
	if r[0].ReplacedOnDisk {
		t.Error("user-owned replacement must not be treated as a package upgrade")
	}
}

func TestAnnotateReplacedNeedsReplacementAfterStart(t *testing.T) {
	r := []Region{{Exec: true, Deleted: true, Path: "/usr/bin/ls", Inode: 1}}
	AnnotateReplaced(os.Getpid(), r, time.Now().Add(time.Hour)) // process "newer" than the file
	if r[0].ReplacedOnDisk {
		t.Error("a file older than the process cannot explain the deletion")
	}
}
