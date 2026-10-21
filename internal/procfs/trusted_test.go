// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestTrustedExeSystemBinary(t *testing.T) {
	cmd := exec.Command("/usr/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	if !TrustedExe(cmd.Process.Pid) {
		t.Error("/usr/bin/sleep (root-owned, in a root-only dir) should be trusted")
	}
}

func TestTrustedExeUserBinary(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("as root the test binary is root-owned")
	}
	// The test binary itself lives in a user-owned temp directory.
	if TrustedExe(os.Getpid()) {
		t.Error("a user-owned binary must not be trusted")
	}
}

func TestTrustedPath(t *testing.T) {
	if !TrustedPath(os.Getpid(), "/usr/bin/ls") {
		t.Error("/usr/bin/ls should be trusted by path")
	}
	if os.Getuid() != 0 {
		p := t.TempDir() + "/x"
		os.WriteFile(p, []byte("x"), 0o755)
		if TrustedPath(os.Getpid(), p) {
			t.Error("user-owned file must not be trusted")
		}
	}
	if TrustedPath(os.Getpid(), "") || TrustedPath(os.Getpid(), "relative/x") {
		t.Error("empty or relative path must not be trusted")
	}
}

func TestTrustedPathUnder(t *testing.T) {
	pid := os.Getpid()
	if !TrustedPathUnder(pid, "/usr", "/usr/bin/ls") {
		t.Error("/usr/bin/ls should be trusted under /usr")
	}
	for _, c := range []struct{ top, file string }{
		{"/usr/bin", "/usr/bin"},             // not strictly below
		{"/usr/lib", "/usr/bin/ls"},          // outside top
		{"/usr", "/usr/lib/../bin/ls"},       // not clean
		{"/usr/b", "/usr/bin/ls"},            // prefix of a dir name, not a parent
		{"/usr", "/usr/bin/no-such-program"}, // missing
	} {
		if TrustedPathUnder(pid, c.top, c.file) {
			t.Errorf("TrustedPathUnder(%q, %q) = true, want false", c.top, c.file)
		}
	}
	if os.Getuid() != 0 {
		dir := t.TempDir()
		os.WriteFile(dir+"/x.sh", []byte("x"), 0o755)
		if TrustedPathUnder(pid, dir, dir+"/x.sh") {
			t.Error("user-owned file must not be trusted")
		}
	}
}

func TestRootOnly(t *testing.T) {
	for _, c := range []struct {
		uid, gid uint32
		mode     uint32
		want     bool
	}{
		{0, 0, 0o755, true},
		{0, 0, 0o775, true},    // group root may write: no unprivileged account gains anything
		{0, 100, 0o775, false}, // another group may write
		{0, 100, 0o755, true},
		{0, 0, 0o757, false},    // world-writable
		{1000, 0, 0o755, false}, // not root-owned
	} {
		st := syscall.Stat_t{Uid: c.uid, Gid: c.gid, Mode: syscall.S_IFREG | c.mode}
		if got := rootOnly(st); got != c.want {
			t.Errorf("rootOnly(uid=%d gid=%d %o) = %v, want %v", c.uid, c.gid, c.mode, got, c.want)
		}
	}
}

func TestReplacedSince(t *testing.T) {
	pid := os.Getpid()
	if !ReplacedSince(pid, "/usr/bin/ls", time.Unix(1, 0)) {
		t.Error("/usr/bin/ls is root-owned and newer than 1970")
	}
	if ReplacedSince(pid, "/usr/bin/ls", time.Now().Add(time.Hour)) {
		t.Error("a file older than the baseline was not replaced since")
	}
	if ReplacedSince(pid, "/usr/bin/ls", time.Time{}) {
		t.Error("no baseline time: no opinion")
	}
	if os.Getuid() != 0 {
		p := t.TempDir() + "/lib.so"
		os.WriteFile(p, []byte("x"), 0o644)
		if ReplacedSince(pid, p, time.Unix(1, 0)) {
			t.Error("a user-owned file must never count as an upgrade")
		}
	}
}
