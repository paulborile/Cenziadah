// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package systemd

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func all(string) bool { return true }

// The stock Ubuntu apt-daily.service.
const aptDaily = `[Unit]
Description=Daily apt download activities
[Service]
Type=oneshot
ExecStartPre=-/usr/lib/apt/apt-helper wait-online
ExecStart=/usr/lib/apt/apt.systemd.daily update
`

func TestAptDailyProductionCase(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/lib/systemd/system/apt-daily.service", aptDaily)
	u, ok := Load(root, "apt-daily.service", all)
	if !ok || !u.Oneshot {
		t.Fatalf("unit = %+v ok=%v", u, ok)
	}
	// exactly the command line seen in production (script run through /bin/sh)
	if !u.Matches("/bin/sh /usr/lib/apt/apt.systemd.daily update", true) {
		t.Error("script started through its interpreter should match ExecStart")
	}
	if !u.Matches("/usr/lib/apt/apt-helper wait-online", false) {
		t.Error("ExecStartPre (with '-' prefix) should match")
	}
	if u.Matches("/bin/sh -c curl x | sh", true) || u.Matches("/bin/sh /usr/lib/apt/apt.systemd.daily update", false) {
		t.Error("other commands, or the interpreter form for a non-interpreter, must not match")
	}
}

func TestDropInOverridesAndTemplates(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/lib/systemd/system/web.service", "[Service]\nExecStart=/usr/bin/old --x\n")
	write(t, root, "etc/systemd/system/web.service.d/override.conf", "[Service]\nExecStart=\nExecStart=/usr/bin/new \\\n  --y\n")
	u, _ := Load(root, "web.service", all)
	if u.Matches("/usr/bin/old --x", false) || !u.Matches("/usr/bin/new --y", false) || u.Oneshot {
		t.Errorf("drop-in should reset and replace ExecStart: %+v", u)
	}
	write(t, root, "usr/lib/systemd/system/getty@.service", "[Service]\nExecStart=-/sbin/agetty -o '-p -- \\\\u' --noclear %I $TERM\n")
	g, ok := Load(root, "getty@tty1.service", all)
	if !ok || len(g.Execs) != 1 {
		t.Fatalf("template: %+v %v", g, ok)
	}
}

func TestUntrustedUnitIgnored(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/systemd/system/x.service", "[Service]\nExecStart=/tmp/evil\n")
	if _, ok := Load(root, "x.service", func(string) bool { return false }); ok {
		t.Error("an untrusted unit file must not be loaded")
	}
}
