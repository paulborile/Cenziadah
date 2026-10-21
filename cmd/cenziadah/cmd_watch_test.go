// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMailConfigValidation(t *testing.T) {
	for _, c := range []struct {
		to, from, min string
		max           int
		sendmail      string
		ok            bool
	}{
		{"ops@example.com", "", "medium", 20, "/usr/bin/true", true},
		{"not-an-address", "", "medium", 20, "/usr/bin/true", false},
		{"ops@example.com", "x\nBcc: y@z.org", "medium", 20, "/usr/bin/true", false},
		{"ops@example.com", "", "loud", 20, "/usr/bin/true", false},
		{"ops@example.com", "", "medium", 0, "/usr/bin/true", false},
		{"ops@example.com", "", "medium", 20, "/nonexistent/sendmail", false},
	} {
		if _, err := mailConfig(c.to, c.from, c.min, c.max, c.sendmail); (err == nil) != c.ok {
			t.Errorf("%+v: err=%v", c, err)
		}
	}
	if os.Getuid() != 0 {
		p := filepath.Join(t.TempDir(), "sendmail")
		os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755)
		if _, err := mailConfig("ops@example.com", "", "medium", 20, p); err == nil {
			t.Error("a sendmail not owned by root must be refused")
		}
	}
}

// --check-config validates and exits without scanning; a quoting mistake in
// /etc/default/cenziadah fails loudly (seen live: CENZIADAH_ARGS="--interval
// 10s" --mail-to x reached cenziadah as "--interval 10s--mail-to x").
func TestWatchCheckConfig(t *testing.T) {
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"--check-config", "--interval", "10s"}, exitClean},
		{[]string{"--check-config", "--interval", "10s", "--mail-to", "ops@example.com", "--sendmail", "/usr/bin/true"}, exitClean},
		{[]string{"--check-config", "--interval", "10s--mail-to", "ops@example.com"}, exitOpError},
		{[]string{"--check-config", "--interval", "10s", "stray"}, exitOpError},
		{[]string{"--check-config", "--mail-to", "not-an-address"}, exitOpError},
		{[]string{"--check-config", "--interval", "100ms"}, exitOpError},
	} {
		if got := cmdWatch(c.args); got != c.want {
			t.Errorf("cmdWatch(%q) = %d, want %d", c.args, got, c.want)
		}
	}
}
