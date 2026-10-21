// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDescendantsSubtree(t *testing.T) {
	// Build a real 3-level process subtree: self -> sh -> sleep, and assert both the
	// child (sh) and grandchild (sleep) are returned by Descendants (direct Children
	// would miss the grandchild).
	// sh spawns a sleep and waits, so both stay alive during the test.
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & wait")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start helper: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	time.Sleep(300 * time.Millisecond) // let the grandchild spawn

	kids, err := Descendants(os.Getpid())
	if err != nil {
		t.Fatalf("Descendants: %v", err)
	}
	var sawSh, sawSleep bool
	for _, k := range kids {
		if k.PID == cmd.Process.Pid {
			sawSh = true // direct child (the sh)
		} else if strings.Contains(k.Cmdline, "sleep 30") {
			sawSleep = true // grandchild (match the sh's own cmdline is excluded above)
		}
	}
	if !sawSh {
		t.Error("expected the direct child (sh) in descendants")
	}
	if !sawSleep {
		t.Error("expected the grandchild (sleep) in descendants — subtree walk failed")
	}
}
