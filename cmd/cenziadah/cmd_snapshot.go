// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/engine"
)

func cmdSnapshot(args []string) int {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	pid := fs.Int("pid", 0, "target process id")
	name := fs.String("name", "", "target process name (comm or argv[0])")
	out := fs.String("o", "baseline.json", "output snapshot path")
	if err := fs.Parse(args); err != nil {
		return exitOpError
	}

	target, err := engine.ResolvePID(*pid, *name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cenziadah: %v\n", err)
		return exitOpError
	}

	// Snapshot needs memory to digest module .text.
	tgt, err := engine.Collect(target, true, nil)
	if err != nil {
		return reportCollectError(err)
	}
	defer tgt.Mem.Close()

	snap, err := engine.BuildSnapshot(tgt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cenziadah: build snapshot: %v\n", err)
		return exitOpError
	}
	if err := baseline.Save(*out, snap); err != nil {
		fmt.Fprintf(os.Stderr, "cenziadah: save: %v\n", err)
		return exitOpError
	}
	fmt.Printf("snapshot of pid %d (%s) written to %s: %d modules, %d region shapes\n",
		target, snap.Target.Name, *out, len(snap.Modules), len(snap.Regions))
	return exitClean
}

// reportCollectError turns a collection error into the right exit code + message,
// specially handling the "needs elevated privilege" case.
func reportCollectError(err error) int {
	if engine.IsPermission(err) {
		fmt.Fprintf(os.Stderr, "cenziadah: permission denied reading /proc — run with sudo or grant CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH\n")
		return exitOpError
	}
	fmt.Fprintf(os.Stderr, "cenziadah: collect: %v\n", err)
	return exitOpError
}
