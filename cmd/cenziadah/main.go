// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Command cenziadah is a defensive runtime-integrity checker for Linux processes.
//
// It opens no listening sockets and reads no attacker-controlled input: the
// target's memory and on-disk ELF files are treated as opaque, bounded, read-only
// data. It requires CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH (or root) to inspect
// another user's process.
package main

import (
	"fmt"
	"os"

	"github.com/paulborile/cenziadah/internal/version"
)

// exit codes (see PLAN.md): 0 clean, 1 findings at/above threshold, 2 operational.
const (
	exitClean   = 0
	exitFinding = 1
	exitOpError = 2
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(exitOpError)
	}
	var code int
	switch os.Args[1] {
	case "snapshot":
		code = cmdSnapshot(os.Args[2:])
	case "check":
		code = cmdCheck(os.Args[2:])
	case "watch":
		code = cmdWatch(os.Args[2:])
	case "incidents":
		fmt.Fprintf(os.Stderr, "cenziadah: %q not implemented yet\n", os.Args[1])
		code = exitOpError
	case "version", "--version", "-v":
		fmt.Println(version.Info())
		code = exitClean
	case "-h", "--help", "help":
		usage(os.Stdout)
		code = exitClean
	default:
		fmt.Fprintf(os.Stderr, "cenziadah: unknown command %q\n", os.Args[1])
		usage(os.Stderr)
		code = exitOpError
	}
	os.Exit(code)
}

func usage(w *os.File) {
	fmt.Fprint(w, `cenziadah - Linux process runtime-integrity checker

usage:
  cenziadah snapshot  --pid <n> | --name <name>  -o baseline.json
  cenziadah check     --pid <n> | --name <name>  [--baseline baseline.json] [--json]
  cenziadah watch     [--tui] [--interval 10s] [--min-age <dur>] [--json] [--no-mem]
                      [--no-auto-learn] [--skip-exe PATH=REASON ...]
                      [--mail-to ADDR [--mail-min medium] [--mail-max-per-hour 20]
                       [--sendmail /usr/sbin/sendmail] [--mail-from ADDR]]
                      all processes: learns a baseline from the first sweep, then
                      reports only new/resolved findings (log lines, or a live list with --tui)
  cenziadah incidents list | show <id> | export
  cenziadah version

exit codes: 0 clean, 1 findings found, 2 operational error (e.g. needs sudo)
`)
}
