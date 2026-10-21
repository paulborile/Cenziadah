// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package watch

import (
	"fmt"
	"io"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/report"
	"github.com/paulborile/cenziadah/internal/scan"
	"github.com/paulborile/cenziadah/internal/version"
)

// LogSink is the silent (headless) output: one line per event on Out, and
// sparse status/progress lines on Status. A steady state prints nothing.
type LogSink struct {
	Out    io.Writer // events
	Status io.Writer // learn summary, errors
	JSON   bool      // JSON Lines instead of text
}

func (l LogSink) Learning() {
	fmt.Fprintln(l.Status, version.Info())
	fmt.Fprintln(l.Status, "cenziadah: learning baseline from all processes (assumes the host is clean now)...")
}

func (l LogSink) Learned(set *baseline.Set, res scan.Result) {
	fmt.Fprintf(l.Status, "cenziadah: baseline learned: %d processes, %d identities, %d module digest conflicts (%s)\n",
		res.Stats.Scanned, set.Len(), set.Conflicts, res.FinishedAt.Sub(res.StartedAt).Round(1e6))
	if len(res.Skipped) > 0 {
		fmt.Fprintf(l.Status, "cenziadah: skipped %d: %s\n", len(res.Skipped), res.SkipSummary())
	}
	if n := degraded(res); n > 0 {
		fmt.Fprintf(l.Status, "cenziadah: warning: %d processes checked without memory access; run as root or grant CAP_SYS_PTRACE for module integrity\n", n)
	}
	if n := len(res.Accepted); n > 0 {
		fmt.Fprintf(l.Status, "cenziadah: %d finding(s) were already present and are now accepted as normal (LEARNED lines); if this host may already be compromised, investigate them\n", n)
	}
	if l.JSON {
		l.emit(res.Accepted) // one event per finding for machines
	} else {
		report.LearnedText(l.Out, res.Accepted) // one line per process for people
	}
}

func (l LogSink) Sweep(_ int, res scan.Result, events []model.Event) {
	for _, t := range res.NewPrograms {
		fmt.Fprintf(l.Status, "cenziadah: learned new program (package-installed binary, not running at start): pid %d %s %s\n",
			t.PID, t.Name, t.Exe)
	}
	if l.JSON {
		l.emit(res.Accepted)
	} else {
		report.LearnedText(l.Out, res.Accepted)
	}
	l.emit(events)
}

// Warn reports an operational warning (watch.Warner).
func (l LogSink) Warn(msg string) {
	fmt.Fprintf(l.Status, "cenziadah: warning: %s\n", msg)
}

func (l LogSink) Error(err error) {
	fmt.Fprintf(l.Status, "cenziadah: sweep failed: %v\n", err)
}

func (l LogSink) emit(events []model.Event) {
	for _, e := range events {
		if l.JSON {
			_ = report.EventJSON(l.Out, e)
		} else {
			report.EventText(l.Out, e)
		}
	}
}

func degraded(res scan.Result) int {
	n := 0
	for _, r := range res.Reports {
		if r.Degraded != "" {
			n++
		}
	}
	return n
}
