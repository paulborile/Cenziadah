// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/version"
)

// EventText writes one event as a single log line, e.g.
//
//	2026-10-11T12:00:00Z NEW CRITICAL pid=123 bash (/usr/bin/bash) maps.rwx: writable+executable (rwx) mapping | 0x7f..-0x7f.. rwx [anon]
//
// Attacker-influenced text (cmdline, paths) is escaped so it cannot forge lines.
func EventText(w io.Writer, e model.Event) {
	f := e.Finding
	fmt.Fprintf(w, "%s %s %s pid=%d %s (%s) %s: %s",
		e.At.UTC().Format(time.RFC3339), strings.ToUpper(string(e.Kind)), f.Severity,
		e.Target.PID, oneLine(e.Target.Name), oneLine(e.Target.Exe), f.Technique, oneLine(f.Title))
	if f.Detail != "" {
		fmt.Fprintf(w, " | %s", oneLine(f.Detail))
	}
	fmt.Fprintln(w)
}

// EventJSON writes one event as a single JSON line (JSON Lines).
// Each line carries the reporting cenziadah version.
func EventJSON(w io.Writer, e model.Event) error {
	if e.Version == "" {
		e.Version = version.Version
	}
	return json.NewEncoder(w).Encode(e)
}

// oneLine quotes control characters so one event is always exactly one line.
func oneLine(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0 {
		return s
	}
	q := fmt.Sprintf("%q", s)
	return q[1 : len(q)-1]
}

// LearnedText writes findings accepted while learning a baseline as ONE line per
// process (a desktop has hundreds of legitimate JIT regions; one line per
// finding would bury the one that matters), e.g.
//
//	2026-10-11T12:00:00Z LEARNED CRITICAL pid=42 victim (/opt/victim) 2 finding(s): maps.rwx x1, proctree.unexpected_child x1
//
// Severity is the worst of the process's findings. Order follows events.
func LearnedText(w io.Writer, events []model.Event) {
	type group struct {
		first  model.Event
		worst  model.Severity
		counts map[model.Technique]int
		order  []model.Technique
		total  int
	}
	var pids []int
	groups := map[int]*group{}
	for _, e := range events {
		g, ok := groups[e.Target.PID]
		if !ok {
			g = &group{first: e, counts: map[model.Technique]int{}}
			groups[e.Target.PID] = g
			pids = append(pids, e.Target.PID)
		}
		if e.Finding.Severity > g.worst {
			g.worst = e.Finding.Severity
		}
		if g.counts[e.Finding.Technique] == 0 {
			g.order = append(g.order, e.Finding.Technique)
		}
		g.counts[e.Finding.Technique]++
		g.total++
	}
	for _, pid := range pids {
		g := groups[pid]
		parts := make([]string, len(g.order))
		for i, t := range g.order {
			parts[i] = fmt.Sprintf("%s x%d", t, g.counts[t])
		}
		fmt.Fprintf(w, "%s LEARNED %s pid=%d %s (%s) %d finding(s): %s\n",
			g.first.At.UTC().Format(time.RFC3339), g.worst, pid, oneLine(g.first.Target.Name),
			oneLine(g.first.Target.Exe), g.total, strings.Join(parts, ", "))
	}
}
