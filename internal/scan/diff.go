// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package scan

import (
	"fmt"
	"time"

	"github.com/paulborile/cenziadah/internal/model"
)

// Diff compares the active findings of two consecutive sweeps and returns what
// appeared (EventNew) and what went away (EventResolved). prev may be nil (the
// first sweep): every active finding in cur is then new. A finding is matched by
// pid + technique + title + detail, so a restarted process (new pid) reports its
// findings again rather than inheriting the old process's state.
func Diff(prev *Result, cur Result) []model.Event {
	before := activeIndex(prev)
	after := activeIndex(&cur)
	at := cur.FinishedAt
	if at.IsZero() {
		at = time.Now()
	}

	var events []model.Event
	for _, rep := range cur.Reports {
		for _, f := range rep.Active() {
			if _, seen := before[findingKey(rep.Target.PID, f)]; !seen {
				events = append(events, model.Event{Kind: model.EventNew, At: at, Target: rep.Target, Finding: f})
			}
		}
	}
	if prev != nil {
		for _, rep := range prev.Reports {
			for _, f := range rep.Active() {
				if _, still := after[findingKey(rep.Target.PID, f)]; !still {
					events = append(events, model.Event{Kind: model.EventResolved, At: at, Target: rep.Target, Finding: f})
				}
			}
		}
	}
	return events
}

func activeIndex(r *Result) map[string]struct{} {
	idx := map[string]struct{}{}
	if r == nil {
		return idx
	}
	for _, rep := range r.Reports {
		for _, f := range rep.Active() {
			idx[findingKey(rep.Target.PID, f)] = struct{}{}
		}
	}
	return idx
}

func findingKey(pid int, f model.Finding) string {
	return fmt.Sprintf("%d|%s|%s|%s", pid, f.Technique, f.Title, f.Detail)
}
