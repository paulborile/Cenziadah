// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package watch is the continuous all-process monitoring loop: learn a baseline
// with one sweep, then sweep on an interval and hand each result plus its delta
// (new / resolved findings) to a Sink. The silent log output and the interactive
// TUI are both Sinks; the loop itself has no output or UI code.
package watch

import (
	"context"
	"fmt"
	"time"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/scan"
)

// Sweeper is the part of scan.Scanner the loop uses (a seam for tests).
type Sweeper interface {
	Learn(ctx context.Context) (*baseline.Set, scan.Result, error)
	Scan(ctx context.Context) (scan.Result, error)
	SetBaselines(scan.BaselineSource)
}

// Sink receives the loop's output. Calls are made from the loop's goroutine, one
// at a time.
type Sink interface {
	// Learning is called before the baseline sweep starts.
	Learning()
	// Learned is called once with the learned baseline and that sweep's result.
	Learned(set *baseline.Set, res scan.Result)
	// Sweep is called after every later sweep (n counts from 1) with the result
	// and its delta against the previous sweep.
	Sweep(n int, res scan.Result, events []model.Event)
	// Error reports a failed sweep; the loop keeps going.
	Error(err error)
}

// Warner is an optional Sink extension for operational warnings (e.g. sweeps
// slower than the interval). Sinks without it do not get them.
type Warner interface {
	Warn(msg string)
}

// slowWarnEvery limits the slow-sweep warning to one per hour.
const slowWarnEvery = time.Hour

// Config controls the loop.
type Config struct {
	Interval time.Duration
	// Rescan, when non-nil, triggers an immediate sweep on receive (TUI "r").
	Rescan <-chan struct{}
}

// Run learns the baseline, then sweeps until ctx is cancelled, waiting Interval
// after each sweep ENDS (not on a fixed ticker): a sweep slower than the
// interval then never chains into the next one, so cenziadah is idle at least
// as long as it works.
// It returns ctx.Err() on cancellation, or the error of a failed learn sweep
// (without a baseline the loop would flag every JIT, so it does not start).
func Run(ctx context.Context, sw Sweeper, cfg Config, sink Sink) error {
	sink.Learning()
	set, prev, err := sw.Learn(ctx)
	if err != nil {
		return err
	}
	sw.SetBaselines(set)
	sink.Learned(set, prev)

	wait := time.NewTimer(cfg.Interval)
	defer wait.Stop()
	var warned time.Time
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait.C:
		case <-cfg.Rescan:
			wait.Stop()
		}
		start := time.Now()
		res, err := sw.Scan(ctx)
		took := time.Since(start)
		wait.Reset(cfg.Interval)
		if ctx.Err() != nil {
			return ctx.Err() // cancelled mid-sweep: drop the partial result
		}
		if w, ok := sink.(Warner); ok && took > cfg.Interval && time.Since(warned) > slowWarnEvery {
			warned = time.Now()
			w.Warn(fmt.Sprintf("a sweep took %s, longer than the interval (%s): consider a longer --interval", took.Round(time.Millisecond), cfg.Interval))
		}
		if err != nil {
			sink.Error(err)
			continue
		}
		sink.Sweep(n, res, scan.Diff(&prev, res))
		prev = res
	}
}
