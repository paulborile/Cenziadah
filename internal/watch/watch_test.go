// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package watch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/scan"
)

// fakeSweeper returns a scripted sequence of sweep results.
type fakeSweeper struct {
	learnErr error
	sweeps   []scan.Result
	n        int
	baseSet  bool
}

func (f *fakeSweeper) Learn(context.Context) (*baseline.Set, scan.Result, error) {
	return baseline.NewSet(), scan.Result{}, f.learnErr
}

func (f *fakeSweeper) Scan(context.Context) (scan.Result, error) {
	if f.n >= len(f.sweeps) {
		return scan.Result{}, nil
	}
	f.n++
	return f.sweeps[f.n-1], nil
}

func (f *fakeSweeper) SetBaselines(scan.BaselineSource) { f.baseSet = true }

type recSink struct {
	learning, learned bool
	sweeps            chan []model.Event
}

func (r *recSink) Learning()                                    { r.learning = true }
func (r *recSink) Learned(*baseline.Set, scan.Result)           { r.learned = true }
func (r *recSink) Sweep(_ int, _ scan.Result, ev []model.Event) { r.sweeps <- ev }
func (r *recSink) Error(error)                                  {}

func TestRunLearnsThenEmitsDeltas(t *testing.T) {
	rogue := model.Report{Target: model.TargetDesc{PID: 7}, Findings: []model.Finding{{Technique: model.TechUnexpectedChild, Title: "x"}}}
	sw := &fakeSweeper{sweeps: []scan.Result{
		{Reports: []model.Report{rogue}}, // sweep 1: rogue child appears
		{Reports: []model.Report{rogue}}, // sweep 2: unchanged
	}}
	sink := &recSink{sweeps: make(chan []model.Event, 4)}
	rescan := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- Run(ctx, sw, Config{Interval: time.Hour, Rescan: rescan}, sink) }()

	rescan <- struct{}{}
	if ev := <-sink.sweeps; len(ev) != 1 || ev[0].Kind != model.EventNew {
		t.Errorf("sweep 1 events = %+v, want one new", ev)
	}
	rescan <- struct{}{}
	if ev := <-sink.sweeps; len(ev) != 0 {
		t.Errorf("sweep 2 unchanged, want no events, got %+v", ev)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v, want context.Canceled", err)
	}
	if !sink.learning || !sink.learned || !sw.baseSet {
		t.Error("learn phase not reported or baseline not installed")
	}
}

func TestRunStopsWhenLearnFails(t *testing.T) {
	sw := &fakeSweeper{learnErr: errors.New("no /proc")}
	err := Run(context.Background(), sw, Config{Interval: time.Hour}, &recSink{})
	if err == nil {
		t.Fatal("a failed learn sweep must stop the loop")
	}
}

type countSink struct{ learning, learned, sweeps, errs int }

func (c *countSink) Learning()                             { c.learning++ }
func (c *countSink) Learned(*baseline.Set, scan.Result)    { c.learned++ }
func (c *countSink) Sweep(int, scan.Result, []model.Event) { c.sweeps++ }
func (c *countSink) Error(error)                           { c.errs++ }

func TestTeeForwardsToAll(t *testing.T) {
	a, b := &countSink{}, &countSink{}
	s := Tee(a, b)
	s.Learning()
	s.Learned(baseline.NewSet(), scan.Result{})
	s.Sweep(1, scan.Result{}, nil)
	s.Error(errors.New("x"))
	for _, c := range []*countSink{a, b} {
		if *c != (countSink{1, 1, 1, 1}) {
			t.Errorf("sink got %+v", *c)
		}
	}
}

// slowSweeper's sweeps each take `took`; it records when each one started and ended.
type slowSweeper struct {
	took        time.Duration
	starts, end []time.Time
}

func (s *slowSweeper) Learn(context.Context) (*baseline.Set, scan.Result, error) {
	return baseline.NewSet(), scan.Result{}, nil
}
func (s *slowSweeper) Scan(context.Context) (scan.Result, error) {
	s.starts = append(s.starts, time.Now())
	time.Sleep(s.took)
	s.end = append(s.end, time.Now())
	return scan.Result{}, nil
}
func (s *slowSweeper) SetBaselines(scan.BaselineSource) {}

type warnSink struct {
	recSink
	warnings []string
}

func (w *warnSink) Warn(msg string) { w.warnings = append(w.warnings, msg) }

// A sweep slower than the interval never chains into the next one: the loop
// waits the full interval after each sweep ends, and warns once.
func TestRunWaitsIntervalAfterEachSweep(t *testing.T) {
	const interval = 20 * time.Millisecond
	sw := &slowSweeper{took: 30 * time.Millisecond}
	sink := &warnSink{recSink: recSink{sweeps: make(chan []model.Event, 100)}}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_ = Run(ctx, sw, Config{Interval: interval}, sink)

	if len(sw.starts) < 3 {
		t.Fatalf("only %d sweeps ran", len(sw.starts))
	}
	for i := 1; i < len(sw.starts); i++ {
		if gap := sw.starts[i].Sub(sw.end[i-1]); gap < interval-2*time.Millisecond {
			t.Errorf("sweep %d started %s after the previous ended, want >= %s", i, gap, interval)
		}
	}
	if len(sink.warnings) != 1 {
		t.Errorf("warnings = %q, want exactly one (rate-limited)", sink.warnings)
	}
}
