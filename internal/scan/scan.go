// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package scan sweeps every eligible process on the host through the existing
// detection pipeline (engine.CollectInScan -> engine.Run) and returns one
// model.Report per process. It is the shared core of the all-process modes: the
// interactive TUI and the silent `watch` loop differ only in what they do with
// the Result. The package is headless and has no UI or network dependency.
//
// Policy: scan everything. No process is trusted by name (attackers live in
// boring processes); cost is controlled instead by a per-cycle .text digest cache
// (detector.TextCache), by skipping processes younger than one interval, and by
// an explicit operator skip list whose reasons are recorded in the Result.
package scan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/detector"
	"github.com/paulborile/cenziadah/internal/elfref"
	"github.com/paulborile/cenziadah/internal/engine"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// BaselineSource returns the known-good Snapshot for a process identity (see
// Identity), or nil when the identity has no baseline; that process then gets
// only the absolute (baseline-less) detectors.
type BaselineSource interface {
	Lookup(identity string) *model.Snapshot
}

// Learner is a BaselineSource that can also take new identities; baseline.Set
// is one. Auto-learning (Options.AutoLearn) needs it.
type Learner interface {
	BaselineSource
	Add(identity string, s *model.Snapshot)
}

// ModuleUpgrader is a Learner that can replace a module's known-good state
// after a package upgrade (baseline.Set).
type ModuleUpgrader interface {
	ReplaceModules(identity string, mods []model.ModuleDigest)
}

// Options configures a Scanner.
type Options struct {
	// WithMem opens /proc/<pid>/mem so module integrity runs. Without it (or
	// without CAP_SYS_PTRACE) reports are marked Degraded.
	WithMem bool
	// MinAge skips processes younger than this: they have no stable state to
	// compare and are usually gone before the next cycle. 0 scans all.
	MinAge time.Duration
	// Baselines supplies per-identity known-good state; nil = no baselines.
	Baselines BaselineSource
	// SkipExe is the operator's explicit skip policy: exe path -> reason. It is
	// never built in; every skip is reported with its reason.
	SkipExe map[string]string
	// IncludeSelf scans cenziadah's own process too (off by default).
	IncludeSelf bool
	// Pace is a pause after each inspected process, so a sweep never holds a
	// CPU at 100% for its whole duration. 0 = no pause.
	Pace time.Duration
	// DiskDigests records on-disk .text digests when learning a baseline (for a
	// persisted baseline; costly, and unused by an in-memory one).
	DiskDigests bool
	// AutoLearn: a process whose identity has no baseline is learned on first
	// sight IF its binary is package-installed (procfs.TrustedExe), e.g. a new
	// version after an upgrade. Requires Baselines to be a Learner. Every such
	// program is listed in Result.NewPrograms; findings it already carried are
	// in Result.Accepted. Untrusted binaries keep the strict, baseline-less check.
	AutoLearn bool
}

// Skipped records a process that was not inspected, and why.
type Skipped struct {
	PID    int    `json:"pid"`
	Name   string `json:"name,omitempty"`
	Exe    string `json:"exe,omitempty"`
	Reason string `json:"reason"`
	// Baseline is set for processes skipped as too young: BaselineKnown when
	// their program already has a baseline, BaselineNone otherwise.
	Baseline model.BaselineState `json:"baseline,omitempty"`
}

// Skip reasons, stable so callers can filter or count them.
const (
	ReasonKernel     = "kernel thread"
	ReasonSelf       = "cenziadah itself"
	ReasonTooYoung   = "younger than min age"
	ReasonExited     = "exited during scan"
	ReasonPermission = "permission denied"
	ReasonPolicy     = "policy: "         // + operator's reason
	ReasonCollect    = "collect failed: " // + error
)

// Stats summarises one cycle's cost.
type Stats struct {
	Candidates      int `json:"candidates"` // processes in the table
	Scanned         int `json:"scanned"`
	TextCacheHits   int `json:"text_cache_hits"`
	TextCacheMisses int `json:"text_cache_misses"`
}

// Result is one complete sweep.
type Result struct {
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Reports    []model.Report `json:"reports"` // one per scanned process, by pid
	Skipped    []Skipped      `json:"skipped,omitempty"`
	// Accepted is set by Learn only: findings (above INFO) that the baseline-less
	// detectors raised during the learn sweep and that the learned baseline now
	// treats as normal. A host that was already compromised shows up here.
	Accepted []model.Event `json:"accepted,omitempty"`
	// NewPrograms lists processes whose identity was auto-learned this sweep.
	NewPrograms []model.TargetDesc `json:"new_programs,omitempty"`
	Stats       Stats              `json:"stats"`
}

// Identity is the stable key a process's baseline is stored under: exe path,
// build-id and process name (pid is not stable across restarts). The name is
// needed because unrelated programs can share one executable: every Android app
// runs as /system/bin/app_process64 and is told apart only by its name
// (e.g. "com.whatsapp").
//
// The exe path is taken without the kernel's " (deleted)" suffix, so a process
// keeps its identity when a package upgrade replaces its binary while it runs
// (the build-id, read from the running image, still names the old version).
//
// An Android app update does not change app_process64, so an app's install
// directory (TargetDesc.AppInstall, new for every update) is part of its
// identity: an updated app is a new program, auto-learned like a new native
// version, instead of being checked against the old version's libraries.
func Identity(d model.TargetDesc) string {
	id := procfs.TrimDeleted(d.Exe)
	if d.BuildID != "" {
		id += "@" + d.BuildID
	}
	id += "#" + d.Name
	if d.AppInstall != "" {
		id += "!" + d.AppInstall
	}
	return id
}

// Scanner runs sweeps. Create it once and call Scan per cycle.
type Scanner struct {
	opts Options

	// Seams over /proc, replaced in tests.
	readTable func() (*procfs.ProcTable, error)
	collect   func(pid int, tab *procfs.ProcTable, withMem bool) (*detector.Target, error)
	now       func() time.Time
	selfPID   int
	trusted   func(pid int) bool
	buildID   func(pid int) string
	// terminalShell tests the interactive-shell SHAPE (engine.TerminalShell).
	terminalShell func(pid int, exe string) bool
	// cronJob finds a cron job by command line (engine.CronJob).
	cronJob func(cronPID int, childCmdline string) string
	// oneshotUnit finds a process's Type=oneshot systemd unit (engine.OneshotUnit).
	oneshotUnit func(pid int) string
	// appInstall reads an Android app's install directory (procfs.AppInstallDir).
	appInstall func(pid int) string

	// cache keeps parsed modules and .text digests across sweeps (see
	// engine.SweepCache for why that is sound).
	cache *engine.SweepCache

	// known holds every process (pid -> start time) present in the learn sweep,
	// so their children are accepted as pre-existing even when unreadable.
	known map[int]time.Time
}

// New returns a Scanner reading the live /proc.
func New(opts Options) *Scanner {
	return &Scanner{
		opts:          opts,
		readTable:     procfs.ReadProcTable,
		collect:       engine.CollectInScan,
		now:           time.Now,
		selfPID:       os.Getpid(),
		trusted:       procfs.TrustedExe,
		buildID:       runningBuildID,
		terminalShell: engine.TerminalShell,
		cronJob:       engine.CronJob,
		oneshotUnit:   engine.OneshotUnit,
		appInstall:    procfs.AppInstallDir,
		cache:         engine.NewSweepCache(),
	}
}

// Scan performs one sweep. Processes are inspected sequentially so peak memory
// stays at one process's working set (memory-budget NFR). Per-process failures
// are recorded in Result.Skipped; only an unreadable /proc fails the sweep.
func (s *Scanner) Scan(ctx context.Context) (Result, error) {
	return s.sweep(ctx, nil)
}

// Learn performs one sweep that also records every scanned process's current
// state as known-good, merged per identity. It assumes the host is clean right
// now: anything already compromised is learned as normal. Reports in the Result
// are checked against the learned state.
func (s *Scanner) Learn(ctx context.Context) (*baseline.Set, Result, error) {
	set := baseline.NewSet()
	res, err := s.sweep(ctx, set)
	return set, res, err
}

// SetBaselines replaces the baseline source used by later sweeps (nil = none).
func (s *Scanner) SetBaselines(src BaselineSource) {
	s.opts.Baselines = src
}

// sweep inspects every process; it stops between processes when ctx is cancelled
// and returns ctx.Err() with the partial result.
func (s *Scanner) sweep(ctx context.Context, learn *baseline.Set) (Result, error) {
	res := Result{StartedAt: s.now()}
	tab, err := s.readTable()
	if err != nil {
		return res, err
	}
	if learn != nil {
		s.known = make(map[int]time.Time, len(tab.Entries))
		for _, e := range tab.Entries {
			if !e.StartedAt.IsZero() {
				s.known[e.PID] = e.StartedAt
			}
		}
	}
	cache := s.cache
	cache.DiskDigests = s.opts.DiskDigests
	cache.BeginSweep()
	defer cache.EndSweep()
	dets := engine.ScanDetectors(cache)
	res.Stats.Candidates = len(tab.Entries)

	for _, e := range tab.Entries {
		if err := ctx.Err(); err != nil {
			res.FinishedAt = s.now()
			return res, err
		}
		if reason := s.skipReason(e, res.StartedAt); reason != "" {
			sk := Skipped{PID: e.PID, Name: e.Name, Exe: e.Exe, Reason: reason}
			if reason == ReasonTooYoung {
				sk.Baseline = s.waitingBaseline(e)
			}
			res.Skipped = append(res.Skipped, sk)
			continue
		}
		in := s.inspect(e, tab, dets, cache, learn)
		if err := s.pause(ctx); err != nil {
			res.FinishedAt = s.now()
			return res, err
		}
		if in.skip != "" {
			res.Skipped = append(res.Skipped, Skipped{PID: e.PID, Name: e.Name, Exe: e.Exe, Reason: in.skip})
			continue
		}
		res.Reports = append(res.Reports, in.rep)
		for _, f := range in.accepted {
			res.Accepted = append(res.Accepted, model.Event{Kind: model.EventLearned, At: in.rep.CheckedAt, Target: in.rep.Target, Finding: f})
		}
		if in.autoLearned {
			res.NewPrograms = append(res.NewPrograms, in.rep.Target)
		}
	}

	res.Stats.Scanned = len(res.Reports)
	res.Stats.TextCacheHits, res.Stats.TextCacheMisses = cache.Text.Stats()
	res.FinishedAt = s.now()
	return res, nil
}

// pause waits Options.Pace, returning early with ctx.Err() on cancellation.
func (s *Scanner) pause(ctx context.Context) error {
	if s.opts.Pace <= 0 {
		return nil
	}
	t := time.NewTimer(s.opts.Pace)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// skipReason applies the cheap, table-only filters.
func (s *Scanner) skipReason(e procfs.ProcEntry, now time.Time) string {
	switch {
	case e.Kernel:
		return ReasonKernel
	case e.PID == s.selfPID && !s.opts.IncludeSelf:
		return ReasonSelf
	case s.opts.MinAge > 0 && !e.StartedAt.IsZero() && now.Sub(e.StartedAt) < s.opts.MinAge:
		return ReasonTooYoung
	}
	if why, ok := s.opts.SkipExe[e.Exe]; ok && e.Exe != "" {
		return ReasonPolicy + why
	}
	return ""
}

// inspection is the outcome of inspecting one process.
type inspection struct {
	rep         model.Report
	accepted    []model.Finding // already present when its state was learned
	autoLearned bool            // identity learned on first sight (AutoLearn)
	skip        string          // non-empty: not inspected, and why
}

// inspect collects and checks one process. With learn set (the learn sweep), or
// when an unknown trusted program is auto-learned, the process's state is first
// added as known-good and the findings it already carried (judged without any
// baseline) are returned as accepted.
func (s *Scanner) inspect(e procfs.ProcEntry, tab *procfs.ProcTable, dets []detector.Detector,
	cache *engine.SweepCache, learn *baseline.Set) inspection {
	tgt, err := s.collect(e.PID, tab, s.opts.WithMem)
	degraded := ""
	if err != nil {
		switch {
		case tgt != nil && tgt.Mem == nil && isPermission(err):
			// maps/fds were readable but mem was not: run the memory-free detectors.
			degraded = "no memory access (needs CAP_SYS_PTRACE): module integrity not checked"
		case isExited(err):
			return inspection{skip: ReasonExited}
		case isPermission(err):
			return inspection{skip: ReasonPermission}
		default:
			return inspection{skip: ReasonCollect + err.Error()}
		}
	}
	if tgt.Mem != nil {
		defer tgt.Mem.Close()
	}
	if !s.opts.WithMem {
		degraded = "memory not requested: module integrity not checked"
	}
	for i, c := range tgt.Children {
		if t, ok := s.known[c.PID]; ok && t.Equal(c.StartedAt) {
			tgt.Children[i].PreExisting = true
		}
	}

	tgt.ScheduledJob = s.scheduledJob(tab, tgt.Desc.PID)
	if tgt.ScheduledJob == "" {
		if u := s.oneshotUnit(tgt.Desc.PID); u != "" {
			tgt.ScheduledJob = "systemd one-shot unit " + u
		}
	}
	if s.terminalShell(tgt.Desc.PID, tgt.Desc.Exe) && s.legitimateShell(tab, tgt.Desc.PID, learn, 0) {
		tgt.InteractiveShell = true
	}

	var in inspection
	state := model.BaselineNone
	id := Identity(tgt.Desc)
	switch {
	case learn != nil:
		in.accepted = s.learnInto(learn, id, tgt, dets, cache)
		state = model.BaselineNew
	case s.opts.Baselines != nil:
		tgt.Baseline = s.opts.Baselines.Lookup(id)
		if tgt.Baseline != nil {
			state = model.BaselineChecked
		} else if l, ok := s.opts.Baselines.(Learner); ok && s.opts.AutoLearn && s.trusted(tgt.Desc.PID) {
			in.accepted = s.learnInto(l, id, tgt, dets, cache)
			in.autoLearned = true
			state = model.BaselineNew
		}
	}
	in.rep = engine.Run(tgt, dets)
	in.rep.Degraded = degraded
	in.rep.Baseline = state
	in.accepted = append(in.accepted, s.applyUpgrades(id, tgt, cache, in.rep.Findings)...)
	return in
}

// applyUpgrades replaces the baseline entries of modules a package upgrade
// replaced on disk (detector.EvidenceUpgraded), so later sweeps check the new
// version's .text, and returns those findings to be reported as accepted.
func (s *Scanner) applyUpgrades(id string, tgt *detector.Target, cache *engine.SweepCache, fs []model.Finding) []model.Finding {
	var paths []string
	var upgraded []model.Finding
	for _, f := range fs {
		if up, _ := f.Evidence[detector.EvidenceUpgraded].(bool); up && f.Suppressed {
			if p, ok := f.Evidence["path"].(string); ok {
				paths = append(paths, p)
				upgraded = append(upgraded, f)
			}
		}
	}
	u, ok := s.opts.Baselines.(ModuleUpgrader)
	if len(paths) == 0 || !ok {
		return nil
	}
	u.ReplaceModules(id, engine.ModuleDigests(tgt, paths, cache))
	return upgraded
}

// learnInto records tgt's current state as known-good for id, points tgt at the
// resulting baseline, and returns the findings (above INFO) that state carried
// when judged without a baseline, so they are reported rather than absorbed.
// INFO is left out: without a baseline every child is INFO.
func (s *Scanner) learnInto(l Learner, id string, tgt *detector.Target, dets []detector.Detector, cache *engine.SweepCache) []model.Finding {
	var accepted []model.Finding
	tgt.Baseline = nil
	for _, f := range engine.Run(tgt, dets).Active() {
		if f.Severity > model.SevInfo {
			accepted = append(accepted, f)
		}
	}
	if snap, err := engine.BuildSnapshotCached(tgt, cache); err == nil {
		l.Add(id, snap)
	}
	tgt.Baseline = l.Lookup(id)
	return accepted
}

// legitimateShell decides whether a process with the terminal-shell shape is a
// user's real terminal, so the commands started from it are not findings. Shape
// alone is not enough: `python3 -c 'import pty; pty.spawn("/bin/bash")'` gives
// an attacker the same shape. A shell is legitimate only if:
//   - it was already running when the baseline was learned, or
//   - its parent's baseline lists this shell as an expected child (a terminal
//     emulator, sshd or tmux that started shells before), or
//   - its parent is itself a legitimate terminal shell (a nested shell).
//
// A pty shell under an exploited service fails all three, so what is typed into
// it keeps alerting.
func (s *Scanner) legitimateShell(tab *procfs.ProcTable, pid int, learn *baseline.Set, depth int) bool {
	if depth > 16 {
		return false // bounded: a pathological chain is not a terminal
	}
	e, ok := tab.Entry(pid)
	if !ok {
		return false
	}
	if t, ok := s.known[pid]; ok && !t.IsZero() && t.Equal(e.StartedAt) {
		return true
	}
	parent, ok := tab.Entry(e.PPID)
	if !ok {
		return false
	}
	var src BaselineSource
	switch {
	case learn != nil:
		src = learn
	case s.opts.Baselines != nil:
		src = s.opts.Baselines
	}
	if src != nil {
		if snap := src.Lookup(s.tableIdentity(parent)); snap != nil {
			for _, c := range snap.Children {
				if procfs.TrimDeleted(c.Exe) == procfs.TrimDeleted(e.Exe) {
					return true
				}
			}
		}
	}
	return s.terminalShell(parent.PID, parent.Exe) && s.legitimateShell(tab, parent.PID, learn, depth+1)
}

// scheduledJob reports which root-configured cron job pid belongs to: walking
// up its ancestors to the nearest cron process, the process directly below cron
// must be the shell of a job from a root-owned crontab (exact command line).
// Everything below that shell (run-parts, the cron.daily scripts, their tools)
// is the job's work. A job from a non-root user's crontab, or any other child
// of cron, does not qualify.
func (s *Scanner) scheduledJob(tab *procfs.ProcTable, pid int) string {
	cur := pid
	for depth := 0; depth < 32; depth++ {
		e, ok := tab.Entry(cur)
		if !ok {
			return ""
		}
		p, ok := tab.Entry(e.PPID)
		if !ok {
			return ""
		}
		if engine.IsCron(p.Exe) {
			if src := s.cronJob(p.PID, e.Cmdline); src != "" {
				return "cron job from " + src
			}
			return ""
		}
		cur = p.PID
	}
	return ""
}

// waitingBaseline tells, for a process too young to inspect, whether its program
// already has a baseline. Only the build-id is read (cheap); nothing else.
func (s *Scanner) waitingBaseline(e procfs.ProcEntry) model.BaselineState {
	if s.opts.Baselines == nil || e.Exe == "" {
		return model.BaselineNone
	}
	if s.opts.Baselines.Lookup(s.tableIdentity(e)) != nil {
		return model.BaselineKnown
	}
	return model.BaselineNone
}

// tableIdentity is Identity for a process known only from the process table
// (not collected): the build-id, and an Android app's install directory, are
// read on demand.
func (s *Scanner) tableIdentity(e procfs.ProcEntry) string {
	d := model.TargetDesc{Exe: e.Exe, Name: e.Name, BuildID: s.buildID(e.PID)}
	if procfs.IsAppProcess(e.Exe) {
		d.AppInstall = s.appInstall(e.PID)
	}
	return Identity(d)
}

// runningBuildID is the build-id of the binary pid is running ("" if unreadable).
func runningBuildID(pid int) string {
	id, _ := elfref.BuildID(procfs.ExeLink(pid))
	return id
}

// isExited reports a process that disappeared between listing and reading.
func isExited(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func isPermission(err error) bool {
	return errors.Is(err, fs.ErrPermission)
}

// SkipSummary renders why processes were skipped, most common reason first,
// e.g. "210 permission denied, 180 kernel thread, 3 younger than min age".
// Operator policy and collect-error reasons are grouped by their prefix.
func (r Result) SkipSummary() string {
	counts := map[string]int{}
	for _, s := range r.Skipped {
		reason := s.Reason
		for _, prefix := range []string{ReasonPolicy, ReasonCollect} {
			if strings.HasPrefix(reason, prefix) {
				reason = strings.TrimSuffix(prefix, ": ")
			}
		}
		counts[reason]++
	}
	reasons := make([]string, 0, len(counts))
	for reason := range counts {
		reasons = append(reasons, reason)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if counts[reasons[i]] != counts[reasons[j]] {
			return counts[reasons[i]] > counts[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})
	parts := make([]string, len(reasons))
	for i, reason := range reasons {
		parts[i] = fmt.Sprintf("%d %s", counts[reason], reason)
	}
	return strings.Join(parts, ", ")
}
