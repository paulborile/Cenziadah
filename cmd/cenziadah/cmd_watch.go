// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/notify"
	"github.com/paulborile/cenziadah/internal/scan"
	"github.com/paulborile/cenziadah/internal/tui"
	"github.com/paulborile/cenziadah/internal/watch"
)

// skipFlag collects repeated --skip-exe PATH=REASON values.
type skipFlag map[string]string

func (s skipFlag) String() string { return fmt.Sprint(map[string]string(s)) }

func (s skipFlag) Set(v string) error {
	path, reason, ok := strings.Cut(v, "=")
	if !ok || path == "" || reason == "" {
		return errors.New("want PATH=REASON (the reason is recorded with every skip)")
	}
	s[path] = reason
	return nil
}

func cmdWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	useTUI := fs.Bool("tui", false, "interactive process list instead of log output")
	interval := fs.Duration("interval", 10*time.Second, "idle time between the end of one sweep and the start of the next")
	pace := fs.Duration("pace", time.Millisecond, "pause after each process during a sweep, so it never holds a CPU at 100% (0 = none)")
	minAge := fs.Duration("min-age", -1, "skip processes younger than this (default: one interval)")
	asJSON := fs.Bool("json", false, "log events as JSON lines (silent mode only)")
	noMem := fs.Bool("no-mem", false, "do not read process memory (no module integrity; no root needed)")
	noAutoLearn := fs.Bool("no-auto-learn", false, "do not learn programs first seen after start, even package-installed ones")
	mailTo := fs.String("mail-to", "", "e-mail new alerts (and a startup summary) to this address via the local sendmail")
	mailFrom := fs.String("mail-from", "", "From address for mails (default: the local MTA's configured sender)")
	mailMin := fs.String("mail-min", "medium", "lowest severity that is mailed: low|medium|high|critical")
	mailMax := fs.Int("mail-max-per-hour", 20, "at most this many alert mails per hour (the log keeps everything)")
	sendmailPath := fs.String("sendmail", "/usr/sbin/sendmail", "sendmail-compatible program used to send mail")
	skip := skipFlag{}
	fs.Var(skip, "skip-exe", "skip an executable: PATH=REASON (repeatable; reasons are reported)")
	checkOnly := fs.Bool("check-config", false, "validate the options (and the mail setup) and exit: 0 = OK (used by the systemd unit before starting)")
	if err := fs.Parse(args); err != nil {
		return exitOpError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "cenziadah: unexpected argument %q (options must come as --name value; check the quoting in /etc/default/cenziadah)\n", fs.Arg(0))
		return exitOpError
	}
	if *interval < time.Second {
		fmt.Fprintln(os.Stderr, "cenziadah: --interval must be at least 1s")
		return exitOpError
	}
	if *useTUI && *asJSON {
		fmt.Fprintln(os.Stderr, "cenziadah: --json applies to log output; it cannot be combined with --tui")
		return exitOpError
	}
	if *useTUI && !*checkOnly && !isTerminal(os.Stdout) {
		fmt.Fprintln(os.Stderr, "cenziadah: --tui needs a terminal; run without --tui for log output")
		return exitOpError
	}
	if *minAge < 0 {
		*minAge = *interval
	}

	var mailCfg *notify.Config
	if *mailTo != "" {
		c, err := mailConfig(*mailTo, *mailFrom, *mailMin, *mailMax, *sendmailPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cenziadah: %v\n", err)
			return exitOpError
		}
		mailCfg = &c
	}
	if *checkOnly {
		fmt.Fprintln(os.Stderr, "cenziadah: configuration OK")
		return exitClean
	}
	var mail *notify.MailSink
	if mailCfg != nil {
		mail = notify.NewMailSink(*mailCfg)
		defer mail.Close()
	}

	sc := scan.New(scan.Options{WithMem: !*noMem, MinAge: *minAge, SkipExe: skip, AutoLearn: !*noAutoLearn, Pace: *pace})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *useTUI {
		return watchTUI(ctx, sc, *interval, mail)
	}
	var sink watch.Sink = watch.LogSink{Out: os.Stdout, Status: os.Stderr, JSON: *asJSON}
	if mail != nil {
		sink = watch.Tee(sink, mail)
	}
	err := watch.Run(ctx, sc, watch.Config{Interval: *interval}, sink)
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "cenziadah: %v\n", err)
		return exitOpError
	}
	return exitClean
}

// watchTUI runs the loop in the background and the TUI in the foreground; quitting
// the TUI stops the loop.
func watchTUI(ctx context.Context, sc *scan.Scanner, interval time.Duration, mail *notify.MailSink) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	rescan := make(chan struct{})
	p := tui.NewProgram(rescan, interval)
	go func() {
		var sink watch.Sink = tui.Sink{P: p}
		if mail != nil {
			sink = watch.Tee(sink, mail)
		}
		err := watch.Run(ctx, sc, watch.Config{Interval: interval, Rescan: rescan}, sink)
		if err != nil && !errors.Is(err, context.Canceled) {
			tui.Fatal(p, err)
		}
	}()
	go func() { <-ctx.Done(); p.Quit() }() // SIGINT/SIGTERM
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "cenziadah: tui: %v\n", err)
		return exitOpError
	}
	return exitClean
}

// mailConfig validates the mail options and the sendmail program: it must be
// root-owned and not writable by others (cenziadah runs as root and executes
// it), and the addresses must be plain addresses (they go into mail headers).
// It starts nothing, so --check-config can use it.
func mailConfig(to, from, minSev string, maxPerHour int, sendmail string) (notify.Config, error) {
	if err := notify.ValidAddress(to); err != nil {
		return notify.Config{}, fmt.Errorf("--mail-to %q: %w", to, err)
	}
	if from != "" {
		if err := notify.ValidAddress(from); err != nil {
			return notify.Config{}, fmt.Errorf("--mail-from %q: %w", from, err)
		}
	}
	sev, ok := strictSeverity(minSev)
	if !ok {
		return notify.Config{}, fmt.Errorf("--mail-min %q: want low|medium|high|critical", minSev)
	}
	if maxPerHour < 1 {
		return notify.Config{}, fmt.Errorf("--mail-max-per-hour must be at least 1")
	}
	real, err := notify.TrustedProgram(sendmail)
	if err != nil {
		return notify.Config{}, fmt.Errorf("--sendmail %s: %w (cenziadah runs as root and executes it, so it must be root-owned and not writable by others)", sendmail, err)
	}
	return notify.Config{
		To: to, From: from, Min: sev, MaxPerHour: maxPerHour,
		Mailer: notify.Sendmail{Path: real}, Status: os.Stderr, Host: notify.Hostname(),
	}, nil
}

func strictSeverity(s string) (model.Severity, bool) {
	switch s {
	case "low":
		return model.SevLow, true
	case "medium":
		return model.SevMedium, true
	case "high":
		return model.SevHigh, true
	case "critical":
		return model.SevCritical, true
	}
	return 0, false
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
