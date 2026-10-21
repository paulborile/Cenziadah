// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package notify

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/report"
	"github.com/paulborile/cenziadah/internal/scan"
	"github.com/paulborile/cenziadah/internal/version"
)

const (
	queueSize   = 16
	sendTimeout = 30 * time.Second
)

// Config configures a MailSink.
type Config struct {
	To, From   string
	Min        model.Severity // lowest severity that is mailed
	MaxPerHour int            // rate limit (sliding hour); <= 0 means 20
	Mailer     Mailer
	Status     io.Writer // where delivery problems are reported (stderr -> journald)
	Host       string    // host name shown in mails
}

// MailSink mails a startup summary and, per sweep, the new alerts at or above
// Config.Min. It implements watch.Sink. Delivery runs on a background worker:
// a slow or failing MTA never delays a sweep; when the queue is full a mail is
// dropped and counted. A sliding-hour rate limit protects the mailbox; mails
// skipped by it are counted and reported in the next mail that goes out.
type MailSink struct {
	cfg Config
	now func() time.Time

	queue chan []byte
	done  chan struct{}

	mu          sync.Mutex
	sent        []time.Time
	rateSkipped int // alerts not mailed because of the rate limit
	queueFull   int // mails dropped because the queue was full
}

// NewMailSink starts the delivery worker. Call Close when done.
func NewMailSink(cfg Config) *MailSink {
	if cfg.MaxPerHour <= 0 {
		cfg.MaxPerHour = 20
	}
	if cfg.Status == nil {
		cfg.Status = io.Discard
	}
	m := &MailSink{cfg: cfg, now: time.Now, queue: make(chan []byte, queueSize), done: make(chan struct{})}
	go m.worker()
	return m
}

func (m *MailSink) worker() {
	defer close(m.done)
	for msg := range m.queue {
		ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
		if err := m.cfg.Mailer.Send(ctx, msg); err != nil {
			fmt.Fprintf(m.cfg.Status, "cenziadah: mail not sent: %v\n", err)
		}
		cancel()
	}
}

// Close stops accepting mail and waits (bounded) for queued mail to go out.
func (m *MailSink) Close() {
	close(m.queue)
	select {
	case <-m.done:
	case <-time.After(sendTimeout + 5*time.Second):
	}
}

func (m *MailSink) Learning() {}

func (m *MailSink) Error(error) {} // the log sink reports sweep errors

// Learned sends the startup mail: cenziadah is running, what it learned, and
// which findings it accepted as normal (a host compromised before start shows
// up here).
func (m *MailSink) Learned(set *baseline.Set, res scan.Result) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s started watching all processes on %s.\n\n", version.Info(), m.cfg.Host)
	fmt.Fprintf(&b, "Baseline learned from the running host at %s:\n", res.FinishedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "  %d processes, %d program identities, %d module digest conflicts\n", res.Stats.Scanned, set.Len(), set.Conflicts)
	if len(res.Skipped) > 0 {
		fmt.Fprintf(&b, "  skipped %d: %s\n", len(res.Skipped), res.SkipSummary())
	}
	degraded := 0
	for _, r := range res.Reports {
		if r.Degraded != "" {
			degraded++
		}
	}
	if degraded > 0 {
		fmt.Fprintf(&b, "  %d processes checked without memory access (not running as root?)\n", degraded)
	}
	fmt.Fprintf(&b, "\nAlerts at %s or above will be mailed to %s (at most %d mails per hour).\n",
		m.cfg.Min, m.cfg.To, m.cfg.MaxPerHour)
	if len(res.Accepted) > 0 {
		fmt.Fprintf(&b, "\n%d finding(s) were already present and are now accepted as normal.\n", len(res.Accepted))
		b.WriteString("If this host may already have been compromised, investigate them:\n\n")
		report.LearnedText(&b, res.Accepted)
	}
	m.enqueue(fmt.Sprintf("cenziadah started on %s: watching %d processes", m.cfg.Host, res.Stats.Scanned), b.String(), false)
}

// Sweep mails the sweep's new alerts at or above the threshold, in one mail.
func (m *MailSink) Sweep(_ int, res scan.Result, events []model.Event) {
	var alerts []model.Event
	for _, e := range events {
		if e.Kind == model.EventNew && e.Finding.Severity >= m.cfg.Min {
			alerts = append(alerts, e)
		}
	}
	if len(alerts) == 0 {
		return
	}
	first := alerts[0]
	subject := fmt.Sprintf("cenziadah: %d alert(s) on %s: %s %s %s", len(alerts), m.cfg.Host,
		first.Finding.Severity, first.Finding.Technique, first.Target.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "%d new alert(s) on %s, sweep finished %s.\n", len(alerts), m.cfg.Host, res.FinishedAt.UTC().Format(time.RFC3339))
	for _, e := range alerts {
		// Every field below is attacker-influenced (process names, paths,
		// command lines): clean() keeps each one on its own single line.
		t, f := e.Target, e.Finding
		fmt.Fprintf(&b, "\n[%s] %s: %s\n", f.Severity, f.Technique, clean(f.Title))
		fmt.Fprintf(&b, "  process  pid=%d %s (uid %d)\n", t.PID, clean(t.Name), t.UID)
		fmt.Fprintf(&b, "  exe      %s\n", clean(t.Exe))
		fmt.Fprintf(&b, "  cmdline  %s\n", clean(t.Cmdline))
		if f.Detail != "" {
			fmt.Fprintf(&b, "  detail   %s\n", clean(f.Detail))
		}
		fmt.Fprintf(&b, "  version  cenziadah %s\n", version.Version)
		b.WriteString("  log      ")
		report.EventText(&b, e)
	}
	m.enqueue(subject, b.String(), true)
}

// enqueue applies the rate limit (alert mails only; the startup mail always
// goes) and hands the message to the worker without blocking.
func (m *MailSink) enqueue(subject, body string, alert bool) {
	m.mu.Lock()
	now := m.now()
	cutoff := now.Add(-time.Hour)
	kept := m.sent[:0]
	for _, t := range m.sent {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	m.sent = kept
	if alert && len(m.sent) >= m.cfg.MaxPerHour {
		m.rateSkipped++
		m.mu.Unlock()
		return
	}
	m.sent = append(m.sent, now)
	var notes []string
	if m.rateSkipped > 0 {
		notes = append(notes, fmt.Sprintf("%d earlier alert mail(s) were not sent (rate limit %d/hour).", m.rateSkipped, m.cfg.MaxPerHour))
		m.rateSkipped = 0
	}
	if m.queueFull > 0 {
		notes = append(notes, fmt.Sprintf("%d earlier mail(s) were dropped (mail queue full: is the MTA working?).", m.queueFull))
		m.queueFull = 0
	}
	m.mu.Unlock()

	if len(notes) > 0 {
		body += "\nNote: " + strings.Join(notes, " ") + " Every event is in the log (journalctl -u cenziadah-watch).\n"
	}
	body += "\n-- \n" + version.Info() + " on " + m.cfg.Host + "\n"
	msg := compose(m.cfg.To, m.cfg.From, subject, body, now, "cenziadah "+version.Version)
	select {
	case m.queue <- msg:
	default:
		m.mu.Lock()
		m.queueFull++
		m.mu.Unlock()
		fmt.Fprintln(m.cfg.Status, "cenziadah: mail queue full, mail dropped")
	}
}
