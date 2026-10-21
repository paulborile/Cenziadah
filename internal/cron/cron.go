// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package cron reads the jobs configured in root-owned crontabs, so a shell
// that cron starts for one of them can be recognised as scheduled work rather
// than as a daemon unexpectedly spawning a shell. Only root-controlled files are
// read: /etc/crontab, /etc/cron.d/*, and root's own crontab. Other users'
// crontabs are deliberately ignored: a compromised service account can add a
// job to its own crontab (persistence), and that must keep alerting.
package cron

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxCrontab bounds how much of one crontab is read.
const maxCrontab = 1 << 20

// Job is one configured job.
type Job struct {
	Source  string // file it comes from, relative to the root (e.g. /etc/crontab)
	Cmdline string // the job's process command line as /proc shows it: "<shell> -c <command>"
}

// Jobs returns the configured root-controlled cron jobs found under root ("/"
// on the host, or /proc/<cron pid>/root for cron in a container), keyed by the
// command line of the shell cron starts for them. trusted decides whether a
// file may be believed (root-owned, not group/world-writable); nil uses
// RootOnlyFile.
func Jobs(root string, trusted func(path string) bool) map[string]Job {
	if trusted == nil {
		trusted = RootOnlyFile
	}
	jobs := map[string]Job{}
	add := func(rel string, withUser bool) {
		p := filepath.Join(root, rel)
		if !trusted(p) {
			return
		}
		for _, j := range parseFile(p, rel, withUser) {
			jobs[j.Cmdline] = j
		}
	}
	add("/etc/crontab", true)
	if entries, err := os.ReadDir(filepath.Join(root, "/etc/cron.d")); err == nil {
		for _, e := range entries {
			// cron itself ignores files with dots or other odd names (run-parts rules)
			if e.Type().IsRegular() && !strings.ContainsAny(e.Name(), ".~") {
				add("/etc/cron.d/"+e.Name(), true)
			}
		}
	}
	add("/var/spool/cron/crontabs/root", false) // Debian/Ubuntu
	add("/var/spool/cron/root", false)          // RHEL/Fedora (cronie)
	return jobs
}

// RootOnlyFile reports whether p is a regular file owned by root and not
// group/world-writable.
func RootOnlyFile(p string) bool {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return false
	}
	return st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Uid == 0 && st.Mode&(syscall.S_IWGRP|syscall.S_IWOTH) == 0
}

func parseFile(p, rel string, withUser bool) []Job {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	return Parse(io.LimitReader(f, maxCrontab), rel, withUser)
}

// Parse reads crontab lines. withUser is true for system crontabs (/etc/crontab,
// /etc/cron.d), whose lines carry a user field after the schedule. SHELL=
// assignments change the shell for the following lines (default /bin/sh). Lines
// whose command contains '%' are skipped: cron rewrites them (stdin), so the
// process command line would not match anyway.
func Parse(r io.Reader, source string, withUser bool) []Job {
	var jobs []Job
	shell := "/bin/sh"
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if name, val, ok := envAssignment(line); ok {
			if name == "SHELL" {
				shell = strings.Trim(val, `"'`)
			}
			continue
		}
		fields := 5
		if line[0] == '@' {
			fields = 1 // @daily, @reboot, ...
		}
		if withUser {
			fields++
		}
		cmd, ok := skipFields(line, fields)
		if !ok || cmd == "" || strings.Contains(cmd, "%") {
			continue
		}
		jobs = append(jobs, Job{Source: source, Cmdline: shell + " -c " + cmd})
	}
	return jobs
}

// envAssignment recognises "NAME=value" lines (no whitespace before '=').
func envAssignment(line string) (name, val string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 || strings.ContainsAny(line[:i], " \t") {
		return "", "", false
	}
	return line[:i], strings.TrimSpace(line[i+1:]), true
}

// skipFields drops n whitespace-separated fields and returns the rest of the
// line verbatim (a command keeps its own spacing).
func skipFields(line string, n int) (string, bool) {
	rest := line
	for i := 0; i < n; i++ {
		rest = strings.TrimLeft(rest, " \t")
		j := strings.IndexAny(rest, " \t")
		if j < 0 {
			return "", false
		}
		rest = rest[j:]
	}
	return strings.TrimLeft(rest, " \t"), true
}
