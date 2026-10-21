// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package notify sends cenziadah's alerts by e-mail through the host's local
// mail transfer agent (the standard /usr/sbin/sendmail interface provided by
// postfix, exim, msmtp-mta, ...). It is opt-in (`watch --mail-to`) and meant
// for an operator's own server; it never talks to the network itself. It is
// the only package that runs an external program.
package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Mailer delivers one complete RFC 5322 message (headers + body).
type Mailer interface {
	Send(ctx context.Context, msg []byte) error
}

// Sendmail delivers through a local sendmail-compatible program:
// `<Path> -t -i` with the message on stdin (-t: recipients from the headers;
// -i: a line with a single dot is not end-of-message). No shell is involved.
type Sendmail struct {
	Path string
}

// Send implements Mailer.
func (s Sendmail) Send(ctx context.Context, msg []byte) error {
	cmd := exec.CommandContext(ctx, s.Path, "-t", "-i")
	cmd.Stdin = bytes.NewReader(msg)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(out.String())
		if len(detail) > 300 {
			detail = detail[:300]
		}
		return fmt.Errorf("%s: %w: %s", s.Path, err, detail)
	}
	return nil
}

// TrustedProgram resolves path (following symlinks, e.g. /usr/sbin/sendmail ->
// msmtp) and checks that it is safe for a root process to execute: a regular,
// executable file owned by root and not group/world-writable, in a directory
// with the same properties. A sendmail anyone else could replace would give
// them code execution as root through cenziadah.
func TrustedProgram(path string) (string, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	var st, dst syscall.Stat_t
	if err := syscall.Stat(real, &st); err != nil {
		return "", err
	}
	switch {
	case st.Mode&syscall.S_IFMT != syscall.S_IFREG:
		return "", fmt.Errorf("%s is not a regular file", real)
	case st.Mode&0o111 == 0:
		return "", fmt.Errorf("%s is not executable", real)
	case !rootOnly(st):
		return "", fmt.Errorf("%s must be owned by root and not group/world-writable", real)
	}
	if err := syscall.Stat(filepath.Dir(real), &dst); err != nil {
		return "", err
	}
	if !rootOnly(dst) {
		return "", fmt.Errorf("directory %s must be owned by root and not group/world-writable", filepath.Dir(real))
	}
	return real, nil
}

func rootOnly(st syscall.Stat_t) bool {
	return st.Uid == 0 && st.Mode&(syscall.S_IWGRP|syscall.S_IWOTH) == 0
}

var addrRE = regexp.MustCompile(`^[^\s@<>,;"'()\\]+@[^\s@<>,;"'()\\]+\.[^\s@<>,;"'()\\]+$`)

// ValidAddress reports whether a is a plain mail address safe to put in a
// header (no display name, no spaces, no CR/LF, one '@').
func ValidAddress(a string) error {
	if !addrRE.MatchString(a) {
		return errors.New("invalid mail address (want a plain address like name@example.com)")
	}
	return nil
}

// compose builds the message. Header values are sanitized (control characters,
// including CR/LF, removed and clipped) so attacker-influenced text such as a
// process name can never add a header; the body is sanitized line by line.
func compose(to, from, subject, body string, date time.Time, mailer string) []byte {
	var b strings.Builder
	b.WriteString("To: " + headerValue(to, 200) + "\n")
	if from != "" {
		b.WriteString("From: " + headerValue(from, 200) + "\n")
	}
	b.WriteString("Subject: " + headerValue(subject, 160) + "\n")
	b.WriteString("Date: " + date.Format(time.RFC1123Z) + "\n")
	b.WriteString("MIME-Version: 1.0\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\n")
	b.WriteString("X-Mailer: " + headerValue(mailer, 80) + "\n")
	b.WriteString("\n")
	for _, line := range strings.Split(body, "\n") {
		b.WriteString(clean(line) + "\n")
	}
	return []byte(b.String())
}

// clean replaces control characters (and DEL) with '?'.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

func headerValue(s string, max int) string {
	s = strings.ReplaceAll(clean(s), "\t", " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max-1]) + "…"
	}
	return s
}

// Hostname is the host name used in mails ("unknown" if unavailable).
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}
