// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package redact removes secrets from text cenziadah records about processes
// (command lines, finding details) before it reaches the journal, e-mail, the
// TUI or a report. Command lines routinely carry credentials (`--key ...`,
// `https://user:pass@host`, API tokens), and an alert must not spread them.
//
// Redaction can only hide text, never add or change findings: detection rules
// match against the raw command line; only what is shown is redacted.
package redact

import (
	"regexp"
	"strconv"
	"strings"
)

// Mask replaces every redacted value.
const Mask = "***"

var (
	// --api-key VALUE, --password=VALUE, -token VALUE: the flag NAME must END in
	// a secret word, so --key-file /path or --auth-type basic are kept.
	flagRE = regexp.MustCompile(`(?i)(\s|^)(--?[a-z0-9_.-]*?(?:key|token|secret|password|passwd|pwd|passphrase|auth|credentials?))(=|\s+)("[^"]*"|'[^']*'|[^\s"']+)`)
	// API_KEY=VALUE, DB_PASSWORD=VALUE (environment assignments in shell commands).
	envRE = regexp.MustCompile(`\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|PASSPHRASE|CREDENTIALS?))=("[^"]*"|'[^']*'|[^\s"']+)`)
	// scheme://user:PASSWORD@host
	urlRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]*:)[^@\s/]+@`)
	// Well-known token shapes, wherever they appear.
	tokenRE = regexp.MustCompile(`\b(?:` + strings.Join([]string{
		`gh[pousr]_[A-Za-z0-9]{20,}`,                                    // GitHub
		`github_pat_[A-Za-z0-9_]{20,}`,                                  // GitHub fine-grained
		`glpat-[A-Za-z0-9_-]{20,}`,                                      // GitLab
		`xox[abposr]-[A-Za-z0-9-]{10,}`,                                 // Slack
		`AKIA[0-9A-Z]{16}`,                                              // AWS access key id
		`sk-[A-Za-z0-9_-]{20,}`,                                         // OpenAI / Anthropic style
		`waka_[0-9a-fA-F-]{20,}`,                                        // WakaTime
		`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`, // JWT
	}, "|") + `)`)
)

// Text returns s with secrets replaced by Mask.
func Text(s string) string {
	if s == "" {
		return s
	}
	s = flagRE.ReplaceAllString(s, "${1}${2}${3}"+Mask)
	s = envRE.ReplaceAllString(s, "${1}="+Mask)
	s = urlRE.ReplaceAllString(s, "${1}"+Mask+"@")
	return tokenRE.ReplaceAllString(s, Mask)
}

// Truncate cuts s to at most max bytes (on a UTF-8 boundary) and says how much
// was left out. Redact BEFORE truncating, so a cut cannot leave half a secret
// that no pattern recognises any more.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && cut < len(s) && s[cut]&0xC0 == 0x80 {
		cut-- // do not split a multi-byte character
	}
	return s[:cut] + "… (" + strconv.Itoa(len(s)-cut) + " more bytes)"
}
