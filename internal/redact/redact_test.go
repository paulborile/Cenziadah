// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package redact

import (
	"strings"
	"testing"
)

// fakeWaka has the shape of a WakaTime key but is made up, and is split so
// secret scanners do not take the source for a leaked key.
const fakeWaka = "waka_" + "11111111-2222-3333-4444-555555555555"

func TestText(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		// the real case: wakatime-cli started by VS Code
		{`/home/u/.wakatime/wakatime-cli-linux-amd64 --sync-ai-activity --plugin "vscode/1.141.0 vscode-wakatime/30.2.1" --key ` + fakeWaka,
			`/home/u/.wakatime/wakatime-cli-linux-amd64 --sync-ai-activity --plugin "vscode/1.141.0 vscode-wakatime/30.2.1" --key ***`},
		{`app --password=hunter2 --user bob`, `app --password=*** --user bob`},
		{`app --api-key "a b c" x`, `app --api-key *** x`},
		{`app -token 'abc' x`, `app -token *** x`},
		{`app --client-secret s3cr3t`, `app --client-secret ***`},
		{`app --key-file /etc/k.pem --auth-type basic`, `app --key-file /etc/k.pem --auth-type basic`},
		{`sh -c DB_PASSWORD=pw API_KEY="x y" ./run`, `sh -c DB_PASSWORD=*** API_KEY=*** ./run`},
		{`git clone https://bob:pa55@gitlab.com/x.git`, `git clone https://bob:***@gitlab.com/x.git`},
		{`curl https://gitlab.com/x.git`, `curl https://gitlab.com/x.git`},
		{`curl -H "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123"`, `curl -H "Authorization: Bearer ***"`},
		{`x glpat-abcdefghijklmnopqrst12 AKIAABCDEFGHIJKLMNOP sk-ant-api03-abcdefghijklmnopqrstu`, `x *** *** ***`},
		{`/usr/sbin/sshd -D -oPubkeyAuthentication=yes`, `/usr/sbin/sshd -D -oPubkeyAuthentication=yes`},
		{`/usr/share/code/code --type=utility --field-trial-handle=3,i,136`, `/usr/share/code/code --type=utility --field-trial-handle=3,i,136`},
		{"", ""},
	} {
		if got := Text(c.in); got != c.want {
			t.Errorf("Text(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// Text is applied to Go-quoted finding details (cmd="..."), not only raw lines.
func TestTextInQuotedDetail(t *testing.T) {
	d := `pid=1 exe=/x cmd="/x --plugin \"a b\" --key ` + fakeWaka + `" (exited)`
	got := Text(d)
	if strings.Contains(got, "11111111") {
		t.Errorf("secret left in detail: %q", got)
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("short", 10); got != "short" {
		t.Errorf("Truncate short = %q", got)
	}
	if got := Truncate("abcdefghij", 4); got != "abcd… (6 more bytes)" {
		t.Errorf("Truncate = %q", got)
	}
	if got := Truncate("aé", 2); got != "a… (2 more bytes)" { // é is 2 bytes: not split
		t.Errorf("Truncate multibyte = %q", got)
	}
}
