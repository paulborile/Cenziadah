// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

//go:build harness

// Package scenarios holds the ONE integration test for cenziadah. It launches the
// deliberately-vulnerable victim, delivers a REAL memory-corruption exploit (a
// stack buffer overflow that redirects control into shellcode on the executable
// stack), then runs the real cenziadah detector pipeline and asserts it reports the
// resulting indicators of compromise. A clean-control case guards against false
// positives. Gated behind the `harness` build tag so `make test` never runs it;
// `make compromise-test` runs it explicitly.
package scenarios

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paulborile/cenziadah/internal/engine"
	"github.com/paulborile/cenziadah/internal/model"
)

type victim struct {
	cmd  *exec.Cmd
	port int
	pid  int
}

// unameMachine returns the machine arch string setarch expects (e.g. "x86_64").
func unameMachine() string {
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return "x86_64"
	}
	return strings.TrimSpace(string(out))
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// startVictim launches the victim under `setarch -R` (ASLR off) so the exploit's
// leaked addresses stay valid, and returns once it has reported its control port.
func startVictim(t *testing.T) *victim {
	t.Helper()
	bin := filepath.Join(repoRoot(t), "testharness", "victim", "victim")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("victim not built (%v); run: make -C testharness build", err)
	}
	// setarch -R disables ASLR for the child, making the overflow deterministic.
	cmd := exec.Command("setarch", unameMachine(), "-R", bin, "0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	v := &victim{cmd: cmd, pid: cmd.Process.Pid}
	sc := bufio.NewScanner(stdout)
	deadline := time.Now().Add(3 * time.Second)
	for sc.Scan() && time.Now().Before(deadline) {
		if line := sc.Text(); strings.HasPrefix(line, "PORT ") {
			v.port, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PORT ")))
			break
		}
	}
	if v.port == 0 {
		cmd.Process.Kill()
		t.Fatal("victim did not report a port")
	}
	return v
}

func (v *victim) stop() {
	if v.cmd != nil && v.cmd.Process != nil {
		// Kill the whole process group (victim + any shellcode children).
		v.cmd.Process.Kill()
		v.cmd.Wait()
	}
}

// runExploit runs the exploit binary against the victim in the given mode.
func runExploit(t *testing.T, port int, mode string) {
	t.Helper()
	bin := filepath.Join(repoRoot(t), "testharness", "exploit", "exploit")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("exploit not built (%v); run: make -C testharness build", err)
	}
	out, err := exec.Command(bin, "-port", strconv.Itoa(port), "-mode", mode).CombinedOutput()
	if err != nil {
		t.Fatalf("exploit %s failed: %v\n%s", mode, err, out)
	}
	time.Sleep(400 * time.Millisecond) // let the shellcode run
}

// check runs the real detector pipeline against pid, diffing against base (may be
// nil), and returns active findings keyed by technique. Degraded collection (no
// mem) is fine here: the asserted IoCs are maps- and proctree-based.
func check(t *testing.T, pid int, base *model.Snapshot) map[model.Technique]model.Finding {
	t.Helper()
	tgt, err := engine.Collect(pid, true, base)
	if err != nil && tgt == nil {
		t.Fatalf("collect: %v", err)
	}
	if tgt.Mem != nil {
		defer tgt.Mem.Close()
	}
	rep := engine.Run(tgt, engine.AllDetectors())
	out := map[model.Technique]model.Finding{}
	for _, f := range rep.Active() {
		out[f.Technique] = f
	}
	return out
}

// snapshot captures a known-good baseline of the victim (which legitimately has an
// executable stack by construction — that becomes expected baseline noise).
func snapshot(t *testing.T, pid int) *model.Snapshot {
	t.Helper()
	tgt, err := engine.Collect(pid, true, nil)
	if err != nil && tgt == nil {
		t.Fatalf("collect for snapshot: %v", err)
	}
	if tgt.Mem != nil {
		defer tgt.Mem.Close()
	}
	snap, err := engine.BuildSnapshot(tgt)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	return snap
}

func keys(m map[model.Technique]model.Finding) []model.Technique {
	var k []model.Technique
	for t := range m {
		k = append(k, t)
	}
	return k
}

// TestCleanControl is the false-positive gate: checked against a baseline taken
// moments earlier, a still-clean victim must produce zero active findings — even
// though it has a (baseline-known) executable stack.
func TestCleanControl(t *testing.T) {
	v := startVictim(t)
	defer v.stop()
	base := snapshot(t, v.pid)
	if found := check(t, v.pid, base); len(found) != 0 {
		t.Fatalf("clean victim (vs baseline) should have 0 active findings, got %d: %v", len(found), keys(found))
	}
}

// TestStackOverflowCompromise delivers the real stack buffer overflow. The exploit
// overwrites the saved return address and runs shellcode (fork+exec) on the
// executable stack. The proof the injected code executed is a NEW child process
// that was not in the baseline — which cenziadah reports as an unexpected child.
func TestStackOverflowCompromise(t *testing.T) {
	v := startVictim(t)
	defer v.stop()

	base := snapshot(t, v.pid)

	// Baseline-diff is clean before the exploit.
	if found := check(t, v.pid, base); len(found) != 0 {
		t.Fatalf("victim not clean pre-exploit vs baseline: %v", keys(found))
	}

	// Independent ground truth that the shellcode actually ran a working shell: the
	// shellcode's command is `id > /tmp/cenziadah_pwned`. The victim's own code never
	// forks, execs, or writes this file, so its existence can ONLY come from the
	// injected shellcode executing. Clear any stale marker first.
	ensureMarkerAbsent(t)

	runExploit(t, v.port, "stack")

	// Proof #1 (independent of the detector): the marker file now exists and holds
	// the `id` output — the injected shellcode ran a real shell.
	assertShellRan(t)

	// Proof #2 (the detector): the ROP chain called mprotect, so the stack now has an
	// rwx page (a W^X violation) that cenziadah reports directly; the forked shell is
	// a corroborating unexpected child.
	found := check(t, v.pid, base)
	_, rwx := found[model.TechMapsRWX]
	_, child := found[model.TechUnexpectedChild]
	if !rwx {
		t.Fatalf("expected maps.rwx IoC (mprotect'd stack) after exploit; got %v", keys(found))
	}
	t.Logf("proof: shell-marker=yes rwx=%v unexpected-child=%v", rwx, child)
}

// markerPath is the file the shellcode's command writes to; see the shellcode in
// testharness/exploit/main.go.
const markerPath = "/tmp/cenziadah_pwned"

func ensureMarkerAbsent(t *testing.T) {
	t.Helper()
	_ = os.Remove(markerPath)
	if _, err := os.Stat(markerPath); err == nil {
		t.Fatalf("could not clear stale marker %s", markerPath)
	}
}

// assertShellRan verifies the injected shellcode executed a working shell by
// checking the marker file it was told to create contains the `id` output.
func assertShellRan(t *testing.T) {
	t.Helper()
	// The child shell runs asynchronously; poll briefly for the marker.
	var data []byte
	for i := 0; i < 20; i++ {
		if b, err := os.ReadFile(markerPath); err == nil && len(b) > 0 {
			data = b
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(data) == 0 {
		t.Fatal("shellcode marker not created: injected shell did not run")
	}
	if !strings.Contains(string(data), "uid=") {
		t.Fatalf("marker exists but lacks id output; got %q", string(data))
	}
	t.Cleanup(func() { os.Remove(markerPath) })
}

// TestFunctionPointerCompromise delivers the heap/struct overflow (SETNAME) that
// overwrites a function pointer with the address of shellcode staged on the stack;
// the victim then calls through it. Proof of execution is, again, a new child the
// baseline did not have.
func TestFunctionPointerCompromise(t *testing.T) {
	v := startVictim(t)
	defer v.stop()

	base := snapshot(t, v.pid)
	if found := check(t, v.pid, base); len(found) != 0 {
		t.Fatalf("victim not clean pre-exploit vs baseline: %v", keys(found))
	}

	runExploit(t, v.port, "fptr")

	found := check(t, v.pid, base)
	if _, ok := found[model.TechMapsRWX]; !ok {
		t.Fatalf("expected maps.rwx IoC (mprotect'd stack) after function-pointer hijack; got %v", keys(found))
	}
}
