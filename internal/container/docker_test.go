// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package container

import (
	"os"
	"path/filepath"
	"testing"
)

const id = "88180067883ca53359dca427b62b6d15431607a442ba941a8cfd7c7fa1f0d46d"

func TestShimContainerID(t *testing.T) {
	cmd := "/usr/bin/containerd-shim-runc-v2 -namespace moby -id " + id + " -address /run/containerd/containerd.sock"
	if got := ShimContainerID(cmd); got != id {
		t.Errorf("ShimContainerID = %q", got)
	}
	if ShimContainerID("/usr/bin/containerd-shim-runc-v2 -id ../../etc") != "" {
		t.Error("non-hex id must be rejected (no path traversal into the state dir)")
	}
}

func writeState(t *testing.T, root, json string) {
	t.Helper()
	dir := filepath.Join(root, "containers", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.v2.json"), []byte(json), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHealthcheckCmdline(t *testing.T) {
	for _, c := range []struct{ json, want string }{
		{`{"ID":"x","Config":{"Healthcheck":{"Test":["CMD-SHELL","dms-healthcheck"],"Interval":30000000000}}}`, "/bin/sh -c dms-healthcheck"},
		{`{"Config":{"Healthcheck":{"Test":["CMD","wget","--spider","http://localhost:8080/health"]}}}`, "wget --spider http://localhost:8080/health"},
		{`{"Config":{"Healthcheck":{"Test":["NONE"]}}}`, ""},
		{`{"Config":{}}`, ""},
	} {
		root := t.TempDir()
		writeState(t, root, c.json)
		got, err := HealthcheckCmdline(root, id)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q (%v), want %q", c.json, got, err, c.want)
		}
	}
}

func TestDockerRoot(t *testing.T) {
	p := filepath.Join(t.TempDir(), "daemon.json")
	os.WriteFile(p, []byte(`{"data-root":"/srv/docker"}`), 0o644)
	if got := DockerRoot(p); got != "/srv/docker" {
		t.Errorf("DockerRoot = %q", got)
	}
	if got := DockerRoot("/nonexistent"); got != DefaultDockerRoot {
		t.Errorf("default = %q", got)
	}
}

func TestHealthcheckOfProgram(t *testing.T) {
	root := t.TempDir()
	writeState(t, root, `{"Config":{"Healthcheck":{"Test":["CMD","wget","--no-verbose","--tries=1","--spider","http://localhost:8080/health"]}}}`)
	hc, err := HealthcheckOf(root, id)
	if err != nil || hc.Program != "wget" || hc.Cmdline != "wget --no-verbose --tries=1 --spider http://localhost:8080/health" {
		t.Errorf("CMD form: %+v %v", hc, err)
	}
	writeState(t, root, `{"Config":{"Healthcheck":{"Test":["CMD-SHELL","dms-healthcheck"]}}}`)
	if hc, _ := HealthcheckOf(root, id); hc.Program != "" || hc.Cmdline != "/bin/sh -c dms-healthcheck" {
		t.Errorf("CMD-SHELL form: %+v", hc)
	}
}
