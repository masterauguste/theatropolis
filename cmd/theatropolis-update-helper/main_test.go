package main

import (
	"debug/buildinfo"
	"runtime/debug"
	"testing"
)

func TestComponentVersionComesFromTargetBuildNotHelper(t *testing.T) {
	t.Parallel()
	metadata := &buildinfo.BuildInfo{
		Path: theatropolisModulePath + "/cmd/theatropolis-master",
		Main: debug.Module{
			Path:    theatropolisModulePath,
			Version: "v0.2.7",
		},
	}
	got, err := componentVersionFromBuildInfo(metadata, "master")
	if err != nil {
		t.Fatal(err)
	}
	if got != "v0.2.7" {
		t.Fatalf("installed Master version = %q, want v0.2.7", got)
	}
}

func TestComponentVersionRejectsWrongCommandIdentity(t *testing.T) {
	t.Parallel()
	metadata := &buildinfo.BuildInfo{
		Path: theatropolisModulePath + "/cmd/theatropolis-update-helper",
		Main: debug.Module{
			Path:    theatropolisModulePath,
			Version: "v0.2.9",
		},
	}
	if _, err := componentVersionFromBuildInfo(metadata, "master"); err == nil {
		t.Fatal("helper build was accepted as the installed Master")
	}
}
