package singbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseSingBoxVersionAndMinimum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		output     string
		major      int
		minor      int
		recognized bool
	}{
		{
			name:       "current beta",
			output:     "sing-box version 1.14.0-beta.2\nEnvironment: go1.25\n",
			major:      1,
			minor:      14,
			recognized: true,
		},
		{
			name:       "future stable",
			output:     "sing-box version 2.0.1\n",
			major:      2,
			minor:      0,
			recognized: true,
		},
		{
			name:   "unrelated output",
			output: "another program version 1.14.0\n",
		},
		{
			name:   "version text injection",
			output: "prefix sing-box version 1.14.0\n",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			major, minor, ok := parseSingBoxVersion(test.output)
			if ok != test.recognized || major != test.major || minor != test.minor {
				t.Fatalf(
					"parseSingBoxVersion() = (%d, %d, %t), want (%d, %d, %t)",
					major,
					minor,
					ok,
					test.major,
					test.minor,
					test.recognized,
				)
			}
		})
	}
}

func TestExecutableVersionRequiresManagedUserBuildTags(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is not portable to Windows")
	}
	directory := t.TempDir()
	writeFixture := func(name, tags string) string {
		t.Helper()
		path := filepath.Join(directory, name)
		contents := "#!/bin/sh\nprintf '%s\\n' 'sing-box version 1.14.0-rc.2.theatropolis.2' 'Tags: " + tags + "'\n"
		if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := writeFixture("valid", "with_v2ray_api,with_theatropolis_managed_users")
	if _, err := ExecutableVersion(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	for name, tags := range map[string]string{
		"stock":    "with_quic,with_clash_api",
		"no-users": "with_v2ray_api,with_quic",
	} {
		if _, err := ExecutableVersion(
			context.Background(),
			writeFixture(name, tags),
		); err == nil {
			t.Fatalf("%s sing-box fixture was accepted", name)
		}
	}
}
