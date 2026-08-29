package singbox

import "testing"

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
