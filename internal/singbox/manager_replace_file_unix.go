//go:build !windows

package singbox

import "os"

func replaceConfigFile(source, destination string) error {
	return os.Rename(source, destination)
}
