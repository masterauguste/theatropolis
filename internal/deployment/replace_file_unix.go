//go:build !windows

package deployment

import "os"

func replaceDeploymentFile(source, destination string) error {
	return os.Rename(source, destination)
}
