package proxynode

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const legacyQuarantineDirectory = "legacy-config-quarantine"

// PrepareMasterCutover removes recognized legacy deployment records from live
// use exactly once, before the first new-format state file is created. Agent
// address metadata remains in the pool registry because the new compiler owns
// and uses it; legacy logical configurations do not.
func PrepareMasterCutover(stateDirectory string, now time.Time) (string, bool, error) {
	stateDirectory = filepath.Clean(stateDirectory)
	newState := filepath.Join(stateDirectory, "proxy-node-state.json")
	if info, err := os.Lstat(newState); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", false, fmt.Errorf("%w: Proxy Node state path is unsafe", ErrUnsafeStorage)
		}
		return "", false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("inspect Proxy Node state before cutover: %w", err)
	}

	legacy := filepath.Join(stateDirectory, "deployments")
	info, err := os.Lstat(legacy)
	legacyDeployments := false
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", false, fmt.Errorf("%w: legacy deployment storage is unsafe", ErrUnsafeStorage)
		}
		entries, readErr := os.ReadDir(legacy)
		if readErr != nil {
			return "", false, fmt.Errorf("inspect legacy deployment records: %w", readErr)
		}
		legacyDeployments = len(entries) > 0
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("inspect legacy deployment storage: %w", err)
	}
	poolPath := filepath.Join(stateDirectory, "outbound-pool.json")
	poolContents, poolExists, err := readLegacyPoolForQuarantine(poolPath)
	if err != nil {
		return "", false, err
	}
	if !legacyDeployments && !poolExists {
		return "", true, nil
	}

	root := filepath.Join(stateDirectory, legacyQuarantineDirectory)
	if err := secureCutoverDirectory(root); err != nil {
		return "", false, err
	}
	directory, err := os.MkdirTemp(root, "master-cutover-"+now.UTC().Format("20060102T150405Z")+"-")
	if err != nil {
		return "", false, fmt.Errorf("create master legacy quarantine: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", false, err
	}
	if legacyDeployments {
		if err := os.Rename(legacy, filepath.Join(directory, "deployments")); err != nil {
			return "", false, fmt.Errorf("quarantine legacy deployment records: %w", err)
		}
	}
	if poolExists {
		if err := os.WriteFile(filepath.Join(directory, "outbound-pool.json"), poolContents, 0o600); err != nil {
			return "", false, fmt.Errorf("quarantine legacy outbound pool: %w", err)
		}
	}
	if err := syncCutoverDirectory(directory); err != nil {
		return "", false, err
	}
	if err := syncCutoverDirectory(stateDirectory); err != nil {
		return "", false, err
	}
	return directory, true, nil
}

func readLegacyPoolForQuarantine(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect legacy outbound pool: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return nil, false, fmt.Errorf("%w: legacy outbound pool is unsafe", ErrUnsafeStorage)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read legacy outbound pool: %w", err)
	}
	return contents, true, nil
}

func secureCutoverDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create legacy quarantine root: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect legacy quarantine root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: legacy quarantine root is unsafe", ErrUnsafeStorage)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure legacy quarantine root: %w", err)
	}
	return nil
}

func syncCutoverDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
