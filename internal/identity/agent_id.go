package identity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxAgentIDFileBytes = 256

// LoadAgentID reads the non-secret logical identity assigned by the master.
// An absent file is represented by an empty ID so first enrollment can resolve
// it from the single-use token.
func LoadAgentID(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("agent ID path is required")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect agent ID: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxAgentIDFileBytes {
		return "", errors.New("agent ID is not a regular file or exceeds the size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open agent ID: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxAgentIDFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("read agent ID: %w", err)
	}
	if len(contents) > maxAgentIDFileBytes {
		return "", errors.New("agent ID exceeds the size limit")
	}
	agentID := strings.TrimSpace(string(contents))
	if !ValidAgentID(agentID) {
		return "", errors.New("stored agent ID is invalid")
	}
	return agentID, nil
}

// StoreAgentID atomically persists the master-assigned logical identity.
func StoreAgentID(path, agentID string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("agent ID path is required")
	}
	if !ValidAgentID(agentID) {
		return ErrInvalidAgentID
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create agent ID directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("agent ID path is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect agent ID path: %w", err)
	}

	tempFile, err := os.CreateTemp(directory, ".agent-id-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary agent ID: %w", err)
	}
	tempPath := tempFile.Name()
	installed := false
	defer func() {
		_ = tempFile.Close()
		if !installed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := tempFile.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary agent ID: %w", err)
	}
	if _, err := fmt.Fprintln(tempFile, agentID); err != nil {
		return fmt.Errorf("write temporary agent ID: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("flush temporary agent ID: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temporary agent ID: %w", err)
	}
	if err := replaceFile(tempPath, path); err != nil {
		return fmt.Errorf("replace agent ID: %w", err)
	}
	installed = true
	return nil
}
