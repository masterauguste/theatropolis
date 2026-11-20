package singbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ProxyNodeConfigGeneration = "proxy-node-v1"
	configStateFilename       = "config-state.json"
	configStateSchema         = "theatropolis/agent-config-state"
	configStateSchemaVersion  = 1
	maxConfigStateBytes       = 8 << 10
	legacyQuarantineDirectory = "legacy-config-quarantine"
)

type configStateBuild struct {
	Component  string    `json:"component"`
	Version    string    `json:"version"`
	Commit     string    `json:"commit"`
	RecordedAt time.Time `json:"recorded_at"`
}

type configState struct {
	Schema        string           `json:"schema"`
	SchemaVersion int              `json:"schema_version"`
	Generation    string           `json:"generation"`
	LastUsedBy    configStateBuild `json:"last_used_by"`
}

// prepareConfigGeneration makes the major-format cutover idempotent. Tests and
// embedders which leave ConfigGeneration empty retain the pre-cutover behavior.
func (m *Manager) prepareConfigGeneration() (string, error) {
	if m.configGeneration == "" {
		return "", nil
	}
	path := filepath.Join(m.configDirectory, configStateFilename)
	state, exists, err := readConfigState(path)
	if err != nil {
		return "", err
	}
	if exists {
		if state.Generation != m.configGeneration {
			return "", fmt.Errorf("agent configuration generation %q is not supported", state.Generation)
		}
		if err := m.writeConfigState(path); err != nil {
			return "", err
		}
		return "", nil
	}

	quarantine, err := m.quarantineLegacyConfig()
	if err != nil {
		return "", err
	}
	if err := m.writeConfigState(path); err != nil {
		return "", err
	}
	return quarantine, nil
}

func readConfigState(path string) (configState, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return configState{}, false, nil
	}
	if err != nil {
		return configState{}, false, fmt.Errorf("inspect agent configuration state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxConfigStateBytes {
		return configState{}, false, errors.New("agent configuration state is unsafe or invalid")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return configState{}, false, fmt.Errorf("read agent configuration state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var state configState
	if err := decoder.Decode(&state); err != nil {
		return configState{}, false, fmt.Errorf("decode agent configuration state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return configState{}, false, errors.New("agent configuration state contains trailing data")
	}
	if state.Schema != configStateSchema || state.SchemaVersion != configStateSchemaVersion || strings.TrimSpace(state.Generation) == "" || state.LastUsedBy.Component != "agent" || strings.TrimSpace(state.LastUsedBy.Version) == "" || strings.TrimSpace(state.LastUsedBy.Commit) == "" || state.LastUsedBy.RecordedAt.IsZero() {
		return configState{}, false, errors.New("agent configuration state has invalid metadata")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return configState{}, false, fmt.Errorf("secure agent configuration state: %w", err)
	}
	return state, true, nil
}

func (m *Manager) writeConfigState(path string) error {
	version := m.agentVersion
	if version == "" {
		version = "development"
	}
	commit := m.agentCommit
	if commit == "" {
		commit = "unknown"
	}
	state := configState{
		Schema: configStateSchema, SchemaVersion: configStateSchemaVersion, Generation: m.configGeneration,
		LastUsedBy: configStateBuild{Component: "agent", Version: version, Commit: commit, RecordedAt: m.now().UTC()},
	}
	contents, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	file, err := os.CreateTemp(m.configDirectory, ".config-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create agent configuration state: %w", err)
	}
	temporary := file.Name()
	installed := false
	defer func() {
		_ = file.Close()
		if !installed {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := m.replaceFile(temporary, path); err != nil {
		return fmt.Errorf("install agent configuration state: %w", err)
	}
	installed = true
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return syncDirectory(m.configDirectory)
}

func (m *Manager) quarantineLegacyConfig() (string, error) {
	activeExists, err := safeRegularFileExists(m.activeConfigPath, m.maxConfigBytes)
	if err != nil {
		return "", err
	}
	certificates := filepath.Join(m.stateDirectory, managedSelfSignedDirectory)
	certificatesExist, err := safeDirectoryExists(certificates)
	if err != nil {
		return "", err
	}
	if !activeExists && !certificatesExist {
		return "", nil
	}
	root := filepath.Join(m.stateDirectory, legacyQuarantineDirectory)
	if err := ensureSecureDirectory(root); err != nil {
		return "", fmt.Errorf("prepare legacy configuration quarantine: %w", err)
	}
	directory, err := os.MkdirTemp(root, "cutover-"+m.now().UTC().Format("20060102T150405Z")+"-")
	if err != nil {
		return "", fmt.Errorf("create legacy configuration quarantine: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", err
	}
	if activeExists {
		if err := os.Rename(m.activeConfigPath, filepath.Join(directory, activeConfigFilename)); err != nil {
			return "", fmt.Errorf("quarantine legacy active configuration: %w", err)
		}
	}
	if certificatesExist {
		if err := os.Rename(certificates, filepath.Join(directory, "theatropolis-self-signed")); err != nil {
			return "", fmt.Errorf("quarantine legacy certificates: %w", err)
		}
	}
	if err := syncDirectory(directory); err != nil {
		return "", err
	}
	if err := syncDirectory(filepath.Dir(certificates)); err != nil {
		return "", err
	}
	if err := syncDirectory(m.configDirectory); err != nil {
		return "", err
	}
	return directory, nil
}

func safeRegularFileExists(path string, maxBytes int) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > int64(maxBytes) {
		return false, errors.New("legacy active configuration is unsafe")
	}
	return true, nil
}

func safeDirectoryExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, errors.New("legacy certificate directory is unsafe")
	}
	return true, nil
}
