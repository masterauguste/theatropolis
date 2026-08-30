package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const controlTargetVersion = 1

var ErrMasterMigrationRequested = errors.New("Master migration requested")

type controlTargetDocument struct {
	Version       int    `json:"version"`
	MigrationID   string `json:"migration_id"`
	MasterAddress string `json:"master_address"`
}

type ControlTargetStore struct{ path string }

func NewControlTargetStore(stateDirectory string) *ControlTargetStore {
	return &ControlTargetStore{path: filepath.Join(stateDirectory, "control-target.json")}
}

func (s *ControlTargetStore) Load(fallback string) (string, error) {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return validateMasterAddress(fallback)
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
		return "", errors.New("stored Master control target is unsafe")
	}
	encoded, err := os.ReadFile(s.path)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document controlTargetDocument
	if err := decoder.Decode(&document); err != nil {
		return "", fmt.Errorf("decode Master control target: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("Master control target contains trailing data")
	}
	if document.Version != controlTargetVersion || strings.TrimSpace(document.MigrationID) == "" {
		return "", errors.New("Master control target is invalid")
	}
	return validateMasterAddress(document.MasterAddress)
}

func (s *ControlTargetStore) StageMasterMigration(migrationID, address string) error {
	migrationID = strings.TrimSpace(migrationID)
	if migrationID == "" || len(migrationID) > 128 {
		return errors.New("migration ID is invalid")
	}
	validated, err := validateMasterAddress(address)
	if err != nil {
		return err
	}
	document := controlTargetDocument{Version: controlTargetVersion, MigrationID: migrationID, MasterAddress: validated}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".control-target-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	installed := false
	defer func() {
		_ = temporary.Close()
		if !installed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return err
	}
	installed = true
	return nil
}

func (s *ControlTargetStore) ResetForEnrollment() error {
	err := os.Remove(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func validateMasterAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	host, port, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return "", errors.New("Master address must be a host:port pair")
	}
	return net.JoinHostPort(host, port), nil
}
