package proxynode

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

	"github.com/masterauguste/theatropolis/internal/singbox"
)

const (
	topologyTransactionFilename = "proxy-node-topology-transaction.json"
	maxTopologyTransactionBytes = 64 << 20
)

type topologyTransaction struct {
	ID               string                     `json:"id"`
	TopologyRevision uint64                     `json:"topology_revision"`
	Phase            string                     `json:"phase"`
	StartedAt        time.Time                  `json:"started_at"`
	Agents           []topologyTransactionAgent `json:"agents"`
	RollbackState    *State                     `json:"rollback_state,omitempty"`
}

type topologyTransactionAgent struct {
	AgentID        string `json:"agent_id"`
	RollbackConfig []byte `json:"rollback_config"`
	Touched        bool   `json:"touched"`
}

func (s *Store) topologyTransactionPath() string {
	return filepath.Join(filepath.Dir(s.path), topologyTransactionFilename)
}

func loadTopologyTransaction(path string) (*topologyTransaction, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect topology transaction: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxTopologyTransactionBytes {
		return nil, errors.New("topology transaction path is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open topology transaction: %w", err)
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, maxTopologyTransactionBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(encoded) > maxTopologyTransactionBytes {
		return nil, errors.New("read topology transaction")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var transaction topologyTransaction
	if err := decoder.Decode(&transaction); err != nil {
		return nil, fmt.Errorf("decode topology transaction: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("topology transaction contains trailing data")
	}
	if err := validateTopologyTransaction(transaction); err != nil {
		return nil, err
	}
	return &transaction, nil
}

func persistTopologyTransaction(path string, transaction topologyTransaction) error {
	if err := validateTopologyTransaction(transaction); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(transaction, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxTopologyTransactionBytes {
		return errors.New("topology transaction exceeds size limit")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".topology-transaction-*.tmp")
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
	if err := replaceStateFile(temporaryPath, path); err != nil {
		return err
	}
	installed = true
	return nil
}

func removeTopologyTransaction(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("topology transaction path is unsafe")
	}
	return os.Remove(path)
}

func validateTopologyTransaction(transaction topologyTransaction) error {
	if strings.TrimSpace(transaction.ID) == "" || len(transaction.ID) > 128 ||
		transaction.TopologyRevision == 0 || transaction.StartedAt.IsZero() ||
		(transaction.Phase != "deploying" && transaction.Phase != "committing") || len(transaction.Agents) == 0 {
		return errors.New("invalid topology transaction")
	}
	seen := make(map[string]struct{}, len(transaction.Agents))
	if transaction.RollbackState != nil {
		if err := validateStoredState(*transaction.RollbackState); err != nil {
			return errors.New("invalid topology transaction rollback state")
		}
	}
	for _, agent := range transaction.Agents {
		if !validAgentID(agent.AgentID) || len(agent.RollbackConfig) == 0 || len(agent.RollbackConfig) > singbox.DefaultMaxConfigBytes {
			return errors.New("invalid topology transaction Agent")
		}
		if _, exists := seen[agent.AgentID]; exists {
			return errors.New("duplicate topology transaction Agent")
		}
		seen[agent.AgentID] = struct{}{}
		if err := singbox.ValidateManagedConfig(agent.RollbackConfig); err != nil {
			return errors.New("invalid topology transaction rollback configuration")
		}
	}
	return nil
}
