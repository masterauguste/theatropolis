package proxynode

import (
	"errors"
	"fmt"
	"os"
)

// HasActiveTopologyTransaction reports whether a durable topology deployment
// or rollback journal exists. The journal is deliberately detected by
// existence rather than decoded here: a truncated or otherwise unreadable
// journal still means that exporting a migration snapshot is unsafe.
func (s *Store) HasActiveTopologyTransaction() (bool, error) {
	_, err := os.Lstat(s.topologyTransactionPath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect topology transaction: %w", err)
	}
	return true, nil
}
