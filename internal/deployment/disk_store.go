package deployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	diskRecordVersion           = 1
	deploymentFilenameSuffix    = ".json"
	deploymentTemporaryPattern  = ".deployment-*.tmp"
	maxPersistedDeploymentBytes = ((MaxConfigBytes + 2) / 3 * 4) + (128 << 10)
)

type diskRecord struct {
	Version      int       `json:"version"`
	ID           string    `json:"id"`
	AgentID      string    `json:"agent_id"`
	RevisionID   string    `json:"revision_id"`
	ConfigJSON   []byte    `json:"config"`
	ConfigSHA256 string    `json:"config_sha256"`
	// RenderedSHA256 is omitted for records written before the
	// outbound-pool feature; they predate refs, so their rendered
	// configuration is the logical one (see Record.RenderedDigest).
	RenderedSHA256 string    `json:"rendered_sha256,omitempty"`
	Status         Status    `json:"status"`
	Diagnostic     string    `json:"diagnostic,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// DiskStore keeps the latest deployment and its exact configuration for each
// agent in a private directory. Each agent has one atomically replaced file.
type DiskStore struct {
	mu        sync.RWMutex
	directory string
	records   map[string]Record
	latest    map[string]string
}

var _ Store = (*DiskStore)(nil)

// NewDiskStore opens or creates a deployment directory and loads its records.
func NewDiskStore(directory string) (*DiskStore, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("deployment storage directory is required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create deployment storage directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect deployment storage directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: deployment storage path is not a directory", ErrUnsafeStorage)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure deployment storage directory: %w", err)
	}

	store := &DiskStore{
		directory: directory,
		records:   make(map[string]Record),
		latest:    make(map[string]string),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *DiskStore) Create(_ context.Context, record Record) error {
	if err := validateRecord(record); err != nil {
		return err
	}
	record = cloneRecord(record)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[record.ID]; exists {
		return ErrAlreadyExists
	}
	if previousID, exists := s.latest[record.AgentID]; exists &&
		deploymentInProgress(s.records[previousID].Status) {
		return ErrDeploymentInProgress
	}
	if err := s.persist(record); err != nil {
		return err
	}
	if previousID, exists := s.latest[record.AgentID]; exists {
		delete(s.records, previousID)
	}
	s.records[record.ID] = record
	s.latest[record.AgentID] = record.ID
	return nil
}

func (s *DiskStore) Get(_ context.Context, id string) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.records[id]
	if !exists {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *DiskStore) LatestForAgent(
	_ context.Context,
	agentID string,
) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.latest[agentID]
	if !exists {
		return Record{}, ErrNotFound
	}
	return cloneRecord(s.records[id]), nil
}

func (s *DiskStore) List(_ context.Context) ([]Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, cloneRecord(record))
	}
	sort.Slice(records, func(left, right int) bool {
		return records[left].AgentID < records[right].AgentID
	})
	return records, nil
}

func (s *DiskStore) Transition(
	_ context.Context,
	id string,
	next Status,
	diagnostic string,
	now time.Time,
) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.records[id]
	if !exists {
		return Record{}, ErrNotFound
	}
	if !canTransition(record.Status, next) {
		return Record{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, record.Status, next)
	}
	if now.IsZero() {
		return Record{}, errors.New("transition time is required")
	}

	record.Status = next
	record.Diagnostic = diagnostic
	record.UpdatedAt = now.UTC()
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	if err := s.persist(record); err != nil {
		return Record{}, err
	}
	s.records[id] = record
	return cloneRecord(record), nil
}

func (s *DiskStore) RemoveAgent(_ context.Context, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, exists := s.latest[agentID]
	if !exists {
		return ErrNotFound
	}
	path := filepath.Join(s.directory, deploymentFilename(agentID))
	if err := inspectDeploymentTarget(path, true); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove deployment file: %w", err)
	}
	delete(s.latest, agentID)
	delete(s.records, id)
	if err := syncDeploymentDirectory(s.directory); err != nil {
		return err
	}
	return nil
}

func (s *DiskStore) load() error {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return fmt.Errorf("read deployment storage directory: %w", err)
	}
	removedTemporaryFile := false
	for _, entry := range entries {
		path := filepath.Join(s.directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect deployment file %q: %w", entry.Name(), err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: deployment entry %q is not a regular file", ErrUnsafeStorage, entry.Name())
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			return fmt.Errorf("%w: deployment file %q has unsafe permissions", ErrUnsafeStorage, entry.Name())
		}
		if isDeploymentTemporaryFile(entry.Name()) {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove interrupted deployment file %q: %w", entry.Name(), err)
			}
			removedTemporaryFile = true
			continue
		}
		if !validDeploymentFilename(entry.Name()) {
			return fmt.Errorf("%w: unexpected deployment file %q", ErrInvalidStoredData, entry.Name())
		}

		record, err := readDiskRecord(path, entry.Name(), info)
		if err != nil {
			return err
		}
		if _, exists := s.records[record.ID]; exists {
			return fmt.Errorf("%w: duplicate deployment ID", ErrInvalidStoredData)
		}
		if _, exists := s.latest[record.AgentID]; exists {
			return fmt.Errorf("%w: duplicate agent deployment", ErrInvalidStoredData)
		}
		s.records[record.ID] = record
		s.latest[record.AgentID] = record.ID
	}
	if removedTemporaryFile {
		return syncDeploymentDirectory(s.directory)
	}
	return nil
}

func (s *DiskStore) persist(record Record) (err error) {
	encoded, err := encodeDiskRecord(record)
	if err != nil {
		return err
	}
	target := filepath.Join(s.directory, deploymentFilename(record.AgentID))
	if err := inspectDeploymentTarget(target, false); err != nil {
		return err
	}

	temp, err := os.CreateTemp(s.directory, deploymentTemporaryPattern)
	if err != nil {
		return fmt.Errorf("create temporary deployment file: %w", err)
	}
	tempPath := temp.Name()
	installed := false
	defer func() {
		_ = temp.Close()
		if !installed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary deployment file: %w", err)
	}
	if err := writeAll(temp, encoded); err != nil {
		return fmt.Errorf("write temporary deployment file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary deployment file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary deployment file: %w", err)
	}
	if err := inspectDeploymentTarget(target, false); err != nil {
		return err
	}
	if err := replaceDeploymentFile(tempPath, target); err != nil {
		return fmt.Errorf("replace deployment file: %w", err)
	}
	installed = true
	if err := syncDeploymentDirectory(s.directory); err != nil {
		return err
	}
	return nil
}

func encodeDiskRecord(record Record) ([]byte, error) {
	if err := validateRecord(record); err != nil {
		return nil, err
	}
	stored := diskRecord{
		Version:      diskRecordVersion,
		ID:           record.ID,
		AgentID:      record.AgentID,
		RevisionID:   record.RevisionID,
		ConfigJSON:   append([]byte(nil), record.ConfigJSON...),
		ConfigSHA256: hex.EncodeToString(record.ConfigSHA256[:]),
		Status:       record.Status,
		Diagnostic:   record.Diagnostic,
		CreatedAt:    record.CreatedAt.UTC(),
		UpdatedAt:    record.UpdatedAt.UTC(),
	}
	if record.RenderedSHA256 != ([sha256.Size]byte{}) {
		stored.RenderedSHA256 = hex.EncodeToString(record.RenderedSHA256[:])
	}
	encoded, err := json.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("encode deployment record: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxPersistedDeploymentBytes {
		return nil, ErrInvalidRecord
	}
	return encoded, nil
}

func readDiskRecord(path, name string, expected os.FileInfo) (Record, error) {
	if expected.Size() <= 0 || expected.Size() > maxPersistedDeploymentBytes {
		return Record{}, fmt.Errorf("%w: deployment file %q has an invalid size", ErrInvalidStoredData, name)
	}
	if runtime.GOOS != "windows" && expected.Mode().Perm() != 0o600 {
		return Record{}, fmt.Errorf("%w: deployment file %q has unsafe permissions", ErrUnsafeStorage, name)
	}
	file, err := os.Open(path)
	if err != nil {
		return Record{}, fmt.Errorf("open deployment file %q: %w", name, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Record{}, fmt.Errorf("inspect opened deployment file %q: %w", name, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return Record{}, fmt.Errorf("%w: deployment file %q changed while opening", ErrUnsafeStorage, name)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxPersistedDeploymentBytes+1))
	if err != nil {
		return Record{}, fmt.Errorf("read deployment file %q: %w", name, err)
	}
	if len(contents) > maxPersistedDeploymentBytes {
		return Record{}, fmt.Errorf("%w: deployment file %q exceeds the size limit", ErrInvalidStoredData, name)
	}
	record, err := decodeDiskRecord(contents)
	if err != nil {
		return Record{}, fmt.Errorf("%w: deployment file %q", ErrInvalidStoredData, name)
	}
	if deploymentFilename(record.AgentID) != name {
		return Record{}, fmt.Errorf("%w: deployment filename does not match its agent", ErrInvalidStoredData)
	}
	return record, nil
}

func decodeDiskRecord(contents []byte) (Record, error) {
	var stored diskRecord
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return Record{}, ErrInvalidStoredData
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Record{}, ErrInvalidStoredData
	}
	if stored.Version != diskRecordVersion {
		return Record{}, ErrInvalidStoredData
	}
	digest, err := hex.DecodeString(stored.ConfigSHA256)
	if err != nil || len(digest) != sha256.Size {
		return Record{}, ErrInvalidStoredData
	}
	var configSHA256 [sha256.Size]byte
	copy(configSHA256[:], digest)
	var renderedSHA256 [sha256.Size]byte
	if stored.RenderedSHA256 != "" {
		renderedDigest, err := hex.DecodeString(stored.RenderedSHA256)
		if err != nil || len(renderedDigest) != sha256.Size {
			return Record{}, ErrInvalidStoredData
		}
		copy(renderedSHA256[:], renderedDigest)
	}
	record := Record{
		ID:             stored.ID,
		AgentID:        stored.AgentID,
		RevisionID:     stored.RevisionID,
		ConfigJSON:     append([]byte(nil), stored.ConfigJSON...),
		ConfigSHA256:   configSHA256,
		RenderedSHA256: renderedSHA256,
		Status:         stored.Status,
		Diagnostic:     stored.Diagnostic,
		CreatedAt:      stored.CreatedAt.UTC(),
		UpdatedAt:      stored.UpdatedAt.UTC(),
	}
	if err := validateRecord(record); err != nil {
		return Record{}, ErrInvalidStoredData
	}
	return record, nil
}

func inspectDeploymentTarget(path string, mustExist bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && !mustExist {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect deployment file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: deployment path is not a regular file", ErrUnsafeStorage)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: deployment file permissions must be 0600", ErrUnsafeStorage)
	}
	return nil
}

func writeAll(file *os.File, contents []byte) error {
	for len(contents) > 0 {
		written, err := file.Write(contents)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		contents = contents[written:]
	}
	return nil
}

func syncDeploymentDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open deployment storage directory: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync deployment storage directory: %w", err)
	}
	return nil
}

func deploymentFilename(agentID string) string {
	digest := sha256.Sum256([]byte(agentID))
	return hex.EncodeToString(digest[:]) + deploymentFilenameSuffix
}

func validDeploymentFilename(name string) bool {
	if len(name) != sha256.Size*2+len(deploymentFilenameSuffix) ||
		!strings.HasSuffix(name, deploymentFilenameSuffix) {
		return false
	}
	for _, character := range name[:sha256.Size*2] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func isDeploymentTemporaryFile(name string) bool {
	return strings.HasPrefix(name, ".deployment-") && strings.HasSuffix(name, ".tmp")
}
