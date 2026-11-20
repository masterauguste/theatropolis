package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxIdentityFileBytes = 8 << 10

// LoadOrCreatePrivateKey loads an agent's Ed25519 identity or creates it with
// owner-only permissions. The key is PKCS#8 encoded so the on-disk format is
// explicit and can be inspected with standard tooling.
func LoadOrCreatePrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("identity path is required")
	}

	key, err := loadPrivateKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent identity: %w", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("encode agent identity: %w", err)
	}
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	})

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadPrivateKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create agent identity: %w", err)
	}
	created := false
	defer func() {
		_ = file.Close()
		if !created {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(block); err != nil {
		return nil, fmt.Errorf("write agent identity: %w", err)
	}
	if err := file.Sync(); err != nil {
		return nil, fmt.Errorf("flush agent identity: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close agent identity: %w", err)
	}
	created = true
	return privateKey, nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("agent identity is not a regular file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure agent identity: %w", err)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open agent identity: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxIdentityFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read agent identity: %w", err)
	}
	if len(contents) > maxIdentityFileBytes {
		return nil, errors.New("agent identity file is too large")
	}
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("agent identity is not a valid PKCS#8 PEM file")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("agent identity contains invalid PKCS#8 data")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("agent identity is not an Ed25519 private key")
	}
	return append(ed25519.PrivateKey(nil), privateKey...), nil
}
