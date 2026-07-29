package singbox

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrepareManagedSelfSignedCertificatesCreatesAndReusesPair(t *testing.T) {
	t.Parallel()

	stateDirectory := t.TempDir()
	config := []byte(`{
		"inbounds": [{
			"type": "anytls",
			"tag": "tls-in",
			"tls": {
				"enabled": true,
				"certificate_path": "certificates/theatropolis-self-signed/tls-in-1234/certificate.pem",
				"key_path": "certificates/theatropolis-self-signed/tls-in-1234/private-key.pem"
			}
		}]
	}`)
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	if err := prepareManagedSelfSignedCertificates(config, stateDirectory, now); err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(
		stateDirectory,
		managedSelfSignedDirectory,
		"tls-in-1234",
		"certificate.pem",
	)
	keyPath := filepath.Join(
		stateDirectory,
		managedSelfSignedDirectory,
		"tls-in-1234",
		"private-key.pem",
	)
	certificateBefore, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareManagedSelfSignedCertificates(
		config,
		stateDirectory,
		now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	certificateAfter, _ := os.ReadFile(certificatePath)
	keyAfter, _ := os.ReadFile(keyPath)
	if string(certificateAfter) != string(certificateBefore) ||
		string(keyAfter) != string(keyBefore) {
		t.Fatal("managed self-signed pair was unexpectedly regenerated")
	}

	certificateBlock, _ := pem.Decode(certificateBefore)
	keyBlock, _ := pem.Decode(keyBefore)
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyValue, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := keyValue.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T", keyValue)
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&privateKey.PublicKey) {
		t.Fatal("generated certificate does not match its private key")
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		t.Fatalf(
			"certificate validity = %s through %s",
			certificate.NotBefore,
			certificate.NotAfter,
		)
	}
}

func TestPrepareManagedSelfSignedCertificatesRejectsMismatchedPaths(t *testing.T) {
	t.Parallel()

	config := []byte(`{
		"inbounds": [{
			"tls": {
				"certificate_path": "certificates/theatropolis-self-signed/one/certificate.pem",
				"key_path": "certificates/theatropolis-self-signed/two/private-key.pem"
			}
		}]
	}`)
	if err := prepareManagedSelfSignedCertificates(
		config,
		t.TempDir(),
		time.Now(),
	); err == nil {
		t.Fatal("mismatched managed paths were accepted")
	}
}

func TestPrepareManagedSelfSignedCertificatesIgnoresUserFilePaths(t *testing.T) {
	t.Parallel()

	stateDirectory := t.TempDir()
	config := []byte(`{
		"inbounds": [{
			"tls": {
				"certificate_path": "/etc/example/certificate.pem",
				"key_path": "/etc/example/private-key.pem"
			}
		}]
	}`)
	if err := prepareManagedSelfSignedCertificates(
		config,
		stateDirectory,
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stateDirectory, "certificates")); !os.IsNotExist(err) {
		t.Fatalf("user file paths created managed state: %v", err)
	}
}
