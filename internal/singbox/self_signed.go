package singbox

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const managedSelfSignedDirectory = "certificates/theatropolis-self-signed"

var managedSelfSignedPathPattern = regexp.MustCompile(
	`^certificates/theatropolis-self-signed/([a-z0-9_-]{1,96})/(certificate\.pem|private-key\.pem)$`,
)
var managedSelfSignedIDPattern = regexp.MustCompile(`^[a-z0-9_-]{1,96}$`)
var selfSignedDNSLabelPattern = regexp.MustCompile(
	`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`,
)

type managedTLSPaths struct {
	CertificatePath string `json:"certificate_path"`
	KeyPath         string `json:"key_path"`
	ServerName      string `json:"server_name"`
}

// prepareManagedSelfSignedCertificates materializes only the reserved paths
// emitted by the web editor. User-supplied certificate paths are never
// created or modified by the agent.
func prepareManagedSelfSignedCertificates(
	config []byte,
	stateDirectory string,
	now time.Time,
) error {
	var document struct {
		Inbounds []struct {
			TLS managedTLSPaths `json:"tls"`
		} `json:"inbounds"`
	}
	decoder := json.NewDecoder(bytes.NewReader(config))
	if err := decoder.Decode(&document); err != nil {
		return nil
	}
	requested := make(map[string]string)
	for _, inbound := range document.Inbounds {
		certificateMatch := managedSelfSignedPathPattern.FindStringSubmatch(
			inbound.TLS.CertificatePath,
		)
		keyMatch := managedSelfSignedPathPattern.FindStringSubmatch(
			inbound.TLS.KeyPath,
		)
		if certificateMatch == nil && keyMatch == nil {
			continue
		}
		if certificateMatch == nil || keyMatch == nil ||
			certificateMatch[1] != keyMatch[1] ||
			certificateMatch[2] != "certificate.pem" ||
			keyMatch[2] != "private-key.pem" {
			return errors.New("managed self-signed certificate paths do not match")
		}
		serverName := strings.TrimSpace(inbound.TLS.ServerName)
		if err := validateSelfSignedServerName(serverName); err != nil {
			return err
		}
		if previous, exists := requested[certificateMatch[1]]; exists &&
			previous != serverName {
			return errors.New("managed self-signed certificate identity has conflicting names")
		}
		requested[certificateMatch[1]] = serverName
	}
	for id, serverName := range requested {
		if err := ensureManagedSelfSignedCertificate(
			stateDirectory,
			id,
			serverName,
			now,
		); err != nil {
			return err
		}
	}
	return nil
}

func ensureManagedSelfSignedCertificate(
	stateDirectory string,
	id string,
	serverName string,
	now time.Time,
) error {
	if !managedSelfSignedIDPattern.MatchString(id) {
		return errors.New("managed self-signed certificate identity is invalid")
	}
	directory := filepath.Join(stateDirectory, managedSelfSignedDirectory, id)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create managed self-signed certificate directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect managed self-signed certificate directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("managed self-signed certificate directory is unsafe")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure managed self-signed certificate directory: %w", err)
	}

	certificatePath := filepath.Join(directory, "certificate.pem")
	keyPath := filepath.Join(directory, "private-key.pem")
	certificateExists, err := regularFileExists(certificatePath)
	if err != nil {
		return err
	}
	keyExists, err := regularFileExists(keyPath)
	if err != nil {
		return err
	}
	if certificateExists || keyExists {
		if !certificateExists || !keyExists {
			return errors.New("managed self-signed certificate pair is incomplete")
		}
		if err := os.Chmod(certificatePath, 0o600); err != nil {
			return fmt.Errorf("secure managed self-signed certificate: %w", err)
		}
		if err := os.Chmod(keyPath, 0o600); err != nil {
			return fmt.Errorf("secure managed self-signed private key: %w", err)
		}
		return validateManagedSelfSignedPair(certificatePath, keyPath, serverName)
	}

	certificatePEM, keyPEM, err := generateSelfSignedPair(serverName, now)
	if err != nil {
		return err
	}
	if err := installNewPrivateFile(keyPath, keyPEM); err != nil {
		return err
	}
	if err := installNewPrivateFile(certificatePath, certificatePEM); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return syncDirectory(directory)
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, errors.New("managed self-signed certificate path is unsafe")
	}
	if info.Size() > 64<<10 {
		return false, errors.New("managed self-signed certificate file is too large")
	}
	return true, nil
}

func generateSelfSignedPair(serverName string, now time.Time) ([]byte, []byte, error) {
	if err := validateSelfSignedServerName(serverName); err != nil {
		return nil, nil, err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate managed self-signed private key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate managed self-signed serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:             now.UTC().Add(-5 * time.Minute),
		NotAfter:              now.UTC().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if address, err := netip.ParseAddr(serverName); err == nil {
		template.IPAddresses = append(template.IPAddresses, address.AsSlice())
	} else {
		template.DNSNames = append(template.DNSNames, serverName)
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("sign managed self-signed certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode managed self-signed private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificateDER,
		}), pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateDER,
		}), nil
}

func installNewPrivateFile(path string, content []byte) error {
	if exists, err := regularFileExists(path); err != nil {
		return err
	} else if exists {
		return errors.New("managed self-signed certificate file already exists")
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".self-signed-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	installed := false
	defer func() {
		_ = file.Close()
		if !installed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("managed self-signed certificate file appeared during creation")
		}
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	installed = true
	return nil
}

func validateManagedSelfSignedPair(
	certificatePath,
	keyPath,
	serverName string,
) error {
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	certificateBlock, _ := pem.Decode(certificatePEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" ||
		keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return errors.New("managed self-signed certificate pair is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return errors.New("managed self-signed certificate is invalid")
	}
	privateKeyValue, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return errors.New("managed self-signed private key is invalid")
	}
	privateKey, keyOK := privateKeyValue.(*ecdsa.PrivateKey)
	publicKey, publicOK := certificate.PublicKey.(*ecdsa.PublicKey)
	if !keyOK || !publicOK || !publicKey.Equal(&privateKey.PublicKey) {
		return errors.New("managed self-signed certificate and private key do not match")
	}
	if err := certificate.VerifyHostname(serverName); err != nil {
		return errors.New("managed self-signed certificate does not cover its configured name")
	}
	return nil
}

func validateSelfSignedServerName(serverName string) error {
	if serverName == "" || len(serverName) > 253 ||
		serverName != strings.TrimSpace(serverName) {
		return errors.New("managed self-signed certificate name is invalid")
	}
	if _, err := netip.ParseAddr(serverName); err == nil {
		return nil
	}
	if strings.HasSuffix(serverName, ".") {
		serverName = strings.TrimSuffix(serverName, ".")
	}
	for _, label := range strings.Split(serverName, ".") {
		if !selfSignedDNSLabelPattern.MatchString(label) {
			return errors.New("managed self-signed certificate name is invalid")
		}
	}
	return nil
}
