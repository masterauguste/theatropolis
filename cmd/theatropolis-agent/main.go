package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/agent"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	maxWireMessageBytes = control.DefaultMaxConfigBytes + 64<<10
	maxCAFileBytes      = 1 << 20
)

var (
	version   = "development"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("theatropolis-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	masterAddress := flags.String("master", "", "master host and port")
	agentID := flags.String("agent-id", "", "agent identity")
	stateDirectory := flags.String(
		"state-dir",
		"/var/lib/theatropolis/agent",
		"agent state directory",
	)
	singBoxPath := flags.String("sing-box", "/usr/local/bin/sing-box", "sing-box executable")
	tokenFile := flags.String("enrollment-token-file", "", "single-use token file")
	caFile := flags.String("ca-file", "", "optional PEM CA bundle")
	showVersion := flags.Bool("version", false, "print version")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("%s (commit %s, built %s)\n", version, commit, buildDate)
		return nil
	}
	if flags.NArg() != 0 ||
		strings.TrimSpace(*masterAddress) == "" ||
		strings.TrimSpace(*agentID) == "" {
		return errors.New("--master and --agent-id are required")
	}

	host, _, err := net.SplitHostPort(*masterAddress)
	if err != nil || strings.TrimSpace(host) == "" {
		return errors.New("--master must be a host:port pair")
	}
	tlsConfig, err := secureTLSConfig(host, *caFile)
	if err != nil {
		return err
	}
	connection, err := grpc.NewClient(
		"dns:///"+*masterAddress,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxWireMessageBytes),
			grpc.MaxCallSendMsgSize(maxWireMessageBytes),
		),
	)
	if err != nil {
		return fmt.Errorf("configure master connection: %w", err)
	}
	defer connection.Close()

	privateKey, err := identity.LoadOrCreatePrivateKey(
		filepath.Join(*stateDirectory, "identity.pem"),
	)
	if err != nil {
		return err
	}
	validator := singbox.Validator{
		BinaryPath:     *singBoxPath,
		StateDirectory: *stateDirectory,
	}
	var manager *singbox.Manager
	if err := singbox.CheckSupportedExecutable(
		context.Background(),
		*singBoxPath,
	); err != nil {
		slog.Warn(
			"sing-box configuration control is unavailable",
			"error",
			err,
		)
	} else {
		manager, err = singbox.NewManager(singbox.ManagerOptions{
			Validator: validator,
		})
		if err != nil {
			return fmt.Errorf("configure sing-box manager: %w", err)
		}
	}
	runner := &agent.Runner{
		AgentID:      *agentID,
		AgentVersion: version,
		PrivateKey:   privateKey,
		Validator:    validator,
	}
	if manager != nil {
		runner.Manager = manager
	}
	client := controlv1.NewAgentControlServiceClient(connection)
	if strings.TrimSpace(*tokenFile) != "" {
		if err := enrollFromFile(context.Background(), runner, client, *tokenFile); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	slog.Info(
		"theatropolis agent starting",
		"version", version,
		"agent_id", *agentID,
		"master", *masterAddress,
	)
	return runner.Run(ctx, client)
}

func secureTLSConfig(serverName, caFile string) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
	}
	if strings.TrimSpace(caFile) == "" {
		return config, nil
	}
	info, err := os.Stat(caFile)
	if err != nil {
		return nil, fmt.Errorf("inspect CA file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxCAFileBytes {
		return nil, errors.New("CA file is not a regular file or exceeds the size limit")
	}
	certificate, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificate pool: %w", err)
	}
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errors.New("CA file does not contain a valid certificate")
	}
	config.RootCAs = roots
	return config, nil
}

func enrollFromFile(
	ctx context.Context,
	runner *agent.Runner,
	client controlv1.AgentControlServiceClient,
	path string,
) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect enrollment token: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 256 {
		return errors.New("enrollment token is not a regular file or exceeds the size limit")
	}
	encodedToken, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read enrollment token: %w", err)
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encodedToken)))
	if err != nil {
		return errors.New("enrollment token is not valid base64url")
	}
	enrollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := runner.Enroll(enrollCtx, client, token); err != nil {
		return err
	}
	for index := range token {
		token[index] = 0
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove consumed enrollment token: %w", err)
	}
	return nil
}
