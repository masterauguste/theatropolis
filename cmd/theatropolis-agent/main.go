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
	"runtime"
	"strings"
	"syscall"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/agent"
	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"github.com/masterauguste/theatropolis/internal/singboxupdate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	maxWireMessageBytes      = control.DefaultMaxConfigBytes + 64<<10
	maxCAFileBytes           = 1 << 20
	controlKeepaliveTime     = 30 * time.Second
	controlKeepaliveTimeout  = 10 * time.Second
	controlConnectMaxBackoff = 30 * time.Second
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
	if len(arguments) > 0 && arguments[0] == "apply-update" {
		return errors.New(
			"privileged updates moved to the dedicated theatropolis-update-helper; rerun the installer",
		)
	}
	if len(arguments) > 0 && arguments[0] == "apply-sing-box-update" {
		return errors.New(
			"privileged updates moved to the dedicated theatropolis-update-helper; rerun the installer",
		)
	}
	flags := flag.NewFlagSet("theatropolis-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	masterAddress := flags.String("master", "", "master host and port")
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
		strings.TrimSpace(*masterAddress) == "" {
		return errors.New("--master is required")
	}

	controlTarget := agent.NewControlTargetStore(*stateDirectory)
	if strings.TrimSpace(*tokenFile) != "" {
		if _, err := os.Lstat(*tokenFile); err == nil {
			if err := controlTarget.ResetForEnrollment(); err != nil {
				return fmt.Errorf("reset migrated Master target: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	resolvedMaster, err := controlTarget.Load(*masterAddress)
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(resolvedMaster)
	if err != nil || strings.TrimSpace(host) == "" {
		return errors.New("--master must be a host:port pair")
	}
	tlsConfig, err := secureTLSConfig(host, *caFile)
	if err != nil {
		return err
	}
	connection, err := grpc.NewClient(
		"dns:///"+resolvedMaster,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   controlConnectMaxBackoff,
			},
			MinConnectTimeout: 10 * time.Second,
		}),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                controlKeepaliveTime,
			Timeout:             controlKeepaliveTimeout,
			PermitWithoutStream: false,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxWireMessageBytes),
			grpc.MaxCallSendMsgSize(maxWireMessageBytes),
		),
	)
	if err != nil {
		return fmt.Errorf("configure master connection: %w", err)
	}
	defer connection.Close()

	identityPath := filepath.Join(*stateDirectory, "identity.pem")
	privateKey, err := identity.LoadOrCreatePrivateKey(identityPath)
	if err != nil {
		return err
	}
	if err := removeLegacyAgentID(filepath.Join(*stateDirectory, "agent-id")); err != nil {
		return err
	}
	validator := singbox.Validator{
		BinaryPath:     *singBoxPath,
		StateDirectory: *stateDirectory,
	}
	var manager *singbox.Manager
	singBoxVersion, singBoxErr := singbox.ExecutableVersion(
		context.Background(),
		*singBoxPath,
	)
	if singBoxErr != nil {
		slog.Warn(
			"sing-box configuration control is unavailable",
			"error",
			singBoxErr,
		)
	} else {
		manager, err = singbox.NewManager(singbox.ManagerOptions{
			Validator:        validator,
			ConfigGeneration: singbox.ProxyNodeConfigGeneration,
			AgentVersion:     version,
			AgentCommit:      commit,
		})
		if err != nil {
			return fmt.Errorf("configure sing-box manager: %w", err)
		}
	}
	runner := &agent.Runner{
		AgentVersion:   version,
		SingBoxVersion: singBoxVersion,
		PrivateKey:     privateKey,
		Validator:      validator,
		MasterMigrator: controlTarget,
	}
	updater, err := agentupdate.NewScheduler(*stateDirectory)
	if err != nil {
		return fmt.Errorf("configure agent updater: %w", err)
	}
	runner.Updater = updater
	if singBoxUpdateHelperAvailable() {
		singBoxUpdater, err := singboxupdate.NewScheduler(*stateDirectory)
		if err != nil {
			return fmt.Errorf("configure sing-box updater: %w", err)
		}
		runner.SingBoxUpdater = singBoxUpdater
	} else {
		slog.Warn(
			"sing-box update control is unavailable; rerun the installer to add the root update helper",
		)
	}
	if manager != nil {
		runner.Manager = manager
	}
	client := controlv1.NewAgentControlServiceClient(connection)
	if strings.TrimSpace(*tokenFile) != "" {
		if err := enrollFromFile(
			context.Background(),
			runner,
			client,
			*tokenFile,
		); err != nil {
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
		"master", resolvedMaster,
	)
	return runner.Run(ctx, client)
}

func singBoxUpdateHelperAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	info, err := os.Lstat(
		"/etc/systemd/system/theatropolis-sing-box-update.path",
	)
	return err == nil && info.Mode().IsRegular()
}

func removeLegacyAgentID(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect obsolete agent ID: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("obsolete agent ID path is not a regular file")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove obsolete agent ID: %w", err)
	}
	return nil
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
