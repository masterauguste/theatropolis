package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/webui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

const (
	maxWireMessageBytes     = control.DefaultMaxConfigBytes + 64<<10
	maxAdminPasswordBytes   = 512
	controlKeepaliveTime    = 30 * time.Second
	controlKeepaliveTimeout = 10 * time.Second
	controlKeepaliveMinTime = 20 * time.Second
)

var (
	version   = "development"
	commit    = "unknown"
	buildDate = "unknown"

	effectiveUserID = os.Geteuid
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("master stopped", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("expected serve, apply-update, create-enrollment, set-web-admin, or version")
	}
	switch arguments[0] {
	case "serve":
		return serve(arguments[1:])
	case "apply-update":
		return applyUpdate(arguments[1:])
	case "create-enrollment":
		return createEnrollment(arguments[1:])
	case "set-web-admin":
		return setWebAdmin(arguments[1:])
	case "version":
		fmt.Printf("%s (commit %s, built %s)\n", version, commit, buildDate)
		return nil
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func applyUpdate(arguments []string) error {
	flags := flag.NewFlagSet("theatropolis-master apply-update", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDirectory := flags.String(
		"state-dir",
		"/var/lib/theatropolis/master",
		"master state directory",
	)
	installPath := flags.String(
		"install-path",
		"/usr/local/bin/theatropolis-master",
		"installed master binary",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("apply-update does not accept positional arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return agentupdate.Apply(ctx, agentupdate.ApplyOptions{
		StateDirectory: *stateDirectory,
		InstallPath:    *installPath,
		Component:      "master",
		Architecture:   runtime.GOARCH,
		RunningVersion: version,
	})
}

func serve(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDirectory := flags.String(
		"state-dir",
		"/var/lib/theatropolis/master",
		"master state directory",
	)
	grpcAddress := flags.String("grpc-listen", "127.0.0.1:8081", "local gRPC address")
	webAddress := flags.String("web-listen", "127.0.0.1:8080", "local HTTP address")
	publicURL := flags.String(
		"public-url",
		"",
		"canonical public HTTPS URL used by operators and agents",
	)
	webAuthFile := flags.String(
		"web-auth-file",
		"",
		"operator access file (defaults to <state-dir>/web-auth.json)",
	)
	adminSocket := flags.String(
		"admin-socket",
		"/run/theatropolis/master-admin.sock",
		"local administrative Unix socket",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	grpcListener, err := listenLoopback(*grpcAddress)
	if err != nil {
		return fmt.Errorf("listen for agent control: %w", err)
	}
	defer grpcListener.Close()
	webListener, err := listenLoopback(*webAddress)
	if err != nil {
		return fmt.Errorf("listen for web interface: %w", err)
	}
	defer webListener.Close()
	adminListener, err := listenUnixSocket(*adminSocket)
	if err != nil {
		return fmt.Errorf("listen for local administration: %w", err)
	}
	defer func() {
		_ = adminListener.Close()
		_ = os.Remove(*adminSocket)
	}()

	identities, err := identity.OpenRegistry(
		filepath.Join(*stateDirectory, "identities.json"),
	)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	deployments, err := deployment.NewDiskStore(
		filepath.Join(*stateDirectory, "deployments"),
	)
	if err != nil {
		return fmt.Errorf("open deployment storage: %w", err)
	}
	// poolRegistry is passed to the control server now and will be handed
	// to the web interface for manual-entry management in a later phase.
	poolRegistry, err := pool.Open(filepath.Join(*stateDirectory, "outbound-pool.json"))
	if err != nil {
		return fmt.Errorf("open outbound pool registry: %w", err)
	}
	server := control.NewServer(
		identities,
		deployments,
		poolRegistry,
		logNotifier{logger: logger},
		logger,
	)
	accessPath := strings.TrimSpace(*webAuthFile)
	if accessPath == "" {
		accessPath = filepath.Join(*stateDirectory, "web-auth.json")
	}
	access, err := webui.LoadAccessWithSessions(
		accessPath,
		filepath.Join(*stateDirectory, "web-sessions.json"),
	)
	if err != nil {
		return fmt.Errorf("load web operator access: %w", err)
	}
	masterUpdater, err := agentupdate.NewScheduler(*stateDirectory)
	if err != nil {
		return fmt.Errorf("configure master updater: %w", err)
	}
	ruleSetCacheDirectory := filepath.Join(*stateDirectory, "rule-set-catalogs")
	geositeRuleSets := webui.NewGeositeRuleSetCatalog(
		nil,
		filepath.Join(ruleSetCacheDirectory, "geosite.json"),
	)
	geoipRuleSets := webui.NewGeoipRuleSetCatalog(
		nil,
		filepath.Join(ruleSetCacheDirectory, "geoip.json"),
	)
	geositeRuleSets.Start(ctx)
	geoipRuleSets.Start(ctx)
	webHandler, err := webui.New(webui.Options{
		Registry:        identities,
		Sessions:        server.Sessions,
		Controller:      server,
		Access:          access,
		Releases:        webui.NewGitHubReleaseCatalog(nil),
		SingBoxReleases: webui.NewSingBoxReleaseCatalog(nil),
		GeositeRuleSets: geositeRuleSets,
		GeoipRuleSets:   geoipRuleSets,
		MasterUpdater:   masterUpdater,
		PublicURL:       *publicURL,
		Version:         version,
		Logger:          logger,
	})
	if err != nil {
		return fmt.Errorf("configure web interface: %w", err)
	}

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxWireMessageBytes),
		grpc.MaxSendMsgSize(maxWireMessageBytes),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             controlKeepaliveMinTime,
			PermitWithoutStream: false,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    controlKeepaliveTime,
			Timeout: controlKeepaliveTimeout,
		}),
	)
	controlv1.RegisterAgentControlServiceServer(grpcServer, server)
	healthServer := health.NewServer()
	healthServer.SetServingStatus(
		controlv1.AgentControlService_ServiceDesc.ServiceName,
		healthv1.HealthCheckResponse_SERVING,
	)
	healthv1.RegisterHealthServer(grpcServer, healthServer)

	webServer := &http.Server{
		Handler:           webHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	adminServer := &http.Server{
		Handler:           adminHandler(identities),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	errorsChannel := make(chan error, 3)
	go func() {
		errorsChannel <- grpcServer.Serve(grpcListener)
	}()
	go func() {
		errorsChannel <- webServer.Serve(webListener)
	}()
	go func() {
		errorsChannel <- adminServer.Serve(adminListener)
	}()
	logger.Info(
		"theatropolis master started",
		"version", version,
		"grpc_listen", grpcListener.Addr().String(),
		"web_listen", webListener.Addr().String(),
	)

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errorsChannel:
		if errors.Is(serveErr, http.ErrServerClosed) ||
			errors.Is(serveErr, grpc.ErrServerStopped) {
			serveErr = nil
		}
	}
	healthServer.SetServingStatus(
		controlv1.AgentControlService_ServiceDesc.ServiceName,
		healthv1.HealthCheckResponse_NOT_SERVING,
	)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = webServer.Shutdown(shutdownCtx)
	_ = adminServer.Shutdown(shutdownCtx)
	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-shutdownCtx.Done():
		grpcServer.Stop()
	}
	return serveErr
}

func setWebAdmin(arguments []string) error {
	flags := flag.NewFlagSet("set-web-admin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDirectory := flags.String(
		"state-dir",
		"/var/lib/theatropolis/master",
		"master state directory",
	)
	username := flags.String("username", "", "admin username")
	passwordStdin := flags.Bool(
		"password-stdin",
		false,
		"read the admin password from standard input",
	)
	replace := flags.Bool("replace", false, "replace an existing admin credential")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if strings.TrimSpace(*stateDirectory) == "" {
		return errors.New("--state-dir is required")
	}
	if strings.TrimSpace(*username) == "" {
		return errors.New("--username is required")
	}
	if !*passwordStdin {
		return errors.New("--password-stdin is required")
	}
	if runtime.GOOS != "windows" && effectiveUserID() != 0 {
		return errors.New("set-web-admin must run as root")
	}
	if err := os.MkdirAll(*stateDirectory, 0o700); err != nil {
		return fmt.Errorf("create master state directory: %w", err)
	}
	password, err := readAdminPassword(os.Stdin)
	if err != nil {
		return err
	}
	defer clear(password)

	accessPath := filepath.Join(*stateDirectory, "web-auth.json")
	if *replace {
		if err := webui.ReplaceAdminAccess(accessPath, *username, password); err != nil {
			return fmt.Errorf("replace web admin access: %w", err)
		}
		return nil
	}
	if err := webui.InitializeAdminAccess(accessPath, *username, password); err != nil {
		return fmt.Errorf("initialize web admin access: %w", err)
	}
	return nil
}

func readAdminPassword(reader io.Reader) ([]byte, error) {
	password, err := io.ReadAll(io.LimitReader(reader, maxAdminPasswordBytes+3))
	if err != nil {
		return nil, fmt.Errorf("read admin password: %w", err)
	}
	if bytes.HasSuffix(password, []byte{'\n'}) {
		password = password[:len(password)-1]
		if bytes.HasSuffix(password, []byte{'\r'}) {
			password = password[:len(password)-1]
		}
	}
	if len(password) == 0 {
		return nil, errors.New("admin password is empty")
	}
	if len(password) > maxAdminPasswordBytes {
		clear(password)
		return nil, errors.New("admin password exceeds the size limit")
	}
	if bytes.ContainsAny(password, "\r\n") {
		clear(password)
		return nil, errors.New("admin password must be a single line")
	}
	return password, nil
}

func createEnrollment(arguments []string) error {
	flags := flag.NewFlagSet("create-enrollment", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	adminSocket := flags.String(
		"admin-socket",
		"/run/theatropolis/master-admin.sock",
		"local administrative Unix socket",
	)
	agentID := flags.String("agent-id", "", "agent identity")
	expiresIn := flags.Duration("expires-in", 15*time.Minute, "token lifetime")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*agentID) == "" {
		return errors.New("--agent-id is required and positional arguments are not accepted")
	}
	if *expiresIn <= 0 || *expiresIn > 24*time.Hour {
		return errors.New("--expires-in must be between 1ns and 24h")
	}

	payload, err := json.Marshal(enrollmentRequest{
		AgentID:    *agentID,
		TTLSeconds: int64(expiresIn.Seconds()),
	})
	if err != nil {
		return err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *adminSocket)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, err := http.NewRequest(
		http.MethodPost,
		"http://theatropolis/v1/enrollments",
		strings.NewReader(string(payload)),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("contact local master: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf(
			"master rejected enrollment creation with status %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}
	var created enrollmentResponse
	if err := json.Unmarshal(body, &created); err != nil {
		return fmt.Errorf("decode master response: %w", err)
	}
	fmt.Println(created.Token)
	return nil
}

func listenLoopback(address string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("listener must be an IP address and port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("listener must use a literal loopback IP address")
	}
	return net.Listen("tcp", address)
}

func listenUnixSocket(path string) (net.Listener, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("administrative socket path is required")
	}
	path = filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("administrative socket path already exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

type enrollmentRequest struct {
	AgentID    string `json:"agent_id"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

type enrollmentResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func adminHandler(registry *identity.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enrollments", func(response http.ResponseWriter, request *http.Request) {
		setSecurityHeaders(response.Header())
		response.Header().Set("Cache-Control", "no-store")
		if request.Method != http.MethodPost {
			response.Header().Set("Allow", http.MethodPost)
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body := http.MaxBytesReader(response, request.Body, 4<<10)
		decoder := json.NewDecoder(body)
		decoder.DisallowUnknownFields()
		var enrollment enrollmentRequest
		if err := decoder.Decode(&enrollment); err != nil {
			http.Error(response, "invalid request", http.StatusBadRequest)
			return
		}
		if err := ensureRequestEOF(decoder); err != nil {
			http.Error(response, "invalid request", http.StatusBadRequest)
			return
		}
		if enrollment.TTLSeconds <= 0 || enrollment.TTLSeconds > 24*60*60 {
			http.Error(response, "invalid enrollment lifetime", http.StatusBadRequest)
			return
		}
		ttl := time.Duration(enrollment.TTLSeconds) * time.Second
		expiresAt := time.Now().UTC().Add(ttl)
		token, err := registry.CreateEnrollment(
			request.Context(),
			enrollment.AgentID,
			expiresAt,
		)
		if err != nil {
			status := http.StatusInternalServerError
			switch {
			case errors.Is(err, identity.ErrInvalidAgentID):
				status = http.StatusBadRequest
			case errors.Is(err, identity.ErrAgentAlreadyEnrolled),
				errors.Is(err, identity.ErrEnrollmentPending):
				status = http.StatusConflict
			default:
				slog.Error(
					"create local enrollment",
					"agent_id",
					enrollment.AgentID,
					"error",
					err,
				)
			}
			http.Error(response, "enrollment was not created", status)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(enrollmentResponse{
			Token:     base64.RawURLEncoding.EncodeToString(token),
			ExpiresAt: expiresAt,
		})
	})
	return mux
}

func ensureRequestEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return err
	}
	return nil
}

func setSecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

type logNotifier struct {
	logger *slog.Logger
}

func (n logNotifier) Notify(ctx context.Context, event deployment.Event) error {
	n.logger.InfoContext(
		ctx,
		"deployment event",
		"deployment_id", event.Deployment.ID,
		"agent_id", event.Deployment.AgentID,
		"status", event.Deployment.Status,
		"message", event.Message,
	)
	return nil
}
