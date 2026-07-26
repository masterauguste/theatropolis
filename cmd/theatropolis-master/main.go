package main

import (
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
	"strings"
	"syscall"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

const maxWireMessageBytes = control.DefaultMaxConfigBytes + 64<<10

var (
	version   = "development"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("master stopped", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("expected serve, create-enrollment, or version")
	}
	switch arguments[0] {
	case "serve":
		return serve(arguments[1:])
	case "create-enrollment":
		return createEnrollment(arguments[1:])
	case "version":
		fmt.Printf("%s (commit %s, built %s)\n", version, commit, buildDate)
		return nil
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
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
	deployments := deployment.NewMemoryStore()
	server := control.NewServer(
		identities,
		deployments,
		logNotifier{logger: logger},
		logger,
	)

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxWireMessageBytes),
		grpc.MaxSendMsgSize(maxWireMessageBytes),
	)
	controlv1.RegisterAgentControlServiceServer(grpcServer, server)
	healthServer := health.NewServer()
	healthServer.SetServingStatus(
		controlv1.AgentControlService_ServiceDesc.ServiceName,
		healthv1.HealthCheckResponse_SERVING,
	)
	healthv1.RegisterHealthServer(grpcServer, healthServer)

	webServer := &http.Server{
		Handler:           webHandler(),
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

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
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

func webHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setSecurityHeaders(response.Header())
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"status":"ok"}`+"\n")
	})
	mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		setSecurityHeaders(response.Header())
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(
			response,
			"Theatropolis master is running; the web interface is not implemented yet.\n",
		)
	})
	return mux
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
		ttl := time.Duration(enrollment.TTLSeconds) * time.Second
		if ttl <= 0 || ttl > 24*time.Hour {
			http.Error(response, "invalid enrollment lifetime", http.StatusBadRequest)
			return
		}
		expiresAt := time.Now().UTC().Add(ttl)
		token, err := registry.CreateEnrollment(
			request.Context(),
			enrollment.AgentID,
			expiresAt,
		)
		if err != nil {
			http.Error(response, "enrollment was not created", http.StatusBadRequest)
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
