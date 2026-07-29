package webui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"github.com/masterauguste/theatropolis/internal/singboxupdate"
)

const (
	maxLoginBodyBytes             = 8 << 10
	maxEnrollmentBodyBytes        = 4 << 10
	maxConfigurationBytes         = 4 << 20
	maxConfigurationFormBytes     = 3*maxConfigurationBytes + 8<<10
	maxConfigurationJSONDepth     = 128
	enrollmentLimit               = 30
	enrollmentWindow              = time.Minute
	enrollmentResultLimit         = 64
	enrollmentResultTTL           = 5 * time.Minute
	configurationDeploymentPeriod = 60 * time.Second
	defaultConfigurationJSON      = "{\n  \"inbounds\": [],\n  \"outbounds\": []\n}\n"
)

var (
	//go:embed assets/* templates/*
	webFiles embed.FS

	domainLabelPattern = regexp.MustCompile(`\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z`)
	allowedTTLs        = map[int64]time.Duration{
		900:   15 * time.Minute,
		3600:  time.Hour,
		86400: 24 * time.Hour,
	}
)

type SessionRegistry interface {
	IsOnline(agentID string) bool
	AgentInfo(agentID string) (control.AgentInfo, bool)
}

type AgentController interface {
	CanDeployConfiguration(agentID string) bool
	CanUpdateAgent(agentID string) bool
	LatestAgentUpdate(agentID string) (control.AgentUpdateState, bool)
	QueueAgentUpdate(context.Context, string, string, string) error
	CanUpdateSingBox(agentID string) bool
	LatestSingBoxUpdate(agentID string) (control.SingBoxUpdateState, bool)
	QueueSingBoxUpdate(context.Context, string, string, string) error
	LatestDeployment(context.Context, string) (deployment.Record, error)
	QueueDeployment(
		context.Context,
		string,
		string,
		string,
		[]byte,
		time.Duration,
	) (deployment.Record, error)
	RevokeAgent(context.Context, string) error
	// DeploymentRecords lists the latest deployment record per agent for
	// outbound-pool derivation.
	DeploymentRecords(context.Context) ([]deployment.Record, error)
	// PoolRegistry exposes the fleet-wide outbound pool; it may be nil, in
	// which case every pool control is hidden.
	PoolRegistry() *pool.Registry
	// PropagateManualPoolChange redeploys agents whose configuration
	// references pool entries after an operator pool mutation.
	PropagateManualPoolChange(context.Context)
	// RequestAddressProbe asks an online, probe-capable agent to resolve
	// its public address for one explicit family ("ipv4" or "ipv6").
	RequestAddressProbe(agentID, family string) error
}

type Options struct {
	Registry        *identity.Registry
	Sessions        SessionRegistry
	Controller      AgentController
	Access          *AccessManager
	Releases        ReleaseCatalog
	SingBoxReleases ReleaseCatalog
	GeositeRuleSets RuleSetOptions
	GeoipRuleSets   RuleSetOptions
	MasterUpdater   *agentupdate.Scheduler
	PublicURL       string
	Version         string
	Logger          *slog.Logger
	Now             func() time.Time
}

type Handler struct {
	registry        *identity.Registry
	sessions        SessionRegistry
	controller      AgentController
	access          *AccessManager
	releases        ReleaseCatalog
	singBoxReleases ReleaseCatalog
	geositeRuleSets RuleSetOptions
	geoipRuleSets   RuleSetOptions
	masterUpdater   *agentupdate.Scheduler
	version         string
	publicURL       string
	publicScheme    string
	publicHost      string
	publicPort      string
	masterAddress   string
	assetVersion    string
	logger          *slog.Logger
	now             func() time.Time
	templates       *template.Template
	mux             *http.ServeMux

	enrollmentMu            sync.Mutex
	enrollmentWindowStarted time.Time
	enrollmentCount         int

	resultMu sync.Mutex
	results  map[string]enrollmentResult

	// agentMutationMu keeps web-originated enrollment creation/result storage
	// and revocation/result removal in one order. Without it, a concurrent
	// revoke could leave the browser holding a newly stored but already
	// invalid installation command.
	agentMutationMu sync.Mutex
}

type pageData struct {
	Title                 string
	ActiveNav             string
	AssetVersion          string
	PublicURL             string
	MasterAddress         string
	CSRFToken             string
	Error                 string
	ErrorField            string
	Username              string
	LegacyLogin           bool
	AgentID               string
	TTLSeconds            int64
	Stats                 fleetStats
	Agents                []agentView
	Agent                 *agentDetailView
	Created               *createdServerView
	AgentVersions         []agentVersionView
	ReleaseCatalogWarning string
	LatestVersion         string
	SingBoxVersions       []agentVersionView
	SingBoxCatalogWarning string
	LatestSingBoxVersion  string
	MasterVersion         string
	MasterUpdateEnabled   bool
	MasterUpdate          *agentUpdateView
	MasterUpdateRequestID string
	Pool                  *poolView
	PoolFormName          string
	PoolFormJSON          string
}

type fleetStats struct {
	Total     int
	Online    int
	Pending   int
	Attention int
}

type agentView struct {
	ID              string
	Initial         string
	EnrollmentLabel string
	EnrollmentClass string
	ConnectionLabel string
	ConnectionClass string
	Detail          string
	URL             string
	IPv4            string
	IPv6            string
}

type agentDetailView struct {
	ID                    string
	URL                   string
	DeploymentStatusURL   string
	EnrollmentLabel       string
	EnrollmentClass       string
	ConnectionLabel       string
	ConnectionClass       string
	ConnectionDetail      string
	Configuration         string
	ConfigurationEnabled  bool
	ConfigurationEditable bool
	ConfigurationHint     string
	Deployment            *deploymentView
	AgentVersion          string
	OperatingSystem       string
	Architecture          string
	SingBoxVersion        string
	SingBoxUpdateEnabled  bool
	SingBoxUpdateHint     string
	SingBoxUpdateTarget   string
	SingBoxUpdate         *agentUpdateView
	UpdateEnabled         bool
	UpdateHint            string
	UpdateTarget          string
	Update                *agentUpdateView
	RevokeLabel           string
}

type agentUpdateView struct {
	TargetVersion  string
	RunningVersion string
	StatusLabel    string
	StatusClass    string
	Diagnostic     string
	UpdatedAt      string
}

type agentVersionView struct {
	Tag    string
	Branch string
}

type deploymentView struct {
	ID          string
	RevisionID  string
	StatusLabel string
	StatusClass string
	Diagnostic  string
	Digest      string
	UpdatedAt   string
	Pending     bool
}

type createdServerView struct {
	AgentID        string
	InstallCommand string
	ExpiresAt      string
	ExpiresAtISO   string
}

type enrollmentResult struct {
	owner     [credentialBytes]byte
	created   createdServerView
	createdAt time.Time
}

func New(options Options) (http.Handler, error) {
	if options.Registry == nil {
		return nil, errors.New("web UI identity registry is required")
	}
	if options.Sessions == nil {
		return nil, errors.New("web UI session registry is required")
	}
	if options.Controller == nil {
		return nil, errors.New("web UI agent controller is required")
	}
	if options.Access == nil {
		return nil, errors.New("web UI access manager is required")
	}
	public, err := parsePublicURL(options.PublicURL)
	if err != nil {
		return nil, err
	}
	templates, err := template.ParseFS(webFiles, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse web UI templates: %w", err)
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	versionLabel := strings.TrimSpace(options.Version)
	if versionLabel == "" {
		versionLabel = "development"
	}
	versionDigest := sha256.Sum256([]byte(versionLabel))

	handler := &Handler{
		registry:        options.Registry,
		sessions:        options.Sessions,
		controller:      options.Controller,
		access:          options.Access,
		releases:        options.Releases,
		singBoxReleases: options.SingBoxReleases,
		geositeRuleSets: options.GeositeRuleSets,
		geoipRuleSets:   options.GeoipRuleSets,
		masterUpdater:   options.MasterUpdater,
		version:         versionLabel,
		publicURL:       public.origin,
		publicScheme:    public.scheme,
		publicHost:      public.hostname,
		publicPort:      public.port,
		masterAddress:   net.JoinHostPort(public.hostname, public.port),
		assetVersion:    base64.RawURLEncoding.EncodeToString(versionDigest[:12]),
		logger:          logger,
		now:             now,
		templates:       templates,
		mux:             http.NewServeMux(),
		results:         make(map[string]enrollmentResult),
	}
	handler.routes()
	return handler, nil
}

func (h *Handler) routes() {
	h.mux.HandleFunc("GET /healthz", h.health)
	h.mux.HandleFunc("GET /assets/app.css", h.asset("assets/app.css", "text/css; charset=utf-8"))
	h.mux.HandleFunc("GET /assets/app.js", h.asset("assets/app.js", "text/javascript; charset=utf-8"))
	h.mux.HandleFunc(
		"GET /assets/config-editor.js",
		h.asset("assets/config-editor.js", "text/javascript; charset=utf-8"),
	)
	h.mux.HandleFunc("GET /login", h.loginPage)
	h.mux.HandleFunc("POST /login", h.login)
	h.mux.HandleFunc("POST /logout", h.logout)
	h.mux.HandleFunc("GET /servers", h.serversPage)
	h.mux.HandleFunc("GET /pool", h.poolPage)
	h.mux.HandleFunc("POST /pool", h.upsertPoolEntry)
	h.mux.HandleFunc("POST /pool/delete", h.deletePoolEntry)
	h.mux.HandleFunc("GET /settings", h.settingsPage)
	h.mux.HandleFunc("GET /settings/versions", h.masterVersions)
	h.mux.HandleFunc("GET /settings/update-status", h.masterUpdateStatus)
	h.mux.HandleFunc("GET /servers/new", h.newServerPage)
	h.mux.HandleFunc("GET /servers/enrollment-result", h.enrollmentResultPage)
	h.mux.HandleFunc(
		"GET /servers/{agent_id}/deployment-status",
		h.deploymentStatus,
	)
	h.mux.HandleFunc("GET /servers/{agent_id}/manage", h.serverPage)
	h.mux.HandleFunc(
		"GET /servers/{agent_id}/versions",
		h.serverVersions,
	)
	h.mux.HandleFunc(
		"GET /servers/{agent_id}/rule-set-options",
		h.serverRuleSetOptions,
	)
	h.mux.HandleFunc(
		"GET /servers/{agent_id}/pool-options",
		h.serverPoolOptions,
	)
	h.mux.HandleFunc(
		"POST /servers/{agent_id}/address",
		h.setServerAddress,
	)
	h.mux.HandleFunc(
		"POST /servers/{agent_id}/probe-address",
		h.requestAddressProbe,
	)
	h.mux.HandleFunc(
		"POST /servers/{agent_id}/configuration",
		h.deployServerConfiguration,
	)
	h.mux.HandleFunc("POST /servers/{agent_id}/revoke", h.revokeServer)
	h.mux.HandleFunc("POST /servers/{agent_id}/agent-update", h.updateAgent)
	h.mux.HandleFunc("POST /servers/{agent_id}/sing-box-update", h.updateSingBox)
	h.mux.HandleFunc("POST /master-update", h.updateMaster)
	h.mux.HandleFunc("POST /servers", h.createServer)
	h.mux.HandleFunc("GET /", h.root)
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(response.Header())
	if request.URL.Path != "/healthz" && !h.validRequestHost(request.Host) {
		http.Error(response, "request host is not configured", http.StatusMisdirectedRequest)
		return
	}
	h.mux.ServeHTTP(response, request)
}

func (h *Handler) root(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(response, request)
		return
	}
	if _, ok := h.authenticate(request); !ok {
		http.Redirect(response, request, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(response, request, "/servers", http.StatusSeeOther)
}

func (h *Handler) health(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(response, `{"status":"ok"}`+"\n")
}

func (h *Handler) asset(path, contentType string) http.HandlerFunc {
	content, err := webFiles.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("read embedded web asset %q: %v", path, err))
	}
	return func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", contentType)
		response.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = response.Write(content)
	}
}

func (h *Handler) loginPage(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.authenticate(request); ok {
		http.Redirect(response, request, "/servers", http.StatusSeeOther)
		return
	}
	h.render(
		response,
		http.StatusOK,
		"login.html",
		loginPageData(h.access.Mode(), ""),
	)
}

func (h *Handler) login(response http.ResponseWriter, request *http.Request) {
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	mode := h.access.Mode()
	var (
		username string
		password string
		err      error
	)
	switch mode {
	case LegacyAccessKey:
		var form url.Values
		form, err = readExactForm(
			response,
			request,
			maxLoginBodyBytes,
			"access_key",
		)
		if err == nil {
			password = form.Get("access_key")
		}
	case UsernamePassword:
		var form url.Values
		form, err = readExactForm(
			response,
			request,
			maxLoginBodyBytes,
			"password",
			"username",
		)
		if err == nil {
			username = form.Get("username")
			password = form.Get("password")
		}
	default:
		h.logger.Error("unsupported web credential mode", "mode", mode)
		http.Error(
			response,
			"interface could not authenticate",
			http.StatusInternalServerError,
		)
		return
	}
	if err != nil {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	session, err := h.access.Login(username, password)
	if err != nil {
		status := http.StatusUnauthorized
		message := "The username or password was not accepted."
		if mode == LegacyAccessKey {
			message = "The access key was not accepted."
		}
		if errors.Is(err, ErrLoginRateLimited) {
			status = http.StatusTooManyRequests
			message = "Too many attempts. Wait one minute and try again."
			response.Header().Set("Retry-After", "60")
		}
		data := loginPageData(mode, username)
		data.Error = message
		h.render(response, status, "login.html", data)
		return
	}
	http.SetCookie(response, NewSessionCookie(session.Token, session.ExpiresAt))
	http.Redirect(response, request, "/servers", http.StatusSeeOther)
}

func loginPageData(mode CredentialMode, username string) pageData {
	return pageData{
		Title:       "Sign in",
		Username:    username,
		LegacyLogin: mode == LegacyAccessKey,
	}
}

func (h *Handler) logout(response http.ResponseWriter, request *http.Request) {
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	sessionToken, ok := h.sessionToken(request)
	if !ok {
		http.Redirect(response, request, "/login", http.StatusSeeOther)
		return
	}
	form, err := readExactForm(response, request, maxLoginBodyBytes, "csrf_token")
	if err != nil || !h.access.AuthorizeCSRF(sessionToken, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	if err := h.access.Logout(sessionToken); err != nil {
		h.logger.Error("persist web logout", "error", err)
		http.Error(response, "logout could not be completed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(response, DeleteSessionCookie())
	http.Redirect(response, request, "/login", http.StatusSeeOther)
}

func (h *Handler) serversPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	now := h.currentTime()
	snapshots := h.registry.Snapshot(now)
	agents := make([]agentView, 0, len(snapshots))
	stats := fleetStats{Total: len(snapshots)}
	for _, snapshot := range snapshots {
		online := snapshot.State == identity.AgentStateEnrolled &&
			h.sessions.IsOnline(snapshot.ID)
		view := agentViewFor(snapshot, now, online)
		if snapshot.State == identity.AgentStateEnrolled {
			view.IPv4, view.IPv6 = h.poolAddresses(snapshot.ID)
		}
		agents = append(agents, view)
		switch {
		case snapshot.State == identity.AgentStatePending:
			stats.Pending++
		case snapshot.State == identity.AgentStateExpired:
			stats.Attention++
		case snapshot.State == identity.AgentStateEnrolled && online:
			stats.Online++
		case snapshot.State == identity.AgentStateEnrolled:
			stats.Attention++
		}
	}
	h.render(response, http.StatusOK, "servers.html", pageData{
		Title:     "Servers",
		ActiveNav: "servers",
		CSRFToken: session.CSRFToken,
		Stats:     stats,
		Agents:    agents,
	})
}

func (h *Handler) settingsPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" {
		http.NotFound(response, request)
		return
	}
	h.render(
		response,
		http.StatusOK,
		"settings.html",
		h.settingsPageData(session),
	)
}

func (h *Handler) settingsPageData(session Session) pageData {
	var masterUpdate *agentUpdateView
	if h.masterUpdater != nil {
		if result, exists, err := h.masterUpdater.LoadResult(); err == nil && exists {
			masterUpdate = updateResultViewFor(result)
		}
	}
	return pageData{
		Title:         "Settings",
		ActiveNav:     "settings",
		CSRFToken:     session.CSRFToken,
		MasterVersion: h.version,
		MasterUpdate:  masterUpdate,
	}
}

func (h *Handler) masterVersions(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.authenticate(request); !ok {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	versions, latest, warning := h.releaseVersions(request.Context())
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(versionCatalogResponse{
		LatestVersion:       latest,
		AgentVersions:       versions,
		AgentCatalogWarning: warning,
	}); err != nil {
		h.logger.Warn("encode master version catalog", "error", err)
	}
}

func (h *Handler) masterUpdateStatus(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.authenticate(request); !ok {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(response, `{"status":"restarting"}`+"\n")
		return
	}
	requestID := request.URL.Query().Get("request_id")
	if !agentupdate.ValidRequestID(requestID) || h.masterUpdater == nil {
		http.Error(response, "invalid update status request", http.StatusBadRequest)
		return
	}
	result, exists, err := h.masterUpdater.LoadResult()
	if err != nil {
		http.Error(response, "update status could not be loaded", http.StatusInternalServerError)
		return
	}
	status := "updating"
	if exists && result.RequestID == requestID {
		status = result.Status
		if status == "applied" && h.version != result.TargetVersion {
			status = "restarting"
		}
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(map[string]string{
		"status":          status,
		"running_version": result.RunningVersion,
		"diagnostic":      result.Diagnostic,
	})
}

func (h *Handler) serverPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" {
		http.NotFound(response, request)
		return
	}
	snapshot, ok := h.agentSnapshot(request.PathValue("agent_id"))
	if !ok {
		http.NotFound(response, request)
		return
	}
	data, err := h.serverPageData(request.Context(), session, snapshot, "")
	if err != nil {
		h.logger.Error(
			"load server management page",
			"agent_id",
			snapshot.ID,
			"error",
			err,
		)
		http.Error(response, "server details could not be loaded", http.StatusInternalServerError)
		return
	}
	h.render(response, http.StatusOK, "server.html", data)
}

func (h *Handler) deploymentStatus(
	response http.ResponseWriter,
	request *http.Request,
) {
	if _, ok := h.requireAuthentication(response, request); !ok {
		return
	}
	if request.URL.RawQuery != "" {
		http.NotFound(response, request)
		return
	}
	snapshot, ok := h.agentSnapshot(request.PathValue("agent_id"))
	if !ok {
		http.NotFound(response, request)
		return
	}
	record, err := h.controller.LatestDeployment(request.Context(), snapshot.ID)
	if err != nil && !errors.Is(err, deployment.ErrNotFound) {
		h.logger.Error(
			"load deployment polling status",
			"agent_id",
			snapshot.ID,
			"error",
			err,
		)
		http.Error(response, "deployment status could not be loaded", http.StatusInternalServerError)
		return
	}
	pending := false
	if err == nil {
		pending = deploymentViewFor(record).Pending
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(response).Encode(struct {
		Pending bool `json:"pending"`
	}{Pending: pending}); err != nil {
		h.logger.Error(
			"write deployment polling status",
			"agent_id",
			snapshot.ID,
			"error",
			err,
		)
	}
}

func (h *Handler) deployServerConfiguration(
	response http.ResponseWriter,
	request *http.Request,
) {
	sessionToken, ok := h.sessionToken(request)
	if !ok {
		h.redirectToLogin(response, request)
		return
	}
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	form, err := readExactForm(
		response,
		request,
		maxConfigurationFormBytes,
		"config_json",
		"csrf_token",
	)
	if err != nil || !h.access.AuthorizeCSRF(sessionToken, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	session, err := h.access.Authenticate(sessionToken)
	if err != nil {
		h.redirectToLogin(response, request)
		return
	}
	snapshot, ok := h.agentSnapshot(request.PathValue("agent_id"))
	if !ok {
		http.NotFound(response, request)
		return
	}

	config := []byte(form.Get("config_json"))
	if err := validateConfigurationJSON(config); err != nil {
		h.renderServerError(
			response,
			http.StatusBadRequest,
			session,
			snapshot,
			string(config),
			err.Error(),
			"config_json",
		)
		return
	}
	if err := singbox.ValidateManagedConfig(config); err != nil {
		message := "The configuration does not satisfy the managed-agent safety policy."
		if errors.Is(err, singbox.ErrReservedListenPort) {
			message = singbox.ReservedListenPortMessage()
		}
		h.renderServerError(
			response,
			http.StatusBadRequest,
			session,
			snapshot,
			string(config),
			message,
			"config_json",
		)
		return
	}
	if snapshot.State != identity.AgentStateEnrolled {
		h.renderServerError(
			response,
			http.StatusConflict,
			session,
			snapshot,
			string(config),
			"Finish enrolling this server before deploying a configuration.",
			"",
		)
		return
	}
	if !h.sessions.IsOnline(snapshot.ID) {
		h.renderServerError(
			response,
			http.StatusConflict,
			session,
			snapshot,
			string(config),
			"The agent is offline. Reconnect it before deploying a configuration.",
			"",
		)
		return
	}
	if !h.controller.CanDeployConfiguration(snapshot.ID) {
		h.renderServerError(
			response,
			http.StatusConflict,
			session,
			snapshot,
			string(config),
			"Update the agent or repair its sing-box installation before deploying configuration from this master.",
			"",
		)
		return
	}

	deploymentID, err := randomOpaqueID("dep")
	if err != nil {
		h.logger.Error("generate deployment ID", "agent_id", snapshot.ID, "error", err)
		http.Error(response, "deployment could not be prepared", http.StatusInternalServerError)
		return
	}
	revisionID, err := randomOpaqueID("rev")
	if err != nil {
		h.logger.Error("generate revision ID", "agent_id", snapshot.ID, "error", err)
		http.Error(response, "deployment could not be prepared", http.StatusInternalServerError)
		return
	}
	record, err := h.controller.QueueDeployment(
		request.Context(),
		snapshot.ID,
		deploymentID,
		revisionID,
		config,
		configurationDeploymentPeriod,
	)
	clear(config)
	if err != nil {
		status := http.StatusInternalServerError
		message := "The configuration could not be deployed."
		switch {
		case record.Status == deployment.StatusDeliveryFailed:
			status = http.StatusConflict
			message = "The agent disconnected before the configuration could be delivered."
		case errors.Is(err, deployment.ErrDeploymentInProgress):
			status = http.StatusConflict
			message = "A configuration deployment is already in progress for this server."
		case errors.Is(err, deployment.ErrNotFound),
			errors.Is(err, identity.ErrAgentNotFound):
			status = http.StatusNotFound
			message = "The server entry no longer exists."
		default:
			h.logger.Error(
				"queue configuration deployment",
				"agent_id",
				snapshot.ID,
				"deployment_id",
				deploymentID,
				"error",
				err,
			)
		}
		h.renderServerError(
			response,
			status,
			session,
			snapshot,
			form.Get("config_json"),
			message,
			"",
		)
		return
	}
	h.logger.Info(
		"configuration deployment queued",
		"agent_id",
		snapshot.ID,
		"deployment_id",
		record.ID,
		"revision_id",
		record.RevisionID,
	)
	http.Redirect(
		response,
		request,
		"/servers/"+url.PathEscape(snapshot.ID)+"/manage",
		http.StatusSeeOther,
	)
}

func (h *Handler) revokeServer(response http.ResponseWriter, request *http.Request) {
	sessionToken, ok := h.sessionToken(request)
	if !ok {
		h.redirectToLogin(response, request)
		return
	}
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	form, err := readExactForm(
		response,
		request,
		maxEnrollmentBodyBytes,
		"agent_id",
		"confirm_revoke",
		"csrf_token",
	)
	if err != nil || !h.access.AuthorizeCSRF(sessionToken, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	if _, err := h.access.Authenticate(sessionToken); err != nil {
		h.redirectToLogin(response, request)
		return
	}
	h.agentMutationMu.Lock()
	defer h.agentMutationMu.Unlock()
	agentID := request.PathValue("agent_id")
	if form.Get("agent_id") != agentID || form.Get("confirm_revoke") != "yes" {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	if _, ok := h.agentSnapshot(agentID); !ok {
		http.NotFound(response, request)
		return
	}
	if err := h.controller.RevokeAgent(request.Context(), agentID); err != nil {
		if errors.Is(err, identity.ErrAgentNotFound) {
			http.NotFound(response, request)
			return
		}
		h.logger.Error("revoke server", "agent_id", agentID, "error", err)
		http.Error(response, "server access could not be revoked", http.StatusInternalServerError)
		return
	}
	h.removeEnrollmentResultsForAgent(agentID)
	h.logger.Info("server access revoked", "agent_id", agentID)
	http.Redirect(response, request, "/servers", http.StatusSeeOther)
}

func (h *Handler) updateAgent(response http.ResponseWriter, request *http.Request) {
	sessionToken, ok := h.sessionToken(request)
	if !ok {
		h.redirectToLogin(response, request)
		return
	}
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	form, err := readExactForm(
		response,
		request,
		maxEnrollmentBodyBytes,
		"csrf_token",
		"target_version",
	)
	if err != nil || !h.access.AuthorizeCSRF(sessionToken, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	session, err := h.access.Authenticate(sessionToken)
	if err != nil {
		h.redirectToLogin(response, request)
		return
	}
	snapshot, ok := h.agentSnapshot(request.PathValue("agent_id"))
	if !ok {
		http.NotFound(response, request)
		return
	}
	targetVersion := strings.TrimSpace(form.Get("target_version"))
	if !agentupdate.ValidVersion(targetVersion) {
		h.renderAgentUpdateError(
			response,
			http.StatusBadRequest,
			session,
			snapshot,
			targetVersion,
			"Enter an exact release such as v0.0.10.",
		)
		return
	}
	if snapshot.State != identity.AgentStateEnrolled ||
		!h.controller.CanUpdateAgent(snapshot.ID) {
		h.renderAgentUpdateError(
			response,
			http.StatusConflict,
			session,
			snapshot,
			targetVersion,
			"Update control is unavailable until this server is online with a compatible agent.",
		)
		return
	}
	requestID, err := randomOpaqueID("update")
	if err != nil {
		h.logger.Error("generate agent update ID", "agent_id", snapshot.ID, "error", err)
		http.Error(response, "agent update could not be prepared", http.StatusInternalServerError)
		return
	}
	if err := h.controller.QueueAgentUpdate(
		request.Context(),
		snapshot.ID,
		requestID,
		targetVersion,
	); err != nil {
		status := http.StatusConflict
		message := "The agent could not accept the update request."
		if errors.Is(err, control.ErrAgentOffline) {
			message = "The agent went offline before the update request could be delivered."
		}
		if !errors.Is(err, agentupdate.ErrUpdatePending) &&
			!errors.Is(err, control.ErrAgentOffline) {
			h.logger.Error("queue agent update", "agent_id", snapshot.ID, "error", err)
			status = http.StatusInternalServerError
		}
		h.renderAgentUpdateError(
			response,
			status,
			session,
			snapshot,
			targetVersion,
			message,
		)
		return
	}
	http.Redirect(response, request, "/servers/"+url.PathEscape(snapshot.ID)+"/manage", http.StatusSeeOther)
}

func (h *Handler) updateSingBox(
	response http.ResponseWriter,
	request *http.Request,
) {
	sessionToken, ok := h.sessionToken(request)
	if !ok {
		h.redirectToLogin(response, request)
		return
	}
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	form, err := readExactForm(
		response,
		request,
		maxEnrollmentBodyBytes,
		"csrf_token",
		"target_version",
	)
	if err != nil ||
		!h.access.AuthorizeCSRF(sessionToken, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	session, err := h.access.Authenticate(sessionToken)
	if err != nil {
		h.redirectToLogin(response, request)
		return
	}
	snapshot, ok := h.agentSnapshot(request.PathValue("agent_id"))
	if !ok {
		http.NotFound(response, request)
		return
	}
	targetVersion := strings.TrimSpace(form.Get("target_version"))
	message := ""
	statusCode := http.StatusBadRequest
	if !singboxupdate.ValidVersion(targetVersion) {
		message = "Choose an exact sing-box 1.14+ stable or testing release."
	} else if snapshot.State != identity.AgentStateEnrolled ||
		!h.controller.CanUpdateSingBox(snapshot.ID) {
		message = "sing-box update control is unavailable until this server is online with a compatible agent."
		statusCode = http.StatusConflict
	} else {
		requestID, randomErr := randomOpaqueID("singbox")
		if randomErr != nil {
			http.Error(
				response,
				"sing-box update could not be prepared",
				http.StatusInternalServerError,
			)
			return
		}
		if queueErr := h.controller.QueueSingBoxUpdate(
			request.Context(),
			snapshot.ID,
			requestID,
			targetVersion,
		); queueErr != nil {
			statusCode = http.StatusConflict
			message = "The agent could not accept the sing-box update request."
			if !errors.Is(queueErr, singboxupdate.ErrUpdatePending) &&
				!errors.Is(queueErr, control.ErrAgentOffline) {
				h.logger.Error(
					"queue sing-box update",
					"agent_id", snapshot.ID,
					"error", queueErr,
				)
				statusCode = http.StatusInternalServerError
			}
		}
	}
	if message != "" {
		data, dataErr := h.serverPageData(
			context.Background(),
			session,
			snapshot,
			"",
		)
		if dataErr != nil {
			http.Error(
				response,
				"server details could not be loaded",
				http.StatusInternalServerError,
			)
			return
		}
		data.Error = message
		data.ErrorField = "sing_box_target_version"
		data.Agent.SingBoxUpdateTarget = targetVersion
		h.render(response, statusCode, "server.html", data)
		return
	}
	http.Redirect(
		response,
		request,
		"/servers/"+url.PathEscape(snapshot.ID)+"/manage",
		http.StatusSeeOther,
	)
}

func (h *Handler) updateMaster(response http.ResponseWriter, request *http.Request) {
	sessionToken, ok := h.sessionToken(request)
	if !ok {
		h.redirectToLogin(response, request)
		return
	}
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	form, err := readExactForm(
		response,
		request,
		maxEnrollmentBodyBytes,
		"csrf_token",
	)
	if err != nil || !h.access.AuthorizeCSRF(sessionToken, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	if _, err := h.access.Authenticate(sessionToken); err != nil {
		h.redirectToLogin(response, request)
		return
	}
	if h.masterUpdater == nil || h.releases == nil {
		http.Error(response, "master update control is unavailable", http.StatusConflict)
		return
	}
	releases, err := h.releases.Versions(request.Context())
	if err != nil || len(releases) == 0 {
		http.Error(response, "the latest release could not be determined", http.StatusServiceUnavailable)
		return
	}
	targetVersion := releases[0].Tag
	if targetVersion == h.version {
		http.Redirect(response, request, "/settings", http.StatusSeeOther)
		return
	}
	requestID, err := randomOpaqueID("master")
	if err != nil {
		http.Error(response, "master update could not be prepared", http.StatusInternalServerError)
		return
	}
	if err := h.masterUpdater.Schedule(requestID, targetVersion); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, agentupdate.ErrUpdatePending) {
			status = http.StatusConflict
		}
		http.Error(response, "master update could not be scheduled", status)
		return
	}
	h.logger.Info(
		"master update scheduled",
		"target_version", targetVersion,
		"request_id", requestID,
	)
	statusURL := "/settings/update-status?request_id=" + url.QueryEscape(requestID)
	if strings.Contains(request.Header.Get("Accept"), "application/json") {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(response).Encode(map[string]string{
			"request_id": requestID,
			"status_url": statusURL,
		})
		return
	}
	h.render(response, http.StatusAccepted, "master-updating.html", pageData{
		Title:                 "Updating master",
		ActiveNav:             "settings",
		CSRFToken:             form.Get("csrf_token"),
		MasterVersion:         h.version,
		MasterUpdateRequestID: requestID,
	})
}

func (h *Handler) renderAgentUpdateError(
	response http.ResponseWriter,
	status int,
	session Session,
	snapshot identity.AgentSnapshot,
	targetVersion string,
	message string,
) {
	data, err := h.serverPageData(
		context.Background(),
		session,
		snapshot,
		"",
	)
	if err != nil {
		http.Error(response, "server details could not be loaded", http.StatusInternalServerError)
		return
	}
	data.Error = message
	data.ErrorField = "target_version"
	h.render(response, status, "server.html", data)
}

func (h *Handler) serverPageData(
	ctx context.Context,
	session Session,
	snapshot identity.AgentSnapshot,
	configurationOverride string,
) (pageData, error) {
	now := h.currentTime()
	online := snapshot.State == identity.AgentStateEnrolled &&
		h.sessions.IsOnline(snapshot.ID)
	summary := agentViewFor(snapshot, now, online)
	detail := &agentDetailView{
		ID:                  snapshot.ID,
		URL:                 "/servers/" + url.PathEscape(snapshot.ID) + "/manage",
		DeploymentStatusURL: "/servers/" + url.PathEscape(snapshot.ID) + "/deployment-status",
		EnrollmentLabel:     summary.EnrollmentLabel,
		EnrollmentClass:     summary.EnrollmentClass,
		ConnectionLabel:     summary.ConnectionLabel,
		ConnectionClass:     summary.ConnectionClass,
		ConnectionDetail:    summary.Detail,
		Configuration:       defaultConfigurationJSON,
		RevokeLabel:         "Remove server entry",
	}
	if info, exists := h.sessions.AgentInfo(snapshot.ID); exists {
		detail.AgentVersion = info.Version
		detail.SingBoxVersion = info.SingBoxVersion
		detail.OperatingSystem = info.OperatingSystem
		detail.Architecture = info.Architecture
	}
	switch snapshot.State {
	case identity.AgentStatePending:
		detail.ConfigurationHint = "The server must enroll before it can receive configuration."
		detail.RevokeLabel = "Cancel enrollment"
	case identity.AgentStateExpired:
		detail.ConfigurationHint = "Remove this expired entry, then add the server again."
		detail.RevokeLabel = "Remove expired entry"
	case identity.AgentStateEnrolled:
		switch {
		case !online:
			detail.ConfigurationHint = "The agent must be online before a configuration can be deployed."
		case !h.controller.CanDeployConfiguration(snapshot.ID):
			detail.ConfigurationHint = "This agent is connected, but its agent or sing-box installation must be updated before it can activate configurations."
		default:
			detail.ConfigurationEnabled = true
			detail.ConfigurationEditable = true
			detail.ConfigurationHint = "The agent checks the JSON with sing-box, atomically activates it, and rolls back if startup fails."
		}
		if h.controller.CanUpdateAgent(snapshot.ID) {
			detail.UpdateEnabled = true
			detail.UpdateHint = "Choose an exact published Theatropolis release. The agent verifies the official checksum before replacing itself."
		} else if online {
			detail.UpdateHint = "Install the current agent once manually to enable secure remote updates."
		} else {
			detail.UpdateHint = "The agent must be online before an update can be requested."
		}
		if h.controller.CanUpdateSingBox(snapshot.ID) {
			detail.SingBoxUpdateEnabled = true
			detail.SingBoxUpdateHint = "Choose any published sing-box 1.14+ stable or testing release. The official GitHub asset digest is verified before installation."
		} else if online {
			detail.SingBoxUpdateHint = "Rerun the current agent installer once to enable secure sing-box installation and updates."
		} else {
			detail.SingBoxUpdateHint = "The agent must be online before sing-box can be installed or updated."
		}
	}

	record, err := h.controller.LatestDeployment(ctx, snapshot.ID)
	if err == nil {
		if len(record.ConfigJSON) != 0 {
			detail.Configuration = string(record.ConfigJSON)
		}
		detail.Deployment = deploymentViewFor(record)
		if detail.Deployment.Pending {
			detail.ConfigurationEditable = false
			detail.ConfigurationHint = "Wait for the current deployment result. This page refreshes automatically."
		}
	} else if !errors.Is(err, deployment.ErrNotFound) {
		return pageData{}, err
	}
	if configurationOverride != "" {
		detail.Configuration = configurationOverride
	}
	if update, exists := h.controller.LatestAgentUpdate(snapshot.ID); exists {
		detail.Update = agentUpdateViewFor(update)
	}
	if update, exists := h.controller.LatestSingBoxUpdate(snapshot.ID); exists {
		detail.SingBoxUpdate = singBoxUpdateViewFor(update)
	}
	return pageData{
		Title:     snapshot.ID,
		ActiveNav: "servers",
		CSRFToken: session.CSRFToken,
		Agent:     detail,
	}, nil
}

type versionCatalogResponse struct {
	LatestVersion         string             `json:"latest_version"`
	AgentVersions         []agentVersionView `json:"agent_versions"`
	AgentCatalogWarning   string             `json:"agent_catalog_warning,omitempty"`
	LatestSingBoxVersion  string             `json:"latest_sing_box_version"`
	SingBoxVersions       []agentVersionView `json:"sing_box_versions"`
	SingBoxCatalogWarning string             `json:"sing_box_catalog_warning,omitempty"`
}

func (h *Handler) serverVersions(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.authenticate(request); !ok {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	if _, exists := h.agentSnapshot(request.PathValue("agent_id")); !exists {
		http.NotFound(response, request)
		return
	}
	result := versionCatalogResponse{}
	switch request.URL.Query().Get("catalog") {
	case "agent":
		result.AgentVersions, result.LatestVersion, result.AgentCatalogWarning =
			h.releaseVersions(request.Context())
	case "sing-box":
		result.SingBoxVersions, result.LatestSingBoxVersion,
			result.SingBoxCatalogWarning = h.releaseVersionsFor(
			request.Context(),
			h.singBoxReleases,
			"sing-box",
		)
	default:
		http.Error(response, "unknown version catalog", http.StatusBadRequest)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(result); err != nil {
		h.logger.Warn("encode version catalog", "error", err)
	}
}

func (h *Handler) releaseVersions(
	ctx context.Context,
) ([]agentVersionView, string, string) {
	return h.releaseVersionsFor(ctx, h.releases, "Theatropolis")
}

func (h *Handler) releaseVersionsFor(
	ctx context.Context,
	catalog ReleaseCatalog,
	component string,
) ([]agentVersionView, string, string) {
	if catalog == nil {
		return nil, "", "Version lookup failed: release catalog is unavailable."
	}
	releases, err := catalog.Versions(ctx)
	if err != nil {
		h.logger.Warn("load release catalog", "component", component, "error", err)
		return nil, "", catalogDiagnostic(err)
	}
	versions := make([]agentVersionView, 0, len(releases))
	for _, release := range releases {
		branch := "Stable"
		if release.Prerelease {
			branch = "Testing"
			tag := release.Tag
			if strings.Contains(tag, "-alpha.") {
				branch = "Alpha"
			} else if strings.Contains(tag, "-beta.") {
				branch = "Beta"
			} else if strings.Contains(tag, "-rc.") {
				branch = "Release Candidate"
			}
		}
		versions = append(versions, agentVersionView{
			Tag:    release.Tag,
			Branch: branch,
		})
	}
	latest := ""
	if len(releases) != 0 {
		latest = releases[0].Tag
	}
	return versions, latest, ""
}

type ruleSetOptionsResponse struct {
	Options []string `json:"options"`
	Warning string   `json:"warning,omitempty"`
}

func (h *Handler) serverRuleSetOptions(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.authenticate(request); !ok {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	if _, exists := h.agentSnapshot(request.PathValue("agent_id")); !exists {
		http.NotFound(response, request)
		return
	}
	var catalog RuleSetOptions
	switch request.URL.Query().Get("kind") {
	case "geosite":
		catalog = h.geositeRuleSets
	case "geoip":
		catalog = h.geoipRuleSets
	default:
		http.Error(response, "unknown rule-set catalog", http.StatusBadRequest)
		return
	}
	result := ruleSetOptionsResponse{}
	if catalog == nil {
		result.Warning = "Rule-set lookup failed: rule-set catalog is unavailable."
	} else if options, err := catalog.Options(request.Context()); err != nil {
		h.logger.Warn("load rule-set catalog", "kind", request.URL.Query().Get("kind"), "error", err)
		result.Warning = ruleSetDiagnostic(err)
	} else {
		result.Options = options
	}
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(result); err != nil {
		h.logger.Warn("encode rule-set catalog", "error", err)
	}
}

func singBoxUpdateViewFor(
	state control.SingBoxUpdateState,
) *agentUpdateView {
	return agentUpdateViewFor(control.AgentUpdateState{
		TargetVersion:  state.TargetVersion,
		RunningVersion: state.RunningVersion,
		Status:         state.Status,
		Diagnostic:     state.Diagnostic,
		UpdatedAt:      state.UpdatedAt,
	})
}

func agentUpdateViewFor(state control.AgentUpdateState) *agentUpdateView {
	label := "Unknown"
	if state.Status != "" {
		label = strings.ToUpper(state.Status[:1]) + state.Status[1:]
	}
	class := "pending"
	switch state.Status {
	case "applied":
		class = "enrolled"
	case "failed", "rejected":
		class = "expired"
	}
	return &agentUpdateView{
		TargetVersion:  state.TargetVersion,
		RunningVersion: state.RunningVersion,
		StatusLabel:    label,
		StatusClass:    class,
		Diagnostic:     state.Diagnostic,
		UpdatedAt:      state.UpdatedAt.UTC().Format("2 Jan 2006, 15:04:05 UTC"),
	}
}

func updateResultViewFor(result agentupdate.Result) *agentUpdateView {
	state := control.AgentUpdateState{
		TargetVersion:  result.TargetVersion,
		RunningVersion: result.RunningVersion,
		Status:         result.Status,
		Diagnostic:     result.Diagnostic,
		UpdatedAt:      result.ObservedAt,
	}
	return agentUpdateViewFor(state)
}

func (h *Handler) renderServerError(
	response http.ResponseWriter,
	status int,
	session Session,
	snapshot identity.AgentSnapshot,
	configuration string,
	message string,
	errorField string,
) {
	data, err := h.serverPageData(
		context.Background(),
		session,
		snapshot,
		configuration,
	)
	if err != nil {
		h.logger.Error(
			"render server error",
			"agent_id",
			snapshot.ID,
			"error",
			err,
		)
		http.Error(response, "server details could not be loaded", http.StatusInternalServerError)
		return
	}
	data.Error = message
	data.ErrorField = errorField
	h.render(response, status, "server.html", data)
}

func (h *Handler) newServerPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	h.render(response, http.StatusOK, "new-server.html", pageData{
		Title:      "Add server",
		ActiveNav:  "servers",
		CSRFToken:  session.CSRFToken,
		TTLSeconds: 900,
	})
}

func (h *Handler) enrollmentResultPage(response http.ResponseWriter, request *http.Request) {
	sessionToken, ok := h.sessionToken(request)
	if !ok {
		h.redirectToLogin(response, request)
		return
	}
	session, err := h.access.Authenticate(sessionToken)
	if err != nil {
		h.redirectToLogin(response, request)
		return
	}
	query := request.URL.Query()
	resultIDs, exists := query["id"]
	if len(query) != 1 || !exists || len(resultIDs) != 1 {
		http.Redirect(response, request, "/servers", http.StatusSeeOther)
		return
	}
	created, ok := h.takeEnrollmentResult(sessionToken, resultIDs[0], h.currentTime())
	if !ok {
		http.Redirect(response, request, "/servers", http.StatusSeeOther)
		return
	}
	h.render(response, http.StatusOK, "server-created.html", pageData{
		Title:     "Enrollment ready",
		ActiveNav: "servers",
		CSRFToken: session.CSRFToken,
		Created:   &created,
	})
}

func (h *Handler) createServer(response http.ResponseWriter, request *http.Request) {
	sessionToken, ok := h.sessionToken(request)
	if !ok {
		h.redirectToLogin(response, request)
		return
	}
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	form, err := readExactForm(
		response,
		request,
		maxEnrollmentBodyBytes,
		"agent_id",
		"csrf_token",
		"ttl_seconds",
	)
	if err != nil || !h.access.AuthorizeCSRF(sessionToken, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	session, err := h.access.Authenticate(sessionToken)
	if err != nil {
		h.redirectToLogin(response, request)
		return
	}

	agentID := strings.TrimSpace(form.Get("agent_id"))
	ttlSeconds, parseErr := strconv.ParseInt(form.Get("ttl_seconds"), 10, 64)
	ttl, ttlAllowed := allowedTTLs[ttlSeconds]
	if parseErr != nil || !ttlAllowed {
		h.renderNewServerError(
			response,
			http.StatusBadRequest,
			session,
			agentID,
			900,
			"Choose a supported enrollment lifetime.",
			"ttl_seconds",
		)
		return
	}
	if !h.allowEnrollment(h.currentTime()) {
		response.Header().Set("Retry-After", "60")
		h.renderNewServerError(
			response,
			http.StatusTooManyRequests,
			session,
			agentID,
			ttlSeconds,
			"Too many enrollment credentials were created. Wait one minute and try again.",
			"",
		)
		return
	}

	expiresAt := h.currentTime().Add(ttl)
	h.agentMutationMu.Lock()
	defer h.agentMutationMu.Unlock()
	token, err := h.registry.CreateEnrollment(request.Context(), agentID, expiresAt)
	if err != nil {
		message := "The server entry could not be created."
		status := http.StatusInternalServerError
		errorField := ""
		switch {
		case errors.Is(err, identity.ErrInvalidAgentID):
			status = http.StatusBadRequest
			message = "Use a valid server ID: letters, numbers, dots, underscores, and hyphens only."
			errorField = "agent_id"
		case errors.Is(err, identity.ErrAgentAlreadyEnrolled):
			status = http.StatusConflict
			message = "That server ID is already enrolled."
		case errors.Is(err, identity.ErrEnrollmentPending):
			status = http.StatusConflict
			message = "That server already has a valid enrollment command. Use it or wait for it to expire."
		default:
			h.logger.Error(
				"create agent enrollment",
				"agent_id",
				agentID,
				"error",
				err,
			)
		}
		h.renderNewServerError(
			response,
			status,
			session,
			agentID,
			ttlSeconds,
			message,
			errorField,
		)
		return
	}
	encodedToken := base64.RawURLEncoding.EncodeToString(token)
	defer clear(token)
	created := createdServerView{
		AgentID:        agentID,
		InstallCommand: h.installCommand(encodedToken),
		ExpiresAt:      expiresAt.UTC().Format("2 Jan 2006, 15:04 UTC"),
		ExpiresAtISO:   expiresAt.UTC().Format(time.RFC3339),
	}
	resultID, err := h.storeEnrollmentResult(sessionToken, created, h.currentTime())
	if err != nil {
		h.logger.Error("store enrollment result", "agent_id", agentID, "error", err)
		http.Error(response, "enrollment result could not be prepared", http.StatusInternalServerError)
		return
	}
	http.Redirect(
		response,
		request,
		"/servers/enrollment-result?id="+url.QueryEscape(resultID),
		http.StatusSeeOther,
	)
}

func (h *Handler) renderNewServerError(
	response http.ResponseWriter,
	status int,
	session Session,
	agentID string,
	ttlSeconds int64,
	message string,
	errorField string,
) {
	h.render(response, status, "new-server.html", pageData{
		Title:      "Add server",
		ActiveNav:  "servers",
		CSRFToken:  session.CSRFToken,
		AgentID:    agentID,
		TTLSeconds: ttlSeconds,
		Error:      message,
		ErrorField: errorField,
	})
}

func agentViewFor(snapshot identity.AgentSnapshot, now time.Time, online bool) agentView {
	view := agentView{
		ID:      snapshot.ID,
		Initial: strings.ToUpper(snapshot.ID[:1]),
		URL:     "/servers/" + url.PathEscape(snapshot.ID) + "/manage",
	}
	switch snapshot.State {
	case identity.AgentStatePending:
		view.EnrollmentLabel = "Pending"
		view.EnrollmentClass = "pending"
		view.ConnectionLabel = "Not connected"
		view.ConnectionClass = "offline"
		view.Detail = "Expires " + relativeTime(snapshot.EnrollmentExpiresAt, now)
	case identity.AgentStateExpired:
		view.EnrollmentLabel = "Expired"
		view.EnrollmentClass = "expired"
		view.ConnectionLabel = "Not connected"
		view.ConnectionClass = "offline"
		view.Detail = "Create a new enrollment command"
	case identity.AgentStateEnrolled:
		view.EnrollmentLabel = "Enrolled"
		view.EnrollmentClass = "enrolled"
		if online {
			view.ConnectionLabel = "Online"
			view.ConnectionClass = "online"
			view.Detail = "Authenticated control session"
		} else {
			view.ConnectionLabel = "Offline"
			view.ConnectionClass = "offline"
			view.Detail = "No active control session"
		}
	}
	return view
}

func deploymentViewFor(record deployment.Record) *deploymentView {
	view := &deploymentView{
		ID:         record.ID,
		RevisionID: record.RevisionID,
		Digest:     hex.EncodeToString(record.ConfigSHA256[:]),
		UpdatedAt:  record.UpdatedAt.UTC().Format("2 Jan 2006, 15:04:05 UTC"),
		Diagnostic: record.Diagnostic,
	}
	switch record.Status {
	case deployment.StatusQueued:
		view.StatusLabel = "Queued"
		view.StatusClass = "pending"
		view.Pending = true
	case deployment.StatusValidating:
		view.StatusLabel = "Validating"
		view.StatusClass = "pending"
		view.Pending = true
	case deployment.StatusValidated:
		view.StatusLabel = "Validated"
		view.StatusClass = "online"
	case deployment.StatusDeploying:
		view.StatusLabel = "Deploying"
		view.StatusClass = "pending"
		view.Pending = true
	case deployment.StatusApplied:
		view.StatusLabel = "Applied"
		view.StatusClass = "online"
	case deployment.StatusRuntimeFailed:
		view.StatusLabel = "Runtime failure"
		view.StatusClass = "expired"
	case deployment.StatusValidationFailed:
		view.StatusLabel = "Validation failed"
		view.StatusClass = "expired"
	case deployment.StatusActivationFailed:
		view.StatusLabel = "Activation failed"
		view.StatusClass = "expired"
	case deployment.StatusInternalError:
		view.StatusLabel = "Agent error"
		view.StatusClass = "expired"
	case deployment.StatusDeliveryFailed:
		view.StatusLabel = "Delivery failed"
		view.StatusClass = "expired"
	default:
		view.StatusLabel = "Unknown"
		view.StatusClass = "offline"
	}
	return view
}

func (h *Handler) agentSnapshot(agentID string) (identity.AgentSnapshot, bool) {
	if strings.TrimSpace(agentID) == "" {
		return identity.AgentSnapshot{}, false
	}
	for _, snapshot := range h.registry.Snapshot(h.currentTime()) {
		if snapshot.ID == agentID {
			return snapshot, true
		}
	}
	return identity.AgentSnapshot{}, false
}

func validateConfigurationJSON(config []byte) error {
	if len(config) == 0 {
		return errors.New("Enter a sing-box configuration.")
	}
	if len(config) > maxConfigurationBytes {
		return errors.New("The configuration exceeds the 4 MiB size limit.")
	}
	decoder := json.NewDecoder(bytes.NewReader(config))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return errors.New("Enter a valid JSON configuration.")
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("The sing-box configuration must be a JSON object.")
	}
	if err := consumeJSONObject(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("Enter one complete JSON configuration.")
	}
	return nil
}

func consumeJSONObject(decoder *json.Decoder, depth int) error {
	if depth > maxConfigurationJSONDepth {
		return errors.New("The configuration is nested too deeply.")
	}
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("Enter a valid JSON configuration.")
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("Enter a valid JSON configuration.")
		}
		if _, duplicate := keys[key]; duplicate {
			return errors.New("The configuration contains a duplicate object key.")
		}
		keys[key] = struct{}{}
		if err := consumeJSONValue(decoder, depth); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("Enter a valid JSON configuration.")
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return errors.New("Enter a valid JSON configuration.")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return errors.New("Enter a valid JSON configuration.")
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		return consumeJSONObject(decoder, depth+1)
	case '[':
		if depth >= maxConfigurationJSONDepth {
			return errors.New("The configuration is nested too deeply.")
		}
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		token, err := decoder.Token()
		if err != nil {
			return errors.New("Enter a valid JSON configuration.")
		}
		if closing, ok := token.(json.Delim); !ok || closing != ']' {
			return errors.New("Enter a valid JSON configuration.")
		}
		return nil
	default:
		return errors.New("Enter a valid JSON configuration.")
	}
}

func randomOpaqueID(prefix string) (string, error) {
	var random [18]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(random[:])
	clear(random[:])
	return prefix + "_" + encoded, nil
}

func (h *Handler) installCommand(token string) string {
	return "curl --proto '=https' --tlsv1.2 -fsSL " +
		"https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh" +
		" | sudo sh -s -- agent --master " + shellQuote(h.masterAddress) +
		" --token " + shellQuote(token)
}

func (h *Handler) storeEnrollmentResult(
	sessionToken string,
	created createdServerView,
	now time.Time,
) (string, error) {
	owner, valid := credentialDigest(sessionToken)
	if valid != 1 {
		return "", ErrAuthenticationFailed
	}

	for attempts := 0; attempts < 3; attempts++ {
		var randomID [credentialBytes]byte
		if _, err := rand.Read(randomID[:]); err != nil {
			return "", fmt.Errorf("generate result ID: %w", err)
		}
		resultID := base64.RawURLEncoding.EncodeToString(randomID[:])
		clear(randomID[:])

		h.resultMu.Lock()
		h.purgeEnrollmentResultsLocked(now)
		if _, collision := h.results[resultID]; collision {
			h.resultMu.Unlock()
			continue
		}
		if len(h.results) >= enrollmentResultLimit {
			h.evictOldestEnrollmentResultLocked()
		}
		h.results[resultID] = enrollmentResult{
			owner:     owner,
			created:   created,
			createdAt: now,
		}
		h.resultMu.Unlock()
		return resultID, nil
	}
	return "", errors.New("could not allocate a unique result ID")
}

func (h *Handler) takeEnrollmentResult(
	sessionToken string,
	resultID string,
	now time.Time,
) (createdServerView, bool) {
	owner, valid := credentialDigest(sessionToken)
	if valid != 1 || len(resultID) != encodedCredentialLength {
		return createdServerView{}, false
	}
	h.resultMu.Lock()
	defer h.resultMu.Unlock()
	h.purgeEnrollmentResultsLocked(now)
	result, exists := h.results[resultID]
	if !exists || result.owner != owner {
		return createdServerView{}, false
	}
	delete(h.results, resultID)
	return result.created, true
}

func (h *Handler) purgeEnrollmentResultsLocked(now time.Time) {
	for resultID, result := range h.results {
		if !now.Before(result.createdAt.Add(enrollmentResultTTL)) {
			delete(h.results, resultID)
		}
	}
}

func (h *Handler) removeEnrollmentResultsForAgent(agentID string) {
	h.resultMu.Lock()
	defer h.resultMu.Unlock()
	for resultID, result := range h.results {
		if result.created.AgentID == agentID {
			delete(h.results, resultID)
		}
	}
}

func (h *Handler) evictOldestEnrollmentResultLocked() {
	var oldestID string
	var oldestAt time.Time
	for resultID, result := range h.results {
		if oldestID == "" || result.createdAt.Before(oldestAt) {
			oldestID = resultID
			oldestAt = result.createdAt
		}
	}
	if oldestID != "" {
		delete(h.results, oldestID)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\"'\"'`) + "'"
}

func (h *Handler) render(
	response http.ResponseWriter,
	status int,
	templateName string,
	data pageData,
) {
	data.AssetVersion = h.assetVersion
	data.PublicURL = h.publicURL
	data.MasterAddress = h.masterAddress
	var rendered bytes.Buffer
	if err := h.templates.ExecuteTemplate(&rendered, templateName, data); err != nil {
		h.logger.Error("render web UI", "template", templateName, "error", err)
		http.Error(response, "interface could not be rendered", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(rendered.Bytes())
}

func (h *Handler) authenticate(request *http.Request) (Session, bool) {
	token, ok := h.sessionToken(request)
	if !ok {
		return Session{}, false
	}
	session, err := h.access.Authenticate(token)
	return session, err == nil
}

func (h *Handler) requireAuthentication(
	response http.ResponseWriter,
	request *http.Request,
) (Session, bool) {
	session, ok := h.authenticate(request)
	if !ok {
		h.redirectToLogin(response, request)
		return Session{}, false
	}
	return session, true
}

func (h *Handler) sessionToken(request *http.Request) (string, bool) {
	cookie, err := request.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func (h *Handler) redirectToLogin(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.sessionToken(request); ok {
		http.SetCookie(response, DeleteSessionCookie())
	}
	http.Redirect(response, request, "/login", http.StatusSeeOther)
}

func (h *Handler) rejectInvalidMutationOrigin(
	response http.ResponseWriter,
	request *http.Request,
) bool {
	reason := h.mutationOriginRejection(request)
	if reason == "" {
		return false
	}
	http.Error(
		response,
		"request origin is not allowed ("+reason+")",
		http.StatusForbidden,
	)
	return true
}

func (h *Handler) mutationOriginRejection(request *http.Request) string {
	if request.Header.Get("Content-Encoding") != "" {
		return "content_encoding"
	}
	if request.URL.RawQuery != "" {
		return "query_string"
	}
	fetchSiteValues := request.Header.Values("Sec-Fetch-Site")
	if len(fetchSiteValues) > 1 {
		return "multiple_fetch_site_headers"
	}
	fetchSite := ""
	if len(fetchSiteValues) == 1 {
		fetchSite = fetchSiteValues[0]
	}
	// "none" is valid for browser-initiated navigation, and unknown values
	// must be ignored for forward compatibility when Origin is present.
	switch fetchSite {
	case "cross-site":
		return "cross_site"
	case "same-site":
		return "same_site"
	}

	originValues := request.Header.Values("Origin")
	if len(originValues) == 0 {
		// Some privacy clients omit Origin. Sec-Fetch-* headers are controlled
		// by the browser, while the canonical request Host was already checked.
		if fetchSite == "same-origin" || fetchSite == "none" {
			return ""
		}
		return "missing_origin"
	}
	if len(originValues) != 1 {
		return "multiple_origin_headers"
	}
	origin := originValues[0]
	parsed, err := url.Parse(origin)
	if err != nil ||
		parsed.Scheme == "" ||
		parsed.User != nil ||
		parsed.Path != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return "invalid_origin"
	}
	host, port, err := splitAuthority(parsed.Host, defaultPort(parsed.Scheme))
	if err != nil {
		return "invalid_origin"
	}
	if !(strings.EqualFold(parsed.Scheme, h.publicScheme) &&
		strings.EqualFold(host, h.publicHost) &&
		port == h.publicPort) {
		return "origin_mismatch"
	}
	return ""
}

func (h *Handler) validRequestHost(hostHeader string) bool {
	host, port, err := splitAuthority(hostHeader, defaultPort(h.publicScheme))
	return err == nil &&
		strings.EqualFold(host, h.publicHost) &&
		port == h.publicPort
}

func setSecurityHeaders(header http.Header) {
	header.Set(
		"Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; "+
			"img-src 'self' data:; connect-src 'self'; font-src 'self'; "+
			"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
	)
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set(
		"Permissions-Policy",
		"accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
	)
	// no-referrer serializes Origin as "null" for non-CORS form POSTs.
	// strict-origin preserves the exact origin without disclosing paths or queries.
	header.Set("Referrer-Policy", "strict-origin")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
}

func readExactForm(
	response http.ResponseWriter,
	request *http.Request,
	maxBytes int64,
	fields ...string,
) (url.Values, error) {
	if request.Body == nil {
		return nil, errors.New("request body is required")
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || len(parameters) != 0 {
		return nil, errors.New("content type must be application/x-www-form-urlencoded")
	}
	body := http.MaxBytesReader(response, request.Body, maxBytes)
	defer body.Close()
	encoded, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(string(encoded))
	if err != nil || len(values) != len(fields) {
		return nil, errors.New("form contains unexpected fields")
	}
	slices.Sort(fields)
	for _, field := range fields {
		value, exists := values[field]
		if !exists || len(value) != 1 {
			return nil, errors.New("form is missing a field or contains duplicates")
		}
	}
	return values, nil
}

func (h *Handler) allowEnrollment(now time.Time) bool {
	h.enrollmentMu.Lock()
	defer h.enrollmentMu.Unlock()
	if h.enrollmentWindowStarted.IsZero() ||
		now.Before(h.enrollmentWindowStarted) ||
		!now.Before(h.enrollmentWindowStarted.Add(enrollmentWindow)) {
		h.enrollmentWindowStarted = now
		h.enrollmentCount = 0
	}
	if h.enrollmentCount >= enrollmentLimit {
		return false
	}
	h.enrollmentCount++
	return true
}

func (h *Handler) currentTime() time.Time {
	return h.now().UTC()
}

type parsedPublicURL struct {
	origin   string
	scheme   string
	hostname string
	port     string
}

func parsePublicURL(raw string) (parsedPublicURL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return parsedPublicURL{}, fmt.Errorf("parse public web URL: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" {
		return parsedPublicURL{}, errors.New("public web URL must use HTTPS")
	}
	if parsed.Opaque != "" ||
		parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawPath != "" ||
		parsed.ForceQuery ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return parsedPublicURL{}, errors.New("public web URL must contain only a scheme and host")
	}
	hostname := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if !validHostname(hostname) {
		return parsedPublicURL{}, errors.New("public web URL contains an invalid host")
	}
	port := parsed.Port()
	if port == "" {
		port = defaultPort(scheme)
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return parsedPublicURL{}, errors.New("public web URL contains an invalid port")
	}
	port = strconv.FormatUint(portNumber, 10)

	displayHost := hostname
	if strings.Contains(hostname, ":") {
		displayHost = "[" + hostname + "]"
	}
	if port != defaultPort(scheme) {
		displayHost = net.JoinHostPort(hostname, port)
	}
	return parsedPublicURL{
		origin:   scheme + "://" + displayHost,
		scheme:   scheme,
		hostname: hostname,
		port:     port,
	}, nil
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil || host == "localhost" {
		return true
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !domainLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func splitAuthority(authority, fallbackPort string) (string, string, error) {
	if authority == "" ||
		strings.ContainsAny(authority, "/\\?#@") {
		return "", "", errors.New("invalid authority")
	}
	candidate, err := url.Parse("//" + authority)
	if err != nil ||
		candidate.Host != authority ||
		candidate.User != nil ||
		candidate.Path != "" {
		return "", "", errors.New("invalid authority")
	}
	host := strings.TrimSuffix(strings.ToLower(candidate.Hostname()), ".")
	if !validHostname(host) {
		return "", "", errors.New("invalid authority host")
	}
	port := candidate.Port()
	if port == "" {
		port = fallbackPort
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", "", errors.New("invalid authority port")
	}
	return host, strconv.FormatUint(portNumber, 10), nil
}

func defaultPort(scheme string) string {
	if strings.EqualFold(scheme, "http") {
		return "80"
	}
	return "443"
}

func relativeTime(future, now time.Time) string {
	remaining := future.Sub(now)
	if remaining <= 0 {
		return "now"
	}
	if remaining < time.Minute {
		return "in less than a minute"
	}
	if remaining < 2*time.Minute {
		return "in 1 minute"
	}
	if remaining < time.Hour {
		return fmt.Sprintf("in %d minutes", int(remaining/time.Minute))
	}
	if remaining < 2*time.Hour {
		return "in 1 hour"
	}
	return fmt.Sprintf("in %d hours", int(remaining/time.Hour))
}

// Ensure Handler still satisfies the interface if its construction changes.
var _ http.Handler = (*Handler)(nil)
