package webui

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
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

	"github.com/masterauguste/theatropolis/internal/identity"
)

const (
	maxLoginBodyBytes      = 2 << 10
	maxEnrollmentBodyBytes = 4 << 10
	enrollmentLimit        = 30
	enrollmentWindow       = time.Minute
	enrollmentResultLimit  = 64
	enrollmentResultTTL    = 5 * time.Minute
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
}

type Options struct {
	Registry  *identity.Registry
	Sessions  SessionRegistry
	Access    *AccessManager
	PublicURL string
	Version   string
	Logger    *slog.Logger
	Now       func() time.Time
}

type Handler struct {
	registry      *identity.Registry
	sessions      SessionRegistry
	access        *AccessManager
	publicURL     string
	publicScheme  string
	publicHost    string
	publicPort    string
	masterAddress string
	assetVersion  string
	logger        *slog.Logger
	now           func() time.Time
	templates     *template.Template
	mux           *http.ServeMux

	enrollmentMu            sync.Mutex
	enrollmentWindowStarted time.Time
	enrollmentCount         int

	resultMu sync.Mutex
	results  map[string]enrollmentResult
}

type pageData struct {
	Title         string
	AssetVersion  string
	PublicURL     string
	MasterAddress string
	CSRFToken     string
	Error         string
	ErrorField    string
	AgentID       string
	TTLSeconds    int64
	Stats         fleetStats
	Agents        []agentView
	Created       *createdServerView
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
		registry:      options.Registry,
		sessions:      options.Sessions,
		access:        options.Access,
		publicURL:     public.origin,
		publicScheme:  public.scheme,
		publicHost:    public.hostname,
		publicPort:    public.port,
		masterAddress: net.JoinHostPort(public.hostname, public.port),
		assetVersion:  base64.RawURLEncoding.EncodeToString(versionDigest[:12]),
		logger:        logger,
		now:           now,
		templates:     templates,
		mux:           http.NewServeMux(),
		results:       make(map[string]enrollmentResult),
	}
	handler.routes()
	return handler, nil
}

func (h *Handler) routes() {
	h.mux.HandleFunc("GET /healthz", h.health)
	h.mux.HandleFunc("GET /assets/app.css", h.asset("assets/app.css", "text/css; charset=utf-8"))
	h.mux.HandleFunc("GET /assets/app.js", h.asset("assets/app.js", "text/javascript; charset=utf-8"))
	h.mux.HandleFunc("GET /login", h.loginPage)
	h.mux.HandleFunc("POST /login", h.login)
	h.mux.HandleFunc("POST /logout", h.logout)
	h.mux.HandleFunc("GET /servers", h.serversPage)
	h.mux.HandleFunc("GET /servers/new", h.newServerPage)
	h.mux.HandleFunc("GET /servers/enrollment-result", h.enrollmentResultPage)
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
	h.render(response, http.StatusOK, "login.html", pageData{Title: "Sign in"})
}

func (h *Handler) login(response http.ResponseWriter, request *http.Request) {
	if !h.validMutationOrigin(request) {
		http.Error(response, "request origin is not allowed", http.StatusForbidden)
		return
	}
	form, err := readExactForm(response, request, maxLoginBodyBytes, "access_key")
	if err != nil {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	session, err := h.access.Login(form.Get("access_key"))
	if err != nil {
		status := http.StatusUnauthorized
		message := "The access key was not accepted."
		if errors.Is(err, ErrLoginRateLimited) {
			status = http.StatusTooManyRequests
			message = "Too many attempts. Wait one minute and try again."
			response.Header().Set("Retry-After", "60")
		}
		h.render(response, status, "login.html", pageData{
			Title: "Sign in",
			Error: message,
		})
		return
	}
	http.SetCookie(response, NewSessionCookie(session.Token, session.ExpiresAt))
	http.Redirect(response, request, "/servers", http.StatusSeeOther)
}

func (h *Handler) logout(response http.ResponseWriter, request *http.Request) {
	if !h.validMutationOrigin(request) {
		http.Error(response, "request origin is not allowed", http.StatusForbidden)
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
	h.access.Logout(sessionToken)
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
		CSRFToken: session.CSRFToken,
		Stats:     stats,
		Agents:    agents,
	})
}

func (h *Handler) newServerPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	h.render(response, http.StatusOK, "new-server.html", pageData{
		Title:      "Add server",
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
	if !h.validMutationOrigin(request) {
		http.Error(response, "request origin is not allowed", http.StatusForbidden)
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
		InstallCommand: h.installCommand(agentID, encodedToken),
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

func (h *Handler) installCommand(agentID, token string) string {
	return "curl --proto '=https' --tlsv1.2 -fsSL " +
		"https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh" +
		" | sudo sh -s -- agent --master " + shellQuote(h.masterAddress) +
		" --agent-id " + shellQuote(agentID) +
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

func (h *Handler) validMutationOrigin(request *http.Request) bool {
	if request.Header.Get("Content-Encoding") != "" || request.URL.RawQuery != "" {
		return false
	}
	fetchSiteValues := request.Header.Values("Sec-Fetch-Site")
	if len(fetchSiteValues) > 1 {
		return false
	}
	fetchSite := ""
	if len(fetchSiteValues) == 1 {
		fetchSite = fetchSiteValues[0]
	}
	// "none" is valid for browser-initiated navigation, and unknown values
	// must be ignored for forward compatibility when Origin is present.
	switch fetchSite {
	case "cross-site", "same-site":
		return false
	}

	originValues := request.Header.Values("Origin")
	if len(originValues) == 0 {
		// Some privacy clients omit Origin. Sec-Fetch-* headers are controlled
		// by the browser, while the canonical request Host was already checked.
		return fetchSite == "same-origin" || fetchSite == "none"
	}
	if len(originValues) != 1 {
		return false
	}
	origin := originValues[0]
	parsed, err := url.Parse(origin)
	if err != nil ||
		parsed.Scheme == "" ||
		parsed.User != nil ||
		parsed.Path != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return false
	}
	host, port, err := splitAuthority(parsed.Host, defaultPort(parsed.Scheme))
	return err == nil &&
		strings.EqualFold(parsed.Scheme, h.publicScheme) &&
		strings.EqualFold(host, h.publicHost) &&
		port == h.publicPort
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
	header.Set("Referrer-Policy", "no-referrer")
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
