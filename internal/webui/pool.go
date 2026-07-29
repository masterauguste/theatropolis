package webui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
)

// maxPoolFormBytes caps one manual pool entry submission: the stored outbound
// object limit plus room for the name, CSRF token, and form encoding.
const maxPoolFormBytes = pool.MaxManualOutboundBytes + 8<<10

type poolUserView struct {
	Label string
	Ref   string
}

type poolInboundView struct {
	DialogID   string
	AgentID    string
	Tag        string
	Type       string
	Port       int
	IPv4       string
	IPv6       string
	Users      []poolUserView
	AddressURL string
	OverrideV4 string
	OverrideV6 string
}

type poolManualView struct {
	Name     string
	Type     string
	Port     int
	Outbound string
}

type poolView struct {
	Inbounds    []poolInboundView
	Manual      []poolManualView
	Diagnostics []string
}

type poolOption struct {
	Ref               string `json:"ref"`
	AgentID           string `json:"agent_id,omitempty"`
	InboundTag        string `json:"inbound_tag,omitempty"`
	User              string `json:"user,omitempty"`
	Type              string `json:"type"`
	Port              int    `json:"port,omitempty"`
	IPv4              string `json:"ipv4,omitempty"`
	IPv6              string `json:"ipv6,omitempty"`
	DefaultTLSAddress string `json:"default_tls_address,omitempty"`
	Available         bool   `json:"available"`
	Manual            bool   `json:"manual"`
}

type poolOptionsResponse struct {
	Options []poolOption `json:"options"`
	Warning string       `json:"warning,omitempty"`
}

// derivePoolEntries builds the pool view for every enrolled agent except
// excludeAgentID ("" keeps all) plus the manual entries. Diagnostics describe
// skipped agents, inbounds, and users.
func (h *Handler) derivePoolEntries(
	ctx context.Context,
	excludeAgentID string,
) ([]pool.Entry, []string) {
	var agentIDs []string
	for _, snapshot := range h.registry.Snapshot(h.currentTime()) {
		if snapshot.State != identity.AgentStateEnrolled || snapshot.ID == excludeAgentID {
			continue
		}
		agentIDs = append(agentIDs, snapshot.ID)
	}
	records, err := h.controller.DeploymentRecords(ctx)
	if err != nil {
		h.logger.Error("list deployment records for pool derivation", "error", err)
		return nil, []string{"deployed configurations could not be loaded"}
	}
	deployments := make(map[string]*deployment.Record, len(records))
	for index := range records {
		deployments[records[index].AgentID] = &records[index]
	}
	var diagnostics []string
	entries := pool.Derive(pool.DeriveInput{
		AgentIDs:    agentIDs,
		Deployments: deployments,
		Registry:    h.controller.PoolRegistry(),
		Diagnostics: &diagnostics,
	})
	return entries, diagnostics
}

// poolPageView builds the read-only derived pool view for the pool page,
// or nil when the pool is not wired into this master.
func (h *Handler) poolPageView(ctx context.Context) *poolView {
	registry := h.controller.PoolRegistry()
	if registry == nil {
		return nil
	}
	entries, diagnostics := h.derivePoolEntries(ctx, "")
	view := &poolView{Diagnostics: diagnostics}
	// Derive sorts by agent, inbound tag, then user. Collapse its user-level
	// routing options into one page summary per inbound while retaining each
	// user inside the summary's detail dialog.
	for _, entry := range entries {
		if entry.Manual {
			continue
		}
		if len(view.Inbounds) == 0 ||
			view.Inbounds[len(view.Inbounds)-1].AgentID != entry.AgentID ||
			view.Inbounds[len(view.Inbounds)-1].Tag != entry.InboundTag {
			overrideV4, overrideV6 := registry.Overrides(entry.AgentID)
			view.Inbounds = append(view.Inbounds, poolInboundView{
				DialogID:   "pool-inbound-" + strconv.Itoa(len(view.Inbounds)),
				AgentID:    entry.AgentID,
				Tag:        entry.InboundTag,
				Type:       entry.Type,
				Port:       entry.Port,
				IPv4:       entry.IPv4,
				IPv6:       entry.IPv6,
				AddressURL: "/servers/" + url.PathEscape(entry.AgentID) + "/address",
				OverrideV4: overrideV4,
				OverrideV6: overrideV6,
			})
		}
		inbound := &view.Inbounds[len(view.Inbounds)-1]
		inbound.Users = append(inbound.Users, poolUserView{
			Label: poolUserLabel(entry),
			Ref:   entry.Ref,
		})
	}
	for _, manual := range registry.Manual() {
		view.Manual = append(view.Manual, poolManualView{
			Name:     manual.Name,
			Type:     poolManualType(manual.Outbound),
			Port:     poolManualPort(manual.Outbound),
			Outbound: string(manual.Outbound),
		})
	}
	return view
}

func poolUserLabel(entry pool.Entry) string {
	switch {
	case entry.ServerKeyOnly:
		return "server key"
	case entry.User == "":
		return "unnamed user"
	default:
		return entry.User
	}
}

// poolManualType/poolManualPort mirror the pool package's display helpers for
// manual outbounds without depending on its unexported parsing.
func poolManualType(outbound json.RawMessage) string {
	var object struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(outbound, &object); err != nil {
		return ""
	}
	return object.Type
}

func poolManualPort(outbound json.RawMessage) int {
	var object struct {
		ServerPort int `json:"server_port"`
	}
	if err := json.Unmarshal(outbound, &object); err != nil {
		return 0
	}
	return object.ServerPort
}

// poolAddresses resolves each family independently for the server list.
// Source attribution is intentionally omitted from the UI.
func (h *Handler) poolAddresses(agentID string) (ipv4, ipv6 string) {
	registry := h.controller.PoolRegistry()
	if registry == nil {
		return "", ""
	}
	ipv4, _ = registry.AgentAddressForFamily(agentID, pool.FamilyIPv4)
	ipv6, _ = registry.AgentAddressForFamily(agentID, pool.FamilyIPv6)
	return ipv4, ipv6
}

func (h *Handler) poolPage(response http.ResponseWriter, request *http.Request) {
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
		"pool.html",
		h.poolPageData(request.Context(), session),
	)
}

func (h *Handler) poolPageData(_ context.Context, session Session) pageData {
	registry := h.controller.PoolRegistry()
	var view *poolView
	if registry != nil {
		view = &poolView{}
		for _, manual := range registry.Manual() {
			view.Manual = append(view.Manual, poolManualView{
				Name:     manual.Name,
				Type:     poolManualType(manual.Outbound),
				Port:     poolManualPort(manual.Outbound),
				Outbound: string(manual.Outbound),
			})
		}
	}
	return pageData{
		Title:     "Pool",
		ActiveNav: "pool",
		CSRFToken: session.CSRFToken,
		Pool:      view,
	}
}

func (h *Handler) poolContent(response http.ResponseWriter, request *http.Request) {
	session, ok := h.authenticate(request)
	if !ok {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	if request.URL.RawQuery != "" {
		http.NotFound(response, request)
		return
	}
	h.render(response, http.StatusOK, "pool-content", pageData{
		Title:     "Pool",
		ActiveNav: "pool",
		CSRFToken: session.CSRFToken,
		Pool:      h.poolPageView(request.Context()),
	})
}

func (h *Handler) upsertPoolEntry(response http.ResponseWriter, request *http.Request) {
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
		maxPoolFormBytes,
		"csrf_token",
		"name",
		"outbound_json",
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
	registry := h.controller.PoolRegistry()
	if registry == nil {
		http.Error(response, "the outbound pool is unavailable", http.StatusConflict)
		return
	}

	name := strings.TrimSpace(form.Get("name"))
	outbound := form.Get("outbound_json")
	if err := registry.UpsertManual(name, json.RawMessage(outbound)); err != nil {
		status := http.StatusInternalServerError
		message := "The pool entry could not be saved."
		errorField := ""
		switch {
		case errors.Is(err, pool.ErrInvalidName):
			status = http.StatusBadRequest
			message = "Use a valid entry name: letters, numbers, dots, underscores, and hyphens only."
			errorField = "pool_name"
		case errors.Is(err, pool.ErrInvalidOutbound):
			status = http.StatusBadRequest
			message = "Enter one complete outbound JSON object with a non-empty \"type\"."
			errorField = "pool_json"
		default:
			h.logger.Error("upsert pool manual entry", "name", name, "error", err)
		}
		data := h.poolPageData(request.Context(), session)
		data.Error = message
		data.ErrorField = errorField
		data.PoolFormName = name
		data.PoolFormJSON = outbound
		h.render(response, status, "pool.html", data)
		return
	}
	h.controller.PropagateManualPoolChange(request.Context())
	h.logger.Info("pool manual entry saved", "name", name)
	http.Redirect(response, request, "/pool", http.StatusSeeOther)
}

func (h *Handler) deletePoolEntry(response http.ResponseWriter, request *http.Request) {
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
		"confirm_delete",
		"csrf_token",
		"name",
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
	registry := h.controller.PoolRegistry()
	if registry == nil {
		http.Error(response, "the outbound pool is unavailable", http.StatusConflict)
		return
	}

	name := form.Get("name")
	if form.Get("confirm_delete") != "yes" {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	if err := registry.RemoveManual(name); err != nil {
		if errors.Is(err, pool.ErrManualNotFound) {
			data := h.poolPageData(request.Context(), session)
			data.Error = "That pool entry no longer exists."
			h.render(response, http.StatusNotFound, "pool.html", data)
			return
		}
		h.logger.Error("delete pool manual entry", "name", name, "error", err)
		http.Error(response, "the pool entry could not be deleted", http.StatusInternalServerError)
		return
	}
	h.controller.PropagateManualPoolChange(request.Context())
	h.logger.Info("pool manual entry deleted", "name", name)
	http.Redirect(response, request, "/pool", http.StatusSeeOther)
}

func (h *Handler) serverPoolOptions(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.authenticate(request); !ok {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	agentID := request.PathValue("agent_id")
	if _, exists := h.agentSnapshot(agentID); !exists {
		http.NotFound(response, request)
		return
	}
	result := poolOptionsResponse{Options: []poolOption{}}
	if h.controller.PoolRegistry() == nil {
		result.Warning = "Pool lookup failed: the outbound pool is unavailable."
	} else {
		entries, diagnostics := h.derivePoolEntries(request.Context(), agentID)
		for _, entry := range entries {
			result.Options = append(result.Options, poolOption{
				Ref:               entry.Ref,
				AgentID:           entry.AgentID,
				InboundTag:        entry.InboundTag,
				User:              poolUserLabel(entry),
				Type:              entry.Type,
				Port:              entry.Port,
				IPv4:              entry.IPv4,
				IPv6:              entry.IPv6,
				DefaultTLSAddress: h.controller.PoolRegistry().DefaultTLSAddress(entry.AgentID),
				Available:         entry.Available,
				Manual:            entry.Manual,
			})
		}
		if len(diagnostics) > 0 {
			result.Warning = strings.Join(diagnostics, "; ")
		}
	}
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(result); err != nil {
		h.logger.Warn("encode pool options", "agent_id", agentID, "error", err)
	}
}

func (h *Handler) setServerAddress(response http.ResponseWriter, request *http.Request) {
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
		"override_ipv4",
		"override_ipv6",
	)
	if err != nil || !h.access.AuthorizeCSRF(sessionToken, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	if _, err := h.access.Authenticate(sessionToken); err != nil {
		h.redirectToLogin(response, request)
		return
	}
	snapshot, ok := h.agentSnapshot(request.PathValue("agent_id"))
	if !ok {
		http.NotFound(response, request)
		return
	}
	registry := h.controller.PoolRegistry()
	if registry == nil {
		http.Error(response, "the outbound pool is unavailable", http.StatusConflict)
		return
	}
	if snapshot.State != identity.AgentStateEnrolled {
		http.Error(response, "the server must be enrolled first", http.StatusConflict)
		return
	}

	overrideV4 := strings.TrimSpace(form.Get("override_ipv4"))
	overrideV6 := strings.TrimSpace(form.Get("override_ipv6"))
	if overrideV4 != "" {
		address, err := netip.ParseAddr(overrideV4)
		if err != nil || !address.Is4() {
			http.Error(response, "the IPv4 override must be an IPv4 address or empty", http.StatusBadRequest)
			return
		}
	}
	if overrideV6 != "" {
		address, err := netip.ParseAddr(overrideV6)
		if err != nil || !address.Is6() {
			http.Error(response, "the IPv6 override must be an IPv6 address or empty", http.StatusBadRequest)
			return
		}
	}
	if err := registry.SetOverrides(snapshot.ID, overrideV4, overrideV6); err != nil {
		if errors.Is(err, pool.ErrInvalidAddress) {
			// The registry rejects anything that is not a globally routable
			// address (private, ULA, CGNAT, reserved).
			http.Error(response, "address overrides must be public IP addresses", http.StatusBadRequest)
			return
		}
		if errors.Is(err, pool.ErrInvalidName) {
			http.Error(response, "invalid server ID", http.StatusBadRequest)
			return
		}
		h.logger.Error("set pool address override", "agent_id", snapshot.ID, "error", err)
		http.Error(response, "the address override could not be saved", http.StatusInternalServerError)
		return
	}
	h.controller.PropagateManualPoolChange(request.Context())
	h.logger.Info("pool address override saved", "agent_id", snapshot.ID)
	http.Redirect(response, request, "/pool", http.StatusSeeOther)
}

func (h *Handler) setServerTLSAddress(response http.ResponseWriter, request *http.Request) {
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
		"default_tls_address",
	)
	if err != nil || !h.access.AuthorizeCSRF(sessionToken, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	if _, err := h.access.Authenticate(sessionToken); err != nil {
		h.redirectToLogin(response, request)
		return
	}
	snapshot, ok := h.agentSnapshot(request.PathValue("agent_id"))
	if !ok {
		http.NotFound(response, request)
		return
	}
	registry := h.controller.PoolRegistry()
	if registry == nil {
		http.Error(response, "the outbound pool is unavailable", http.StatusConflict)
		return
	}
	if err := registry.SetDefaultTLSAddress(snapshot.ID, form.Get("default_tls_address")); err != nil {
		if errors.Is(err, pool.ErrInvalidTLSAddress) {
			http.Error(
				response,
				"enter a DNS hostname without a scheme, port, path, wildcard, or IP address",
				http.StatusBadRequest,
			)
			return
		}
		h.logger.Error("save agent default TLS address", "agent_id", snapshot.ID, "error", err)
		http.Error(response, "the default TLS address could not be saved", http.StatusInternalServerError)
		return
	}
	h.logger.Info(
		"agent default TLS address saved",
		"agent_id",
		snapshot.ID,
		"default_tls_address",
		registry.DefaultTLSAddress(snapshot.ID),
	)
	http.Redirect(
		response,
		request,
		"/servers/"+url.PathEscape(snapshot.ID)+"/manage",
		http.StatusSeeOther,
	)
}

// requestAddressProbe asks the SOURCE agent (the path agent_id, whose pool
// address is unknown) to resolve its public address for one IP family. It is
// a fetch API for the guided config editor, so failures are plain-text status
// responses rather than redirects or re-rendered pages.
func (h *Handler) requestAddressProbe(response http.ResponseWriter, request *http.Request) {
	sessionToken, ok := h.sessionToken(request)
	if !ok {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
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
		"family",
	)
	if err != nil || !h.access.AuthorizeCSRF(sessionToken, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	if _, err := h.access.Authenticate(sessionToken); err != nil {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	family, err := pool.ParseFamily(form.Get("family"))
	if err != nil || family == pool.FamilyAuto {
		http.Error(response, "family must be ipv4 or ipv6", http.StatusBadRequest)
		return
	}
	snapshot, ok := h.agentSnapshot(request.PathValue("agent_id"))
	if !ok {
		http.NotFound(response, request)
		return
	}
	if snapshot.State != identity.AgentStateEnrolled {
		http.Error(response, "the server must be enrolled first", http.StatusConflict)
		return
	}
	if err := h.controller.RequestAddressProbe(snapshot.ID, family.String()); err != nil {
		status := http.StatusInternalServerError
		message := "The probe request could not be delivered."
		switch {
		case errors.Is(err, control.ErrAgentOffline):
			status = http.StatusConflict
			message = "The agent is offline. Reconnect it before requesting a probe."
		case errors.Is(err, control.ErrAgentProbeUnsupported):
			status = http.StatusConflict
			message = "This agent does not support address probes. Update the agent first."
		case errors.Is(err, control.ErrProbeFamilyInvalid):
			status = http.StatusBadRequest
			message = "family must be ipv4 or ipv6"
		default:
			h.logger.Error(
				"request address probe",
				"agent_id", snapshot.ID,
				"family", family.String(),
				"error", err,
			)
		}
		http.Error(response, message, status)
		return
	}
	h.logger.Info("address probe requested", "agent_id", snapshot.ID, "family", family.String())
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(response, `{"status":"probe requested"}`+"\n")
}
