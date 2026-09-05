package webui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
)

const maxProxyFormBytes = 128 << 10

var membershipPlanFormFields = []string{
	"quota_mode", "monthly_quota_gib", "expiration_mode", "subscription_value", "subscription_unit",
}

type proxyNodeListView struct {
	ID              string
	Name            string
	URL             string
	Entrance        string
	EntranceAgent   string
	HopCount        int
	MemberCount     int
	UpdatedAt       string
	PendingApply    bool
	PendingRemoval  bool
	EntranceDeleted bool
	RelayDeleted    bool
	EntranceOffline bool
	RelayOffline    bool
}

type proxyNodeDetailView struct {
	ID                      string
	Name                    string
	URL                     string
	UsersURL                string
	EntranceFallback        string
	Entrance                endpointView
	Tree                    *proxyTreeHopView
	HopCount                int
	LinkCount               int
	MemberCount             int
	EndUserCount            int
	FiniteMemberCount       int
	CompensationStart       string
	CompensationEnd         string
	CompensationSelected    int
	TerminalCount           int
	UnusedLinkCount         int
	UserAccess              []nodeUserAccessView
	AvailableUsers          []nodeUserOptionView
	DefaultPlan             membershipPlanView
	SubscriptionAddressMode string
	OperationalStatus       proxyNodeOperationalStatusView
}

type proxyNodeOperationalStatusView struct {
	TopologyPending bool
	EntranceDeleted []proxyNodeOfflineAgentView
	RelayDeleted    []proxyNodeOfflineAgentView
	EntranceOffline []proxyNodeOfflineAgentView
	RelayOffline    []proxyNodeOfflineAgentView
}

type proxyNodeOfflineAgentView struct {
	Name    string
	Applied bool
}

type membershipPlanView struct {
	QuotaMode         string
	QuotaGiB          string
	ExpirationMode    string
	SubscriptionValue string
	SubscriptionUnit  string
	CanExtend         bool
	QuotaLabel        string
	UsageLabel        string
	ResetLabel        string
	ResetAt           string
	ExpirationLabel   string
	ExpirationAt      string
	StatusLabel       string
	StatusClass       string
}

type nodeUserAccessView struct {
	UserID                string
	MembershipID          string
	Name                  string
	Initial               string
	URL                   string
	Plan                  membershipPlanView
	SubscriptionStartedAt string
	SubscriptionEndsAfter string
	CompensationSelected  bool
	System                bool
}

type nodeUserOptionView struct {
	UserID string
	Label  string
}

type proxyTreeHopView struct {
	ProxyID                 string
	ID                      string
	Name                    string
	AgentID                 string
	URL                     string
	IsEntrance              bool
	Deleted                 bool
	Offline                 bool
	IngressProtocol         string
	IngressLabel            string
	Routes                  []proxyTreeRouteView
	Fallback                proxyTreeRouteView
	ShowFallback            bool
	Children                []proxyTreeLinkView
	BlockRules              []proxyBlockRuleView
	Branches                []proxyTreeBranchView
	AllRuleIDs              string
	TerminalCount           int
	RuntimeBranches         int
	BranchCount             int
	Final                   string
	AgentOptions            []agentOptionView
	DestinationAgentOptions []agentOptionView
	NewRule                 proxyRuleView
	NewLinkEndpoint         endpointView
	CSRFToken               string
}

type proxyTreeRouteView struct {
	InspectorID  string
	ProxyID      string
	HopID        string
	CSRFToken    string
	Label        string
	Match        string
	Values       string
	TargetLabel  string
	TargetDetail string
	TargetKind   string
	TargetURL    string
	Uncertain    bool
}

type proxyTreeLinkView struct {
	ID                      string
	ParentHopID             string
	EditURL                 string
	Protocol                string
	ListenPort              int
	Listener                string
	Family                  string
	Order                   int
	Endpoint                endpointView
	Rules                   []proxyRuleView
	NewRule                 proxyRuleView
	Used                    bool
	Fallback                bool
	CanMoveUp               bool
	CanMoveDown             bool
	Child                   *proxyTreeHopView
	Latency                 linkLatencyView
	HistoryURL              string
	ProbeURL                string
	DestinationAgentOptions []agentOptionView
}

// proxyTreeBranchView is one visible route through one logical Link. Active
// conditional Links own exactly one Rule and one independently authenticated
// downstream context, even when their physical listeners are compatible.
type proxyTreeBranchView struct {
	LinkID       string
	RuleID       string
	RulePosition int
	Protocol     string
	RuleLabel    string
	RuleValues   string
	Used         bool
	Fallback     bool
	Block        bool
	InspectorID  string
	AgentID      string
	Name         string
	Uncertain    bool
	Child        *proxyTreeHopView
	Latency      linkLatencyView
}

type linkLatencyView struct {
	Status     string `json:"status"`
	Label      string `json:"label"`
	Detail     string `json:"detail,omitempty"`
	ProbeType  string `json:"probe_type,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
}

type proxyBlockRuleView struct {
	Rule     proxyRuleView
	AgentID  string
	Name     string
	ParentID string
}

type endUserListView struct {
	ID            string
	Name          string
	URL           string
	Memberships   int
	LoginUsername string
	LoginStatus   string
	LoginClass    string
}

type endUserDetailView struct {
	ID              string
	Name            string
	ProxyNodeCount  int
	AssignedAccess  []userProxyAccessView
	AvailableAccess []userProxyOptionView
	DefaultPlan     membershipPlanView
	Login           endUserLoginAccessView
	DailyUsage      []dailyUsageDayView
}

type dailyUsageDayView struct {
	Date       time.Time
	DateLabel  string
	Total      uint64
	TotalLabel string
	Nodes      []dailyUsageNodeView
}

type dailyUsageNodeView struct {
	ProxyNodeID string
	Name        string
	UsageLabel  string
}

type endUserLoginAccessView struct {
	Claimed         bool
	LoginUsername   string
	StatusLabel     string
	StatusClass     string
	InvitationReady bool
	InviteExpiresAt string
	Invitation      *endUserInvitationView
}

type userProxyAccessView struct {
	UserName      string
	ProxyID       string
	ProxyName     string
	ProxyURL      string
	DialogID      string
	Initial       string
	Tone          string
	EntranceLabel string
	EntranceAgent string
	AuthUser      string
	URIs          []credentialURIView
	Plan          membershipPlanView
}

type userProxyOptionView struct {
	ProxyID       string
	ProxyName     string
	EntranceLabel string
	EntranceAgent string
	Initial       string
	Tone          string
}

type credentialURIView struct {
	Family string
	URI    string
}

type agentOptionView struct {
	ID             string
	Name           string
	Selected       bool
	Online         bool
	Deleted        bool
	LatencyDetail  string
	LatencyStatus  string
	LatencyLinkIDs string
}

type endpointView struct {
	AgentID           string
	ListenerID        string
	Protocol          string
	ProtocolLabel     string
	Listen            string
	ListenPort        int
	Family            string
	Method            string
	MuxEnabled        bool
	MuxPadding        bool
	MuxBrutal         bool
	MuxBrutalUpMbps   int
	MuxBrutalDownMbps int
	TLSMode           string
	ServerName        string
	Email             string
	CertificatePath   string
	KeyPath           string
	UpMbps            int
	DownMbps          int
	ObfsType          string
}

type listenerOptionView struct {
	ID              string
	AgentID         string
	Label           string
	Protocol        string
	ProtocolLabel   string
	Listen          string
	ListenPort      int
	Method          string
	MuxPadding      bool
	MuxBrutal       bool
	MuxBrutalUp     int
	MuxBrutalDown   int
	TLSMode         string
	ServerName      string
	Email           string
	CertificatePath string
	KeyPath         string
	UpMbps          int
	DownMbps        int
	ObfsType        string
	ReferenceCount  int
}

type proxyRuleView struct {
	ID          string
	Position    int
	Match       string
	MatchLabel  string
	Values      string
	FormValues  string
	CanMoveUp   bool
	CanMoveDown bool
}

type proxyDeploymentView struct {
	ID     string                     `json:"id"`
	Status string                     `json:"status"`
	Label  string                     `json:"label"`
	Class  string                     `json:"class"`
	Error  string                     `json:"error,omitempty"`
	Active bool                       `json:"active"`
	Agents []proxyDeploymentAgentView `json:"agents,omitempty"`
}

type proxyDeploymentAgentView struct {
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Status    string `json:"status"`
}

func (h *Handler) proxyNodesPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	if h.proxyNodes == nil {
		writeUserError(response, "Proxy Node manager is unavailable", http.StatusServiceUnavailable)
		return
	}
	state := h.proxyNodes.Snapshot()
	views := make([]proxyNodeListView, 0, len(state.ProxyNodes)+len(state.AppliedProxyNodes))
	desiredIDs := make(map[string]struct{}, len(state.ProxyNodes))
	for _, node := range state.ProxyNodes {
		desiredIDs[node.ID] = struct{}{}
		root, _ := proxyHop(node, node.Entrance.HopID)
		status := &proxyNodeDetailView{}
		h.attachProxyNodeOperationalStatus(status, node, state)
		views = append(views, proxyNodeListView{
			ID: node.ID, Name: node.Name, URL: proxyNodeURL(node.ID),
			Entrance: protocolLabel(node.Entrance.Endpoint.Protocol), EntranceAgent: h.agentDisplayName(root.AgentID),
			HopCount: len(node.Hops), MemberCount: len(node.Memberships),
			UpdatedAt:       node.UpdatedAt.In(proxynode.BillingLocation()).Format("2006-01-02 15:04 UTC+8"),
			PendingApply:    proxyNodeTopologyPending(node, state.AppliedProxyNodes),
			EntranceDeleted: len(status.OperationalStatus.EntranceDeleted) > 0,
			RelayDeleted:    len(status.OperationalStatus.RelayDeleted) > 0,
			EntranceOffline: len(status.OperationalStatus.EntranceOffline) > 0,
			RelayOffline:    len(status.OperationalStatus.RelayOffline) > 0,
		})
	}
	// An offline Agent can keep the last-applied topology after the desired
	// Proxy Node has been deleted. Keep that runtime visible as a read-only card
	// until fleet deployment retires it; never turn it into an editable ghost.
	for _, node := range state.AppliedProxyNodes {
		if _, desired := desiredIDs[node.ID]; desired {
			continue
		}
		root, _ := proxyHop(node, node.Entrance.HopID)
		views = append(views, proxyNodeListView{
			ID: node.ID, Name: node.Name,
			Entrance: protocolLabel(node.Entrance.Endpoint.Protocol), EntranceAgent: h.agentDisplayName(root.AgentID),
			HopCount: len(node.Hops), MemberCount: len(node.Memberships),
			UpdatedAt:      node.UpdatedAt.In(proxynode.BillingLocation()).Format("2006-01-02 15:04 UTC+8"),
			PendingRemoval: true,
		})
	}
	sort.Slice(views, func(left, right int) bool {
		return strings.ToLower(views[left].Name) < strings.ToLower(views[right].Name)
	})
	h.render(response, http.StatusOK, "proxy-nodes.html", pageData{
		Title: "Proxy Nodes", ActiveNav: "proxy-nodes", CSRFToken: session.CSRFToken,
		ProxyNodes: views, ProxyDeployment: h.proxyDeploymentView(),
	})
}

func (h *Handler) newProxyNodePage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	h.render(response, http.StatusOK, "proxy-node-new.html", pageData{
		Title: "New Proxy Node", ActiveNav: "proxy-nodes", CSRFToken: session.CSRFToken,
		AgentOptions: h.proxyAgentOptions(""), Endpoint: defaultEndpointView(),
		ListenerOptions: h.proxyListenerOptions(), ProxyDeployment: h.proxyDeploymentView(),
	})
}

func (h *Handler) createProxyNode(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, append([]string{"name", "agent_id", "terminal"}, endpointFormFields...)...)
	if !ok {
		return
	}
	endpoint, err := parseEndpointForm(form)
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	terminal, err := parseProxyTarget(form.Get("terminal"))
	if err != nil || terminal.Type == proxynode.TargetLink {
		writeUserError(response, "terminal exit must be Direct or Reject", http.StatusBadRequest)
		return
	}
	var node proxynode.ProxyNode
	if !h.applyProxyTopologyMutation(response, func() error {
		var err error
		node, err = h.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
			Name: form.Get("name"), RootAgent: form.Get("agent_id"), Entrance: endpoint, Final: terminal,
		})
		return err
	}) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(node.ID), http.StatusSeeOther)
}

func (h *Handler) proxyNodePage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	node, ok := h.loadProxyNode(response, request)
	if !ok {
		return
	}
	state := h.proxyNodes.Snapshot()
	detail := h.proxyNodeDetail(node, state)
	h.attachProxyNodeUsers(detail, node, state.Users)
	h.attachProxyNodeOperationalStatus(detail, node, state)
	setProxyTreeCSRF(detail.Tree, session.CSRFToken)
	h.render(response, http.StatusOK, "proxy-node.html", pageData{
		Title: node.Name, ActiveNav: "proxy-nodes", CSRFToken: session.CSRFToken,
		ProxyNode: detail, ProxyDeployment: h.proxyDeploymentView(),
		ListenerOptions: h.proxyListenerOptions(),
	})
}

func (h *Handler) proxyNodeUsersPage(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.requireAuthentication(response, request); !ok {
		return
	}
	if _, ok := h.loadProxyNode(response, request); !ok {
		return
	}
	http.Redirect(response, request, proxyNodeUsersURL(request.PathValue("proxy_id")), http.StatusSeeOther)
}

func setProxyTreeCSRF(tree *proxyTreeHopView, token string) {
	if tree == nil {
		return
	}
	tree.CSRFToken = token
	tree.Fallback.CSRFToken = token
	for _, link := range tree.Children {
		setProxyTreeCSRF(link.Child, token)
	}
	for _, branch := range tree.Branches {
		setProxyTreeCSRF(branch.Child, token)
	}
}

func (h *Handler) renameProxyNode(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "name")
	if !ok {
		return
	}
	id := request.PathValue("proxy_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.RenameProxyNode(id, form.Get("name"))
	}) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(id), http.StatusSeeOther)
}

func (h *Handler) updateProxyNodeSubscriptionAddresses(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "mode")
	if !ok {
		return
	}
	nodeID := request.PathValue("proxy_id")
	if err := h.proxyNodes.SetProxyNodeSubscriptionAddressMode(nodeID, proxynode.SubscriptionAddressMode(form.Get("mode"))); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) deleteProxyNode(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "confirm_delete")
	if !ok {
		return
	}
	if form.Get("confirm_delete") != "yes" {
		writeUserError(response, "deletion was not confirmed", http.StatusBadRequest)
		return
	}
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.DeleteProxyNode(request.PathValue("proxy_id"))
	}) {
		return
	}
	if h.proxyDeployer == nil {
		h.triggerProxyUserSync()
	}
	http.Redirect(response, request, "/proxy-nodes", http.StatusSeeOther)
}

func (h *Handler) deployProxyNodes(response http.ResponseWriter, request *http.Request) {
	_, _, ok := h.authorizeProxyMutation(response, request)
	if !ok {
		return
	}
	if id := request.PathValue("proxy_id"); id != "" {
		if _, exists := h.proxyNodes.ProxyNode(id); !exists {
			http.NotFound(response, request)
			return
		}
	}
	if !h.queueProxyDeployment(response) {
		return
	}
	redirect := "/proxy-nodes"
	if id := request.PathValue("proxy_id"); id != "" {
		redirect = proxyNodeURL(id)
	}
	http.Redirect(response, request, redirect, http.StatusSeeOther)
}

func (h *Handler) queueProxyDeployment(response http.ResponseWriter) bool {
	if h.proxyDeployer == nil {
		writeUserError(response, "Proxy Node deployment is unavailable", http.StatusServiceUnavailable)
		return false
	}
	if _, err := h.proxyDeployer.Start(); err != nil {
		status := http.StatusConflict
		if !errors.Is(err, proxynode.ErrDeploymentActive) {
			status = http.StatusBadRequest
		}
		writeUserError(response, err.Error(), status)
		return false
	}
	return true
}

func (h *Handler) applyProxyTopologyMutation(response http.ResponseWriter, mutation func() error) bool {
	if h.proxyDeployer == nil {
		// Keep the Store independently usable by embedded/test consumers. The
		// production master always supplies a Deployer and therefore always uses
		// the reserved immediate-apply path.
		if err := mutation(); err != nil {
			handleProxyMutationError(response, err)
			return false
		}
		return true
	}
	if _, err := h.proxyDeployer.MutateAndStart(mutation); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, proxynode.ErrDeploymentActive) {
			status = http.StatusConflict
		}
		writeUserError(response, err.Error(), status)
		return false
	}
	return true
}

func (h *Handler) proxyDeploymentStatus(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.requireAuthentication(response, request); !ok {
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	view := h.proxyDeploymentView()
	if view != nil {
		view.Label = localizedText(response.Header().Get("Content-Language"), view.Label)
		view.Error = localizedText(response.Header().Get("Content-Language"), view.Error)
	}
	_ = json.NewEncoder(response).Encode(view)
}

func (h *Handler) proxyEntrancePage(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.requireAuthentication(response, request); !ok {
		return
	}
	if _, ok := h.loadProxyNode(response, request); !ok {
		return
	}
	http.Redirect(response, request, proxyNodeURL(request.PathValue("proxy_id"))+"?dialog=proxy-entrance-dialog", http.StatusSeeOther)
}

func (h *Handler) updateProxyEntrance(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, endpointFormFields...)
	if !ok {
		return
	}
	id := request.PathValue("proxy_id")
	node, exists := h.proxyNodes.ProxyNode(id)
	if !exists {
		http.NotFound(response, request)
		return
	}
	endpoint, err := parseEndpointForm(form, node.Entrance.Endpoint)
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.UpdateEntrance(id, endpoint)
	}) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(id), http.StatusSeeOther)
}

func (h *Handler) proxyHopPage(response http.ResponseWriter, request *http.Request) {
	_, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	node, ok := h.loadProxyNode(response, request)
	if !ok {
		return
	}
	hop, exists := proxyHop(node, request.PathValue("hop_id"))
	if !exists {
		http.NotFound(response, request)
		return
	}
	if hop.ID == node.Entrance.HopID {
		http.Redirect(response, request, proxyNodeURL(node.ID)+"?dialog=proxy-entrance-dialog", http.StatusSeeOther)
		return
	}
	http.Redirect(response, request, proxyInspectorURL(node.ID, "hop-"+hop.ID), http.StatusSeeOther)
}

func (h *Handler) updateProxyHop(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "agent_id")
	if !ok {
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	node, exists := h.proxyNodes.ProxyNode(nodeID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	hop, exists := proxyHop(node, hopID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	targetAgent := strings.TrimSpace(form.Get("agent_id"))
	if targetAgent != hop.AgentID {
		if endpoint, exists := proxyHopEndpoint(node, hopID); exists && endpoint.TLS.Mode == proxynode.TLSModeFiles {
			writeUserError(response, "legacy file certificate endpoints cannot move to another Agent", http.StatusBadRequest)
			return
		}
	}
	isEntrance := hopID == node.Entrance.HopID
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.MoveHop(nodeID, hopID, targetAgent)
	}) {
		return
	}
	if isEntrance {
		http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
		return
	}
	http.Redirect(response, request, proxyInspectorURL(nodeID, "hop-"+hopID), http.StatusSeeOther)
}

func (h *Handler) addProxyLink(response http.ResponseWriter, request *http.Request) {
	fields := append([]string{"match", "values", "child_agent", "child_terminal"}, endpointFormFields...)
	_, form, ok := h.authorizeProxyMutation(response, request, fields...)
	if !ok {
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	match := proxynode.MatchType(form.Get("match"))
	values := splitProxyValues(form.Get("values"))
	endpoint, err := parseEndpointForm(form)
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	terminal, err := parseProxyTarget(form.Get("child_terminal"))
	if err != nil || terminal.Type == proxynode.TargetLink {
		writeUserError(response, "terminal exit must be Direct or Reject", http.StatusBadRequest)
		return
	}
	if !h.applyProxyTopologyMutation(response, func() error {
		_, _, _, err = h.proxyNodes.AddBranch(nodeID, proxynode.AddBranchInput{
			AddLinkInput: proxynode.AddLinkInput{
				ParentHopID: hopID, ChildAgent: form.Get("child_agent"), Endpoint: endpoint, Final: terminal,
			},
			Match: match, Values: values,
		})
		return err
	}) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) addProxyBlockRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "match", "values")
	if !ok {
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		_, err := h.proxyNodes.AddBlockBranch(nodeID, proxynode.AddBlockBranchInput{
			ParentHopID: hopID, Match: proxynode.MatchType(form.Get("match")), Values: splitProxyValues(form.Get("values")),
		})
		return err
	}) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) updateProxyBlockRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "match", "values")
	if !ok {
		return
	}
	nodeID, ruleID := request.PathValue("proxy_id"), request.PathValue("rule_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.UpdateBlockBranch(nodeID, ruleID, proxynode.UpdateRuleInput{
			Match: proxynode.MatchType(form.Get("match")), Values: splitProxyValues(form.Get("values")),
		})
	}) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) deleteProxyBlockRule(response http.ResponseWriter, request *http.Request) {
	_, _, ok := h.authorizeProxyMutation(response, request)
	if !ok {
		return
	}
	nodeID, ruleID := request.PathValue("proxy_id"), request.PathValue("rule_id")
	if !h.applyProxyTopologyMutation(response, func() error { return h.proxyNodes.DeleteBlockBranch(nodeID, ruleID) }) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) moveProxyBlockRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "direction")
	if !ok {
		return
	}
	delta := 1
	if form.Get("direction") == "up" {
		delta = -1
	} else if form.Get("direction") != "down" {
		writeUserError(response, "invalid Rule direction", http.StatusBadRequest)
		return
	}
	nodeID, ruleID := request.PathValue("proxy_id"), request.PathValue("rule_id")
	if !h.applyProxyTopologyMutation(response, func() error { return h.proxyNodes.MoveBlockBranch(nodeID, ruleID, delta) }) {
		return
	}
	http.Redirect(response, request, proxyInspectorURL(nodeID, "block-rule-"+ruleID), http.StatusSeeOther)
}

func (h *Handler) deleteProxyLink(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "link_id", "confirm_delete")
	if !ok {
		return
	}
	if form.Get("confirm_delete") != "yes" {
		writeUserError(response, "branch deletion was not confirmed", http.StatusBadRequest)
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.DeleteLink(nodeID, form.Get("link_id"))
	}) {
		return
	}
	http.Redirect(response, request, proxyInspectorURL(nodeID, "hop-"+hopID), http.StatusSeeOther)
}

func (h *Handler) proxyLinkPage(response http.ResponseWriter, request *http.Request) {
	_, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	node, ok := h.loadProxyNode(response, request)
	if !ok {
		return
	}
	linkID := request.PathValue("link_id")
	_, exists := proxyLink(node, linkID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	http.Redirect(response, request, proxyInspectorURL(node.ID, "link-"+linkID), http.StatusSeeOther)
}

func (h *Handler) updateProxyLink(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, endpointFormFields...)
	if !ok {
		return
	}
	nodeID, linkID := request.PathValue("proxy_id"), request.PathValue("link_id")
	node, exists := h.proxyNodes.ProxyNode(nodeID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	link, exists := proxyLink(node, linkID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	endpoint, err := parseEndpointForm(form, link.Endpoint)
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.UpdateLink(nodeID, linkID, endpoint)
	}) {
		return
	}
	http.Redirect(response, request, proxyInspectorURL(nodeID, "link-"+linkID), http.StatusSeeOther)
}

func (h *Handler) updateProxyLinkDestination(response http.ResponseWriter, request *http.Request) {
	fields := append([]string{"agent_id", "terminal", "confirm_replace"}, endpointFormFields...)
	_, form, ok := h.authorizeProxyMutation(response, request, fields...)
	if !ok {
		return
	}
	if form.Get("confirm_replace") != "yes" {
		writeUserError(response, "destination replacement must be confirmed", http.StatusBadRequest)
		return
	}
	endpoint, err := parseEndpointForm(form)
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	terminal, err := parseProxyTarget(form.Get("terminal"))
	if err != nil || terminal.Type == proxynode.TargetLink {
		writeUserError(response, "terminal exit must be Direct or Reject", http.StatusBadRequest)
		return
	}
	nodeID, linkID := request.PathValue("proxy_id"), request.PathValue("link_id")
	node, exists := h.proxyNodes.ProxyNode(nodeID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	if _, exists := proxyLink(node, linkID); !exists {
		http.NotFound(response, request)
		return
	}
	if !h.applyProxyTopologyMutation(response, func() error {
		_, err := h.proxyNodes.ReplaceLinkDestination(nodeID, linkID, form.Get("agent_id"), endpoint, terminal)
		return err
	}) {
		return
	}
	http.Redirect(response, request, proxyInspectorURL(nodeID, "link-"+linkID), http.StatusSeeOther)
}

func (h *Handler) addProxyRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "match", "values")
	if !ok {
		return
	}
	nodeID, linkID := request.PathValue("proxy_id"), request.PathValue("link_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		_, err := h.proxyNodes.AddRule(nodeID, proxynode.AddRuleInput{LinkID: linkID, Match: proxynode.MatchType(form.Get("match")), Values: splitProxyValues(form.Get("values"))})
		return err
	}) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) updateProxyRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "match", "values")
	if !ok {
		return
	}
	nodeID, linkID, ruleID := request.PathValue("proxy_id"), request.PathValue("link_id"), request.PathValue("rule_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.UpdateRule(nodeID, ruleID, proxynode.UpdateRuleInput{
			LinkID: linkID,
			Match:  proxynode.MatchType(form.Get("match")), Values: splitProxyValues(form.Get("values")),
		})
	}) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) deleteProxyRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "rule_id")
	if !ok {
		return
	}
	nodeID, linkID := request.PathValue("proxy_id"), request.PathValue("link_id")
	node, exists := h.proxyNodes.ProxyNode(nodeID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	link, exists := proxyLink(node, linkID)
	if !exists || !slices.ContainsFunc(link.Rules, func(rule proxynode.Rule) bool { return rule.ID == form.Get("rule_id") }) {
		http.NotFound(response, request)
		return
	}
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.DeleteLink(nodeID, linkID)
	}) {
		return
	}
	http.Redirect(response, request, proxyInspectorURL(nodeID, "hop-"+link.ParentHopID), http.StatusSeeOther)
}

func (h *Handler) moveProxyRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "rule_id", "direction")
	if !ok {
		return
	}
	delta := 1
	if form.Get("direction") == "up" {
		delta = -1
	} else if form.Get("direction") != "down" {
		writeUserError(response, "invalid Rule direction", http.StatusBadRequest)
		return
	}
	nodeID, linkID := request.PathValue("proxy_id"), request.PathValue("link_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.MoveRule(nodeID, linkID, form.Get("rule_id"), delta)
	}) {
		return
	}
	http.Redirect(response, request, proxyInspectorURL(nodeID, "rule-"+form.Get("rule_id")), http.StatusSeeOther)
}

func (h *Handler) reorderProxyRules(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "rule_ids")
	if !ok {
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.ReorderRules(nodeID, hopID, splitProxyValues(form.Get("rule_ids")))
	}) {
		return
	}
	if strings.Contains(request.Header.Get("Accept"), "application/json") {
		if h.proxyDeployer == nil {
			response.WriteHeader(http.StatusNoContent)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusAccepted)
		view := h.proxyDeploymentView()
		if view != nil {
			view.Label = localizedText(response.Header().Get("Content-Language"), view.Label)
			view.Error = localizedText(response.Header().Get("Content-Language"), view.Error)
		}
		_ = json.NewEncoder(response).Encode(view)
		return
	}
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) updateProxyLinkFallback(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "mode")
	if !ok {
		return
	}
	fallback := form.Get("mode") == "fallback"
	if !fallback && form.Get("mode") != "conditional" {
		writeUserError(response, "invalid Link routing mode", http.StatusBadRequest)
		return
	}
	nodeID, linkID := request.PathValue("proxy_id"), request.PathValue("link_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.SetLinkFallback(nodeID, linkID, fallback)
	}) {
		return
	}
	http.Redirect(response, request, proxyInspectorURL(nodeID, "link-"+linkID), http.StatusSeeOther)
}

func (h *Handler) moveProxyLink(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "direction")
	if !ok {
		return
	}
	delta := 1
	if form.Get("direction") == "up" {
		delta = -1
	} else if form.Get("direction") != "down" {
		writeUserError(response, "invalid Link direction", http.StatusBadRequest)
		return
	}
	nodeID, linkID := request.PathValue("proxy_id"), request.PathValue("link_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.MoveLink(nodeID, linkID, delta)
	}) {
		return
	}
	http.Redirect(response, request, proxyInspectorURL(nodeID, "link-"+linkID), http.StatusSeeOther)
}

func (h *Handler) updateProxyFinal(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "target", "return_to")
	if !ok {
		return
	}
	target, err := parseProxyTarget(form.Get("target"))
	if err != nil || target.Type == proxynode.TargetLink {
		writeUserError(response, "terminal exit must be Direct or Reject", http.StatusBadRequest)
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	node, exists := h.proxyNodes.ProxyNode(nodeID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	if _, exists := proxyHop(node, hopID); !exists {
		http.NotFound(response, request)
		return
	}
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.SetFinal(nodeID, hopID, target)
	}) {
		return
	}
	if form.Get("return_to") == "fallback" {
		http.Redirect(response, request, proxyInspectorURL(nodeID, "terminal-"+hopID+"-fallback"), http.StatusSeeOther)
		return
	}
	if form.Get("return_to") == "hop" {
		http.Redirect(response, request, proxyInspectorURL(nodeID, "hop-"+hopID), http.StatusSeeOther)
		return
	}
	if hopID == node.Entrance.HopID {
		http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
		return
	}
	for _, link := range node.Links {
		if link.ChildHopID == hopID {
			http.Redirect(response, request, proxyInspectorURL(nodeID, "link-"+link.ID), http.StatusSeeOther)
			return
		}
	}
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) endUsersPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	if h.proxyNodes == nil {
		writeUserError(response, "user manager is unavailable", http.StatusServiceUnavailable)
		return
	}
	state := h.proxyNodes.Snapshot()
	counts := make(map[string]int)
	for _, node := range state.ProxyNodes {
		for _, membership := range node.Memberships {
			counts[membership.UserID]++
		}
	}
	views := make([]endUserListView, 0, len(state.Users))
	query := norm.NFC.String(strings.TrimSpace(request.URL.Query().Get("q")))
	folder := cases.Fold()
	search := folder.String(query)
	for _, user := range state.Users {
		if proxynode.IsSystemAdministrator(user) {
			continue
		}
		view := endUserListView{ID: user.ID, Name: user.Name, URL: "/users/" + url.PathEscape(user.ID), Memberships: counts[user.ID], LoginStatus: "Not registered", LoginClass: "disabled"}
		if h.endUserAccess != nil {
			status := h.endUserAccess.Status(user.ID)
			view.LoginUsername = status.LoginUsername
			if status.Claimed {
				view.LoginStatus, view.LoginClass = "Registered", "active"
			} else if status.InvitationReady {
				view.LoginStatus, view.LoginClass = "Invitation ready", "warning"
			}
		}
		if search == "" || strings.Contains(folder.String(view.Name), search) || strings.Contains(folder.String(view.LoginUsername), search) {
			views = append(views, view)
		}
	}
	sort.Slice(views, func(left, right int) bool {
		if strings.EqualFold(views[left].Name, views[right].Name) {
			return views[left].ID < views[right].ID
		}
		return strings.ToLower(views[left].Name) < strings.ToLower(views[right].Name)
	})
	const pageSize = 50
	total := len(views)
	pages := max(1, (total+pageSize-1)/pageSize)
	page, _ := strconv.Atoi(request.URL.Query().Get("page"))
	page = min(max(page, 1), pages)
	start, end := (page-1)*pageSize, min(page*pageSize, total)
	pageURL := func(page int) string {
		return "/users?" + url.Values{"q": {query}, "page": {strconv.Itoa(page)}}.Encode()
	}
	data := pageData{Title: "Users", ActiveNav: "users", CSRFToken: session.CSRFToken, EndUsers: views[start:end], UserSearch: query, UserTotal: total, UserStart: min(start+1, total), UserEnd: end}
	if page > 1 {
		data.UsersPreviousURL = pageURL(page - 1)
	}
	if page < pages {
		data.UsersNextURL = pageURL(page + 1)
	}
	h.render(response, http.StatusOK, "users.html", data)
}

func (h *Handler) createEndUser(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "name")
	if !ok {
		return
	}
	user, err := h.proxyNodes.CreateUser(form.Get("name"))
	if err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, "/users/"+url.PathEscape(user.ID), http.StatusSeeOther)
}

func (h *Handler) endUserPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	user, exists := h.proxyNodes.User(request.PathValue("user_id"))
	if !exists || proxynode.IsSystemAdministrator(user) {
		http.NotFound(response, request)
		return
	}
	state := h.proxyNodes.Snapshot()
	detail := &endUserDetailView{ID: user.ID, Name: user.Name, ProxyNodeCount: len(state.ProxyNodes), DefaultPlan: defaultMembershipPlanView()}
	daily, err := h.proxyNodes.UserDailyUsage(user.ID, 30)
	if err != nil {
		h.logger.Error("read user daily traffic", "user_id", user.ID, "error", err)
		writeUserError(response, "daily traffic could not be loaded", http.StatusInternalServerError)
		return
	}
	detail.DailyUsage = dailyUsageViews(daily)
	detail.Login = endUserLoginAccessView{StatusLabel: "Not registered", StatusClass: "disabled"}
	if h.endUserAccess != nil {
		status := h.endUserAccess.Status(user.ID)
		detail.Login.Claimed = status.Claimed
		detail.Login.LoginUsername = status.LoginUsername
		detail.Login.InvitationReady = status.InvitationReady
		if status.Claimed {
			detail.Login.StatusLabel, detail.Login.StatusClass = "Registered", "active"
		} else if status.InvitationReady {
			detail.Login.StatusLabel, detail.Login.StatusClass = "Invitation ready", "warning"
			detail.Login.InviteExpiresAt = status.InviteExpiresAt.In(proxynode.BillingLocation()).Format("Jan 2, 2006 15:04") + " (UTC+8)"
		}
		detail.Login.Invitation = h.endUserInvitationResult(request, user.ID)
	}
	for _, node := range state.ProxyNodes {
		activeNode, active := h.proxyNodes.AppliedProxyNode(node.ID)
		if !active {
			activeNode = node
		}
		root, _ := proxyHop(activeNode, activeNode.Entrance.HopID)
		access := userProxyAccessView{
			UserName: user.Name, ProxyID: node.ID, ProxyName: node.Name, ProxyURL: proxyNodeURL(node.ID),
			DialogID: "user-proxy-access-" + node.ID, Initial: nodeInitial(node.Name), Tone: nodeRoleTone(node.Name),
			EntranceLabel: protocolLabel(activeNode.Entrance.Endpoint.Protocol), EntranceAgent: h.agentDisplayName(root.AgentID),
		}
		assigned := false
		for _, membership := range node.Memberships {
			if membership.UserID != user.ID {
				continue
			}
			assigned = true
			access.AuthUser = proxynode.AuthenticatedUserLabel(membership.ID)
			if active {
				access.URIs = h.membershipURIs(activeNode, user, membership)
			}
			access.Plan = membershipPlanViewFor(membership)
			break
		}
		if assigned {
			detail.AssignedAccess = append(detail.AssignedAccess, access)
			continue
		}
		detail.AvailableAccess = append(detail.AvailableAccess, userProxyOptionView{
			ProxyID: node.ID, ProxyName: node.Name, EntranceLabel: access.EntranceLabel,
			EntranceAgent: access.EntranceAgent, Initial: access.Initial, Tone: access.Tone,
		})
	}
	sort.Slice(detail.AssignedAccess, func(left, right int) bool {
		return strings.ToLower(detail.AssignedAccess[left].ProxyName) < strings.ToLower(detail.AssignedAccess[right].ProxyName)
	})
	sort.Slice(detail.AvailableAccess, func(left, right int) bool {
		return strings.ToLower(detail.AvailableAccess[left].ProxyName) < strings.ToLower(detail.AvailableAccess[right].ProxyName)
	})
	h.render(response, http.StatusOK, "user.html", pageData{
		Title: user.Name, ActiveNav: "users", CSRFToken: session.CSRFToken, EndUser: detail,
	})
}

func dailyUsageViews(records []proxynode.DailyUsage) []dailyUsageDayView {
	var days []dailyUsageDayView
	dayIndex := make(map[string]int)
	for _, record := range records {
		key := record.Date.In(proxynode.BillingLocation()).Format("2006-01-02")
		index, exists := dayIndex[key]
		if !exists {
			index = len(days)
			dayIndex[key] = index
			days = append(days, dailyUsageDayView{
				Date: record.Date, DateLabel: record.Date.In(proxynode.BillingLocation()).Format("2 Jan 2006"),
			})
		}
		day := &days[index]
		if ^uint64(0)-day.Total < record.UsedBytes {
			day.Total = ^uint64(0)
		} else {
			day.Total += record.UsedBytes
		}
		day.Nodes = append(day.Nodes, dailyUsageNodeView{
			ProxyNodeID: record.ProxyNodeID, Name: record.ProxyNodeName, UsageLabel: formatByteCount(record.UsedBytes),
		})
	}
	for index := range days {
		days[index].TotalLabel = formatByteCount(days[index].Total)
		sort.Slice(days[index].Nodes, func(left, right int) bool {
			return strings.ToLower(days[index].Nodes[left].Name) < strings.ToLower(days[index].Nodes[right].Name)
		})
	}
	return days
}

func (h *Handler) addUserProxyAccess(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, append([]string{"proxy_id"}, membershipPlanFormFields...)...)
	if !ok {
		return
	}
	userID := request.PathValue("user_id")
	if _, exists := h.proxyNodes.User(userID); !exists {
		http.NotFound(response, request)
		return
	}
	plan, err := parseMembershipPlan(form)
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := h.proxyNodes.AddMembershipWithPlan(form.Get("proxy_id"), userID, plan); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, "/users/"+url.PathEscape(userID), http.StatusSeeOther)
}

func (h *Handler) updateUserProxyAccess(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, append([]string{"proxy_id"}, membershipPlanFormFields...)...)
	if !ok {
		return
	}
	plan, err := parseMembershipPlan(form)
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	userID := request.PathValue("user_id")
	if err := h.proxyNodes.UpdateMembershipPlan(form.Get("proxy_id"), userID, plan); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, "/users/"+url.PathEscape(userID), http.StatusSeeOther)
}

func (h *Handler) addProxyNodeUser(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, append([]string{"user_id"}, membershipPlanFormFields...)...)
	if !ok {
		return
	}
	plan, err := parseMembershipPlan(form)
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	nodeID := request.PathValue("proxy_id")
	if _, err := h.proxyNodes.AddMembershipWithPlan(nodeID, form.Get("user_id"), plan); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, proxyNodeUsersURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) updateProxyNodeUser(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, membershipPlanFormFields...)
	if !ok {
		return
	}
	plan, err := parseMembershipPlan(form)
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	nodeID := request.PathValue("proxy_id")
	if err := h.proxyNodes.UpdateMembershipPlan(nodeID, request.PathValue("user_id"), plan); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, proxyNodeUsersURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) resetProxyNodeUserCredential(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "return_to", "confirm_reset")
	if !ok {
		return
	}
	if form.Get("confirm_reset") != "yes" {
		writeUserError(response, "credential reset was not confirmed", http.StatusBadRequest)
		return
	}
	nodeID, userID := request.PathValue("proxy_id"), request.PathValue("user_id")
	if err := h.proxyNodes.ResetMembershipCredential(nodeID, userID); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	h.redirectMembershipAction(response, request, form.Get("return_to"), nodeID, userID)
}

func (h *Handler) resetEndUserCredentials(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "confirm_reset")
	if !ok {
		return
	}
	if form.Get("confirm_reset") != "yes" {
		writeUserError(response, "credential reset was not confirmed", http.StatusBadRequest)
		return
	}
	userID := request.PathValue("user_id")
	if _, err := h.proxyNodes.ResetUserCredentials(userID); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, "/users/"+url.PathEscape(userID), http.StatusSeeOther)
}

func (h *Handler) resetProxyNodeUserTraffic(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "return_to")
	if !ok {
		return
	}
	nodeID, userID := request.PathValue("proxy_id"), request.PathValue("user_id")
	if agentID, exists := h.appliedEntranceAgent(nodeID); exists && h.controller != nil {
		ctx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
		err := h.controller.RequestManagedUserTraffic(ctx, agentID)
		cancel()
		if err != nil {
			writeUserError(response, "could not establish a durable traffic-reset boundary: "+err.Error(), http.StatusConflict)
			return
		}
	}
	configurationChanged, err := h.proxyNodes.ResetMembershipTraffic(nodeID, userID)
	if err != nil {
		handleProxyMutationError(response, err)
		return
	}
	if configurationChanged {
		h.triggerProxyUserSync()
	}
	h.redirectMembershipAction(response, request, form.Get("return_to"), nodeID, userID)
}

func (h *Handler) extendProxyNodeUserSubscription(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "return_to", "extension_value", "extension_unit")
	if !ok {
		return
	}
	value, unit, err := parseSubscriptionDuration(form.Get("extension_value"), form.Get("extension_unit"))
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	nodeID, userID := request.PathValue("proxy_id"), request.PathValue("user_id")
	if err := h.proxyNodes.ExtendMembershipSubscription(nodeID, userID, value, unit); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	h.redirectMembershipAction(response, request, form.Get("return_to"), nodeID, userID)
}

func (h *Handler) compensateProxyNodeSubscriptions(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(
		response, request,
		"outage_started_at", "outage_ended_at", "compensation_value", "compensation_unit", "membership_ids",
	)
	if !ok {
		return
	}
	startedAt, err := parseBillingDateTimeLocal(form.Get("outage_started_at"))
	if err != nil {
		writeUserError(response, "outage start time is invalid", http.StatusBadRequest)
		return
	}
	endedAt, err := parseBillingDateTimeLocal(form.Get("outage_ended_at"))
	if err != nil || !startedAt.Before(endedAt) {
		writeUserError(response, "outage end time must be after its start time", http.StatusBadRequest)
		return
	}
	value, unit, err := parseSubscriptionDuration(form.Get("compensation_value"), form.Get("compensation_unit"))
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	nodeID := request.PathValue("proxy_id")
	membershipIDs := slices.DeleteFunc(slices.Clone(form["membership_ids"]), func(id string) bool {
		return strings.TrimSpace(id) == ""
	})
	if _, err := h.proxyNodes.ExtendProxyNodeSubscriptions(nodeID, membershipIDs, value, unit); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, proxyNodeUsersURL(nodeID), http.StatusSeeOther)
}

func parseBillingDateTimeLocal(raw string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02T15:04", strings.TrimSpace(raw), proxynode.BillingLocation())
}

func (h *Handler) redirectMembershipAction(response http.ResponseWriter, request *http.Request, returnTo, nodeID, userID string) {
	target := proxyNodeUsersURL(nodeID)
	if returnTo == "user" {
		target = "/users/" + url.PathEscape(userID)
	}
	http.Redirect(response, request, target, http.StatusSeeOther)
}

func (h *Handler) appliedEntranceAgent(nodeID string) (string, bool) {
	node, exists := h.proxyNodes.AppliedProxyNode(nodeID)
	if !exists {
		return "", false
	}
	for _, hop := range node.Hops {
		if hop.ID == node.Entrance.HopID {
			return hop.AgentID, true
		}
	}
	return "", false
}

func (h *Handler) removeProxyNodeUser(response http.ResponseWriter, request *http.Request) {
	_, _, ok := h.authorizeProxyMutation(response, request)
	if !ok {
		return
	}
	nodeID := request.PathValue("proxy_id")
	if err := h.proxyNodes.RemoveMembership(nodeID, request.PathValue("user_id")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, proxyNodeUsersURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) removeUserProxyAccess(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "proxy_id")
	if !ok {
		return
	}
	userID := request.PathValue("user_id")
	if err := h.proxyNodes.RemoveMembership(form.Get("proxy_id"), userID); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, "/users/"+url.PathEscape(userID), http.StatusSeeOther)
}

func (h *Handler) renameEndUser(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "name")
	if !ok {
		return
	}
	id := request.PathValue("user_id")
	if err := h.proxyNodes.RenameUser(id, form.Get("name")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, "/users/"+url.PathEscape(id), http.StatusSeeOther)
}

func (h *Handler) deleteEndUser(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "confirm_delete")
	if !ok {
		return
	}
	if form.Get("confirm_delete") != "yes" {
		writeUserError(response, "deletion was not confirmed", http.StatusBadRequest)
		return
	}
	if err := h.proxyNodes.DeleteUser(request.PathValue("user_id")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	if h.endUserAccess != nil {
		if err := h.endUserAccess.RemoveUser(request.PathValue("user_id")); err != nil {
			h.logger.Error("remove end-user web access", "user_id", request.PathValue("user_id"), "error", err)
		}
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, "/users", http.StatusSeeOther)
}

func (h *Handler) triggerProxyUserSync() {
	if h.proxyUserSync != nil {
		h.proxyUserSync.TriggerDeployment()
	}
}

func (h *Handler) proxyNodeDetail(node proxynode.ProxyNode, state proxynode.State) *proxyNodeDetailView {
	compensationEnd := h.now().In(proxynode.BillingLocation()).Truncate(time.Minute)
	compensationStart := compensationEnd.Add(-time.Hour)
	detail := &proxyNodeDetailView{
		ID: node.ID, Name: node.Name, URL: proxyNodeURL(node.ID),
		UsersURL:                proxyNodeUsersURL(node.ID),
		SubscriptionAddressMode: string(proxynode.EffectiveSubscriptionAddressMode(node.SubscriptionAddressMode)),
		Entrance:                endpointViewFor(node.Entrance.Endpoint), HopCount: len(node.Hops), LinkCount: len(node.Links), MemberCount: len(node.Memberships),
		DefaultPlan:       defaultMembershipPlanView(),
		CompensationStart: compensationStart.Format("2006-01-02T15:04"),
		CompensationEnd:   compensationEnd.Format("2006-01-02T15:04"),
	}
	if entrance, ok := proxyHop(node, node.Entrance.HopID); ok {
		detail.Entrance = endpointViewForAgent(node.Entrance.Endpoint, entrance.AgentID)
		detail.EntranceFallback = targetLabelWithNames(node, entrance.Final, h.agentDisplayName)
	}
	detail.Tree, detail.TerminalCount, detail.UnusedLinkCount = buildProxyTreeWithNames(node, h.agentDisplayName)
	h.attachProxyTreeControls(node, detail.Tree)
	h.attachProxyTreeLatencies(node, state.AppliedProxyNodes, detail.Tree)
	h.attachProxyTreeAvailability(detail.Tree)
	return detail
}

func (h *Handler) attachProxyTreeAvailability(tree *proxyTreeHopView) {
	h.attachProxyTreeAvailabilityWithRecords(tree, h.proxyAgentRecordIDs())
}

func (h *Handler) attachProxyTreeAvailabilityWithRecords(tree *proxyTreeHopView, records map[string]struct{}) {
	if tree == nil {
		return
	}
	_, exists := records[tree.AgentID]
	tree.Deleted = !exists
	tree.Offline = !tree.Deleted && !h.sessions.IsOnline(tree.AgentID)
	for index := range tree.Children {
		h.attachProxyTreeAvailabilityWithRecords(tree.Children[index].Child, records)
	}
	for index := range tree.Branches {
		h.attachProxyTreeAvailabilityWithRecords(tree.Branches[index].Child, records)
	}
}

func (h *Handler) proxyAgentRecordIDs() map[string]struct{} {
	records := make(map[string]struct{})
	for _, snapshot := range h.registry.Snapshot(h.currentTime()) {
		records[snapshot.ID] = struct{}{}
	}
	return records
}

func (h *Handler) attachProxyNodeOperationalStatus(detail *proxyNodeDetailView, desired proxynode.ProxyNode, state proxynode.State) {
	if detail == nil {
		return
	}
	detail.OperationalStatus.TopologyPending = proxyNodeTopologyPending(desired, state.AppliedProxyNodes)

	type role struct {
		entranceDesired bool
		entranceApplied bool
		relayDesired    bool
		relayApplied    bool
	}
	roles := make(map[string]role)
	collect := func(node proxynode.ProxyNode, applied bool) {
		for _, hop := range node.Hops {
			current := roles[hop.AgentID]
			entrance := hop.ID == node.Entrance.HopID
			if applied {
				current.entranceApplied = current.entranceApplied || entrance
				current.relayApplied = current.relayApplied || !entrance
			} else {
				current.entranceDesired = current.entranceDesired || entrance
				current.relayDesired = current.relayDesired || !entrance
			}
			roles[hop.AgentID] = current
		}
	}
	collect(desired, false)
	for _, node := range state.AppliedProxyNodes {
		if node.ID == desired.ID {
			collect(node, true)
			break
		}
	}

	records := h.proxyAgentRecordIDs()
	entranceDeleted := make([]proxyNodeOfflineAgentView, 0)
	relayDeleted := make([]proxyNodeOfflineAgentView, 0)
	entrances := make([]proxyNodeOfflineAgentView, 0)
	relays := make([]proxyNodeOfflineAgentView, 0)
	for agentID, current := range roles {
		name := h.agentDisplayName(agentID)
		_, exists := records[agentID]
		if !exists {
			if current.entranceDesired || current.entranceApplied {
				entranceDeleted = append(entranceDeleted, proxyNodeOfflineAgentView{Name: name, Applied: current.entranceApplied})
			}
			relayDesired := current.relayDesired && !current.entranceDesired
			relayApplied := current.relayApplied && !current.entranceApplied
			if relayDesired || relayApplied {
				relayDeleted = append(relayDeleted, proxyNodeOfflineAgentView{Name: name, Applied: relayApplied})
			}
			continue
		}
		if h.sessions.IsOnline(agentID) {
			continue
		}
		if current.entranceDesired || current.entranceApplied {
			entrances = append(entrances, proxyNodeOfflineAgentView{Name: name, Applied: current.entranceApplied})
		}
		// Entrance severity wins within one plane. When a server changes roles
		// between the saved and currently applied topology, retain both truthful
		// role summaries until the pending topology is committed.
		relayDesired := current.relayDesired && !current.entranceDesired
		relayApplied := current.relayApplied && !current.entranceApplied
		if !relayDesired && !relayApplied {
			continue
		}
		relays = append(relays, proxyNodeOfflineAgentView{Name: name, Applied: relayApplied})
	}
	sort.Slice(entrances, func(left, right int) bool { return entrances[left].Name < entrances[right].Name })
	sort.Slice(relays, func(left, right int) bool { return relays[left].Name < relays[right].Name })
	sort.Slice(entranceDeleted, func(left, right int) bool { return entranceDeleted[left].Name < entranceDeleted[right].Name })
	sort.Slice(relayDeleted, func(left, right int) bool { return relayDeleted[left].Name < relayDeleted[right].Name })
	detail.OperationalStatus.EntranceDeleted = entranceDeleted
	detail.OperationalStatus.RelayDeleted = relayDeleted
	detail.OperationalStatus.EntranceOffline = entrances
	detail.OperationalStatus.RelayOffline = relays
}

func proxyNodeTopologyPending(desired proxynode.ProxyNode, applied []proxynode.ProxyNode) bool {
	for _, node := range applied {
		if node.ID == desired.ID {
			return !reflect.DeepEqual(normalizeProxyNodeTopology(desired), normalizeProxyNodeTopology(node))
		}
	}
	return true
}

func normalizeProxyNodeTopology(node proxynode.ProxyNode) proxynode.ProxyNode {
	node.Memberships = nil
	node.SubscriptionAddressMode = ""
	node.CreatedAt = time.Time{}
	node.UpdatedAt = time.Time{}
	for index := range node.Hops {
		node.Hops[index].Name = ""
		node.Hops[index].CreatedAt = time.Time{}
		node.Hops[index].UpdatedAt = time.Time{}
	}
	for index := range node.Links {
		node.Links[index].CreatedAt = time.Time{}
		node.Links[index].UpdatedAt = time.Time{}
	}
	for index := range node.BlockBranches {
		node.BlockBranches[index].CreatedAt = time.Time{}
		node.BlockBranches[index].UpdatedAt = time.Time{}
	}
	return node
}

func (h *Handler) attachProxyTreeLatencies(node proxynode.ProxyNode, appliedNodes []proxynode.ProxyNode, tree *proxyTreeHopView) {
	if tree == nil {
		return
	}
	views := make(map[string]linkLatencyView, len(node.Links))
	for _, link := range node.Links {
		views[link.ID] = h.topologyLinkLatencyView(node, appliedNodes, link)
	}
	var visit func(*proxyTreeHopView)
	visit = func(hop *proxyTreeHopView) {
		if hop == nil {
			return
		}
		for index := range hop.Children {
			hop.Children[index].Latency = views[hop.Children[index].ID]
			visit(hop.Children[index].Child)
		}
		for index := range hop.Branches {
			if hop.Branches[index].LinkID != "" {
				hop.Branches[index].Latency = views[hop.Branches[index].LinkID]
			}
			visit(hop.Branches[index].Child)
		}
	}
	visit(tree)
}

type proxyLinkProbeIdentity struct {
	ParentAgent string
	ChildAgent  string
	Protocol    proxynode.Protocol
	Port        int
	Family      string
	ServerName  string
	ObfsType    string
	ObfsSecret  string
}

func proxyLinkPhysicalProbeIdentity(node proxynode.ProxyNode, link proxynode.Link) (proxyLinkProbeIdentity, bool) {
	parent, parentExists := proxyHop(node, link.ParentHopID)
	child, childExists := proxyHop(node, link.ChildHopID)
	if !parentExists || !childExists {
		return proxyLinkProbeIdentity{}, false
	}
	identity := proxyLinkProbeIdentity{
		ParentAgent: parent.AgentID,
		ChildAgent:  child.AgentID,
		Protocol:    link.Endpoint.Protocol,
		Port:        link.Endpoint.ListenPort,
		Family:      link.Endpoint.Family,
	}
	if link.Endpoint.Protocol == proxynode.ProtocolAnyTLS || link.Endpoint.Protocol == proxynode.ProtocolHysteria2 {
		identity.ServerName = link.Endpoint.TLS.ServerName
	}
	if link.Endpoint.Protocol == proxynode.ProtocolHysteria2 {
		identity.ObfsType = link.Endpoint.ObfsType
		identity.ObfsSecret = link.Endpoint.ObfsSecret
	}
	return identity, true
}

func proxyLinkMatchesAppliedPath(desired proxynode.ProxyNode, appliedNodes []proxynode.ProxyNode, link proxynode.Link) bool {
	desiredIdentity, ok := proxyLinkPhysicalProbeIdentity(desired, link)
	if !ok {
		return false
	}
	for _, appliedNode := range appliedNodes {
		if appliedNode.ID != desired.ID {
			continue
		}
		for _, appliedLink := range appliedNode.Links {
			if appliedLink.ID != link.ID {
				continue
			}
			appliedIdentity, valid := proxyLinkPhysicalProbeIdentity(appliedNode, appliedLink)
			return valid && appliedIdentity == desiredIdentity
		}
		return false
	}
	return false
}

func (h *Handler) topologyLinkLatencyView(node proxynode.ProxyNode, appliedNodes []proxynode.ProxyNode, link proxynode.Link) linkLatencyView {
	if !proxyLinkMatchesAppliedPath(node, appliedNodes, link) {
		return linkLatencyView{Status: "pending", Label: "Pending Apply"}
	}
	parent, exists := proxyHop(node, link.ParentHopID)
	if !exists {
		return linkLatencyView{Status: "pending", Label: "—"}
	}
	return h.linkLatencyView(parent.AgentID, link)
}

func (h *Handler) linkLatencyView(parentAgent string, link proxynode.Link) linkLatencyView {
	if h.controller == nil {
		return linkLatencyView{Status: "pending", Label: "—"}
	}
	sample, exists := h.controller.LinkLatency(parentAgent, proxynode.LinkOutboundTag(link.ID))
	if !exists {
		return linkLatencyView{Status: "pending", Label: "—"}
	}
	if !link.UpdatedAt.IsZero() && sample.ObservedAt.Before(link.UpdatedAt) {
		return linkLatencyView{Status: "pending", Label: "Pending Apply"}
	}
	observed := sample.ObservedAt.Format(time.RFC3339)
	if h.now().Sub(sample.ObservedAt) > 90*time.Second {
		probeType := sample.ProbeType
		if probeType == "" {
			probeType = "tcp"
		}
		return linkLatencyView{Status: "stale", Label: "Stale", ProbeType: probeType, ObservedAt: observed}
	}
	return linkLatencyViewFromSample(sample, h.now())
}

func (h *Handler) proxyNodeLatencies(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.requireAuthentication(response, request); !ok {
		return
	}
	node, ok := h.loadProxyNode(response, request)
	if !ok {
		return
	}
	result := make(map[string]linkLatencyView, len(node.Links))
	appliedNodes := h.proxyNodes.Snapshot().AppliedProxyNodes
	for _, link := range node.Links {
		result[link.ID] = h.topologyLinkLatencyView(node, appliedNodes, link)
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(response).Encode(map[string]any{"links": result})
}

type linkLatencyPointView struct {
	At          string  `json:"at"`
	Samples     uint64  `json:"samples"`
	Responses   uint64  `json:"responses"`
	AverageMS   float64 `json:"average_ms"`
	MinimumMS   int64   `json:"minimum_ms"`
	MaximumMS   int64   `json:"maximum_ms"`
	LossPercent float64 `json:"loss_percent"`
}

func (h *Handler) proxyLinkLatencyHistory(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.requireAuthentication(response, request); !ok {
		return
	}
	node, ok := h.loadProxyNode(response, request)
	if !ok {
		return
	}
	link, exists := proxyLink(node, request.PathValue("link_id"))
	if !exists {
		http.NotFound(response, request)
		return
	}
	parent, exists := proxyHop(node, link.ParentHopID)
	if !exists || h.controller == nil {
		writeUserError(response, "Link monitor is unavailable", http.StatusServiceUnavailable)
		return
	}
	rangeName, duration, interval := linkLatencyRange(request.URL.Query().Get("range"))
	if duration == 0 {
		writeUserError(response, "invalid Link monitor range", http.StatusBadRequest)
		return
	}
	appliedNodes := h.proxyNodes.Snapshot().AppliedProxyNodes
	if !proxyLinkMatchesAppliedPath(node, appliedNodes, link) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"range": rangeName, "current": linkLatencyView{Status: "pending", Label: "Pending Apply"}, "points": []linkLatencyPointView{},
		})
		return
	}
	sample, sampled := h.controller.LinkLatency(parent.AgentID, proxynode.LinkOutboundTag(link.ID))
	points := make([]linkLatencyPointView, 0)
	if sampled && sample.TargetID != "" && (link.UpdatedAt.IsZero() || !sample.ObservedAt.Before(link.UpdatedAt)) {
		buckets, err := h.proxyNodes.LinkLatencyHistory(parent.AgentID, sample.TargetID, h.now().Add(-duration), interval)
		if err != nil {
			h.logger.Error("load Link latency history", "proxy_id", node.ID, "link_id", link.ID, "error", err)
			writeUserError(response, "Link monitor history is unavailable", http.StatusInternalServerError)
			return
		}
		points = make([]linkLatencyPointView, 0, len(buckets))
		for _, bucket := range buckets {
			point := linkLatencyPointView{
				At: bucket.StartedAt.Format(time.RFC3339), Samples: bucket.Samples,
				Responses: bucket.Responses,
			}
			if bucket.Responses > 0 {
				point.AverageMS = float64(bucket.DurationSum.Milliseconds()) / float64(bucket.Responses)
				point.MinimumMS = bucket.DurationMin.Milliseconds()
				point.MaximumMS = bucket.DurationMax.Milliseconds()
			}
			if bucket.Samples > 0 {
				point.LossPercent = float64(bucket.Samples-bucket.Responses) * 100 / float64(bucket.Samples)
			}
			points = append(points, point)
		}
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(response).Encode(map[string]any{
		"range": rangeName, "current": h.linkLatencyView(parent.AgentID, link), "points": points,
	})
}

func linkLatencyRange(value string) (string, time.Duration, time.Duration) {
	switch strings.TrimSpace(value) {
	case "", "24h":
		return "24h", 24 * time.Hour, 15 * time.Minute
	case "1h":
		return "1h", time.Hour, 5 * time.Minute
	case "7d":
		return "7d", 7 * 24 * time.Hour, time.Hour
	case "30d":
		return "30d", 30 * 24 * time.Hour, 3 * time.Hour
	default:
		return "", 0, 0
	}
}

func (h *Handler) proxyHopLatencyProbe(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "agent_id", "family", "protocol", "listen", "listen_port", "server_name", "obfs_type")
	if !ok {
		return
	}
	node, ok := h.loadProxyNode(response, request)
	if !ok {
		return
	}
	parent, exists := proxyHop(node, request.PathValue("hop_id"))
	if !exists {
		http.NotFound(response, request)
		return
	}
	h.proxyLatencyProbe(response, request, parent.AgentID, form)
}

func (h *Handler) proxyLinkLatencyProbe(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "agent_id", "family", "protocol", "listen", "listen_port", "server_name", "obfs_type")
	if !ok {
		return
	}
	node, ok := h.loadProxyNode(response, request)
	if !ok {
		return
	}
	link, exists := proxyLink(node, request.PathValue("link_id"))
	if !exists {
		http.NotFound(response, request)
		return
	}
	parent, exists := proxyHop(node, link.ParentHopID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	h.proxyLatencyProbe(response, request, parent.AgentID, form)
}

func (h *Handler) proxyLatencyProbe(response http.ResponseWriter, request *http.Request, parentAgent string, form url.Values) {
	if h.controller == nil || h.controller.PoolRegistry() == nil || !h.enrolledAgent(form.Get("agent_id")) {
		writeUserError(response, "target Agent is unavailable", http.StatusBadRequest)
		return
	}
	family, err := pool.ParseFamily(form.Get("family"))
	if err != nil {
		writeUserError(response, "address family is invalid", http.StatusBadRequest)
		return
	}
	port, err := strconv.ParseUint(form.Get("listen_port"), 10, 16)
	if err != nil || port == 0 {
		writeUserError(response, "listen port is invalid", http.StatusBadRequest)
		return
	}
	address, exists := h.controller.PoolRegistry().AgentAddressForFamily(form.Get("agent_id"), family)
	if !exists {
		writeUserError(response, "target Agent has no routable address", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	probeType := "tcp"
	if form.Get("protocol") == string(proxynode.ProtocolHysteria2) {
		probeType = "quic"
	}
	material := h.proxyProbeEndpointMaterial(form.Get("agent_id"), form.Get("protocol"), form.Get("listen"), int(port))
	target := control.LinkLatencyProbeTarget{
		Address: address, Port: uint16(port), ProbeType: probeType,
		ServerName: form.Get("server_name"), ObfsType: form.Get("obfs_type"),
	}
	if probeType == "quic" && material != nil && material.ObfsType == target.ObfsType {
		target.ObfsSecret = material.ObfsSecret
		if target.ServerName == "" {
			target.ServerName = material.TLS.ServerName
		}
	}
	if probeType == "quic" && target.ObfsType != "" && target.ObfsSecret == "" {
		writeUserError(response, "Hysteria2 listener is not active yet", http.StatusConflict)
		return
	}
	sample, err := h.controller.RequestLinkLatencyProbe(ctx, parentAgent, target)
	if err != nil {
		statusCode := http.StatusServiceUnavailable
		if errors.Is(err, control.ErrLinkLatencyProbeUnsupported) {
			statusCode = http.StatusConflict
		}
		writeUserError(response, "path probe is unavailable", statusCode)
		return
	}
	view := linkLatencyViewFromSample(sample, h.now())
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(response).Encode(view)
}

func (h *Handler) proxyProbeEndpointMaterial(agentID, protocol, listen string, port int) *proxynode.Endpoint {
	state := h.proxyNodes.Snapshot()
	for _, node := range state.ProxyNodes {
		hops := make(map[string]string, len(node.Hops))
		for _, hop := range node.Hops {
			hops[hop.ID] = hop.AgentID
		}
		if hops[node.Entrance.HopID] == agentID && string(node.Entrance.Endpoint.Protocol) == protocol &&
			node.Entrance.Endpoint.Listen == listen && node.Entrance.Endpoint.ListenPort == port {
			endpoint := node.Entrance.Endpoint
			return &endpoint
		}
		for _, link := range node.Links {
			if hops[link.ChildHopID] == agentID && string(link.Endpoint.Protocol) == protocol &&
				link.Endpoint.Listen == listen && link.Endpoint.ListenPort == port {
				endpoint := link.Endpoint
				return &endpoint
			}
		}
	}
	return nil
}

func (h *Handler) enrolledAgent(agentID string) bool {
	for _, agent := range h.registry.Snapshot(h.currentTime()) {
		if agent.ID == agentID {
			return agent.State == identity.AgentStateEnrolled
		}
	}
	return false
}

func linkLatencyViewFromSample(sample control.LinkLatencyState, _ time.Time) linkLatencyView {
	observed := sample.ObservedAt.Format(time.RFC3339)
	probeType := sample.ProbeType
	if probeType == "" {
		probeType = "tcp"
	}
	if !sample.Responded {
		return linkLatencyView{Status: "unreachable", Label: "No response", Detail: strings.ToUpper(probeType) + " loss", ProbeType: probeType, ObservedAt: observed}
	}
	milliseconds := sample.Duration.Milliseconds()
	label := "<1 ms"
	if milliseconds > 0 {
		label = strconv.FormatInt(milliseconds, 10) + " ms"
	}
	if !sample.Connected {
		return linkLatencyView{Status: "reference", Label: label, Detail: "Connection refused", ProbeType: probeType, ObservedAt: observed}
	}
	return linkLatencyView{Status: "reachable", Label: label, Detail: "Connected", ProbeType: probeType, ObservedAt: observed}
}

func defaultMembershipPlanView() membershipPlanView {
	return membershipPlanView{QuotaMode: "unlimited", ExpirationMode: "none", SubscriptionValue: "1", SubscriptionUnit: "months"}
}

func nodeRoleTone(name string) string {
	toneNames := [...]string{"blue", "violet", "teal", "amber", "coral"}
	checksum := 0
	for _, character := range strings.ToLower(name) {
		checksum += int(character)
	}
	return toneNames[checksum%len(toneNames)]
}

func nodeInitial(name string) string {
	for _, character := range strings.TrimSpace(name) {
		return strings.ToUpper(string(character))
	}
	return "?"
}

func (h *Handler) attachProxyNodeUsers(detail *proxyNodeDetailView, node proxynode.ProxyNode, users []proxynode.User) {
	detail.EndUserCount = 0
	for _, user := range users {
		if !proxynode.IsSystemAdministrator(user) {
			detail.EndUserCount++
		}
	}
	compensationStart, _ := parseBillingDateTimeLocal(detail.CompensationStart)
	compensationEnd, _ := parseBillingDateTimeLocal(detail.CompensationEnd)
	assigned := make(map[string]proxynode.Membership, len(node.Memberships))
	for _, membership := range node.Memberships {
		assigned[membership.UserID] = membership
		if !membership.SubscriptionEndsAfter.IsZero() {
			detail.FiniteMemberCount++
		}
	}
	for _, user := range users {
		membership, exists := assigned[user.ID]
		if !exists {
			if !proxynode.IsSystemAdministrator(user) {
				detail.AvailableUsers = append(detail.AvailableUsers, nodeUserOptionView{UserID: user.ID, Label: user.Name})
			}
			continue
		}
		system := proxynode.IsSystemAdministrator(user)
		access := nodeUserAccessView{
			UserID: user.ID, Name: user.Name, Initial: nodeInitial(user.Name), URL: "/users/" + url.PathEscape(user.ID),
			Plan: membershipPlanViewFor(membership), System: system,
		}
		if system {
			access.URL = "/subscriptions/admin"
		}
		if !membership.SubscriptionEndsAfter.IsZero() {
			access.MembershipID = membership.ID
			access.SubscriptionStartedAt = membership.SubscriptionStartedAt.In(proxynode.BillingLocation()).Format(time.RFC3339)
			access.SubscriptionEndsAfter = membership.SubscriptionEndsAfter.In(proxynode.BillingLocation()).Format(time.RFC3339)
			access.CompensationSelected = membership.SubscriptionStartedAt.Before(compensationEnd) &&
				membership.SubscriptionEndsAfter.After(compensationStart)
			if access.CompensationSelected {
				detail.CompensationSelected++
			}
		}
		detail.UserAccess = append(detail.UserAccess, access)
	}
	sort.Slice(detail.UserAccess, func(left, right int) bool {
		return strings.ToLower(detail.UserAccess[left].Name) < strings.ToLower(detail.UserAccess[right].Name)
	})
	sort.Slice(detail.AvailableUsers, func(left, right int) bool {
		return strings.ToLower(detail.AvailableUsers[left].Label) < strings.ToLower(detail.AvailableUsers[right].Label)
	})
}

func membershipPlanViewFor(membership proxynode.Membership) membershipPlanView {
	resetAt := proxynode.MembershipQuotaResetAt(membership)
	view := membershipPlanView{
		QuotaMode: "unlimited", QuotaLabel: "Unlimited", UsageLabel: formatByteCount(membership.UsedBytes),
		ExpirationMode: "none", SubscriptionValue: "1", SubscriptionUnit: "months",
		ResetLabel:      resetAt.In(proxynode.BillingLocation()).Format("Jan 2, 2006 15:04"),
		ResetAt:         resetAt.Format(time.RFC3339),
		ExpirationLabel: "No expiration", StatusLabel: "Active", StatusClass: "active",
	}
	if membership.MonthlyQuotaBytes > 0 {
		view.QuotaMode = "limited"
		view.QuotaGiB = strconv.FormatUint(membership.MonthlyQuotaBytes/(1<<30), 10)
		if view.QuotaGiB == "0" {
			view.QuotaGiB = "1"
		}
		view.QuotaLabel = formatByteCount(membership.MonthlyQuotaBytes) + " / month"
	}
	if !membership.SubscriptionEndsAfter.IsZero() {
		view.ExpirationMode = "finite"
		view.SubscriptionValue = strconv.Itoa(membership.SubscriptionValue)
		view.SubscriptionUnit = string(membership.SubscriptionUnit)
		view.CanExtend = true
		view.ExpirationLabel = membership.SubscriptionEndsAfter.In(proxynode.BillingLocation()).Format("Jan 2, 2006 15:04")
		view.ExpirationAt = membership.SubscriptionEndsAfter.Format(time.RFC3339)
	}
	switch membership.DisabledReason {
	case proxynode.MembershipQuotaReached:
		view.StatusLabel, view.StatusClass = "Quota reached", "warning"
	case proxynode.MembershipExpired:
		view.StatusLabel, view.StatusClass = "Expired", "disabled"
	}
	return view
}

func parseMembershipPlan(form url.Values) (proxynode.MembershipPlan, error) {
	var plan proxynode.MembershipPlan
	switch form.Get("quota_mode") {
	case "unlimited":
	case "limited":
		gib, err := strconv.ParseUint(strings.TrimSpace(form.Get("monthly_quota_gib")), 10, 32)
		if err != nil || gib == 0 || gib > 1_000_000 {
			return plan, errors.New("monthly quota must be between 1 and 1,000,000 GiB")
		}
		plan.MonthlyQuotaBytes = gib << 30
	default:
		return plan, errors.New("quota mode is invalid")
	}
	switch form.Get("expiration_mode") {
	case "none":
	case "finite":
		value, unit, err := parseSubscriptionDuration(form.Get("subscription_value"), form.Get("subscription_unit"))
		if err != nil {
			return plan, err
		}
		plan.SubscriptionValue, plan.SubscriptionUnit = value, unit
	default:
		return plan, errors.New("expiration mode is invalid")
	}
	return plan, nil
}

func parseSubscriptionDuration(rawValue, rawUnit string) (int, proxynode.SubscriptionUnit, error) {
	value, err := strconv.Atoi(strings.TrimSpace(rawValue))
	unit := proxynode.SubscriptionUnit(strings.TrimSpace(rawUnit))
	maximum := map[proxynode.SubscriptionUnit]int{
		proxynode.SubscriptionMinutes: 52_560_000,
		proxynode.SubscriptionHours:   876_000,
		proxynode.SubscriptionDays:    36_500,
		proxynode.SubscriptionMonths:  1200,
	}[unit]
	if err != nil || value < 1 || maximum == 0 || value > maximum {
		return 0, "", errors.New("subscription duration is invalid or exceeds 100 years")
	}
	return value, unit, nil
}

func formatByteCount(value uint64) string {
	const (
		kib = uint64(1 << 10)
		mib = uint64(1 << 20)
		gib = uint64(1 << 30)
		tib = uint64(1 << 40)
	)
	switch {
	case value >= tib:
		return fmt.Sprintf("%.2f TiB", float64(value)/float64(tib))
	case value >= gib:
		return fmt.Sprintf("%.2f GiB", float64(value)/float64(gib))
	case value >= mib:
		return fmt.Sprintf("%.2f MiB", float64(value)/float64(mib))
	case value >= kib:
		return fmt.Sprintf("%.2f KiB", float64(value)/float64(kib))
	default:
		return fmt.Sprintf("%d B", value)
	}
}

func (h *Handler) attachProxyTreeControls(node proxynode.ProxyNode, tree *proxyTreeHopView) {
	if tree == nil {
		return
	}
	hop, exists := proxyHop(node, tree.ID)
	if !exists {
		return
	}
	tree.ProxyID = node.ID
	tree.Final = targetValue(hop.Final)
	tree.AgentOptions = h.proxyAgentOptions(hop.AgentID)
	tree.DestinationAgentOptions = h.proxyDestinationAgentOptions(node, hop.ID, "")
	tree.NewRule = proxyRuleView{Match: string(proxynode.MatchProtocol)}
	tree.NewLinkEndpoint = defaultEndpointView()
	for index := range tree.Children {
		link := &tree.Children[index]
		link.DestinationAgentOptions = h.proxyDestinationAgentOptions(node, hop.ID, link.Child.AgentID)
		h.attachProxyTreeControls(node, link.Child)
	}
}

func (h *Handler) proxyDestinationAgentOptions(node proxynode.ProxyNode, parentHopID, selected string) []agentOptionView {
	options := h.proxyAgentOptions(selected)
	excluded := proxynode.AncestorAgentIDs(node, parentHopID)
	options = slices.DeleteFunc(options, func(option agentOptionView) bool {
		_, exists := excluded[option.ID]
		return exists
	})
	if h.controller == nil {
		return options
	}
	hops := make(map[string]string, len(node.Hops))
	for _, hop := range node.Hops {
		hops[hop.ID] = hop.AgentID
	}
	parentAgent := hops[parentHopID]
	type pathView struct {
		latency linkLatencyView
		links   []string
	}
	paths := make(map[string]pathView)
	appliedNodes := h.proxyNodes.Snapshot().AppliedProxyNodes
	for _, link := range node.Links {
		if hops[link.ParentHopID] != parentAgent {
			continue
		}
		childAgent := hops[link.ChildHopID]
		path := paths[childAgent]
		path.links = append(path.links, link.ID)
		candidate := h.topologyLinkLatencyView(node, appliedNodes, link)
		if path.latency.ObservedAt == "" || candidate.ObservedAt > path.latency.ObservedAt {
			path.latency = candidate
		}
		paths[childAgent] = path
	}
	for index := range options {
		path, exists := paths[options[index].ID]
		if !exists {
			if options[index].Online {
				options[index].LatencyDetail = "Not measured"
				options[index].LatencyStatus = "pending"
			} else {
				options[index].LatencyDetail = "Offline"
				options[index].LatencyStatus = "offline"
			}
			continue
		}
		options[index].LatencyLinkIDs = strings.Join(path.links, ",")
		options[index].LatencyStatus = path.latency.Status
		if path.latency.Label == "" || path.latency.Label == "—" {
			if options[index].Online {
				options[index].LatencyDetail = "Not measured"
			} else {
				options[index].LatencyDetail = "Offline"
				options[index].LatencyStatus = "offline"
			}
			continue
		}
		probeType := path.latency.ProbeType
		if probeType == "" {
			probeType = "tcp"
		}
		options[index].LatencyDetail = path.latency.Label + " · " + strings.ToUpper(probeType)
	}
	return options
}

func buildProxyTree(node proxynode.ProxyNode) (*proxyTreeHopView, int, int) {
	return buildProxyTreeWithNames(node, func(agentID string) string { return agentID })
}

func buildProxyTreeWithNames(node proxynode.ProxyNode, displayName func(string) string) (*proxyTreeHopView, int, int) {
	hops := make(map[string]proxynode.Hop, len(node.Hops))
	for _, hop := range node.Hops {
		hops[hop.ID] = hop
	}
	children := make(map[string][]proxynode.Link)
	for _, link := range node.Links {
		children[link.ParentHopID] = append(children[link.ParentHopID], link)
	}
	blocks := make(map[string][]proxynode.BlockBranch)
	for _, branch := range node.BlockBranches {
		blocks[branch.ParentHopID] = append(blocks[branch.ParentHopID], branch)
	}
	for parent := range children {
		sort.Slice(children[parent], func(left, right int) bool {
			return children[parent][left].Order < children[parent][right].Order
		})
	}
	unusedLinks := 0
	var visit func(string, *proxynode.Link, proxyTreeConstraint, bool) *proxyTreeHopView
	visit = func(hopID string, incoming *proxynode.Link, constraint proxyTreeConstraint, includeDetails bool) *proxyTreeHopView {
		hop, exists := hops[hopID]
		if !exists {
			return nil
		}
		ingressProtocol := protocolLabel(node.Entrance.Endpoint.Protocol)
		ingressLabel := "Entrance listener · port " + strconv.Itoa(node.Entrance.Endpoint.ListenPort)
		if incoming != nil {
			ingressProtocol = protocolLabel(incoming.Endpoint.Protocol)
			ingressLabel = "Incoming Link · port " + strconv.Itoa(incoming.Endpoint.ListenPort)
		}
		fallback := proxyTreeRouteWithNames(node, hop, "Fallback", "", "", hop.Final, displayName)
		for _, link := range children[hopID] {
			if link.Fallback {
				fallback = proxyTreeRouteWithNames(node, hop, "Fallback", "When no conditional Link matches", "", proxynode.Target{Type: proxynode.TargetLink, LinkID: link.ID}, displayName)
				break
			}
		}
		view := &proxyTreeHopView{
			ProxyID: node.ID, ID: hop.ID, Name: displayName(hop.AgentID), AgentID: hop.AgentID, URL: proxyHopURL(node.ID, hop.ID),
			IsEntrance: hop.ID == node.Entrance.HopID, IngressProtocol: ingressProtocol, IngressLabel: ingressLabel,
			Fallback: fallback,
		}
		view.Fallback.ProxyID = node.ID
		view.Fallback.HopID = hop.ID
		view.Fallback.InspectorID = "terminal-" + hop.ID + "-fallback"
		totalRules := 0
		for _, link := range children[hopID] {
			totalRules += len(link.Rules)
		}
		totalRules += len(blocks[hopID])
		if includeDetails {
			for _, branch := range blocks[hopID] {
				views := proxyRuleViews([]proxynode.Rule{branch.Rule}, totalRules)
				view.BlockRules = append(view.BlockRules, proxyBlockRuleView{Rule: views[0], AgentID: hop.AgentID, Name: displayName(hop.AgentID), ParentID: hop.ID})
			}
			sort.SliceStable(view.BlockRules, func(left, right int) bool {
				return view.BlockRules[left].Rule.Position < view.BlockRules[right].Rule.Position
			})
		}
		for index := range children[hopID] {
			link := children[hopID][index]
			used := link.Fallback || len(link.Rules) > 0
			if includeDetails && !used {
				unusedLinks++
			}
			if includeDetails {
				child := visit(link.ChildHopID, &link, proxyTreeConstraint{}, true)
				childAgent := hops[link.ChildHopID].AgentID
				ruleViews := proxyRuleViews(link.Rules, totalRules)
				view.Children = append(view.Children, proxyTreeLinkView{
					ID: link.ID, ParentHopID: link.ParentHopID, EditURL: proxyLinkURL(node.ID, link.ID), Protocol: protocolLabel(link.Endpoint.Protocol),
					HistoryURL: proxyLinkURL(node.ID, link.ID) + "/latency-history",
					ProbeURL:   proxyLinkURL(node.ID, link.ID) + "/latency-probe",
					ListenPort: link.Endpoint.ListenPort, Listener: listenEndpointLabel(link.Endpoint.Listen, link.Endpoint.ListenPort),
					Family: relayFamilyLabel(link.Endpoint.Family), Order: index + 1, Endpoint: endpointViewForAgent(link.Endpoint, childAgent),
					Rules: ruleViews, NewRule: proxyRuleView{Match: string(proxynode.MatchProtocol)}, Used: used,
					Fallback: link.Fallback, CanMoveUp: index > 0 && !link.Fallback,
					CanMoveDown: index+1 < len(children[hopID]) && !children[hopID][index+1].Fallback, Child: child,
				})
				if child != nil {
					view.BranchCount += child.BranchCount
				}
			}
		}
		type routedBranch struct {
			link  *proxynode.Link
			block *proxynode.BlockBranch
			rule  proxynode.Rule
		}
		routes := make([]routedBranch, 0, totalRules)
		for _, link := range children[hopID] {
			for _, rule := range link.Rules {
				linkCopy := link
				routes = append(routes, routedBranch{link: &linkCopy, rule: rule})
			}
		}
		for _, block := range blocks[hopID] {
			blockCopy := block
			routes = append(routes, routedBranch{block: &blockCopy, rule: block.Rule})
		}
		sort.SliceStable(routes, func(left, right int) bool { return routes[left].rule.Order < routes[right].rule.Order })
		allRuleIDs := make([]string, 0, len(routes))
		for _, route := range routes {
			allRuleIDs = append(allRuleIDs, route.rule.ID)
		}
		view.AllRuleIDs = strings.Join(allRuleIDs, ",")
		earlierRules := make([]proxynode.Rule, 0, len(routes))
		for _, route := range routes {
			branchConstraint := constraint.selectRule(route.rule, earlierRules)
			if branchConstraint.feasible() {
				uncertain := branchConstraint.runtimeDependent() && !constraint.runtimeDependent()
				if route.block != nil {
					view.Branches = append(view.Branches, proxyTreeBranchView{
						RuleID: route.rule.ID, RulePosition: route.rule.Order + 1, RuleLabel: matchLabel(route.rule.Match),
						RuleValues: strings.Join(route.rule.Values, ", "), Used: true, Block: true,
						InspectorID: "block-rule-" + route.rule.ID, AgentID: hop.AgentID, Name: displayName(hop.AgentID), Uncertain: uncertain,
					})
					view.TerminalCount++
				} else {
					child := visit(route.link.ChildHopID, route.link, branchConstraint, false)
					view.Branches = append(view.Branches, proxyTreeBranchView{
						LinkID: route.link.ID, RuleID: route.rule.ID, RulePosition: route.rule.Order + 1,
						Protocol: protocolLabel(route.link.Endpoint.Protocol), RuleLabel: matchLabel(route.rule.Match),
						RuleValues: strings.Join(route.rule.Values, ", "), Used: true, Uncertain: uncertain, Child: child,
					})
					if child != nil {
						view.TerminalCount += child.TerminalCount
						view.RuntimeBranches += child.RuntimeBranches
					}
				}
				if uncertain {
					view.RuntimeBranches++
				}
			}
			earlierRules = append(earlierRules, route.rule)
		}
		for _, link := range children[hopID] {
			if link.Fallback || len(link.Rules) != 0 {
				continue
			}
			child := visit(link.ChildHopID, &link, constraint, false)
			view.Branches = append(view.Branches, proxyTreeBranchView{
				LinkID: link.ID, Protocol: protocolLabel(link.Endpoint.Protocol), RuleLabel: "Inactive Link", RuleValues: "Add a match rule", Child: child,
			})
			if child != nil {
				view.TerminalCount += child.TerminalCount
				view.RuntimeBranches += child.RuntimeBranches
			}
		}
		for _, link := range children[hopID] {
			if !link.Fallback {
				continue
			}
			branchConstraint := constraint.selectFallback(earlierRules)
			if branchConstraint.feasible() {
				child := visit(link.ChildHopID, &link, branchConstraint, false)
				uncertain := branchConstraint.runtimeDependent() && !constraint.runtimeDependent()
				view.Branches = append(view.Branches, proxyTreeBranchView{
					LinkID: link.ID, Protocol: protocolLabel(link.Endpoint.Protocol), RuleLabel: "Fallback", RuleValues: "When no earlier rule matches",
					Used: true, Fallback: true, Uncertain: uncertain, Child: child,
				})
				if uncertain {
					view.RuntimeBranches++
				}
				if child != nil {
					view.TerminalCount += child.TerminalCount
					view.RuntimeBranches += child.RuntimeBranches
				}
			}
			break
		}
		fallbackConstraint := constraint.selectFallback(earlierRules)
		view.ShowFallback = fallback.TargetKind != string(proxynode.TargetLink) && fallbackConstraint.feasible()
		if view.ShowFallback {
			view.Fallback.Uncertain = fallbackConstraint.runtimeDependent() && !constraint.runtimeDependent()
			view.TerminalCount++
			if view.Fallback.Uncertain {
				view.RuntimeBranches++
			}
		}
		if includeDetails {
			view.BranchCount += len(view.Children)
		}
		return view
	}
	root := visit(node.Entrance.HopID, nil, proxyTreeConstraint{}, true)
	if root == nil {
		return nil, 0, unusedLinks
	}
	return root, root.TerminalCount, unusedLinks
}

func proxyTreeRouteWithNames(node proxynode.ProxyNode, hop proxynode.Hop, label, match, values string, target proxynode.Target, displayName func(string) string) proxyTreeRouteView {
	view := proxyTreeRouteView{Label: label, Match: match, Values: values, TargetKind: string(target.Type)}
	switch target.Type {
	case proxynode.TargetDirect:
		view.TargetLabel = "Direct"
		view.TargetDetail = "Terminal on " + displayName(hop.AgentID)
	case proxynode.TargetReject:
		view.TargetLabel = "Reject"
		view.TargetDetail = "Terminal on " + displayName(hop.AgentID)
	case proxynode.TargetLink:
		view.TargetLabel = targetLabelWithNames(node, target, displayName)
		if link, ok := proxyLink(node, target.LinkID); ok {
			if child, exists := proxyHop(node, link.ChildHopID); exists {
				view.TargetDetail = "Relay to " + displayName(child.AgentID)
				view.TargetURL = proxyHopURL(node.ID, child.ID)
			}
		}
	}
	return view
}

func (h *Handler) membershipURIs(node proxynode.ProxyNode, user proxynode.User, membership proxynode.Membership) []credentialURIView {
	root, ok := proxyHop(node, node.Entrance.HopID)
	if !ok || h.controller.PoolRegistry() == nil {
		return nil
	}
	result := make([]credentialURIView, 0, 2)
	for _, family := range []struct {
		name string
		kind pool.Family
	}{{"IPv4", pool.FamilyIPv4}, {"IPv6", pool.FamilyIPv6}} {
		address, exists := h.controller.PoolRegistry().AgentAddressForFamily(root.AgentID, family.kind)
		if !exists {
			continue
		}
		if uri := membershipURI(node, user, membership, address); uri != "" {
			result = append(result, credentialURIView{Family: family.name, URI: uri})
		}
	}
	return result
}

func membershipURI(node proxynode.ProxyNode, user proxynode.User, membership proxynode.Membership, address string) string {
	endpoint := node.Entrance.Endpoint
	host := address
	if strings.Contains(address, ":") {
		host = "[" + address + "]"
	}
	label := url.QueryEscape(node.Name + " - " + user.Name)
	switch endpoint.Protocol {
	case proxynode.ProtocolAnyTLS:
		query := url.Values{"sni": {endpoint.TLS.ServerName}, "insecure": {boolDigit(endpoint.TLS.Mode != proxynode.TLSModeACME)}}
		return "anytls://" + url.QueryEscape(membership.Credential.Secret) + "@" + host + ":" + strconv.Itoa(endpoint.ListenPort) + "?" + query.Encode() + "#" + label
	case proxynode.ProtocolHysteria2:
		query := url.Values{"sni": {endpoint.TLS.ServerName}, "insecure": {boolDigit(endpoint.TLS.Mode != proxynode.TLSModeACME)}}
		if endpoint.ObfsType != "" {
			query.Set("obfs", endpoint.ObfsType)
			query.Set("obfs-password", endpoint.ObfsSecret)
		}
		return "hysteria2://" + url.QueryEscape(membership.Credential.Secret) + "@" + host + ":" + strconv.Itoa(endpoint.ListenPort) + "?" + query.Encode() + "#" + label
	case proxynode.ProtocolShadowsocks:
		credentials := endpoint.Method + ":" + endpoint.ServerKey + ":" + membership.Credential.Secret
		return "ss://" + base64.RawURLEncoding.EncodeToString([]byte(credentials)) + "@" + host + ":" + strconv.Itoa(endpoint.ListenPort) + "#" + label
	default:
		return ""
	}
}

func (h *Handler) authorizeProxyMutation(response http.ResponseWriter, request *http.Request, fields ...string) (Session, url.Values, bool) {
	if h.proxyNodes == nil {
		writeUserError(response, "Proxy Node manager is unavailable", http.StatusServiceUnavailable)
		return Session{}, nil, false
	}
	token, ok := h.sessionToken(request)
	if !ok {
		h.redirectToLogin(response, request)
		return Session{}, nil, false
	}
	if h.rejectInvalidMutationOrigin(response, request) {
		return Session{}, nil, false
	}
	expected := append([]string{"csrf_token"}, fields...)
	form, err := readExactForm(response, request, maxProxyFormBytes, expected...)
	if err != nil {
		writeUserError(response, "request form is invalid", http.StatusBadRequest)
		return Session{}, nil, false
	}
	if !h.authorizeCSRF(response, token, form.Get("csrf_token")) {
		writeUserError(response, "request was not authorized", http.StatusForbidden)
		return Session{}, nil, false
	}
	if form.Get("match") == string(proxynode.MatchRuleSet) {
		writeUserError(response, "Custom Rule Sets are no longer supported. Choose Geosite, GeoIP, or another match type. Existing rules remain active until you change or delete them.", http.StatusBadRequest)
		return Session{}, nil, false
	}
	session, err := h.access.Authenticate(token)
	if err != nil {
		h.redirectToLogin(response, request)
		return Session{}, nil, false
	}
	return session, form, true
}

func (h *Handler) loadProxyNode(response http.ResponseWriter, request *http.Request) (proxynode.ProxyNode, bool) {
	if h.proxyNodes == nil {
		writeUserError(response, "Proxy Node manager is unavailable", http.StatusServiceUnavailable)
		return proxynode.ProxyNode{}, false
	}
	node, exists := h.proxyNodes.ProxyNode(request.PathValue("proxy_id"))
	if !exists {
		http.NotFound(response, request)
		return proxynode.ProxyNode{}, false
	}
	return node, true
}

func (h *Handler) proxyAgentOptions(selected string) []agentOptionView {
	snapshots := h.registry.Snapshot(h.currentTime())
	options := make([]agentOptionView, 0, len(snapshots)+1)
	selectedFound := false
	for _, snapshot := range snapshots {
		if snapshot.ID == selected {
			selectedFound = true
		}
		if snapshot.State != identity.AgentStateEnrolled {
			if snapshot.ID == selected {
				options = append(options, agentOptionView{ID: snapshot.ID, Name: snapshot.DisplayName, Selected: true})
			}
			continue
		}
		options = append(options, agentOptionView{ID: snapshot.ID, Name: snapshot.DisplayName, Selected: snapshot.ID == selected, Online: h.sessions.IsOnline(snapshot.ID)})
	}
	if selected != "" && !selectedFound {
		options = append(options, agentOptionView{ID: selected, Name: selected, Selected: true, Deleted: true})
	}
	sort.Slice(options, func(left, right int) bool {
		if options[left].Name != options[right].Name {
			return options[left].Name < options[right].Name
		}
		return options[left].ID < options[right].ID
	})
	return options
}

func (h *Handler) proxyDeploymentView() *proxyDeploymentView {
	if h.proxyDeployer == nil {
		return nil
	}
	state := h.proxyNodes.Snapshot()
	topologyPending := state.Revision != state.AppliedRevision
	job, exists := h.proxyDeployer.Current()
	if !exists {
		if !topologyPending {
			return nil
		}
		return &proxyDeploymentView{
			Status: string(proxynode.FleetDeploymentPending), Label: "Pending", Class: "pending",
			Error: "Saved topology differs from the running configuration. It remains pending across Master restarts; check the affected Servers and deployment details.",
		}
	}
	metadata, metadataExists := h.proxyDeployer.DeploymentMetadata(job.ID)
	currentTopologyJob := metadataExists &&
		metadata.Kind == proxynode.FleetDeploymentKindTopology &&
		metadata.TopologyRevision == state.Revision
	currentRecoveryFailure := metadataExists &&
		metadata.Kind == proxynode.FleetDeploymentKindRecovery &&
		metadata.RecoveryStillNeeded
	// A completed applied-refresh or stale topology job may share this
	// presentation slot with a newer desired topology. It must not imply those
	// edits are active. Conversely, retain a failure for the current desired
	// revision (or an unfinished rollback): that diagnostic is the reason the
	// reconciler stopped retrying and must not be hidden behind generic Pending.
	terminal := job.Status == proxynode.FleetDeploymentApplied || job.Status == proxynode.FleetDeploymentFailed
	showCurrentFailure := job.Status == proxynode.FleetDeploymentFailed &&
		(currentTopologyJob || currentRecoveryFailure)
	if topologyPending && terminal && !showCurrentFailure {
		return &proxyDeploymentView{
			Status: string(proxynode.FleetDeploymentPending), Label: "Pending", Class: "pending",
			Error: "Saved topology differs from the running configuration. It remains pending across Master restarts; check the affected Servers and deployment details.",
		}
	}
	labels := map[proxynode.FleetDeploymentStatus]string{
		proxynode.FleetDeploymentQueued:    "Queued",
		proxynode.FleetDeploymentDeploying: "Deploying",
		proxynode.FleetDeploymentPending:   "Pending",
		proxynode.FleetDeploymentApplied:   "Applied",
		proxynode.FleetDeploymentFailed:    "Failed",
	}
	view := &proxyDeploymentView{ID: job.ID, Status: string(job.Status), Label: labels[job.Status], Class: "pending", Error: job.Error}
	for _, agent := range job.Agents {
		view.Agents = append(view.Agents, proxyDeploymentAgentView{AgentID: agent.AgentID, AgentName: h.agentDisplayName(agent.AgentID), Status: agent.Status})
	}
	view.Active = job.Status == proxynode.FleetDeploymentQueued || job.Status == proxynode.FleetDeploymentDeploying
	if job.Status == proxynode.FleetDeploymentApplied {
		view.Class = "online"
	} else if job.Status == proxynode.FleetDeploymentFailed {
		view.Class = "attention"
	}
	return view
}

var endpointFormFields = []string{"protocol", "listen", "listen_port", "family", "method", "mux_enabled", "mux_padding", "mux_brutal", "mux_brutal_up_mbps", "mux_brutal_down_mbps", "tls_mode", "server_name", "email", "certificate_path", "key_path", "up_mbps", "down_mbps", "obfs_type"}

func parseEndpointForm(form url.Values, current ...proxynode.Endpoint) (proxynode.Endpoint, error) {
	if len(current) > 1 {
		return proxynode.Endpoint{}, errors.New("endpoint form has ambiguous edit context")
	}
	port, err := strconv.Atoi(form.Get("listen_port"))
	if err != nil {
		return proxynode.Endpoint{}, errors.New("listen port must be a number")
	}
	endpoint := proxynode.Endpoint{
		Protocol: proxynode.Protocol(form.Get("protocol")), Listen: form.Get("listen"), ListenPort: port,
		Family: form.Get("family"),
	}
	switch endpoint.Protocol {
	case proxynode.ProtocolShadowsocks:
		endpoint.Method = form.Get("method")
		multiplex, err := parseMultiplexForm(form)
		if err != nil {
			return proxynode.Endpoint{}, err
		}
		endpoint.Multiplex = multiplex
	case proxynode.ProtocolAnyTLS, proxynode.ProtocolHysteria2:
		endpoint.TLS = proxynode.TLSConfig{Mode: proxynode.TLSMode(form.Get("tls_mode")), ServerName: form.Get("server_name"), Email: form.Get("email"), CertificatePath: form.Get("certificate_path"), KeyPath: form.Get("key_path")}
		if endpoint.TLS.Mode == proxynode.TLSModeFiles {
			if len(current) != 1 || current[0].TLS.Mode != proxynode.TLSModeFiles {
				return proxynode.Endpoint{}, errors.New("legacy file certificate mode cannot be selected for a new endpoint")
			}
			if endpoint.TLS.CertificatePath != current[0].TLS.CertificatePath || endpoint.TLS.KeyPath != current[0].TLS.KeyPath {
				return proxynode.Endpoint{}, errors.New("legacy file certificate paths cannot be changed")
			}
		} else {
			// File paths are accepted only as an exact round-trip of an existing
			// legacy endpoint. Never let hidden or crafted fields survive a move
			// to an Agent-managed certificate mode.
			endpoint.TLS.CertificatePath = ""
			endpoint.TLS.KeyPath = ""
		}
		if endpoint.Protocol == proxynode.ProtocolHysteria2 {
			up, err := optionalPositiveInt(form.Get("up_mbps"))
			if err != nil {
				return proxynode.Endpoint{}, errors.New("upload Mbps must be a positive number")
			}
			down, err := optionalPositiveInt(form.Get("down_mbps"))
			if err != nil {
				return proxynode.Endpoint{}, errors.New("download Mbps must be a positive number")
			}
			endpoint.UpMbps = up
			endpoint.DownMbps = down
			endpoint.ObfsType = form.Get("obfs_type")
		}
	}
	return endpoint, nil
}

func endpointViewFor(endpoint proxynode.Endpoint) endpointView {
	view := endpointView{Protocol: string(endpoint.Protocol), ProtocolLabel: protocolLabel(endpoint.Protocol), Listen: endpoint.Listen, ListenPort: endpoint.ListenPort, Family: endpoint.Family, Method: endpoint.Method, TLSMode: string(endpoint.TLS.Mode), ServerName: endpoint.TLS.ServerName, Email: endpoint.TLS.Email, CertificatePath: endpoint.TLS.CertificatePath, KeyPath: endpoint.TLS.KeyPath, UpMbps: endpoint.UpMbps, DownMbps: endpoint.DownMbps, ObfsType: endpoint.ObfsType}
	if endpoint.Multiplex != nil {
		view.MuxEnabled = endpoint.Multiplex.Enabled
		view.MuxPadding = endpoint.Multiplex.Padding
		if endpoint.Multiplex.Brutal != nil {
			view.MuxBrutal = endpoint.Multiplex.Brutal.Enabled
			view.MuxBrutalUpMbps = endpoint.Multiplex.Brutal.UpMbps
			view.MuxBrutalDownMbps = endpoint.Multiplex.Brutal.DownMbps
		}
	}
	return view
}

func endpointViewForAgent(endpoint proxynode.Endpoint, agentID string) endpointView {
	view := endpointViewFor(endpoint)
	view.AgentID = agentID
	view.ListenerID = proxynode.ListenerPresetID(agentID, endpoint)
	return view
}

func (h *Handler) proxyListenerOptions() []listenerOptionView {
	if h.proxyNodes == nil {
		return nil
	}
	presets := proxynode.ListenerPresets(h.proxyNodes.Snapshot())
	options := make([]listenerOptionView, 0, len(presets))
	for _, preset := range presets {
		endpoint := preset.Endpoint
		view := listenerOptionView{
			ID: preset.ID, AgentID: preset.AgentID, Protocol: string(endpoint.Protocol),
			ProtocolLabel: protocolLabel(endpoint.Protocol), Listen: endpoint.Listen,
			ListenPort: endpoint.ListenPort, Method: endpoint.Method,
			TLSMode: string(endpoint.TLS.Mode), ServerName: endpoint.TLS.ServerName,
			Email: endpoint.TLS.Email, CertificatePath: endpoint.TLS.CertificatePath,
			KeyPath: endpoint.TLS.KeyPath, UpMbps: endpoint.UpMbps, DownMbps: endpoint.DownMbps,
			ObfsType: endpoint.ObfsType, ReferenceCount: preset.ReferenceCount,
		}
		if endpoint.Multiplex != nil {
			view.MuxPadding = endpoint.Multiplex.Padding
			if endpoint.Multiplex.Brutal != nil {
				view.MuxBrutal = endpoint.Multiplex.Brutal.Enabled
				view.MuxBrutalUp = endpoint.Multiplex.Brutal.UpMbps
				view.MuxBrutalDown = endpoint.Multiplex.Brutal.DownMbps
			}
		}
		view.Label = fmt.Sprintf("%s · %s:%d · %d reference", view.ProtocolLabel, endpoint.Listen, endpoint.ListenPort, preset.ReferenceCount)
		if preset.ReferenceCount != 1 {
			view.Label += "s"
		}
		options = append(options, view)
	}
	return options
}

func defaultEndpointView() endpointView {
	return endpointView{Protocol: string(proxynode.ProtocolAnyTLS), Listen: "::", ListenPort: 443, Family: "auto", Method: "2022-blake3-aes-128-gcm", TLSMode: string(proxynode.TLSModeSelfSigned)}
}

func parseMultiplexForm(form url.Values) (*proxynode.MultiplexConfig, error) {
	enabled, err := parseBinaryChoice(form.Get("mux_enabled"), "multiplex")
	if err != nil {
		return nil, err
	}
	config := &proxynode.MultiplexConfig{Enabled: enabled}
	config.Padding, err = parseBinaryChoice(form.Get("mux_padding"), "multiplex padding")
	if err != nil {
		return nil, err
	}
	brutal, err := parseBinaryChoice(form.Get("mux_brutal"), "TCP Brutal")
	if err != nil {
		return nil, err
	}
	if !brutal {
		if !config.Enabled && !config.Padding {
			return nil, nil
		}
		return config, nil
	}
	up, err := optionalPositiveInt(form.Get("mux_brutal_up_mbps"))
	if err != nil || up == 0 {
		return nil, errors.New("TCP Brutal upload Mbps must be a positive number")
	}
	down, err := optionalPositiveInt(form.Get("mux_brutal_down_mbps"))
	if err != nil || down == 0 {
		return nil, errors.New("TCP Brutal download Mbps must be a positive number")
	}
	config.Brutal = &proxynode.TCPBrutalConfig{Enabled: true, UpMbps: up, DownMbps: down}
	return config, nil
}

func parseBinaryChoice(value, label string) (bool, error) {
	switch value {
	case "", "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("%s setting is invalid", label)
	}
}

func optionalPositiveInt(value string) (int, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 || parsed > 1_000_000 {
		return 0, errors.New("invalid positive number")
	}
	return parsed, nil
}

func parseProxyTarget(value string) (proxynode.Target, error) {
	switch value {
	case "direct":
		return proxynode.Target{Type: proxynode.TargetDirect}, nil
	case "reject":
		return proxynode.Target{Type: proxynode.TargetReject}, nil
	}
	return proxynode.Target{}, errors.New("routing target is invalid")
}

func targetValue(target proxynode.Target) string {
	if target.Type == proxynode.TargetLink {
		return "link:" + target.LinkID
	}
	return string(target.Type)
}

func proxyRuleViews(rules []proxynode.Rule, total int) []proxyRuleView {
	views := make([]proxyRuleView, 0, len(rules))
	for _, rule := range rules {
		views = append(views, proxyRuleView{
			ID: rule.ID, Position: rule.Order + 1, Match: string(rule.Match), MatchLabel: matchLabel(rule.Match),
			Values: strings.Join(rule.Values, ", "), FormValues: strings.Join(rule.Values, "\n"),
			CanMoveUp: rule.Order > 0, CanMoveDown: rule.Order+1 < total,
		})
	}
	sort.SliceStable(views, func(left, right int) bool { return views[left].Position < views[right].Position })
	return views
}

func targetLabel(node proxynode.ProxyNode, target proxynode.Target) string {
	return targetLabelWithNames(node, target, func(agentID string) string { return agentID })
}

func targetLabelWithNames(node proxynode.ProxyNode, target proxynode.Target, displayName func(string) string) string {
	if target.Type == proxynode.TargetDirect {
		return "Direct"
	}
	if target.Type == proxynode.TargetReject {
		return "Reject"
	}
	if link, ok := proxyLink(node, target.LinkID); ok {
		if child, exists := proxyHop(node, link.ChildHopID); exists {
			return "Link to " + displayName(child.AgentID)
		}
	}
	return "Unknown Link"
}

func proxyHop(node proxynode.ProxyNode, id string) (proxynode.Hop, bool) {
	for _, hop := range node.Hops {
		if hop.ID == id {
			return hop, true
		}
	}
	return proxynode.Hop{}, false
}

func proxyLink(node proxynode.ProxyNode, id string) (proxynode.Link, bool) {
	for _, link := range node.Links {
		if link.ID == id {
			return link, true
		}
	}
	return proxynode.Link{}, false
}

func proxyHopEndpoint(node proxynode.ProxyNode, hopID string) (proxynode.Endpoint, bool) {
	if hopID == node.Entrance.HopID {
		return node.Entrance.Endpoint, true
	}
	for _, link := range node.Links {
		if link.ChildHopID == hopID {
			return link.Endpoint, true
		}
	}
	return proxynode.Endpoint{}, false
}

func proxyNodeURL(id string) string      { return "/proxy-nodes/" + url.PathEscape(id) + "/manage" }
func proxyNodeUsersURL(id string) string { return proxyNodeURL(id) + "?dialog=proxy-node-users" }
func proxyHopURL(nodeID, hopID string) string {
	return "/proxy-nodes/" + url.PathEscape(nodeID) + "/hops/" + url.PathEscape(hopID)
}
func proxyInspectorURL(nodeID, viewID string) string {
	return proxyNodeURL(nodeID) + "?inspect=" + url.QueryEscape(viewID)
}
func proxyLinkURL(nodeID, linkID string) string {
	return "/proxy-nodes/" + url.PathEscape(nodeID) + "/links/" + url.PathEscape(linkID)
}

func listenEndpointLabel(address string, port int) string {
	if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") {
		address = "[" + address + "]"
	}
	return address + ":" + strconv.Itoa(port)
}

func relayFamilyLabel(family string) string {
	switch family {
	case "ipv4":
		return "IPv4"
	case "ipv6":
		return "IPv6"
	default:
		return "Automatic"
	}
}

func protocolLabel(protocol proxynode.Protocol) string {
	switch protocol {
	case proxynode.ProtocolAnyTLS:
		return "AnyTLS"
	case proxynode.ProtocolHysteria2:
		return "Hysteria2"
	case proxynode.ProtocolShadowsocks:
		return "SS2022"
	default:
		return string(protocol)
	}
}

func matchLabel(match proxynode.MatchType) string {
	labels := map[proxynode.MatchType]string{proxynode.MatchNone: "ALL", proxynode.MatchProtocol: "Protocol", proxynode.MatchDomain: "Domain", proxynode.MatchDomainSuffix: "Domain suffix", proxynode.MatchDomainKeyword: "Domain keyword", proxynode.MatchDomainRegex: "Domain regex", proxynode.MatchIPCIDR: "IP / CIDR", proxynode.MatchGeosite: "Geosite", proxynode.MatchGeoIP: "GeoIP", proxynode.MatchRuleSet: "Custom Rule Set", proxynode.MatchNetwork: "Network"}
	return labels[match]
}

func splitProxyValues(value string) []string {
	return strings.FieldsFunc(value, func(character rune) bool { return character == ',' || character == '\n' || character == '\r' })
}

func boolDigit(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func handleProxyMutationError(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, proxynode.ErrNotFound) {
		status = http.StatusNotFound
	} else if errors.Is(err, proxynode.ErrConflict) {
		status = http.StatusConflict
	}
	writeUserError(response, err.Error(), status)
}
