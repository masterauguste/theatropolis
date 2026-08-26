package webui

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
)

const maxProxyFormBytes = 128 << 10

var membershipPlanFormFields = []string{
	"quota_mode", "monthly_quota_gib", "expiration_mode", "subscription_months",
}

type proxyNodeListView struct {
	ID            string
	Name          string
	URL           string
	Entrance      string
	EntranceAgent string
	HopCount      int
	MemberCount   int
	UpdatedAt     string
}

type proxyNodeDetailView struct {
	ID               string
	Name             string
	URL              string
	EntranceURL      string
	EntranceHopURL   string
	EntranceFallback string
	RuleSetsURL      string
	Entrance         endpointView
	Tree             *proxyTreeHopView
	RuleSets         []proxynode.CustomRuleSet
	HopCount         int
	LinkCount        int
	MemberCount      int
	TerminalCount    int
	UnusedLinkCount  int
	UserAccess       []nodeUserAccessView
	AvailableUsers   []nodeUserOptionView
	DefaultPlan      membershipPlanView
}

type membershipPlanView struct {
	QuotaMode          string
	QuotaGiB           string
	ExpirationMode     string
	SubscriptionMonths string
	QuotaLabel         string
	UsageLabel         string
	ResetLabel         string
	ExpirationLabel    string
	StatusLabel        string
	StatusClass        string
}

type nodeUserAccessView struct {
	UserID string
	Name   string
	URL    string
	Plan   membershipPlanView
}

type nodeUserOptionView struct {
	UserID string
	Label  string
}

type proxyTreeHopView struct {
	ProxyID         string
	ID              string
	Name            string
	AgentID         string
	URL             string
	IsEntrance      bool
	IngressProtocol string
	IngressLabel    string
	Routes          []proxyTreeRouteView
	Fallback        proxyTreeRouteView
	ShowFallback    bool
	Children        []proxyTreeLinkView
	Branches        []proxyTreeBranchView
	AllRuleIDs      string
	TerminalCount   int
	RuntimeBranches int
	BranchCount     int
	Final           string
	AgentOptions    []agentOptionView
	NewRule         proxyRuleView
	NewLinkEndpoint endpointView
	CSRFToken       string
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
	ID          string
	ParentHopID string
	EditURL     string
	Protocol    string
	ListenPort  int
	Listener    string
	Family      string
	Order       int
	Endpoint    endpointView
	Rules       []proxyRuleView
	NewRule     proxyRuleView
	Used        bool
	Fallback    bool
	CanMoveUp   bool
	CanMoveDown bool
	Child       *proxyTreeHopView
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
	Uncertain    bool
	Child        *proxyTreeHopView
}

type endUserListView struct {
	ID          string
	Name        string
	URL         string
	Memberships int
}

type endUserDetailView struct {
	ID              string
	Name            string
	ProxyNodeCount  int
	AssignedAccess  []userProxyAccessView
	AvailableAccess []userProxyOptionView
	DefaultPlan     membershipPlanView
}

type userProxyAccessView struct {
	ProxyID       string
	ProxyName     string
	ProxyURL      string
	DialogID      string
	Initial       string
	EntranceLabel string
	EntranceAgent string
	AuthUser      string
	URIs          []credentialURIView
	Plan          membershipPlanView
}

type userProxyOptionView struct {
	ProxyID string
	Label   string
}

type credentialURIView struct {
	Family string
	URI    string
}

type agentOptionView struct {
	ID       string
	Selected bool
	Online   bool
}

type endpointView struct {
	AgentID           string
	ListenerID        string
	Protocol          string
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
	ID     string                              `json:"id"`
	Status string                              `json:"status"`
	Label  string                              `json:"label"`
	Class  string                              `json:"class"`
	Error  string                              `json:"error,omitempty"`
	Active bool                                `json:"active"`
	Agents []proxynode.AgentDeploymentProgress `json:"agents,omitempty"`
}

func (h *Handler) proxyNodesPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	if h.proxyNodes == nil {
		http.Error(response, "Proxy Node manager is unavailable", http.StatusServiceUnavailable)
		return
	}
	state := h.proxyNodes.Snapshot()
	views := make([]proxyNodeListView, 0, len(state.ProxyNodes))
	for _, node := range state.ProxyNodes {
		root, _ := proxyHop(node, node.Entrance.HopID)
		views = append(views, proxyNodeListView{
			ID: node.ID, Name: node.Name, URL: proxyNodeURL(node.ID),
			Entrance: protocolLabel(node.Entrance.Endpoint.Protocol), EntranceAgent: root.AgentID,
			HopCount: len(node.Hops), MemberCount: len(node.Memberships),
			UpdatedAt: node.UpdatedAt.Local().Format("2006-01-02 15:04"),
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
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	terminal, err := parseProxyTarget(form.Get("terminal"))
	if err != nil || terminal.Type == proxynode.TargetLink {
		http.Error(response, "terminal exit must be Direct or Reject", http.StatusBadRequest)
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
	detail := h.proxyNodeDetail(node)
	h.attachProxyNodeUsers(detail, node, h.proxyNodes.Snapshot().Users)
	setProxyTreeCSRF(detail.Tree, session.CSRFToken)
	h.render(response, http.StatusOK, "proxy-node.html", pageData{
		Title: node.Name, ActiveNav: "proxy-nodes", CSRFToken: session.CSRFToken,
		ProxyNode: detail, ProxyDeployment: h.proxyDeploymentView(),
		ListenerOptions: h.proxyListenerOptions(),
	})
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

func (h *Handler) deleteProxyNode(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "confirm_delete")
	if !ok {
		return
	}
	if form.Get("confirm_delete") != "yes" {
		http.Error(response, "deletion was not confirmed", http.StatusBadRequest)
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
		http.Error(response, "Proxy Node deployment is unavailable", http.StatusServiceUnavailable)
		return false
	}
	if _, err := h.proxyDeployer.Start(); err != nil {
		status := http.StatusConflict
		if !errors.Is(err, proxynode.ErrDeploymentActive) {
			status = http.StatusBadRequest
		}
		http.Error(response, err.Error(), status)
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
		http.Error(response, err.Error(), status)
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
	_ = json.NewEncoder(response).Encode(h.proxyDeploymentView())
}

func (h *Handler) proxyEntrancePage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	node, ok := h.loadProxyNode(response, request)
	if !ok {
		return
	}
	root, _ := proxyHop(node, node.Entrance.HopID)
	h.render(response, http.StatusOK, "proxy-node-entrance.html", pageData{
		Title: node.Name + " entrance", ActiveNav: "proxy-nodes", CSRFToken: session.CSRFToken,
		ProxyNode: h.proxyNodeDetail(node), Endpoint: endpointViewForAgent(node.Entrance.Endpoint, root.AgentID),
		AgentOptions:    h.proxyAgentOptions(root.AgentID),
		ListenerOptions: h.proxyListenerOptions(),
		ProxyDeployment: h.proxyDeploymentView(),
	})
}

func (h *Handler) updateProxyEntrance(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, endpointFormFields...)
	if !ok {
		return
	}
	endpoint, err := parseEndpointForm(form)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	id := request.PathValue("proxy_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.UpdateEntrance(id, endpoint)
	}) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(id), http.StatusSeeOther)
}

func (h *Handler) proxyRuleSetsPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	node, ok := h.loadProxyNode(response, request)
	if !ok {
		return
	}
	h.render(response, http.StatusOK, "proxy-node-rule-sets.html", pageData{
		Title: node.Name + " Rule Sets", ActiveNav: "proxy-nodes", CSRFToken: session.CSRFToken,
		ProxyNode: h.proxyNodeDetail(node), ProxyDeployment: h.proxyDeploymentView(),
	})
}

func (h *Handler) upsertProxyRuleSet(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "tag", "url", "update_interval")
	if !ok {
		return
	}
	id := request.PathValue("proxy_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.UpsertRuleSet(id, proxynode.CustomRuleSet{Tag: form.Get("tag"), URL: form.Get("url"), Format: "binary", UpdateInterval: form.Get("update_interval")})
	}) {
		return
	}
	http.Redirect(response, request, proxyRuleSetsURL(id), http.StatusSeeOther)
}

func (h *Handler) deleteProxyRuleSet(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "tag")
	if !ok {
		return
	}
	id := request.PathValue("proxy_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.DeleteRuleSet(id, form.Get("tag"))
	}) {
		return
	}
	http.Redirect(response, request, proxyRuleSetsURL(id), http.StatusSeeOther)
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
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.UpdateHop(nodeID, hopID, hop.Name, form.Get("agent_id"))
	}) {
		return
	}
	http.Redirect(response, request, proxyInspectorURL(nodeID, "hop-"+hopID), http.StatusSeeOther)
}

func (h *Handler) addProxyLink(response http.ResponseWriter, request *http.Request) {
	fields := append([]string{"match", "values", "child_name", "child_agent", "child_terminal"}, endpointFormFields...)
	_, form, ok := h.authorizeProxyMutation(response, request, fields...)
	if !ok {
		return
	}
	endpoint, err := parseEndpointForm(form)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	terminal, err := parseProxyTarget(form.Get("child_terminal"))
	if err != nil || terminal.Type == proxynode.TargetLink {
		http.Error(response, "terminal exit must be Direct or Reject", http.StatusBadRequest)
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	if !h.applyProxyTopologyMutation(response, func() error {
		_, _, _, err = h.proxyNodes.AddBranch(nodeID, proxynode.AddBranchInput{
			AddLinkInput: proxynode.AddLinkInput{
				ParentHopID: hopID, ChildName: form.Get("child_name"), ChildAgent: form.Get("child_agent"), Endpoint: endpoint, Final: terminal,
			},
			Match: proxynode.MatchType(form.Get("match")), Values: splitProxyValues(form.Get("values")),
		})
		return err
	}) {
		return
	}
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) deleteProxyLink(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "link_id", "confirm_delete")
	if !ok {
		return
	}
	if form.Get("confirm_delete") != "yes" {
		http.Error(response, "branch deletion was not confirmed", http.StatusBadRequest)
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
	endpoint, err := parseEndpointForm(form)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	nodeID, linkID := request.PathValue("proxy_id"), request.PathValue("link_id")
	node, exists := h.proxyNodes.ProxyNode(nodeID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	_, exists = proxyLink(node, linkID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	if !h.applyProxyTopologyMutation(response, func() error {
		return h.proxyNodes.UpdateLink(nodeID, linkID, endpoint)
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
		http.Error(response, "invalid Rule direction", http.StatusBadRequest)
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
		_ = json.NewEncoder(response).Encode(h.proxyDeploymentView())
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
		http.Error(response, "invalid Link routing mode", http.StatusBadRequest)
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
		http.Error(response, "invalid Link direction", http.StatusBadRequest)
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
		http.Error(response, "terminal exit must be Direct or Reject", http.StatusBadRequest)
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
	if hopID == node.Entrance.HopID {
		http.Redirect(response, request, proxyNodeURL(nodeID)+"/entrance", http.StatusSeeOther)
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
		http.Error(response, "user manager is unavailable", http.StatusServiceUnavailable)
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
	for _, user := range state.Users {
		views = append(views, endUserListView{ID: user.ID, Name: user.Name, URL: "/users/" + url.PathEscape(user.ID), Memberships: counts[user.ID]})
	}
	sort.Slice(views, func(left, right int) bool {
		return strings.ToLower(views[left].Name) < strings.ToLower(views[right].Name)
	})
	h.render(response, http.StatusOK, "users.html", pageData{Title: "Users", ActiveNav: "users", CSRFToken: session.CSRFToken, EndUsers: views})
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
	if !exists {
		http.NotFound(response, request)
		return
	}
	state := h.proxyNodes.Snapshot()
	detail := &endUserDetailView{ID: user.ID, Name: user.Name, ProxyNodeCount: len(state.ProxyNodes), DefaultPlan: defaultMembershipPlanView()}
	for _, node := range state.ProxyNodes {
		activeNode, active := h.proxyNodes.AppliedProxyNode(node.ID)
		if !active {
			activeNode = node
		}
		root, _ := proxyHop(activeNode, activeNode.Entrance.HopID)
		access := userProxyAccessView{
			ProxyID: node.ID, ProxyName: node.Name, ProxyURL: proxyNodeURL(node.ID),
			DialogID: "user-proxy-access-" + node.ID, Initial: strings.ToUpper(node.Name[:1]),
			EntranceLabel: protocolLabel(activeNode.Entrance.Endpoint.Protocol), EntranceAgent: root.AgentID,
		}
		assigned := false
		for _, membership := range node.Memberships {
			if membership.UserID != user.ID {
				continue
			}
			assigned = true
			access.AuthUser = proxynode.AuthenticatedUserLabel(activeNode.Name, user.Name, membership.ID)
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
			ProxyID: node.ID,
			Label:   node.Name + " — " + access.EntranceLabel + " · " + access.EntranceAgent,
		})
	}
	sort.Slice(detail.AssignedAccess, func(left, right int) bool {
		return strings.ToLower(detail.AssignedAccess[left].ProxyName) < strings.ToLower(detail.AssignedAccess[right].ProxyName)
	})
	sort.Slice(detail.AvailableAccess, func(left, right int) bool {
		return strings.ToLower(detail.AvailableAccess[left].Label) < strings.ToLower(detail.AvailableAccess[right].Label)
	})
	h.render(response, http.StatusOK, "user.html", pageData{
		Title: user.Name, ActiveNav: "users", CSRFToken: session.CSRFToken, EndUser: detail,
	})
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
		http.Error(response, err.Error(), http.StatusBadRequest)
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
		http.Error(response, err.Error(), http.StatusBadRequest)
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
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	nodeID := request.PathValue("proxy_id")
	if _, err := h.proxyNodes.AddMembershipWithPlan(nodeID, form.Get("user_id"), plan); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
}

func (h *Handler) updateProxyNodeUser(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, membershipPlanFormFields...)
	if !ok {
		return
	}
	plan, err := parseMembershipPlan(form)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	nodeID := request.PathValue("proxy_id")
	if err := h.proxyNodes.UpdateMembershipPlan(nodeID, request.PathValue("user_id"), plan); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
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
	http.Redirect(response, request, proxyNodeURL(nodeID), http.StatusSeeOther)
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
		http.Error(response, "deletion was not confirmed", http.StatusBadRequest)
		return
	}
	if err := h.proxyNodes.DeleteUser(request.PathValue("user_id")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, "/users", http.StatusSeeOther)
}

func (h *Handler) triggerProxyUserSync() {
	if h.proxyUserSync != nil {
		h.proxyUserSync.TriggerDeployment()
	}
}

func (h *Handler) proxyNodeDetail(node proxynode.ProxyNode) *proxyNodeDetailView {
	detail := &proxyNodeDetailView{
		ID: node.ID, Name: node.Name, URL: proxyNodeURL(node.ID),
		EntranceURL: proxyNodeURL(node.ID) + "/entrance", RuleSetsURL: proxyRuleSetsURL(node.ID),
		Entrance: endpointViewFor(node.Entrance.Endpoint), HopCount: len(node.Hops), LinkCount: len(node.Links), MemberCount: len(node.Memberships),
		RuleSets:    append([]proxynode.CustomRuleSet(nil), node.RuleSets...),
		DefaultPlan: defaultMembershipPlanView(),
	}
	if entrance, ok := proxyHop(node, node.Entrance.HopID); ok {
		detail.Entrance = endpointViewForAgent(node.Entrance.Endpoint, entrance.AgentID)
		detail.EntranceHopURL = proxyHopURL(node.ID, entrance.ID)
		detail.EntranceFallback = targetLabel(node, entrance.Final)
	}
	detail.Tree, detail.TerminalCount, detail.UnusedLinkCount = buildProxyTree(node)
	h.attachProxyTreeControls(node, detail.Tree)
	return detail
}

func defaultMembershipPlanView() membershipPlanView {
	return membershipPlanView{QuotaMode: "unlimited", ExpirationMode: "none", SubscriptionMonths: "1"}
}

func (h *Handler) attachProxyNodeUsers(detail *proxyNodeDetailView, node proxynode.ProxyNode, users []proxynode.User) {
	assigned := make(map[string]proxynode.Membership, len(node.Memberships))
	for _, membership := range node.Memberships {
		assigned[membership.UserID] = membership
	}
	for _, user := range users {
		membership, exists := assigned[user.ID]
		if !exists {
			detail.AvailableUsers = append(detail.AvailableUsers, nodeUserOptionView{UserID: user.ID, Label: user.Name})
			continue
		}
		detail.UserAccess = append(detail.UserAccess, nodeUserAccessView{
			UserID: user.ID, Name: user.Name, URL: "/users/" + url.PathEscape(user.ID),
			Plan: membershipPlanViewFor(membership),
		})
	}
	sort.Slice(detail.UserAccess, func(left, right int) bool {
		return strings.ToLower(detail.UserAccess[left].Name) < strings.ToLower(detail.UserAccess[right].Name)
	})
	sort.Slice(detail.AvailableUsers, func(left, right int) bool {
		return strings.ToLower(detail.AvailableUsers[left].Label) < strings.ToLower(detail.AvailableUsers[right].Label)
	})
}

func membershipPlanViewFor(membership proxynode.Membership) membershipPlanView {
	view := membershipPlanView{
		QuotaMode: "unlimited", QuotaLabel: "Unlimited", UsageLabel: formatByteCount(membership.UsedBytes),
		ExpirationMode: "none", SubscriptionMonths: "1",
		ResetLabel:      membership.QuotaResetsAfter.Format("Jan 2, 2006") + " (UTC)",
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
		view.ExpirationMode = "months"
		view.SubscriptionMonths = strconv.Itoa(membership.SubscriptionMonths)
		view.ExpirationLabel = "After " + membership.SubscriptionEndsAfter.Format("Jan 2, 2006") + " (UTC)"
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
	case "months":
		months, err := strconv.Atoi(strings.TrimSpace(form.Get("subscription_months")))
		if err != nil || months < 1 || months > 1200 {
			return plan, errors.New("subscription must be between 1 and 1200 months")
		}
		plan.SubscriptionMonths = months
	default:
		return plan, errors.New("expiration mode is invalid")
	}
	return plan, nil
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
	tree.NewRule = proxyRuleView{Match: string(proxynode.MatchProtocol)}
	tree.NewLinkEndpoint = defaultEndpointView()
	for _, link := range tree.Children {
		h.attachProxyTreeControls(node, link.Child)
	}
}

func buildProxyTree(node proxynode.ProxyNode) (*proxyTreeHopView, int, int) {
	hops := make(map[string]proxynode.Hop, len(node.Hops))
	for _, hop := range node.Hops {
		hops[hop.ID] = hop
	}
	children := make(map[string][]proxynode.Link)
	for _, link := range node.Links {
		children[link.ParentHopID] = append(children[link.ParentHopID], link)
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
		fallback := proxyTreeRoute(node, hop, "Fallback", "When no Link matches", "", hop.Final)
		for _, link := range children[hopID] {
			if link.Fallback {
				fallback = proxyTreeRoute(node, hop, "Fallback", "When no conditional Link matches", "", proxynode.Target{Type: proxynode.TargetLink, LinkID: link.ID})
				break
			}
		}
		view := &proxyTreeHopView{
			ProxyID: node.ID, ID: hop.ID, Name: hop.Name, AgentID: hop.AgentID, URL: proxyHopURL(node.ID, hop.ID),
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
			link proxynode.Link
			rule proxynode.Rule
		}
		routes := make([]routedBranch, 0, totalRules)
		for _, link := range children[hopID] {
			for _, rule := range link.Rules {
				routes = append(routes, routedBranch{link: link, rule: rule})
			}
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
				child := visit(route.link.ChildHopID, &route.link, branchConstraint, false)
				uncertain := branchConstraint.runtimeDependent() && !constraint.runtimeDependent()
				view.Branches = append(view.Branches, proxyTreeBranchView{
					LinkID: route.link.ID, RuleID: route.rule.ID, RulePosition: route.rule.Order + 1,
					Protocol: protocolLabel(route.link.Endpoint.Protocol), RuleLabel: matchLabel(route.rule.Match),
					RuleValues: strings.Join(route.rule.Values, ", "), Used: true, Uncertain: uncertain, Child: child,
				})
				if uncertain {
					view.RuntimeBranches++
				}
				if child != nil {
					view.TerminalCount += child.TerminalCount
					view.RuntimeBranches += child.RuntimeBranches
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

func proxyTreeRoute(node proxynode.ProxyNode, hop proxynode.Hop, label, match, values string, target proxynode.Target) proxyTreeRouteView {
	view := proxyTreeRouteView{Label: label, Match: match, Values: values, TargetKind: string(target.Type)}
	switch target.Type {
	case proxynode.TargetDirect:
		view.TargetLabel = "Direct"
		view.TargetDetail = "Terminal on " + hop.AgentID
	case proxynode.TargetReject:
		view.TargetLabel = "Reject"
		view.TargetDetail = "Terminal on " + hop.AgentID
	case proxynode.TargetLink:
		view.TargetLabel = targetLabel(node, target)
		if link, ok := proxyLink(node, target.LinkID); ok {
			if child, exists := proxyHop(node, link.ChildHopID); exists {
				view.TargetDetail = "Relay to " + child.AgentID
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
		http.Error(response, "Proxy Node manager is unavailable", http.StatusServiceUnavailable)
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
		http.Error(response, "request form is invalid", http.StatusBadRequest)
		return Session{}, nil, false
	}
	if !h.authorizeCSRF(response, token, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
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
		http.Error(response, "Proxy Node manager is unavailable", http.StatusServiceUnavailable)
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
	options := make([]agentOptionView, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot.State != identity.AgentStateEnrolled {
			continue
		}
		options = append(options, agentOptionView{ID: snapshot.ID, Selected: snapshot.ID == selected, Online: h.sessions.IsOnline(snapshot.ID)})
	}
	sort.Slice(options, func(left, right int) bool { return options[left].ID < options[right].ID })
	return options
}

func (h *Handler) proxyDeploymentView() *proxyDeploymentView {
	if h.proxyDeployer == nil {
		return nil
	}
	job, exists := h.proxyDeployer.Current()
	if !exists {
		return nil
	}
	labels := map[proxynode.FleetDeploymentStatus]string{
		proxynode.FleetDeploymentQueued:    "Queued",
		proxynode.FleetDeploymentDeploying: "Deploying",
		proxynode.FleetDeploymentApplied:   "Applied",
		proxynode.FleetDeploymentFailed:    "Failed",
	}
	view := &proxyDeploymentView{ID: job.ID, Status: string(job.Status), Label: labels[job.Status], Class: "pending", Error: job.Error, Agents: job.Agents}
	view.Active = job.Status == proxynode.FleetDeploymentQueued || job.Status == proxynode.FleetDeploymentDeploying
	if job.Status == proxynode.FleetDeploymentApplied {
		view.Class = "online"
	} else if job.Status == proxynode.FleetDeploymentFailed {
		view.Class = "attention"
	}
	return view
}

var endpointFormFields = []string{"protocol", "listen", "listen_port", "family", "method", "mux_enabled", "mux_padding", "mux_brutal", "mux_brutal_up_mbps", "mux_brutal_down_mbps", "tls_mode", "server_name", "email", "certificate_path", "key_path", "up_mbps", "down_mbps", "obfs_type"}

func parseEndpointForm(form url.Values) (proxynode.Endpoint, error) {
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
	view := endpointView{Protocol: string(endpoint.Protocol), Listen: endpoint.Listen, ListenPort: endpoint.ListenPort, Family: endpoint.Family, Method: endpoint.Method, TLSMode: string(endpoint.TLS.Mode), ServerName: endpoint.TLS.ServerName, Email: endpoint.TLS.Email, CertificatePath: endpoint.TLS.CertificatePath, KeyPath: endpoint.TLS.KeyPath, UpMbps: endpoint.UpMbps, DownMbps: endpoint.DownMbps, ObfsType: endpoint.ObfsType}
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
	if target.Type == proxynode.TargetDirect {
		return "Direct"
	}
	if target.Type == proxynode.TargetReject {
		return "Reject"
	}
	if link, ok := proxyLink(node, target.LinkID); ok {
		if child, exists := proxyHop(node, link.ChildHopID); exists {
			return "Link to " + child.Name
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

func proxyNodeURL(id string) string     { return "/proxy-nodes/" + url.PathEscape(id) + "/manage" }
func proxyRuleSetsURL(id string) string { return "/proxy-nodes/" + url.PathEscape(id) + "/rule-sets" }
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
	http.Error(response, err.Error(), status)
}
