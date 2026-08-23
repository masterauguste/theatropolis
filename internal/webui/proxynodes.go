package webui

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
)

const maxProxyFormBytes = 128 << 10

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
	MembersURL       string
	RuleSetsURL      string
	Entrance         endpointView
	Tree             *proxyTreeHopView
	Members          []proxyMemberView
	RuleSets         []proxynode.CustomRuleSet
	HopCount         int
	LinkCount        int
	MemberCount      int
	TerminalCount    int
	UnusedLinkCount  int
}

type proxyTreeHopView struct {
	ID              string
	Name            string
	AgentID         string
	URL             string
	IsEntrance      bool
	IngressProtocol string
	IngressLabel    string
	Routes          []proxyTreeRouteView
	Fallback        proxyTreeRouteView
	Children        []proxyTreeLinkView
	TerminalCount   int
	BranchCount     int
}

type proxyTreeRouteView struct {
	Label        string
	Match        string
	Values       string
	TargetLabel  string
	TargetDetail string
	TargetKind   string
	TargetURL    string
}

type proxyTreeLinkView struct {
	ID         string
	EditURL    string
	Protocol   string
	ListenPort int
	Usage      string
	Used       bool
	Child      *proxyTreeHopView
}

type proxyMemberView struct {
	UserID   string
	UserName string
	UserURL  string
}

type endUserListView struct {
	ID          string
	Name        string
	URL         string
	Memberships int
	Assigned    bool
}

type endUserDetailView struct {
	ID          string
	Name        string
	Memberships []userMembershipView
}

type userMembershipView struct {
	ProxyID   string
	ProxyName string
	ProxyURL  string
	AuthUser  string
	URIs      []credentialURIView
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
	Protocol        string
	Listen          string
	ListenPort      int
	Family          string
	Method          string
	TLSMode         string
	ServerName      string
	Email           string
	CertificatePath string
	KeyPath         string
	UpMbps          int
	DownMbps        int
	ObfsType        string
}

type hopDetailView struct {
	ProxyID    string
	ProxyName  string
	ID         string
	Name       string
	AgentID    string
	IsEntrance bool
	Rules      []proxyRuleView
	Links      []proxyLinkView
	Targets    []targetOptionView
	Final      string
	FinalLabel string
}

type proxyRuleView struct {
	ID          string
	Position    int
	Match       string
	MatchLabel  string
	Values      string
	Target      string
	TargetLabel string
	CanMoveUp   bool
	CanMoveDown bool
}

type proxyLinkView struct {
	ID         string
	ChildHopID string
	ChildName  string
	ChildAgent string
	ChildURL   string
	EditURL    string
	Protocol   string
	ListenPort int
}

type targetOptionView struct {
	Value    string
	Label    string
	Selected bool
}

type linkDetailView struct {
	ProxyID   string
	ProxyName string
	ID        string
	ParentID  string
	ChildID   string
	ChildName string
	Endpoint  endpointView
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
	node, err := h.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: form.Get("name"), RootAgent: form.Get("agent_id"), Entrance: endpoint, Final: terminal,
	})
	if err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyHopURL(node.ID, node.Entrance.HopID), http.StatusSeeOther)
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
	h.render(response, http.StatusOK, "proxy-node.html", pageData{
		Title: node.Name, ActiveNav: "proxy-nodes", CSRFToken: session.CSRFToken,
		ProxyNode: h.proxyNodeDetail(node), ProxyDeployment: h.proxyDeploymentView(),
	})
}

func (h *Handler) renameProxyNode(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "name")
	if !ok {
		return
	}
	id := request.PathValue("proxy_id")
	if err := h.proxyNodes.RenameProxyNode(id, form.Get("name")); err != nil {
		handleProxyMutationError(response, err)
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
	if err := h.proxyNodes.DeleteProxyNode(request.PathValue("proxy_id")); err != nil {
		handleProxyMutationError(response, err)
		return
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
	if h.proxyDeployer == nil {
		http.Error(response, "Proxy Node deployment is unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := h.proxyDeployer.Start(); err != nil {
		status := http.StatusConflict
		if !errors.Is(err, proxynode.ErrDeploymentActive) {
			status = http.StatusBadRequest
		}
		http.Error(response, err.Error(), status)
		return
	}
	redirect := "/proxy-nodes"
	if id := request.PathValue("proxy_id"); id != "" {
		redirect = proxyNodeURL(id)
	}
	http.Redirect(response, request, redirect, http.StatusSeeOther)
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
		ProxyNode: h.proxyNodeDetail(node), Endpoint: endpointViewFor(node.Entrance.Endpoint),
		AgentOptions: h.proxyAgentOptions(root.AgentID),
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
	if err := h.proxyNodes.UpdateEntrance(id, endpoint); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyNodeURL(id), http.StatusSeeOther)
}

func (h *Handler) proxyMembersPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	node, ok := h.loadProxyNode(response, request)
	if !ok {
		return
	}
	state := h.proxyNodes.Snapshot()
	assigned := make(map[string]bool, len(node.Memberships))
	for _, membership := range node.Memberships {
		assigned[membership.UserID] = true
	}
	users := make([]endUserListView, 0, len(state.Users))
	for _, user := range state.Users {
		users = append(users, endUserListView{ID: user.ID, Name: user.Name, URL: "/users/" + url.PathEscape(user.ID), Assigned: assigned[user.ID]})
	}
	sort.Slice(users, func(left, right int) bool {
		return strings.ToLower(users[left].Name) < strings.ToLower(users[right].Name)
	})
	h.render(response, http.StatusOK, "proxy-node-members.html", pageData{
		Title: node.Name + " users", ActiveNav: "proxy-nodes", CSRFToken: session.CSRFToken,
		ProxyNode: h.proxyNodeDetail(node), EndUsers: users,
	})
}

func (h *Handler) addProxyMembership(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "user_id")
	if !ok {
		return
	}
	id := request.PathValue("proxy_id")
	if _, err := h.proxyNodes.AddMembership(id, form.Get("user_id")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyMembersURL(id), http.StatusSeeOther)
}

func (h *Handler) removeProxyMembership(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "user_id")
	if !ok {
		return
	}
	id := request.PathValue("proxy_id")
	if err := h.proxyNodes.RemoveMembership(id, form.Get("user_id")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyMembersURL(id), http.StatusSeeOther)
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
		ProxyNode: h.proxyNodeDetail(node),
	})
}

func (h *Handler) upsertProxyRuleSet(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "tag", "url", "update_interval")
	if !ok {
		return
	}
	id := request.PathValue("proxy_id")
	if err := h.proxyNodes.UpsertRuleSet(id, proxynode.CustomRuleSet{Tag: form.Get("tag"), URL: form.Get("url"), Format: "binary", UpdateInterval: form.Get("update_interval")}); err != nil {
		handleProxyMutationError(response, err)
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
	if err := h.proxyNodes.DeleteRuleSet(id, form.Get("tag")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyRuleSetsURL(id), http.StatusSeeOther)
}

func (h *Handler) proxyHopPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
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
	h.render(response, http.StatusOK, "proxy-node-hop.html", pageData{
		Title: hop.Name, ActiveNav: "proxy-nodes", CSRFToken: session.CSRFToken,
		ProxyNode: h.proxyNodeDetail(node), Hop: h.hopDetail(node, hop),
		AgentOptions: h.proxyAgentOptions(hop.AgentID), Endpoint: defaultEndpointView(),
	})
}

func (h *Handler) updateProxyHop(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "name", "agent_id")
	if !ok {
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	if err := h.proxyNodes.UpdateHop(nodeID, hopID, form.Get("name"), form.Get("agent_id")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyHopURL(nodeID, hopID), http.StatusSeeOther)
}

func (h *Handler) addProxyLink(response http.ResponseWriter, request *http.Request) {
	fields := append([]string{"child_name", "child_agent", "child_terminal"}, endpointFormFields...)
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
	if _, _, err := h.proxyNodes.AddLink(nodeID, proxynode.AddLinkInput{ParentHopID: hopID, ChildName: form.Get("child_name"), ChildAgent: form.Get("child_agent"), Endpoint: endpoint, Final: terminal}); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyHopURL(nodeID, hopID), http.StatusSeeOther)
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
	if err := h.proxyNodes.DeleteLink(nodeID, form.Get("link_id")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyHopURL(nodeID, hopID), http.StatusSeeOther)
}

func (h *Handler) proxyLinkPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
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
	child, _ := proxyHop(node, link.ChildHopID)
	h.render(response, http.StatusOK, "proxy-node-link.html", pageData{
		Title: node.Name + " Link", ActiveNav: "proxy-nodes", CSRFToken: session.CSRFToken,
		ProxyNode: h.proxyNodeDetail(node), Endpoint: endpointViewFor(link.Endpoint),
		Link: &linkDetailView{ProxyID: node.ID, ProxyName: node.Name, ID: link.ID, ParentID: link.ParentHopID, ChildID: child.ID, ChildName: child.Name, Endpoint: endpointViewFor(link.Endpoint)},
	})
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
	link, exists := proxyLink(node, linkID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	if err := h.proxyNodes.UpdateLink(nodeID, linkID, endpoint); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyHopURL(nodeID, link.ParentHopID), http.StatusSeeOther)
}

func (h *Handler) addProxyRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "match", "values", "target")
	if !ok {
		return
	}
	target, err := parseProxyTarget(form.Get("target"))
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	if _, err := h.proxyNodes.AddRule(nodeID, proxynode.AddRuleInput{HopID: hopID, Match: proxynode.MatchType(form.Get("match")), Values: splitProxyValues(form.Get("values")), Target: target}); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyHopURL(nodeID, hopID), http.StatusSeeOther)
}

func (h *Handler) deleteProxyRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "rule_id")
	if !ok {
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	if err := h.proxyNodes.DeleteRule(nodeID, hopID, form.Get("rule_id")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyHopURL(nodeID, hopID), http.StatusSeeOther)
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
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	if err := h.proxyNodes.MoveRule(nodeID, hopID, form.Get("rule_id"), delta); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyHopURL(nodeID, hopID), http.StatusSeeOther)
}

func (h *Handler) updateProxyFinal(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "target")
	if !ok {
		return
	}
	target, err := parseProxyTarget(form.Get("target"))
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	nodeID, hopID := request.PathValue("proxy_id"), request.PathValue("hop_id")
	if err := h.proxyNodes.SetFinal(nodeID, hopID, target); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, proxyHopURL(nodeID, hopID), http.StatusSeeOther)
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
	detail := &endUserDetailView{ID: user.ID, Name: user.Name}
	for _, node := range state.ProxyNodes {
		for _, membership := range node.Memberships {
			if membership.UserID != user.ID {
				continue
			}
			detail.Memberships = append(detail.Memberships, userMembershipView{
				ProxyID: node.ID, ProxyName: node.Name, ProxyURL: proxyNodeURL(node.ID),
				AuthUser: node.Name + "-" + user.Name,
				URIs:     h.membershipURIs(node, user, membership),
			})
		}
	}
	sort.Slice(detail.Memberships, func(left, right int) bool {
		return strings.ToLower(detail.Memberships[left].ProxyName) < strings.ToLower(detail.Memberships[right].ProxyName)
	})
	h.render(response, http.StatusOK, "user.html", pageData{Title: user.Name, ActiveNav: "users", CSRFToken: session.CSRFToken, EndUser: detail})
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
	http.Redirect(response, request, "/users", http.StatusSeeOther)
}

func (h *Handler) proxyNodeDetail(node proxynode.ProxyNode) *proxyNodeDetailView {
	detail := &proxyNodeDetailView{
		ID: node.ID, Name: node.Name, URL: proxyNodeURL(node.ID),
		EntranceURL: proxyNodeURL(node.ID) + "/entrance", MembersURL: proxyMembersURL(node.ID), RuleSetsURL: proxyRuleSetsURL(node.ID),
		Entrance: endpointViewFor(node.Entrance.Endpoint), HopCount: len(node.Hops), LinkCount: len(node.Links), MemberCount: len(node.Memberships),
		RuleSets: append([]proxynode.CustomRuleSet(nil), node.RuleSets...),
	}
	if entrance, ok := proxyHop(node, node.Entrance.HopID); ok {
		detail.EntranceHopURL = proxyHopURL(node.ID, entrance.ID)
		detail.EntranceFallback = targetLabel(node, entrance.Final)
	}
	state := h.proxyNodes.Snapshot()
	userNames := make(map[string]string, len(state.Users))
	for _, user := range state.Users {
		userNames[user.ID] = user.Name
	}
	for _, membership := range node.Memberships {
		detail.Members = append(detail.Members, proxyMemberView{UserID: membership.UserID, UserName: userNames[membership.UserID], UserURL: "/users/" + url.PathEscape(membership.UserID)})
	}
	sort.Slice(detail.Members, func(left, right int) bool {
		return strings.ToLower(detail.Members[left].UserName) < strings.ToLower(detail.Members[right].UserName)
	})
	detail.Tree, detail.TerminalCount, detail.UnusedLinkCount = buildProxyTree(node)
	return detail
}

func (h *Handler) hopDetail(node proxynode.ProxyNode, hop proxynode.Hop) *hopDetailView {
	detail := &hopDetailView{ProxyID: node.ID, ProxyName: node.Name, ID: hop.ID, Name: hop.Name, AgentID: hop.AgentID, IsEntrance: hop.ID == node.Entrance.HopID}
	for _, link := range node.Links {
		if link.ParentHopID != hop.ID {
			continue
		}
		child, _ := proxyHop(node, link.ChildHopID)
		detail.Links = append(detail.Links, proxyLinkView{ID: link.ID, ChildHopID: child.ID, ChildName: child.Name, ChildAgent: child.AgentID, ChildURL: proxyHopURL(node.ID, child.ID), EditURL: proxyLinkURL(node.ID, link.ID), Protocol: protocolLabel(link.Endpoint.Protocol), ListenPort: link.Endpoint.ListenPort})
	}
	detail.Targets = targetOptions(node, hop, "")
	detail.Final = targetValue(hop.Final)
	detail.FinalLabel = targetLabel(node, hop.Final)
	for index, rule := range hop.Rules {
		detail.Rules = append(detail.Rules, proxyRuleView{ID: rule.ID, Position: index + 1, Match: string(rule.Match), MatchLabel: matchLabel(rule.Match), Values: strings.Join(rule.Values, ", "), Target: targetValue(rule.Target), TargetLabel: targetLabel(node, rule.Target), CanMoveUp: index > 0, CanMoveDown: index+1 < len(hop.Rules)})
	}
	return detail
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
			leftHop, _ := proxyHop(node, children[parent][left].ChildHopID)
			rightHop, _ := proxyHop(node, children[parent][right].ChildHopID)
			return strings.ToLower(leftHop.Name) < strings.ToLower(rightHop.Name)
		})
	}
	uses := make(map[string][]string, len(node.Links))
	for _, hop := range node.Hops {
		for index, rule := range hop.Rules {
			if rule.Target.Type == proxynode.TargetLink {
				uses[rule.Target.LinkID] = append(uses[rule.Target.LinkID], "Rule "+strconv.Itoa(index+1))
			}
		}
		if hop.Final.Type == proxynode.TargetLink {
			uses[hop.Final.LinkID] = append(uses[hop.Final.LinkID], "Fallback")
		}
	}
	unusedLinks := 0
	var visit func(string, *proxynode.Link) *proxyTreeHopView
	visit = func(hopID string, incoming *proxynode.Link) *proxyTreeHopView {
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
		view := &proxyTreeHopView{
			ID: hop.ID, Name: hop.Name, AgentID: hop.AgentID, URL: proxyHopURL(node.ID, hop.ID),
			IsEntrance: hop.ID == node.Entrance.HopID, IngressProtocol: ingressProtocol, IngressLabel: ingressLabel,
			Fallback: proxyTreeRoute(node, hop, "Fallback", "When no ordered rule matches", "", hop.Final),
		}
		if hop.Final.Type != proxynode.TargetLink {
			view.TerminalCount++
		}
		for index, rule := range hop.Rules {
			values := strings.Join(rule.Values, ", ")
			view.Routes = append(view.Routes, proxyTreeRoute(node, hop, "Rule "+strconv.Itoa(index+1), matchLabel(rule.Match), values, rule.Target))
			if rule.Target.Type != proxynode.TargetLink {
				view.TerminalCount++
			}
		}
		for index := range children[hopID] {
			link := children[hopID][index]
			usage := uses[link.ID]
			used := len(usage) > 0
			usageLabel := "Not selected by any rule or fallback"
			if used {
				usageLabel = "Used by " + strings.Join(usage, ", ")
			} else {
				unusedLinks++
			}
			child := visit(link.ChildHopID, &link)
			view.Children = append(view.Children, proxyTreeLinkView{
				ID: link.ID, EditURL: proxyLinkURL(node.ID, link.ID), Protocol: protocolLabel(link.Endpoint.Protocol),
				ListenPort: link.Endpoint.ListenPort, Usage: usageLabel, Used: used, Child: child,
			})
			if child != nil {
				view.TerminalCount += child.TerminalCount
				view.BranchCount += child.BranchCount
			}
		}
		view.BranchCount += len(view.Children)
		return view
	}
	root := visit(node.Entrance.HopID, nil)
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
	session, err := h.access.Authenticate(token)
	if err != nil {
		h.redirectToLogin(response, request)
		return Session{}, nil, false
	}
	if !h.access.AuthorizeCSRF(token, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
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

var endpointFormFields = []string{"protocol", "listen", "listen_port", "family", "method", "tls_mode", "server_name", "email", "certificate_path", "key_path", "up_mbps", "down_mbps", "obfs_type"}

func parseEndpointForm(form url.Values) (proxynode.Endpoint, error) {
	port, err := strconv.Atoi(form.Get("listen_port"))
	if err != nil {
		return proxynode.Endpoint{}, errors.New("listen port must be a number")
	}
	up, err := optionalPositiveInt(form.Get("up_mbps"))
	if err != nil {
		return proxynode.Endpoint{}, errors.New("upload Mbps must be a positive number")
	}
	down, err := optionalPositiveInt(form.Get("down_mbps"))
	if err != nil {
		return proxynode.Endpoint{}, errors.New("download Mbps must be a positive number")
	}
	return proxynode.Endpoint{
		Protocol: proxynode.Protocol(form.Get("protocol")), Listen: form.Get("listen"), ListenPort: port,
		Family: form.Get("family"), Method: form.Get("method"), UpMbps: up, DownMbps: down, ObfsType: form.Get("obfs_type"),
		TLS: proxynode.TLSConfig{Mode: proxynode.TLSMode(form.Get("tls_mode")), ServerName: form.Get("server_name"), Email: form.Get("email"), CertificatePath: form.Get("certificate_path"), KeyPath: form.Get("key_path")},
	}, nil
}

func endpointViewFor(endpoint proxynode.Endpoint) endpointView {
	return endpointView{Protocol: string(endpoint.Protocol), Listen: endpoint.Listen, ListenPort: endpoint.ListenPort, Family: endpoint.Family, Method: endpoint.Method, TLSMode: string(endpoint.TLS.Mode), ServerName: endpoint.TLS.ServerName, Email: endpoint.TLS.Email, CertificatePath: endpoint.TLS.CertificatePath, KeyPath: endpoint.TLS.KeyPath, UpMbps: endpoint.UpMbps, DownMbps: endpoint.DownMbps, ObfsType: endpoint.ObfsType}
}

func defaultEndpointView() endpointView {
	return endpointView{Protocol: string(proxynode.ProtocolAnyTLS), Listen: "::", ListenPort: 443, Family: "auto", Method: "2022-blake3-aes-128-gcm", TLSMode: string(proxynode.TLSModeSelfSigned)}
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
	if linkID, ok := strings.CutPrefix(value, "link:"); ok && linkID != "" {
		return proxynode.Target{Type: proxynode.TargetLink, LinkID: linkID}, nil
	}
	return proxynode.Target{}, errors.New("routing target is invalid")
}

func targetValue(target proxynode.Target) string {
	if target.Type == proxynode.TargetLink {
		return "link:" + target.LinkID
	}
	return string(target.Type)
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

func targetOptions(node proxynode.ProxyNode, hop proxynode.Hop, selected string) []targetOptionView {
	options := []targetOptionView{{Value: "direct", Label: "Direct on this server"}, {Value: "reject", Label: "Reject traffic"}}
	for _, link := range node.Links {
		if link.ParentHopID != hop.ID {
			continue
		}
		child, _ := proxyHop(node, link.ChildHopID)
		options = append(options, targetOptionView{Value: "link:" + link.ID, Label: "Relay to " + child.Name + " (" + child.AgentID + ")"})
	}
	for index := range options {
		options[index].Selected = options[index].Value == selected
	}
	return options
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
func proxyMembersURL(id string) string  { return "/proxy-nodes/" + url.PathEscape(id) + "/members" }
func proxyRuleSetsURL(id string) string { return "/proxy-nodes/" + url.PathEscape(id) + "/rule-sets" }
func proxyHopURL(nodeID, hopID string) string {
	return "/proxy-nodes/" + url.PathEscape(nodeID) + "/hops/" + url.PathEscape(hopID)
}
func proxyLinkURL(nodeID, linkID string) string {
	return "/proxy-nodes/" + url.PathEscape(nodeID) + "/links/" + url.PathEscape(linkID)
}

func protocolLabel(protocol proxynode.Protocol) string {
	switch protocol {
	case proxynode.ProtocolAnyTLS:
		return "AnyTLS"
	case proxynode.ProtocolHysteria2:
		return "Hysteria2"
	case proxynode.ProtocolShadowsocks:
		return "Shadowsocks 2022"
	default:
		return string(protocol)
	}
}

func matchLabel(match proxynode.MatchType) string {
	labels := map[proxynode.MatchType]string{proxynode.MatchNone: "All traffic", proxynode.MatchProtocol: "Protocol", proxynode.MatchDomain: "Domain", proxynode.MatchDomainSuffix: "Domain suffix", proxynode.MatchDomainKeyword: "Domain keyword", proxynode.MatchDomainRegex: "Domain regex", proxynode.MatchIPCIDR: "IP / CIDR", proxynode.MatchGeosite: "Geosite", proxynode.MatchGeoIP: "GeoIP", proxynode.MatchRuleSet: "Custom Rule Set", proxynode.MatchNetwork: "Network"}
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
