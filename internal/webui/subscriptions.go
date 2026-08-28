package webui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
	"github.com/masterauguste/theatropolis/internal/subscription"
)

const maxGeositeContentBytes = 8 << 20

var subscriptionGeositeNamePattern = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._@!-]{0,127}\z`)

type userSubscriptionView struct {
	UserID     string
	UserName   string
	Enabled    bool
	ClashURL   string
	SurgeURL   string
	SingBoxURL string
	Nodes      []subscriptionNodeView
}

type subscriptionPolicyView struct {
	DefaultAction string
	Rules         []subscriptionRuleView
}

type subscriptionNodeView struct {
	Name      string
	Protocol  string
	AgentID   string
	Status    string
	StatusCSS string
	Addresses []string
}

type subscriptionRuleView struct {
	ID          string
	Position    int
	Match       string
	MatchLabel  string
	Values      string
	Summary     string
	Action      string
	ActionLabel string
	CanMoveUp   bool
	CanMoveDown bool
}

func (h *Handler) userSubscriptionRoot(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.requireAuthentication(response, request); !ok {
		return
	}
	if _, exists := h.proxyNodes.User(request.PathValue("user_id")); !exists {
		http.NotFound(response, request)
		return
	}
	http.Redirect(response, request, userSubscriptionNodesURL(request.PathValue("user_id")), http.StatusSeeOther)
}

func (h *Handler) userSubscriptionNodesPage(response http.ResponseWriter, request *http.Request) {
	h.userSubscriptionPage(response, request)
}

func (h *Handler) userSubscriptionRulesPage(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.requireAuthentication(response, request); !ok {
		return
	}
	http.Redirect(response, request, "/subscriptions", http.StatusSeeOther)
}

func (h *Handler) userSubscriptionPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	view, _, exists := h.subscriptionViewAndProfile(request.PathValue("user_id"))
	if !exists {
		http.NotFound(response, request)
		return
	}
	h.render(response, http.StatusOK, "user-subscription-nodes.html", pageData{
		Title: view.UserName + " subscription", ActiveNav: "users", CSRFToken: session.CSRFToken,
		UserSubscription: view,
	})
}

func (h *Handler) subscriptionPolicyPage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	h.render(response, http.StatusOK, "subscription-policy.html", pageData{
		Title: "Subscriptions", ActiveNav: "subscriptions", CSRFToken: session.CSRFToken,
		SubscriptionPolicy: subscriptionPolicyViewFor(h.proxyNodes.SubscriptionPolicy()),
	})
}

func (h *Handler) rotateUserSubscriptionToken(response http.ResponseWriter, request *http.Request) {
	_, _, ok := h.authorizeProxyMutation(response, request)
	if !ok {
		return
	}
	userID := request.PathValue("user_id")
	if _, err := h.proxyNodes.RotateUserSubscription(userID); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, userSubscriptionNodesURL(userID), http.StatusSeeOther)
}

func (h *Handler) resetUserSubscription(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "confirm_reset")
	if !ok {
		return
	}
	if form.Get("confirm_reset") != "yes" {
		http.Error(response, "subscription reset was not confirmed", http.StatusBadRequest)
		return
	}
	userID := request.PathValue("user_id")
	if _, _, err := h.proxyNodes.ResetUserSubscriptionAndCredentials(userID); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	h.triggerProxyUserSync()
	http.Redirect(response, request, userSubscriptionNodesURL(userID), http.StatusSeeOther)
}

func (h *Handler) revokeUserSubscriptionToken(response http.ResponseWriter, request *http.Request) {
	_, _, ok := h.authorizeProxyMutation(response, request)
	if !ok {
		return
	}
	userID := request.PathValue("user_id")
	if err := h.proxyNodes.RevokeUserSubscription(userID); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, userSubscriptionNodesURL(userID), http.StatusSeeOther)
}

func (h *Handler) updateSubscriptionDefault(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "action")
	if !ok {
		return
	}
	if err := h.proxyNodes.SetSubscriptionDefault(proxynode.SubscriptionAction(form.Get("action"))); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, "/subscriptions", http.StatusSeeOther)
}

func (h *Handler) addSubscriptionRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "match", "values", "action")
	if !ok {
		return
	}
	if _, err := h.proxyNodes.AddSubscriptionRule(subscriptionRuleInput(form)); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, "/subscriptions", http.StatusSeeOther)
}

func (h *Handler) updateSubscriptionRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "match", "values", "action")
	if !ok {
		return
	}
	if err := h.proxyNodes.UpdateSubscriptionRule(request.PathValue("rule_id"), subscriptionRuleInput(form)); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, "/subscriptions", http.StatusSeeOther)
}

func (h *Handler) deleteSubscriptionRule(response http.ResponseWriter, request *http.Request) {
	_, _, ok := h.authorizeProxyMutation(response, request)
	if !ok {
		return
	}
	if err := h.proxyNodes.DeleteSubscriptionRule(request.PathValue("rule_id")); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, "/subscriptions", http.StatusSeeOther)
}

func (h *Handler) moveSubscriptionRule(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "direction")
	if !ok {
		return
	}
	direction := 0
	if form.Get("direction") == "up" {
		direction = -1
	}
	if form.Get("direction") == "down" {
		direction = 1
	}
	if err := h.proxyNodes.MoveSubscriptionRule(request.PathValue("rule_id"), direction); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, "/subscriptions", http.StatusSeeOther)
}

func (h *Handler) publicUserSubscription(response http.ResponseWriter, request *http.Request) {
	h.ensurePublicCaches()
	if h.proxyNodes == nil {
		http.NotFound(response, request)
		return
	}
	user, exists := h.proxyNodes.UserBySubscriptionToken(request.PathValue("token"))
	if !exists {
		http.NotFound(response, request)
		return
	}
	_, profile, exists := h.subscriptionViewAndProfile(user.ID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	format := subscription.Format(request.PathValue("format"))
	if format != subscription.FormatClash && format != subscription.FormatSurge && format != subscription.FormatSingBox {
		http.NotFound(response, request)
		return
	}
	content, contentType, err := h.subscriptionCache.render(format, profile, h.now())
	if err != nil {
		h.logger.Error("render user subscription", "user_id", user.ID, "format", format, "error", err)
		http.Error(response, "subscription could not be rendered", http.StatusInternalServerError)
		return
	}
	extension := map[subscription.Format]string{subscription.FormatClash: "yaml", subscription.FormatSurge: "conf", subscription.FormatSingBox: "json"}[format]
	if extension == "" {
		http.NotFound(response, request)
		return
	}
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	response.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	response.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.%s"`, user.Name, format, extension))
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(content); err != nil {
		h.logger.Warn("write user subscription", "user_id", user.ID, "format", format, "error", err)
	}
}

// publicSurgeRuleSet adapts MetaCubeX's public Geosite and GeoIP lists to
// Surge's remote rule formats. It exposes no private state and accepts only a
// tightly validated category name on a fixed upstream origin.
func (h *Handler) publicSurgeRuleSet(response http.ResponseWriter, request *http.Request) {
	h.ensurePublicCaches()
	if !h.ruleSetGlobalLimiter.allow("global", h.now()) ||
		!h.ruleSetLimiter.allow(publicClientIdentity(request), h.now()) {
		response.Header().Set("Retry-After", "60")
		http.Error(response, "Too many rule-set requests", http.StatusTooManyRequests)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(request.PathValue("kind")))
	if kind != "geosite" && kind != "geoip" {
		http.NotFound(response, request)
		return
	}
	name := strings.ToLower(strings.TrimSpace(request.PathValue("name")))
	if !subscriptionGeositeNamePattern.MatchString(name) {
		http.NotFound(response, request)
		return
	}
	converted, status, err := h.ruleSetCache.get(request.Context(), kind+"/"+name, h.now(), func(ctx context.Context) ([]byte, int, error) {
		return h.fetchSurgeRuleSet(ctx, kind, name)
	})
	if err != nil {
		http.Error(response, "Rule set is unavailable", http.StatusBadGateway)
		return
	}
	if status == http.StatusNotFound {
		http.NotFound(response, request)
		return
	}
	if status != http.StatusOK || len(converted) == 0 {
		http.Error(response, "Rule set is unavailable", http.StatusBadGateway)
		return
	}
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	response.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(converted); err != nil {
		h.logger.Warn("write Surge rule set", "kind", kind, "name", name, "error", err)
	}
}

func publicClientIdentity(request *http.Request) string {
	if candidate := strings.TrimSpace(request.Header.Get("CF-Connecting-IP")); candidate != "" {
		if address, err := netip.ParseAddr(candidate); err == nil {
			return address.String()
		}
	}
	if values := request.Header.Values("X-Forwarded-For"); len(values) > 0 {
		for _, candidate := range strings.Split(values[0], ",") {
			if address, err := netip.ParseAddr(strings.TrimSpace(candidate)); err == nil {
				return address.String()
			}
		}
	}
	return loginClientIdentity(request)
}

func (h *Handler) fetchSurgeRuleSet(ctx context.Context, kind, name string) ([]byte, int, error) {
	upstream := &url.URL{
		Scheme: "https", Host: "raw.githubusercontent.com",
		Path: "/MetaCubeX/meta-rules-dat/meta/geo/" + kind + "/" + name + ".list",
	}
	upstreamRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.String(), nil)
	if err != nil {
		return nil, 0, errRuleSetUnavailable
	}
	upstreamResponse, err := h.geositeContent.Do(upstreamRequest)
	if err != nil {
		return nil, 0, errRuleSetUnavailable
	}
	defer upstreamResponse.Body.Close()
	if upstreamResponse.StatusCode == http.StatusNotFound {
		return nil, http.StatusNotFound, nil
	}
	if upstreamResponse.StatusCode != http.StatusOK {
		return nil, upstreamResponse.StatusCode, errRuleSetUnavailable
	}
	content, err := io.ReadAll(io.LimitReader(upstreamResponse.Body, maxGeositeContentBytes+1))
	if err != nil || len(content) > maxGeositeContentBytes {
		return nil, 0, errRuleSetUnavailable
	}
	converted := surgeDomainSet(content)
	if kind == "geoip" {
		converted = surgeIPRuleSet(content)
	}
	if len(converted) == 0 {
		return nil, 0, errRuleSetUnavailable
	}
	return converted, http.StatusOK, nil
}

func surgeIPRuleSet(content []byte) []byte {
	var converted bytes.Buffer
	for _, raw := range bytes.Split(content, []byte{'\n'}) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			address, addressErr := netip.ParseAddr(line)
			if addressErr != nil {
				continue
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		kind := "IP-CIDR"
		if prefix.Addr().Is6() {
			kind = "IP-CIDR6"
		}
		converted.WriteString(kind)
		converted.WriteByte(',')
		converted.WriteString(prefix.Masked().String())
		converted.WriteString(",no-resolve\n")
	}
	return converted.Bytes()
}

func surgeDomainSet(content []byte) []byte {
	var converted bytes.Buffer
	for _, raw := range bytes.Split(content, []byte{'\n'}) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "+.") {
			line = "." + strings.TrimPrefix(line, "+.")
		}
		if !validSurgeDomainSetLine(line) {
			continue
		}
		converted.WriteString(line)
		converted.WriteByte('\n')
	}
	return converted.Bytes()
}

func validSurgeDomainSetLine(line string) bool {
	if len(line) == 0 || len(line) > 254 || strings.ContainsAny(line, "\x00\r\n\t /:@") {
		return false
	}
	if strings.HasPrefix(line, ".") {
		line = strings.TrimPrefix(line, ".")
	}
	if line == "" || strings.HasPrefix(line, ".") || strings.HasSuffix(line, ".") {
		return false
	}
	for _, character := range line {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func (h *Handler) subscriptionViewAndProfile(userID string) (*userSubscriptionView, subscription.Profile, bool) {
	projection, exists := h.proxyNodes.SubscriptionProjection(userID)
	if !exists {
		return nil, subscription.Profile{}, false
	}
	user := projection.User
	view := &userSubscriptionView{
		UserID: user.ID, UserName: user.Name, Enabled: user.Subscription.Token != "",
	}
	if view.Enabled {
		base := h.publicURL + "/subscriptions/" + url.PathEscape(user.Subscription.Token) + "/"
		view.ClashURL, view.SurgeURL, view.SingBoxURL = base+"clash", base+"surge", base+"sing-box"
	}
	policy := projection.Policy
	profile := subscription.Profile{Name: user.Name, Default: policy.DefaultAction,
		Rules: append([]proxynode.SubscriptionRule(nil), policy.Rules...), RuleSetBaseURL: h.publicURL + "/subscription-rule-sets"}
	for _, node := range projection.ProxyNodes {
		membership, assigned := membershipForSubscriptionUser(node, user.ID)
		if !assigned {
			continue
		}
		activeNode, applied := projection.AppliedProxyNodes[node.ID]
		root, hasRoot := proxyHop(activeNode, activeNode.Entrance.HopID)
		nodeView := subscriptionNodeView{Name: node.Name, Status: "Unavailable", StatusCSS: "disabled"}
		if hasRoot {
			nodeView.AgentID = root.AgentID
			nodeView.Protocol = protocolLabel(activeNode.Entrance.Endpoint.Protocol)
		}
		switch membership.DisabledReason {
		case proxynode.MembershipQuotaReached:
			nodeView.Status, nodeView.StatusCSS = "Quota reached", "warning"
		case proxynode.MembershipExpired:
			nodeView.Status, nodeView.StatusCSS = "Expired", "disabled"
		case proxynode.MembershipEnabled:
			if applied && hasRoot {
				nodeView.Status, nodeView.StatusCSS = "Included", "active"
			}
		}
		if applied && hasRoot && membershipVisibleInSubscription(membership.DisabledReason) && h.controller.PoolRegistry() != nil {
			addresses := subscriptionAddresses(h.controller.PoolRegistry(), root.AgentID, node.SubscriptionAddressMode)
			for _, address := range addresses {
				name := node.Name
				if len(addresses) > 1 {
					name += " - " + address.family
				}
				candidate := subscription.Node{
					Name: name, Protocol: activeNode.Entrance.Endpoint.Protocol, Server: address.address,
					Port: activeNode.Entrance.Endpoint.ListenPort, Password: membership.Credential.Secret,
					Method: activeNode.Entrance.Endpoint.Method, ServerKey: activeNode.Entrance.Endpoint.ServerKey,
					ServerName: activeNode.Entrance.Endpoint.TLS.ServerName,
					Insecure:   activeNode.Entrance.Endpoint.TLS.Mode != proxynode.TLSModeACME,
					UpMbps:     activeNode.Entrance.Endpoint.UpMbps, DownMbps: activeNode.Entrance.Endpoint.DownMbps,
					ObfsType: activeNode.Entrance.Endpoint.ObfsType, ObfsSecret: activeNode.Entrance.Endpoint.ObfsSecret,
				}
				if subscription.ValidateNode(candidate) == nil {
					profile.Nodes = append(profile.Nodes, candidate)
					nodeView.Addresses = append(nodeView.Addresses, address.family)
				}
			}
			if len(nodeView.Addresses) == 0 {
				nodeView.Status, nodeView.StatusCSS = "Unavailable", "disabled"
			}
		}
		view.Nodes = append(view.Nodes, nodeView)
	}
	sort.Slice(view.Nodes, func(left, right int) bool {
		return strings.ToLower(view.Nodes[left].Name) < strings.ToLower(view.Nodes[right].Name)
	})
	return view, profile, true
}

func membershipVisibleInSubscription(status proxynode.MembershipStatus) bool {
	return status == proxynode.MembershipEnabled || status == proxynode.MembershipQuotaReached
}

func subscriptionPolicyViewFor(policy proxynode.SubscriptionPolicy) *subscriptionPolicyView {
	view := &subscriptionPolicyView{DefaultAction: string(policy.DefaultAction)}
	rules := append([]proxynode.SubscriptionRule(nil), policy.Rules...)
	sort.SliceStable(rules, func(left, right int) bool { return rules[left].Order < rules[right].Order })
	for index, rule := range rules {
		summary := strings.Join(rule.Values, ", ")
		view.Rules = append(view.Rules, subscriptionRuleView{
			ID: rule.ID, Position: index + 1, Match: string(rule.Match), MatchLabel: subscriptionMatchLabel(rule.Match),
			Values: strings.Join(rule.Values, "\n"), Summary: summary,
			Action: string(rule.Action), ActionLabel: subscriptionActionLabel(rule.Action),
			CanMoveUp: index > 0, CanMoveDown: index+1 < len(rules),
		})
	}
	return view
}

type subscriptionAddress struct {
	family  string
	address string
}

func subscriptionAddresses(registry *pool.Registry, agentID string, mode proxynode.SubscriptionAddressMode) []subscriptionAddress {
	result := make([]subscriptionAddress, 0, 2)
	effectiveMode := proxynode.EffectiveSubscriptionAddressMode(mode)
	for _, candidate := range []struct {
		family string
		kind   pool.Family
	}{{"IPv4", pool.FamilyIPv4}, {"IPv6", pool.FamilyIPv6}} {
		if effectiveMode == proxynode.SubscriptionAddressIPv4 && candidate.kind != pool.FamilyIPv4 {
			continue
		}
		if effectiveMode == proxynode.SubscriptionAddressIPv6 && candidate.kind != pool.FamilyIPv6 {
			continue
		}
		if address, exists := registry.AgentAddressForFamily(agentID, candidate.kind); exists {
			result = append(result, subscriptionAddress{family: candidate.family, address: address})
		}
	}
	return result
}

func membershipForSubscriptionUser(node proxynode.ProxyNode, userID string) (proxynode.Membership, bool) {
	for _, membership := range node.Memberships {
		if membership.UserID == userID {
			return membership, true
		}
	}
	return proxynode.Membership{}, false
}

func subscriptionRuleInput(form url.Values) proxynode.SubscriptionRuleInput {
	values := strings.FieldsFunc(strings.ReplaceAll(form.Get("values"), "\r\n", "\n"), func(character rune) bool { return character == '\n' })
	return proxynode.SubscriptionRuleInput{
		Match: proxynode.SubscriptionMatch(form.Get("match")), Values: values,
		Action: proxynode.SubscriptionAction(form.Get("action")),
	}
}

func subscriptionMatchLabel(match proxynode.SubscriptionMatch) string {
	return map[proxynode.SubscriptionMatch]string{
		proxynode.SubscriptionMatchDomain: "Domain", proxynode.SubscriptionMatchDomainSuffix: "Domain suffix",
		proxynode.SubscriptionMatchDomainKeyword: "Domain keyword", proxynode.SubscriptionMatchDomainRegex: "Domain regex",
		proxynode.SubscriptionMatchIPCIDR: "IP/CIDR", proxynode.SubscriptionMatchSourceIPCIDR: "Source IP/CIDR",
		proxynode.SubscriptionMatchGeosite: "Geosite", proxynode.SubscriptionMatchGeoIP: "GeoIP", proxynode.SubscriptionMatchDestinationPort: "Destination port",
		proxynode.SubscriptionMatchSourcePort: "Source port", proxynode.SubscriptionMatchNetwork: "Network",
		proxynode.SubscriptionMatchProcessName: "Process name",
	}[match]
}

func subscriptionActionLabel(action proxynode.SubscriptionAction) string {
	return map[proxynode.SubscriptionAction]string{
		proxynode.SubscriptionProxy: "Proxy", proxynode.SubscriptionDirect: "Direct", proxynode.SubscriptionReject: "Reject",
	}[action]
}

func userSubscriptionNodesURL(userID string) string {
	return "/users/" + url.PathEscape(userID) + "/subscription/nodes"
}
