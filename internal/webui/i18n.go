package webui

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

const (
	localeEnglish           = "en"
	localeSimplifiedChinese = "zh-CN"
	languageCookieName      = "theatropolis_language"
	languageCookieLifetime  = 365 * 24 * time.Hour
)

func parseLocalizedTemplates() (map[string]*template.Template, error) {
	paths, err := webFiles.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("read web UI templates: %w", err)
	}
	result := make(map[string]*template.Template, 2)
	for _, locale := range []string{localeEnglish, localeSimplifiedChinese} {
		activeLocale := locale
		set := template.New("webui").Funcs(template.FuncMap{
			"t": func(key string) string { return messageText(activeLocale, key) },
			"count": func(count int, kind string) string {
				return localizedCount(activeLocale, count, kind)
			},
		})
		for _, entry := range paths {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".html") {
				continue
			}
			path := "templates/" + entry.Name()
			content, readErr := webFiles.ReadFile(path)
			if readErr != nil {
				return nil, fmt.Errorf("read web UI template %q: %w", path, readErr)
			}
			source := string(content)
			if _, parseErr := set.New(entry.Name()).Parse(source); parseErr != nil {
				return nil, fmt.Errorf("parse %s web UI template %q: %w", locale, path, parseErr)
			}
		}
		result[locale] = set
	}
	return result, nil
}

func localizedCount(locale string, count int, kind string) string {
	if normalizeLocale(locale) == localeSimplifiedChinese {
		switch kind {
		case "hop", "node":
			return fmt.Sprintf("%d 个节点", count)
		case "relay-hop":
			return fmt.Sprintf("%d 个中继节点", count)
		case "link":
			return fmt.Sprintf("%d 条链路", count)
		case "user":
			return fmt.Sprintf("%d 位用户", count)
		case "exit":
			return fmt.Sprintf("%d 个出口", count)
		case "available-node":
			return fmt.Sprintf("%d 个可用节点", count)
		case "proxy-access":
			return fmt.Sprintf("已授权 %d 个代理节点", count)
		case "reference":
			return fmt.Sprintf("%d 个配置", count)
		default:
			return fmt.Sprintf("共 %d 项", count)
		}
	}
	noun := map[string]string{
		"hop": "Hop", "node": "Node", "relay-hop": "Relay Hop", "link": "Link", "user": "user", "exit": "exit",
		"available-node": "Node available",
		"proxy-access":   "Proxy Node access grant", "reference": "reference",
	}[kind]
	if noun == "" {
		return fmt.Sprintf("%d total", count)
	}
	if count != 1 {
		switch kind {
		case "available-node":
			noun = "Nodes available"
		default:
			noun += "s"
		}
	}
	return fmt.Sprintf("%d %s", count, noun)
}

func normalizeLocale(locale string) string {
	if strings.EqualFold(strings.TrimSpace(locale), localeSimplifiedChinese) ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(locale)), "zh") {
		return localeSimplifiedChinese
	}
	return localeEnglish
}

func localeForRequest(request *http.Request) (string, bool) {
	if cookie, err := request.Cookie(languageCookieName); err == nil {
		switch cookie.Value {
		case localeEnglish, localeSimplifiedChinese:
			return cookie.Value, true
		}
	}
	return localeFromAcceptLanguage(request.Header.Get("Accept-Language")), false
}

func localeFromAcceptLanguage(header string) string {
	bestLocale := localeEnglish
	bestQuality := -1.0
	for _, preference := range strings.Split(header, ",") {
		parts := strings.Split(preference, ";")
		tag := strings.ToLower(strings.TrimSpace(parts[0]))
		quality := 1.0
		valid := tag != ""
		for _, parameter := range parts[1:] {
			name, value, found := strings.Cut(strings.TrimSpace(parameter), "=")
			if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || parsed < 0 || parsed > 1 {
				valid = false
				break
			}
			quality = parsed
		}
		if !valid || quality == 0 {
			continue
		}
		locale := ""
		switch {
		case tag == "zh" || strings.HasPrefix(tag, "zh-"):
			locale = localeSimplifiedChinese
		case tag == "en" || strings.HasPrefix(tag, "en-"), tag == "*":
			locale = localeEnglish
		}
		if locale != "" && quality > bestQuality {
			bestLocale = locale
			bestQuality = quality
		}
	}
	return bestLocale
}

func (h *Handler) languagePreferenceCookie(locale string) *http.Cookie {
	return &http.Cookie{
		Name: languageCookieName, Value: normalizeLocale(locale), Path: "/",
		MaxAge: int(languageCookieLifetime.Seconds()), Expires: h.currentTime().Add(languageCookieLifetime),
		Secure: h.publicScheme == "https" && !isLocalDevelopmentHost(h.publicHost), SameSite: http.SameSiteLaxMode,
	}
}

func (h *Handler) changeLanguage(response http.ResponseWriter, request *http.Request) {
	requested := request.PathValue("locale")
	locale := normalizeLocale(requested)
	if requested != localeEnglish && requested != localeSimplifiedChinese {
		http.NotFound(response, request)
		return
	}
	http.SetCookie(response, h.languagePreferenceCookie(locale))
	target := "/servers"
	if _, ok := h.sessionToken(request); !ok {
		target = "/login"
	}
	switch request.URL.Query().Get("return_to") {
	case "/portal", "/portal/login", "/claim":
		target = request.URL.Query().Get("return_to")
	}
	if referer := request.Referer(); referer != "" {
		if parsed, err := url.Parse(referer); err == nil && parsed.Scheme == h.publicScheme && parsed.Hostname() == h.publicHost && effectiveURLPort(parsed) == h.publicPort && strings.HasPrefix(parsed.Path, "/") && !strings.HasPrefix(parsed.Path, "//") {
			target = parsed.RequestURI()
		}
	}
	http.Redirect(response, request, target, http.StatusSeeOther)
}

func isLocalDevelopmentHost(host string) bool {
	return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
}

func effectiveURLPort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	if parsed.Scheme == "https" {
		return "443"
	}
	if parsed.Scheme == "http" {
		return "80"
	}
	return ""
}

func localizedText(locale, text string) string {
	if _, exists := messages[text]; exists {
		return messageText(locale, text)
	}
	if normalizeLocale(locale) != localeSimplifiedChinese {
		return text
	}
	for suffix, translated := range map[string]string{
		" subscription": " · 订阅",
		" entrance":     " · 入口",
		" access":       " · 用户权限",
		" Rule Sets":    " · 规则集",
	} {
		if strings.HasSuffix(text, suffix) {
			return strings.TrimSuffix(text, suffix) + translated
		}
	}
	for prefix, translated := range map[string]string{
		"Expires ":                  "到期时间：",
		"Link to ":                  "链路至 ",
		"Terminal on ":              "终端位于 ",
		"Relay to ":                 "中继至 ",
		"Entrance listener · port ": "入口监听器 · 端口 ",
		"Incoming Link · port ":     "入站链路 · 端口 ",
	} {
		if strings.HasPrefix(text, prefix) {
			return translated + strings.TrimPrefix(text, prefix)
		}
	}
	return text
}

func localizePageData(locale string, data *pageData) {
	if normalizeLocale(locale) != localeSimplifiedChinese {
		return
	}
	data.Title = localizedText(locale, data.Title)
	data.Error = localizedText(locale, data.Error)
	data.Notice = localizedText(locale, data.Notice)
	data.MigrationNotice = localizedText(locale, data.MigrationNotice)
	data.ReleaseCatalogWarning = localizedText(locale, data.ReleaseCatalogWarning)
	data.SingBoxCatalogWarning = localizedText(locale, data.SingBoxCatalogWarning)
	for index := range data.Agents {
		data.Agents[index].EnrollmentLabel = localizedText(locale, data.Agents[index].EnrollmentLabel)
		data.Agents[index].ConnectionLabel = localizedText(locale, data.Agents[index].ConnectionLabel)
	}
	if data.Agent != nil {
		localizeAgentDetail(locale, data.Agent)
	}
	if data.MasterUpdate != nil {
		localizeAgentUpdate(locale, data.MasterUpdate)
	}
	if data.ProxyDeployment != nil {
		data.ProxyDeployment.Label = localizedText(locale, data.ProxyDeployment.Label)
		data.ProxyDeployment.Error = localizedText(locale, data.ProxyDeployment.Error)
		for index := range data.ProxyDeployment.Agents {
			data.ProxyDeployment.Agents[index].Status = localizedText(locale, data.ProxyDeployment.Agents[index].Status)
		}
	}
	for index := range data.ProxyNodes {
		data.ProxyNodes[index].Entrance = localizedText(locale, data.ProxyNodes[index].Entrance)
	}
	for index := range data.EndUsers {
		data.EndUsers[index].LoginStatus = localizedText(locale, data.EndUsers[index].LoginStatus)
	}
	for index := range data.ListenerOptions {
		option := &data.ListenerOptions[index]
		option.Label = fmt.Sprintf("%s · %s:%d · %s", option.ProtocolLabel, option.Listen, option.ListenPort, localizedCount(locale, option.ReferenceCount, "reference"))
	}
	if data.ProxyNode != nil {
		localizeProxyNodeDetail(locale, data.ProxyNode)
	}
	if data.EndUser != nil {
		localizeEndUserDetail(locale, data.EndUser)
	}
	if data.EndUserPortal != nil {
		localizeDailyUsage(locale, data.EndUserPortal.DailyUsage)
		for index := range data.EndUserPortal.Nodes {
			node := &data.EndUserPortal.Nodes[index]
			plan := membershipPlanView{
				QuotaLabel: node.QuotaLabel, ResetLabel: node.ResetLabel, ResetAt: node.ResetAt,
				ExpirationLabel: node.ExpirationLabel, ExpirationAt: node.ExpirationAt, StatusLabel: node.StatusLabel,
			}
			localizeMembershipPlan(locale, &plan)
			node.QuotaLabel = plan.QuotaLabel
			node.ResetLabel = plan.ResetLabel
			node.ResetAt = plan.ResetAt
			node.ExpirationLabel = plan.ExpirationLabel
			node.ExpirationAt = plan.ExpirationAt
			node.StatusLabel = plan.StatusLabel
		}
	}
	if data.UserSubscription != nil {
		for index := range data.UserSubscription.Nodes {
			data.UserSubscription.Nodes[index].Status = localizedText(locale, data.UserSubscription.Nodes[index].Status)
		}
	}
	if data.SubscriptionPolicy != nil {
		for index := range data.SubscriptionPolicy.Rules {
			data.SubscriptionPolicy.Rules[index].MatchLabel = localizedText(locale, data.SubscriptionPolicy.Rules[index].MatchLabel)
			data.SubscriptionPolicy.Rules[index].ActionLabel = localizedText(locale, data.SubscriptionPolicy.Rules[index].ActionLabel)
		}
	}
	for index := range data.AccountingFailures {
		data.AccountingFailures[index].Reason = localizedText(locale, data.AccountingFailures[index].Reason)
	}
}

func localizeAgentDetail(locale string, view *agentDetailView) {
	view.EnrollmentLabel = localizedText(locale, view.EnrollmentLabel)
	view.ConnectionLabel = localizedText(locale, view.ConnectionLabel)
	view.ConfigurationHint = localizedText(locale, view.ConfigurationHint)
	view.SingBoxUpdateHint = localizedText(locale, view.SingBoxUpdateHint)
	view.UpdateHint = localizedText(locale, view.UpdateHint)
	view.RevokeLabel = localizedText(locale, view.RevokeLabel)
	for index := range view.ProxyNodeReferences {
		reference := &view.ProxyNodeReferences[index]
		reference.DesiredRelayHopLabel = localizedCount(locale, reference.DesiredRelayHops, "relay-hop")
		reference.AppliedRelayHopLabel = localizedCount(locale, reference.AppliedRelayHops, "relay-hop")
	}
	if view.Deployment != nil {
		view.Deployment.StatusLabel = localizedText(locale, view.Deployment.StatusLabel)
		view.Deployment.Diagnostic = localizedText(locale, view.Deployment.Diagnostic)
	}
	if view.Update != nil {
		localizeAgentUpdate(locale, view.Update)
	}
	if view.SingBoxUpdate != nil {
		localizeAgentUpdate(locale, view.SingBoxUpdate)
	}
}

func localizeAgentUpdate(locale string, view *agentUpdateView) {
	view.StatusLabel = localizedText(locale, view.StatusLabel)
	view.Diagnostic = localizedText(locale, view.Diagnostic)
}

func localizeMembershipPlan(locale string, view *membershipPlanView) {
	if normalizeLocale(locale) == localeSimplifiedChinese && strings.HasSuffix(view.QuotaLabel, " / month") {
		view.QuotaLabel = "每月 " + strings.TrimSuffix(view.QuotaLabel, " / month")
	}
	view.QuotaLabel = localizedText(locale, view.QuotaLabel)
	view.ResetLabel = localizedMembershipTime(locale, view.ResetLabel)
	view.ExpirationLabel = localizedMembershipTime(locale, view.ExpirationLabel)
	view.StatusLabel = localizedText(locale, view.StatusLabel)
}

func localizedMembershipTime(locale, label string) string {
	if normalizeLocale(locale) != localeSimplifiedChinese {
		return label
	}
	value := strings.TrimPrefix(label, "Expires ")
	for _, candidate := range []struct {
		parseLayout   string
		displayLayout string
	}{
		{parseLayout: "Jan 2, 2006 15:04", displayLayout: "2006年1月2日 15:04"},
		{parseLayout: "Jan 2, 2006", displayLayout: "2006年1月2日"},
	} {
		parsed, err := time.ParseInLocation(candidate.parseLayout, value, proxynode.BillingLocation())
		if err == nil {
			return parsed.Format(candidate.displayLayout)
		}
	}
	return localizedText(locale, label)
}

func localizedBillingTime(locale, label string) string {
	if normalizeLocale(locale) != localeSimplifiedChinese {
		return label
	}
	const zoneSuffix = " (UTC+8)"
	value := strings.TrimSuffix(strings.TrimPrefix(label, "Expires "), zoneSuffix)
	for _, candidate := range []struct {
		parseLayout   string
		displayLayout string
	}{
		{parseLayout: "Jan 2, 2006 15:04", displayLayout: "2006年1月2日 15:04"},
		{parseLayout: "Jan 2, 2006", displayLayout: "2006年1月2日"},
	} {
		parsed, err := time.ParseInLocation(candidate.parseLayout, value, proxynode.BillingLocation())
		if err == nil {
			return parsed.Format(candidate.displayLayout) + "（UTC+8）"
		}
	}
	return localizedText(locale, label)
}

func localizeEndUserDetail(locale string, view *endUserDetailView) {
	view.Login.StatusLabel = localizedText(locale, view.Login.StatusLabel)
	view.Login.InviteExpiresAt = localizedBillingTime(locale, view.Login.InviteExpiresAt)
	if view.Login.Invitation != nil {
		view.Login.Invitation.ExpiresAt = localizedBillingTime(locale, view.Login.Invitation.ExpiresAt)
	}
	localizeMembershipPlan(locale, &view.DefaultPlan)
	localizeDailyUsage(locale, view.DailyUsage)
	for index := range view.AssignedAccess {
		view.AssignedAccess[index].EntranceLabel = localizedText(locale, view.AssignedAccess[index].EntranceLabel)
		localizeMembershipPlan(locale, &view.AssignedAccess[index].Plan)
	}
	for index := range view.AvailableAccess {
		view.AvailableAccess[index].EntranceLabel = localizedText(locale, view.AvailableAccess[index].EntranceLabel)
	}
}

func localizeDailyUsage(locale string, days []dailyUsageDayView) {
	if normalizeLocale(locale) != localeSimplifiedChinese {
		return
	}
	for index := range days {
		days[index].DateLabel = days[index].Date.In(proxynode.BillingLocation()).Format("2006 年 1 月 2 日")
	}
}

func localizeProxyNodeDetail(locale string, view *proxyNodeDetailView) {
	localizeMembershipPlan(locale, &view.DefaultPlan)
	view.EntranceFallback = localizedText(locale, view.EntranceFallback)
	for index := range view.UserAccess {
		if view.UserAccess[index].System {
			view.UserAccess[index].Name = localizedText(locale, view.UserAccess[index].Name)
		}
		localizeMembershipPlan(locale, &view.UserAccess[index].Plan)
	}
	if view.Tree != nil {
		localizeProxyTreeHop(locale, view.Tree)
	}
}

func localizeProxyTreeHop(locale string, hop *proxyTreeHopView) {
	hop.IngressProtocol = localizedText(locale, hop.IngressProtocol)
	hop.IngressLabel = localizedText(locale, hop.IngressLabel)
	for index := range hop.Routes {
		localizeProxyTreeRoute(locale, &hop.Routes[index])
	}
	localizeProxyTreeRoute(locale, &hop.Fallback)
	for index := range hop.Branches {
		hop.Branches[index].RuleLabel = localizedText(locale, hop.Branches[index].RuleLabel)
		hop.Branches[index].RuleValues = localizedText(locale, hop.Branches[index].RuleValues)
		if hop.Branches[index].Child != nil {
			localizeProxyTreeHop(locale, hop.Branches[index].Child)
		}
	}
	for index := range hop.Children {
		if hop.Children[index].Child != nil {
			localizeProxyTreeHop(locale, hop.Children[index].Child)
		}
	}
	hop.NewRule.MatchLabel = localizedText(locale, hop.NewRule.MatchLabel)
}

func localizeProxyTreeRoute(locale string, route *proxyTreeRouteView) {
	route.Label = localizedText(locale, route.Label)
	route.TargetLabel = localizedText(locale, route.TargetLabel)
	route.TargetDetail = localizedText(locale, route.TargetDetail)
}
