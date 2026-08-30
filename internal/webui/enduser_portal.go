package webui

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

const (
	endUserInvitationResultTTL    = 10 * time.Minute
	endUserClaimRequestsPerMinute = 10
)

type endUserInvitationView struct {
	URL       string
	ExpiresAt string
	createdAt time.Time
}

type endUserLoginView struct {
	Username    string
	Unavailable bool
	ReturnTo    string
}

type endUserPortalView struct {
	LoginUsername string
	CSRFToken     string
	Subscription  *userSubscriptionView
	Nodes         []endUserPortalNodeView
	DailyUsage    []dailyUsageDayView
}

type endUserPortalNodeView struct {
	Name            string
	Initial         string
	Tone            string
	Protocol        string
	EntranceAgent   string
	UsageLabel      string
	QuotaLabel      string
	ResetLabel      string
	ExpirationLabel string
	StatusLabel     string
	StatusClass     string
}

func (h *Handler) issueEndUserInvitation(response http.ResponseWriter, request *http.Request) {
	if h.endUserAccess == nil {
		http.Error(response, "end-user login is unavailable", http.StatusServiceUnavailable)
		return
	}
	session, form, ok := h.authorizeProxyMutation(response, request, "confirm_reset")
	if !ok {
		return
	}
	userID := request.PathValue("user_id")
	if _, exists := h.proxyNodes.User(userID); !exists {
		http.NotFound(response, request)
		return
	}
	status := h.endUserAccess.Status(userID)
	if (status.Claimed || status.InvitationReady) && form.Get("confirm_reset") != "yes" {
		http.Error(response, "registration reset was not confirmed", http.StatusBadRequest)
		return
	}
	token, expiresAt, err := h.endUserAccess.IssueInvitation(userID, defaultUserInviteLifetime)
	if err != nil {
		h.logger.Error("issue end-user invitation", "user_id", userID, "error", err)
		http.Error(response, "invitation could not be created", http.StatusInternalServerError)
		return
	}
	result := endUserInvitationView{
		URL:       endUserInvitationURL(h.publicURL, token),
		ExpiresAt: expiresAt.In(proxynode.BillingLocation()).Format("Jan 2, 2006 15:04") + " (UTC+8)",
		createdAt: h.currentTime(),
	}
	digest := sha256.Sum256([]byte(session.Token))
	h.userInviteMu.Lock()
	for owner, results := range h.userInviteResults {
		for id, stored := range results {
			if h.currentTime().Sub(stored.createdAt) > endUserInvitationResultTTL {
				delete(results, id)
			}
		}
		if len(results) == 0 {
			delete(h.userInviteResults, owner)
		}
	}
	if h.userInviteResults[digest] == nil {
		h.userInviteResults[digest] = make(map[string]endUserInvitationView)
	}
	h.userInviteResults[digest][userID] = result
	h.userInviteMu.Unlock()
	http.Redirect(response, request, "/users/"+url.PathEscape(userID), http.StatusSeeOther)
}

func (h *Handler) endUserInvitationResult(request *http.Request, userID string) *endUserInvitationView {
	token, ok := h.sessionToken(request)
	if !ok {
		return nil
	}
	digest := sha256.Sum256([]byte(token))
	h.userInviteMu.Lock()
	defer h.userInviteMu.Unlock()
	result, exists := h.userInviteResults[digest][userID]
	if !exists || h.currentTime().Sub(result.createdAt) > endUserInvitationResultTTL {
		if h.userInviteResults[digest] != nil {
			delete(h.userInviteResults[digest], userID)
		}
		return nil
	}
	copy := result
	return &copy
}

func (h *Handler) endUserLoginPage(response http.ResponseWriter, request *http.Request) {
	h.noStore(response)
	if h.endUserAccess == nil {
		http.NotFound(response, request)
		return
	}
	if h.endUserAccess.Unified() {
		http.Redirect(response, request, "/login", http.StatusSeeOther)
		return
	}
	if _, ok := h.authenticateEndUser(request); ok {
		http.Redirect(response, request, "/portal", http.StatusSeeOther)
		return
	}
	h.render(response, http.StatusOK, "portal-login.html", pageData{
		Title: "User Sign In", EndUserLogin: &endUserLoginView{ReturnTo: "/portal/login"},
	})
}

func (h *Handler) endUserLogin(response http.ResponseWriter, request *http.Request) {
	h.noStore(response)
	if h.endUserAccess == nil {
		http.NotFound(response, request)
		return
	}
	if h.endUserAccess.Unified() {
		h.login(response, request)
		return
	}
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	form, err := readExactForm(response, request, maxLoginBodyBytes, "username", "password")
	if err != nil {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(strings.ToLower(form.Get("username")))
	session, err := h.endUserAccess.LoginForClient(loginClientIdentity(request), username, form.Get("password"))
	if err != nil {
		status := http.StatusUnauthorized
		message := "The username or password was not accepted."
		if errors.Is(err, ErrLoginRateLimited) {
			status = http.StatusTooManyRequests
			message = "Too many attempts. Wait one minute and try again."
			response.Header().Set("Retry-After", "60")
		}
		h.render(response, status, "portal-login.html", pageData{
			Title: "User Sign In", Error: message,
			EndUserLogin: &endUserLoginView{Username: username, ReturnTo: "/portal/login"},
		})
		return
	}
	http.SetCookie(response, NewEndUserSessionCookie(session.Token, session.ExpiresAt))
	http.Redirect(response, request, "/portal", http.StatusSeeOther)
}

func (h *Handler) endUserClaimLink(response http.ResponseWriter, request *http.Request) {
	h.noStore(response)
	// The invitation bearer token exists only on this exchange URL. Prevent it
	// from becoming a referrer, then redirect to the token-free claim form.
	response.Header().Set("Referrer-Policy", "no-referrer")
	if h.endUserAccess == nil {
		http.NotFound(response, request)
		return
	}
	token := request.PathValue("token")
	if !h.endUserAccess.InvitationValid(token) {
		h.render(response, http.StatusGone, "portal-claim.html", pageData{
			Title: "Set Up Account", Error: "This invitation is invalid or has expired.",
			EndUserLogin: &endUserLoginView{Unavailable: true, ReturnTo: "/claim"},
		})
		return
	}
	http.SetCookie(response, NewEndUserClaimCookie(token, h.currentTime().Add(15*time.Minute)))
	http.Redirect(response, request, "/claim", http.StatusSeeOther)
}

func (h *Handler) endUserClaimPage(response http.ResponseWriter, request *http.Request) {
	h.noStore(response)
	if h.endUserAccess == nil {
		http.NotFound(response, request)
		return
	}
	token, ok := h.endUserClaimToken(request)
	if !ok || !h.endUserAccess.InvitationValid(token) {
		h.render(response, http.StatusGone, "portal-claim.html", pageData{
			Title: "Set Up Account", Error: "This invitation is invalid or has expired.",
			EndUserLogin: &endUserLoginView{Unavailable: true, ReturnTo: "/claim"},
		})
		return
	}
	h.render(response, http.StatusOK, "portal-claim.html", pageData{
		Title: "Set Up Account", EndUserLogin: &endUserLoginView{ReturnTo: "/claim"},
	})
}

func (h *Handler) endUserClaim(response http.ResponseWriter, request *http.Request) {
	h.noStore(response)
	if h.endUserAccess == nil {
		http.NotFound(response, request)
		return
	}
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	token, ok := h.endUserClaimToken(request)
	if !ok || !h.endUserAccess.InvitationValid(token) {
		h.render(response, http.StatusGone, "portal-claim.html", pageData{
			Title: "Set Up Account", Error: "This invitation is invalid or has expired.",
			EndUserLogin: &endUserLoginView{Unavailable: true, ReturnTo: "/claim"},
		})
		return
	}
	if !h.allowEndUserClaim(request) {
		response.Header().Set("Retry-After", "60")
		h.render(response, http.StatusTooManyRequests, "portal-claim.html", pageData{
			Title: "Set Up Account", Error: "Too many account setup attempts. Wait one minute and try again.",
			EndUserLogin: &endUserLoginView{ReturnTo: "/claim"},
		})
		return
	}
	form, err := readExactForm(response, request, maxLoginBodyBytes, "username", "password", "password_confirmation")
	if err != nil {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(strings.ToLower(form.Get("username")))
	if form.Get("password") != form.Get("password_confirmation") {
		h.render(response, http.StatusBadRequest, "portal-claim.html", pageData{
			Title: "Set Up Account", Error: "The passwords do not match.", ErrorField: "password_confirmation",
			EndUserLogin: &endUserLoginView{Username: username, ReturnTo: "/claim"},
		})
		return
	}
	session, err := h.endUserAccess.ClaimInvitation(token, username, form.Get("password"))
	if err != nil {
		status := http.StatusBadRequest
		message := "The account could not be created."
		field := ""
		switch {
		case errors.Is(err, ErrInvitationInvalid):
			status, message, field = http.StatusGone, "This invitation is invalid or has expired.", ""
		case errors.Is(err, ErrUsernameTaken):
			status, message, field = http.StatusConflict, "This login username is already in use.", "username"
		case errors.Is(err, ErrLoginRateLimited):
			status, message, field = http.StatusTooManyRequests, "Account setup is busy. Try again in a moment.", ""
		case isEndUserClaimValidationError(err):
			message, field = err.Error(), "password"
			if strings.HasPrefix(err.Error(), "username ") {
				field = "username"
			}
		default:
			status = http.StatusInternalServerError
			h.logger.Error("claim end-user invitation", "error", err)
		}
		unavailable := errors.Is(err, ErrInvitationInvalid)
		h.render(response, status, "portal-claim.html", pageData{
			Title: "Set Up Account", Error: message, ErrorField: field,
			EndUserLogin: &endUserLoginView{Username: username, Unavailable: unavailable, ReturnTo: "/claim"},
		})
		return
	}
	if _, exists := h.proxyNodes.User(session.UserID); !exists {
		_ = h.endUserAccess.RemoveUser(session.UserID)
		http.SetCookie(response, DeleteEndUserClaimCookie())
		h.render(response, http.StatusGone, "portal-claim.html", pageData{
			Title: "Set Up Account", Error: "This invitation is invalid or has expired.",
			EndUserLogin: &endUserLoginView{Unavailable: true, ReturnTo: "/claim"},
		})
		return
	}
	http.SetCookie(response, DeleteEndUserClaimCookie())
	http.SetCookie(response, NewEndUserSessionCookie(session.Token, session.ExpiresAt))
	http.Redirect(response, request, "/portal", http.StatusSeeOther)
}

func (h *Handler) endUserPortal(response http.ResponseWriter, request *http.Request) {
	h.noStore(response)
	session, ok := h.requireEndUserAuthentication(response, request)
	if !ok {
		return
	}
	user, exists := h.proxyNodes.User(session.UserID)
	if !exists {
		_ = h.endUserAccess.Logout(session.Token)
		http.SetCookie(response, DeleteEndUserSessionCookie())
		http.Redirect(response, request, "/portal/login", http.StatusSeeOther)
		return
	}
	subscriptionView, _, exists := h.subscriptionViewAndProfile(user.ID)
	if !exists {
		http.NotFound(response, request)
		return
	}
	view := &endUserPortalView{
		LoginUsername: session.LoginUsername, CSRFToken: session.CSRFToken,
		Subscription: subscriptionView,
	}
	daily, err := h.proxyNodes.UserDailyUsage(user.ID, 30)
	if err != nil {
		h.logger.Error("read portal daily traffic", "user_id", user.ID, "error", err)
		http.Error(response, "daily traffic could not be loaded", http.StatusInternalServerError)
		return
	}
	view.DailyUsage = dailyUsageViews(daily)
	state := h.proxyNodes.Snapshot()
	for _, node := range state.ProxyNodes {
		var membership *proxynode.Membership
		for index := range node.Memberships {
			if node.Memberships[index].UserID == user.ID {
				membership = &node.Memberships[index]
				break
			}
		}
		if membership == nil {
			continue
		}
		activeNode, applied := h.proxyNodes.AppliedProxyNode(node.ID)
		if !applied {
			activeNode = node
		}
		root, _ := proxyHop(activeNode, activeNode.Entrance.HopID)
		plan := membershipPlanViewFor(*membership)
		view.Nodes = append(view.Nodes, endUserPortalNodeView{
			Name: node.Name, Initial: nodeInitial(node.Name), Tone: nodeRoleTone(node.Name),
			Protocol: protocolLabel(activeNode.Entrance.Endpoint.Protocol), EntranceAgent: root.AgentID,
			UsageLabel: plan.UsageLabel, QuotaLabel: plan.QuotaLabel, ResetLabel: plan.ResetLabel,
			ExpirationLabel: plan.ExpirationLabel, StatusLabel: plan.StatusLabel, StatusClass: plan.StatusClass,
		})
	}
	sort.Slice(view.Nodes, func(i, j int) bool { return strings.ToLower(view.Nodes[i].Name) < strings.ToLower(view.Nodes[j].Name) })
	h.render(response, http.StatusOK, "portal.html", pageData{
		Title: "User Portal", EndUserPortal: view,
	})
}

func (h *Handler) endUserLogout(response http.ResponseWriter, request *http.Request) {
	h.noStore(response)
	if h.endUserAccess == nil {
		http.NotFound(response, request)
		return
	}
	if h.rejectInvalidMutationOrigin(response, request) {
		return
	}
	token, ok := h.endUserSessionToken(request)
	if !ok {
		http.Redirect(response, request, "/portal/login", http.StatusSeeOther)
		return
	}
	form, err := readExactForm(response, request, maxLoginBodyBytes, "csrf_token")
	if err != nil || !h.endUserAccess.AuthorizeCSRF(token, form.Get("csrf_token")) {
		http.Error(response, "request was not authorized", http.StatusForbidden)
		return
	}
	if err := h.endUserAccess.Logout(token); err != nil {
		h.logger.Error("persist end-user logout", "error", err)
		http.Error(response, "logout could not be completed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(response, DeleteEndUserSessionCookie())
	http.Redirect(response, request, "/portal/login", http.StatusSeeOther)
}

func (h *Handler) authenticateEndUser(request *http.Request) (EndUserSession, bool) {
	if h.endUserAccess == nil {
		return EndUserSession{}, false
	}
	token, ok := h.endUserSessionToken(request)
	if !ok {
		return EndUserSession{}, false
	}
	session, err := h.endUserAccess.Authenticate(token)
	return session, err == nil
}

func (h *Handler) requireEndUserAuthentication(response http.ResponseWriter, request *http.Request) (EndUserSession, bool) {
	session, ok := h.authenticateEndUser(request)
	if !ok {
		http.SetCookie(response, DeleteEndUserSessionCookie())
		target := "/portal/login"
		if h.endUserAccess != nil && h.endUserAccess.Unified() {
			target = "/login"
		}
		http.Redirect(response, request, target, http.StatusSeeOther)
		return EndUserSession{}, false
	}
	http.SetCookie(response, NewEndUserSessionCookie(session.Token, session.ExpiresAt))
	return session, true
}

func (h *Handler) endUserSessionToken(request *http.Request) (string, bool) {
	cookie, err := request.Cookie(EndUserSessionCookieName)
	if err != nil || len(cookie.Value) != encodedCredentialLength {
		return "", false
	}
	return cookie.Value, true
}

func (h *Handler) endUserClaimToken(request *http.Request) (string, bool) {
	cookie, err := request.Cookie(EndUserClaimCookieName)
	if err != nil || len(cookie.Value) != encodedCredentialLength {
		return "", false
	}
	return cookie.Value, true
}

func (h *Handler) noStore(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	// Keep the handler-wide strict-origin policy on token-free forms. Setting
	// no-referrer here can make WebKit serialize same-origin form POSTs with an
	// opaque Origin, which the mutation guard must reject.
}

func endUserInvitationURL(publicURL, token string) string {
	return fmt.Sprintf("%s/claim/%s", strings.TrimRight(publicURL, "/"), url.PathEscape(token))
}

func (h *Handler) allowEndUserClaim(request *http.Request) bool {
	return h.claimLimiter.allow(loginClientIdentity(request), h.currentTime())
}

func isEndUserClaimValidationError(err error) bool {
	message := err.Error()
	return strings.HasPrefix(message, "username must ") ||
		strings.HasPrefix(message, "password must ") ||
		message == "password is too common or too closely related to the username"
}
