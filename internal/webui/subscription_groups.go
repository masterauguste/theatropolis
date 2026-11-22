package webui

import (
	"net/http"
	"slices"
	"strings"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

type subscriptionTargetOption struct {
	Value, Label, Kind string
	Selected, Builtin  bool
}
type subscriptionTargetPicker struct {
	Action  string
	Options []subscriptionTargetOption
}
type subscriptionGroupView struct {
	ID, Name, Type, Members         string
	AllNodes                        bool
	Interval, Tolerance, References int
	Choices                         []subscriptionTargetOption
	Replacement                     subscriptionTargetPicker
}

func isGlobalSubscriptionTarget(action proxynode.SubscriptionAction) bool {
	return !strings.HasPrefix(string(action), "node:")
}

func populateSubscriptionTargets(view *subscriptionPolicyView, policy proxynode.SubscriptionPolicy, _ []proxynode.ProxyNode) {
	options := []subscriptionTargetOption{
		{Value: "proxy", Label: "PROXY", Kind: "Follow PROXY selection", Builtin: true},
		{Value: "direct", Label: "Direct", Kind: "Built-in", Builtin: true},
		{Value: "reject", Label: "Reject", Kind: "Built-in", Builtin: true},
	}
	for _, group := range policy.Groups {
		options = append(options, subscriptionTargetOption{Value: "group:" + group.ID, Label: group.Name, Kind: "Proxy group"})
	}
	// Retain legacy/unavailable references so opening an editor cannot
	// silently replace a persisted target before the administrator chooses one.
	ensure := func(action proxynode.SubscriptionAction) {
		value := string(action)
		if value == "" || action == proxynode.SubscriptionAllNodes {
			return
		}
		if !slices.ContainsFunc(options, func(o subscriptionTargetOption) bool { return o.Value == value }) {
			options = append(options, subscriptionTargetOption{Value: value, Label: "Unavailable Node", Kind: "Unavailable", Builtin: true})
		}
	}
	ensure(policy.DefaultAction)
	for _, rule := range policy.Rules {
		ensure(rule.Action)
	}
	for _, group := range policy.Groups {
		for _, member := range group.Members {
			ensure(member)
		}
	}
	groupOptions := make([]subscriptionTargetOption, 0, len(options)+1)
	groupOptions = append(groupOptions,
		options[0],
		subscriptionTargetOption{Value: string(proxynode.SubscriptionAllNodes), Label: "All available nodes", Kind: "Each user's accessible proxies", Builtin: true},
	)
	groupOptions = append(groupOptions, options[1:]...)

	picker := func(action string, exclude string) subscriptionTargetPicker {
		p := subscriptionTargetPicker{Action: action}
		for _, option := range options {
			if option.Value != exclude {
				p.Options = append(p.Options, option)
			}
		}
		return p
	}
	view.DefaultTargets, view.NewRuleTargets = picker(view.DefaultAction, ""), picker("proxy", "")
	for i := range view.Rules {
		view.Rules[i].Targets = picker(view.Rules[i].Action, "")
	}
	makeGroup := func(group proxynode.SubscriptionGroup) subscriptionGroupView {
		v := subscriptionGroupView{ID: group.ID, Name: group.Name, Type: group.Type, AllNodes: group.AllNodes, Interval: group.Interval, Tolerance: group.Tolerance}
		if v.Interval == 0 {
			v.Interval = 300
		}
		if v.Tolerance == 0 {
			v.Tolerance = 50
		}
		ref := "group:" + group.ID
		members := make([]string, 0, len(group.Members)+1)
		for _, member := range group.Members {
			members = append(members, string(member))
		}
		// Backwards compatibility: older groups stored AllNodes=true without
		// an explicit "all_nodes" entry in Members. Project it at its effective
		// export position so the admin can reorder or remove it cleanly.
		if group.AllNodes && !slices.Contains(members, string(proxynode.SubscriptionAllNodes)) {
			splitAt := len(members)
			for splitAt > 0 && (members[splitAt-1] == string(proxynode.SubscriptionDirect) || members[splitAt-1] == string(proxynode.SubscriptionReject)) {
				splitAt--
			}
			if splitAt == 0 && len(members) > 0 {
				splitAt = 1
			}
			members = slices.Insert(members, splitAt, string(proxynode.SubscriptionAllNodes))
		}
		v.Members = strings.Join(members, "\n")
		// Selected choices come first in their saved order; the picker supports
		// moving them without changing the default selection on a simple rename.
		for _, member := range members {
			for _, option := range groupOptions {
				if option.Value == member {
					option.Selected = true
					v.Choices = append(v.Choices, option)
				}
			}
		}
		for _, option := range groupOptions {
			if option.Value != ref && !slices.Contains(members, option.Value) && !strings.HasPrefix(option.Value, "node:") {
				v.Choices = append(v.Choices, option)
			}
		}
		v.Replacement = picker("reject", ref)
		if view.DefaultAction == ref {
			v.References++
		}
		for _, rule := range policy.Rules {
			if string(rule.Action) == ref {
				v.References++
			}
		}
		for _, parent := range policy.Groups {
			for _, member := range parent.Members {
				if string(member) == ref {
					v.References++
				}
			}
		}
		return v
	}
	for _, group := range policy.Groups {
		view.Groups = append(view.Groups, makeGroup(group))
	}
	view.NewGroup = makeGroup(proxynode.SubscriptionGroup{
		Type:     "select",
		AllNodes: true,
		Members: []proxynode.SubscriptionAction{
			proxynode.SubscriptionProxy,
			proxynode.SubscriptionAllNodes,
			proxynode.SubscriptionDirect,
			proxynode.SubscriptionReject,
		},
	})
}

func (h *Handler) saveSubscriptionGroup(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutationWithOptional(response, request, []string{"name", "members"}, "type", "all_nodes", "interval", "tolerance")
	if !ok {
		return
	}
	groupType := strings.TrimSpace(form.Get("type"))
	if groupType == "" {
		groupType = "select"
	}
	if groupType != "select" {
		writeUserError(response, "Automatic latency test groups are currently disabled.", http.StatusBadRequest)
		return
	}
	group := proxynode.SubscriptionGroup{
		ID:   request.PathValue("group_id"),
		Name: form.Get("name"),
		Type: "select",
	}
	for _, member := range splitProxyValues(form.Get("members")) {
		action := proxynode.SubscriptionAction(member)
		if !isGlobalSubscriptionTarget(action) {
			writeUserError(response, "Individual Proxy Nodes cannot be selected in the global subscription template.", http.StatusBadRequest)
			return
		}
		group.Members = append(group.Members, action)
	}
	group.AllNodes = slices.Contains(group.Members, proxynode.SubscriptionAllNodes)
	if len(group.Members) == 0 {
		writeUserError(response, "Select at least one option for the proxy group.", http.StatusBadRequest)
		return
	}
	if _, err := h.proxyNodes.SaveSubscriptionGroup(group); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, "/subscriptions#proxy-groups", http.StatusSeeOther)
}

func (h *Handler) deleteSubscriptionGroup(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "replacement")
	if !ok {
		return
	}
	replacement := proxynode.SubscriptionAction(form.Get("replacement"))
	if !isGlobalSubscriptionTarget(replacement) {
		writeUserError(response, "Individual Proxy Nodes cannot be targeted in the global subscription template.", http.StatusBadRequest)
		return
	}
	if err := h.proxyNodes.DeleteSubscriptionGroup(request.PathValue("group_id"), replacement); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, "/subscriptions#proxy-groups", http.StatusSeeOther)
}

func (h *Handler) updateSubscriptionRuleAction(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "action")
	if !ok {
		return
	}
	action := proxynode.SubscriptionAction(form.Get("action"))
	if !isGlobalSubscriptionTarget(action) {
		writeUserError(response, "Individual Proxy Nodes cannot be targeted in the global subscription template.", http.StatusBadRequest)
		return
	}
	if err := h.proxyNodes.SetSubscriptionRuleAction(request.PathValue("rule_id"), action); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, "/subscriptions#subscription-rules", http.StatusSeeOther)
}
