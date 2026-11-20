package webui

import (
	"net/http"
	"slices"
	"strconv"
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

func populateSubscriptionTargets(view *subscriptionPolicyView, policy proxynode.SubscriptionPolicy, nodes []proxynode.ProxyNode) {
	options := []subscriptionTargetOption{
		{Value: "proxy", Label: "PROXY · All available proxies", Kind: "Built-in", Builtin: true},
		{Value: "direct", Label: "Direct", Kind: "Built-in", Builtin: true},
		{Value: "reject", Label: "Reject", Kind: "Built-in", Builtin: true},
	}
	for _, group := range policy.Groups {
		options = append(options, subscriptionTargetOption{Value: "group:" + group.ID, Label: group.Name, Kind: "Proxy group"})
	}
	nodes = slices.Clone(nodes)
	slices.SortFunc(nodes, func(a, b proxynode.ProxyNode) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	for _, node := range nodes {
		for _, family := range []string{"", "ipv4", "ipv6"} {
			value, label := "node:"+node.ID, node.Name
			if family != "" {
				value += ":" + family
				label += " · " + strings.ToUpper(family[:2]) + family[2:]
			}
			options = append(options, subscriptionTargetOption{Value: value, Label: label, Kind: "Proxy Node"})
		}
	}
	// Retain unavailable references so opening and saving an editor cannot
	// silently replace a deleted Node with the first available target.
	ensure := func(action proxynode.SubscriptionAction) {
		value := string(action)
		if value != "" && !slices.ContainsFunc(options, func(o subscriptionTargetOption) bool { return o.Value == value }) {
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
		var members []string
		for _, member := range group.Members {
			members = append(members, string(member))
		}
		v.Members = strings.Join(members, "\n")
		// Selected choices come first in their saved order; the picker supports
		// moving them without changing the default selection on a simple rename.
		for _, member := range members {
			for _, option := range options {
				if option.Value == member {
					option.Selected = true
					v.Choices = append(v.Choices, option)
				}
			}
		}
		for _, option := range options {
			if option.Value != ref && !slices.Contains(members, option.Value) {
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
	view.NewGroup = makeGroup(proxynode.SubscriptionGroup{Type: "select", AllNodes: true})
}

func (h *Handler) saveSubscriptionGroup(response http.ResponseWriter, request *http.Request) {
	_, form, ok := h.authorizeProxyMutation(response, request, "name", "type", "all_nodes", "members", "interval", "tolerance")
	if !ok {
		return
	}
	interval, err1 := strconv.Atoi(form.Get("interval"))
	tolerance, err2 := strconv.Atoi(form.Get("tolerance"))
	if err1 != nil || err2 != nil || form.Get("all_nodes") != "yes" && form.Get("all_nodes") != "no" {
		writeUserError(response, "Invalid proxy group settings.", http.StatusBadRequest)
		return
	}
	group := proxynode.SubscriptionGroup{ID: request.PathValue("group_id"), Name: form.Get("name"), Type: form.Get("type"), AllNodes: form.Get("all_nodes") == "yes", Interval: interval, Tolerance: tolerance}
	for _, member := range splitProxyValues(form.Get("members")) {
		group.Members = append(group.Members, proxynode.SubscriptionAction(member))
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
	if err := h.proxyNodes.DeleteSubscriptionGroup(request.PathValue("group_id"), proxynode.SubscriptionAction(form.Get("replacement"))); err != nil {
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
	if err := h.proxyNodes.SetSubscriptionRuleAction(request.PathValue("rule_id"), proxynode.SubscriptionAction(form.Get("action"))); err != nil {
		handleProxyMutationError(response, err)
		return
	}
	http.Redirect(response, request, "/subscriptions#subscription-rules", http.StatusSeeOther)
}
