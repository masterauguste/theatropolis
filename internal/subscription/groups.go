package subscription

import (
	"slices"
	"strings"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

type exportGroup struct {
	Name, Type          string
	Members             []string
	Interval, Tolerance int
}

func nodeTargets(profile Profile, action proxynode.SubscriptionAction) []string {
	parts := strings.Split(string(action), ":")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "node" {
		return nil
	}
	var names []string
	for _, node := range profile.Nodes {
		if node.ID == parts[1] && (len(parts) == 2 || strings.EqualFold(parts[2], node.Family)) {
			names = append(names, node.Name)
		}
	}
	return names
}

// Only the caller's eligible Nodes enter Profile. Missing/deleted/unassigned
// targets resolve to REJECT, never another user's proxy or an implicit Direct.
func resolvedAction(profile Profile, action proxynode.SubscriptionAction) proxynode.SubscriptionAction {
	switch action {
	case proxynode.SubscriptionDirect, proxynode.SubscriptionReject, proxynode.SubscriptionProxy, "":
		return action
	}
	if names := nodeTargets(profile, action); len(names) > 0 {
		return proxynode.SubscriptionAction("resolved:" + names[0])
	}
	for _, group := range profile.Groups {
		if string(action) == "group:"+group.ID {
			return proxynode.SubscriptionAction("resolved:" + group.Name)
		}
	}
	return proxynode.SubscriptionReject
}

func profileGroups(profile Profile) []exportGroup {
	all := make([]string, 0, len(profile.Nodes)+2)
	for _, node := range profile.Nodes {
		all = append(all, node.Name)
	}
	result := []exportGroup{{Name: "PROXY", Type: "select", Members: append(slices.Clone(all), "DIRECT", "REJECT")}}
	// Dependency-first output also works in clients that resolve members while
	// reading a group. Store validation rejects cycles before persistence.
	visited := make(map[string]bool)
	var appendGroup func(proxynode.SubscriptionGroup)
	appendGroup = func(group proxynode.SubscriptionGroup) {
		if visited[group.ID] {
			return
		}
		visited[group.ID] = true
		members := make([]string, 0)
		add := func(names ...string) {
			for _, name := range names {
				if !slices.Contains(members, name) {
					members = append(members, name)
				}
			}
		}
		for _, member := range group.Members {
			if strings.HasPrefix(string(member), "node:") {
				add(nodeTargets(profile, member)...)
				continue
			}
			for _, dependency := range profile.Groups {
				if string(member) == "group:"+dependency.ID {
					appendGroup(dependency)
				}
			}
			add(actionName(resolvedAction(profile, member)))
		}
		if group.AllNodes {
			add(all...)
		}
		kind := group.Type
		if len(members) == 0 {
			members = []string{"REJECT"}
			kind = "select"
		}
		result = append(result, exportGroup{Name: group.Name, Type: kind, Members: members, Interval: group.Interval, Tolerance: group.Tolerance})
	}
	for _, group := range profile.Groups {
		appendGroup(group)
	}
	return result
}
