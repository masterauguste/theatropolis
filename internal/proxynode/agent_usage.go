package proxynode

import (
	"fmt"
	"slices"
)

// AgentEntranceUsage summarizes the current billing plane for Proxy Nodes
// whose entrance Hop is assigned to one Agent. Finite allowances are summed per
// Membership because one user can hold independent quotas on multiple Nodes.
// UnlimitedUsers is de-duplicated by global user identity.
type AgentEntranceUsage struct {
	AllocatedBytes uint64
	UsedBytes      uint64
	UnlimitedUsers int
}

func (s *Store) EntranceUsageForAgent(agentID string) (AgentEntranceUsage, error) {
	if !validAgentID(agentID) {
		return AgentEntranceUsage{}, fmt.Errorf("%w: invalid Agent ID", ErrInvalidState)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result AgentEntranceUsage
	unlimited := make(map[string]struct{})
	liveNodes := make(map[string]ProxyNode, len(s.state.ProxyNodes))
	for _, node := range s.state.ProxyNodes {
		liveNodes[node.ID] = node
	}
	for _, applied := range s.state.AppliedProxyNodes {
		root := slices.IndexFunc(applied.Hops, func(hop Hop) bool { return hop.ID == applied.Entrance.HopID })
		if root < 0 || applied.Hops[root].AgentID != agentID {
			continue
		}
		node, exists := liveNodes[applied.ID]
		if !exists {
			continue
		}
		for _, membership := range node.Memberships {
			if membership.MonthlyQuotaBytes == 0 {
				unlimited[membership.UserID] = struct{}{}
				continue
			}
			result.AllocatedBytes = saturatingAdd(result.AllocatedBytes, membership.MonthlyQuotaBytes)
			result.UsedBytes = saturatingAdd(result.UsedBytes, membership.UsedBytes)
		}
	}
	result.UnlimitedUsers = len(unlimited)
	return result, nil
}
