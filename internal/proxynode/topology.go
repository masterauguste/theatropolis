package proxynode

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// AncestorAgentIDs returns every Agent already traversed on the unique path
// from the entrance through hopID, including hopID itself. Proxy Node topology
// forbids merging, so every non-entrance Hop has at most one parent.
func AncestorAgentIDs(node ProxyNode, hopID string) map[string]struct{} {
	hops := make(map[string]Hop, len(node.Hops))
	for _, hop := range node.Hops {
		hops[hop.ID] = hop
	}
	parents := make(map[string]string, len(node.Links))
	for _, link := range node.Links {
		parents[link.ChildHopID] = link.ParentHopID
	}
	agents := make(map[string]struct{})
	visited := make(map[string]struct{})
	for current := hopID; current != ""; current = parents[current] {
		if _, duplicate := visited[current]; duplicate {
			break
		}
		visited[current] = struct{}{}
		hop, exists := hops[current]
		if !exists {
			break
		}
		agents[hop.AgentID] = struct{}{}
	}
	return agents
}

// RequireAgentUnreferenced rejects removal of an Agent while either the
// desired or last-applied Proxy Node topology still assigns a Hop to it. The
// managed-Agent set is checked as a final safety net: an Agent must receive
// its empty retirement profile before its control identity can be revoked.
func (s *Store) RequireAgentUnreferenced(agentID string) error {
	agentID = strings.TrimSpace(agentID)
	if !validAgentID(agentID) {
		return fmt.Errorf("%w: invalid Agent ID", ErrInvalidState)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	references := make(map[string]string)
	collect := func(nodes []ProxyNode) {
		for _, node := range nodes {
			if slices.ContainsFunc(node.Hops, func(hop Hop) bool { return hop.AgentID == agentID }) {
				references[node.ID] = node.Name
			}
		}
	}
	collect(s.state.ProxyNodes)
	collect(s.state.AppliedProxyNodes)
	if len(references) > 0 {
		names := make([]string, 0, len(references))
		for _, name := range references {
			names = append(names, name)
		}
		sort.Strings(names)
		const maxReportedNames = 3
		detail := strings.Join(names[:min(len(names), maxReportedNames)], ", ")
		if len(names) > maxReportedNames {
			detail += fmt.Sprintf(" and %d more", len(names)-maxReportedNames)
		}
		return fmt.Errorf("%w: Agent %q is used by %s", ErrAgentReferenced, agentID, detail)
	}
	if slices.Contains(s.state.ManagedAgents, agentID) {
		return fmt.Errorf("%w: Agent %q still owns an applied managed configuration", ErrAgentReferenced, agentID)
	}
	return nil
}
