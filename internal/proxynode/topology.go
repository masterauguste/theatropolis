package proxynode

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
