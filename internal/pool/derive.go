package pool

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/masterauguste/theatropolis/internal/deployment"
)

// serverKeyRefComponent is the ref user component addressing a shadowsocks
// inbound's server key (zero-user inbound) or an unnamed user.
const serverKeyRefComponent = "_server"

// Entry is one importable outbound in the fleet-wide pool view.
type Entry struct {
	Ref        string // agent/<id>/<inbound-tag>/<user> or manual/<name>
	AgentID    string // "" for manual entries
	InboundTag string
	User       string // may be "" (unnamed user or ss server-key entry)
	Type       string // shadowsocks|anytls|hysteria2|manual outbound type
	Port       int
	// IPv4/IPv6 hold the resolved address per family; "" when no source
	// yields an address of that family. Manual entries leave both empty.
	IPv4 string
	IPv6 string
	// Available is false when neither family resolved an address.
	Available bool
	Manual    bool
	// ServerKeyOnly marks the single entry derived from a shadowsocks
	// inbound with zero users; its credential is the server key alone.
	ServerKeyOnly bool
}

// DeriveInput carries everything Derive needs to build the pool view.
type DeriveInput struct {
	// AgentIDs lists the enrolled agents to derive entries for.
	AgentIDs []string
	// Deployments maps agent ID to its latest deployment record; a missing
	// or nil record means the agent has nothing deployed yet.
	Deployments map[string]*deployment.Record
	// Registry supplies addresses and manual entries; may be nil.
	Registry *Registry
	// Diagnostics, when non-nil, receives notes about skipped agents,
	// inbounds, and users.
	Diagnostics *[]string
}

func (input DeriveInput) note(format string, args ...any) {
	if input.Diagnostics != nil {
		*input.Diagnostics = append(*input.Diagnostics, fmt.Sprintf(format, args...))
	}
}

// Derive builds the deterministic pool view: one entry per (inbound × user)
// for every supported inbound in each agent's latest deployed config, plus
// the registry's manual entries. Entries are sorted by agent, inbound tag,
// then user (manual entries sort first, with an empty agent ID).
func Derive(input DeriveInput) []Entry {
	var entries []Entry
	for _, agentID := range input.AgentIDs {
		if !validComponent(agentID) {
			input.note("agent %q skipped: invalid agent ID", agentID)
			continue
		}
		record := input.Deployments[agentID]
		if record == nil {
			continue
		}
		config, err := parseDeployedConfig(record.ConfigJSON)
		if err != nil {
			input.note("agent %s skipped: deployed config is unusable: %v", agentID, err)
			continue
		}
		ipv4, ipv6 := "", ""
		if input.Registry != nil {
			ipv4, _ = input.Registry.AgentAddressForFamily(agentID, FamilyIPv4)
			ipv6, _ = input.Registry.AgentAddressForFamily(agentID, FamilyIPv6)
		}
		available := ipv4 != "" || ipv6 != ""
		for _, rawInbound := range config.Inbounds {
			inbound, err := parseInbound(rawInbound)
			if err != nil {
				input.note("agent %s: an inbound was skipped: %v", agentID, err)
				continue
			}
			if !supportedInboundType(inbound.Type) {
				continue
			}
			if !validComponent(inbound.Tag) {
				input.note("agent %s: inbound skipped: tag %q is not a valid ref component", agentID, inbound.Tag)
				continue
			}
			base := Entry{
				AgentID:    agentID,
				InboundTag: inbound.Tag,
				Type:       inbound.Type,
				Port:       inbound.ListenPort,
				IPv4:       ipv4,
				IPv6:       ipv6,
				Available:  available,
			}
			if inbound.Type == "shadowsocks" && len(inbound.Users) == 0 {
				entry := base
				entry.Ref = agentRef(agentID, inbound.Tag, serverKeyRefComponent)
				entry.ServerKeyOnly = true
				entries = append(entries, entry)
				continue
			}
			for _, user := range inbound.Users {
				component := user.Name
				if component == "" {
					component = serverKeyRefComponent
				}
				if !validUserComponent(component) {
					input.note(
						"agent %s: inbound %s: user %q skipped: not a valid ref component",
						agentID, inbound.Tag, user.Name,
					)
					continue
				}
				entry := base
				entry.Ref = agentRef(agentID, inbound.Tag, component)
				entry.User = user.Name
				entries = append(entries, entry)
			}
		}
	}
	if input.Registry != nil {
		for _, manual := range input.Registry.Manual() {
			entries = append(entries, Entry{
				Ref:       "manual/" + manual.Name,
				Type:      manualOutboundType(manual.Outbound),
				Port:      manualOutboundPort(manual.Outbound),
				Available: true,
				Manual:    true,
			})
		}
	}
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].AgentID != entries[right].AgentID {
			return entries[left].AgentID < entries[right].AgentID
		}
		if entries[left].InboundTag != entries[right].InboundTag {
			return entries[left].InboundTag < entries[right].InboundTag
		}
		if entries[left].User != entries[right].User {
			return entries[left].User < entries[right].User
		}
		return entries[left].Ref < entries[right].Ref
	})
	return entries
}

func agentRef(agentID, inboundTag, userComponent string) string {
	return "agent/" + agentID + "/" + inboundTag + "/" + userComponent
}

func manualOutboundType(outbound json.RawMessage) string {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(outbound, &object); err != nil {
		return ""
	}
	outboundType, _ := stringField(object, "type")
	return outboundType
}

func manualOutboundPort(outbound json.RawMessage) int {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(outbound, &object); err != nil {
		return 0
	}
	raw, exists := object["server_port"]
	if !exists {
		return 0
	}
	var port int
	if err := json.Unmarshal(raw, &port); err != nil {
		return 0
	}
	return port
}
