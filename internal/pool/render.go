package pool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/masterauguste/theatropolis/internal/deployment"
)

// PoolRefType is the outbound type marking a pool reference in a logical
// configuration: {"type":"theatropolis-pool-ref","tag":…,"ref":…}.
const PoolRefType = "theatropolis-pool-ref"

var poolRefTypeBytes = []byte(PoolRefType)

var (
	errRefTagMissing = errors.New("pool: pool-ref outbound requires a valid string tag")
	errOutboundsType = errors.New("pool: outbounds is not an array")
	errRenderedLarge = errors.New("pool: rendered configuration exceeds the 4 MiB size limit")
)

// DeriveSource resolves the latest deployed record for an agent; it returns
// nil when the agent has nothing deployed. The control server backs it with
// the deployment store.
type DeriveSource func(agentID string) *deployment.Record

// Render resolves every theatropolis-pool-ref outbound in a logical config
// into a concrete sing-box outbound and returns the rendered document plus
// all ref strings encountered, in order of appearance. An unresolvable ref
// (unknown manual name, agent gone, inbound or user not found, no usable
// address, malformed ref) degrades to {"type":"direct","tag":<tag>} and never
// fails the render.
func Render(reg *Registry, logical []byte, source DeriveSource) ([]byte, []string, error) {
	// Fast path: no pool reference can appear without the literal type name.
	if !bytes.Contains(logical, poolRefTypeBytes) {
		return logical, nil, nil
	}
	document, err := parseLogicalDocument(logical)
	if err != nil {
		return nil, nil, err
	}
	rawOutbounds, exists := document["outbounds"]
	if !exists || bytes.Equal(bytes.TrimSpace(rawOutbounds), []byte("null")) {
		return logical, nil, nil
	}
	var outbounds []json.RawMessage
	if err := json.Unmarshal(rawOutbounds, &outbounds); err != nil {
		return nil, nil, errOutboundsType
	}

	var refs []string
	rendered := make([]json.RawMessage, 0, len(outbounds))
	for _, rawOutbound := range outbounds {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(rawOutbound, &object); err != nil || object == nil {
			// Not an object: not a ref, pass through for sing-box to judge.
			rendered = append(rendered, rawOutbound)
			continue
		}
		outboundType, _ := stringField(object, "type")
		if outboundType != PoolRefType {
			rendered = append(rendered, rawOutbound)
			continue
		}
		tag, ok := stringField(object, "tag")
		if !ok || !validComponent(tag) {
			return nil, nil, fmt.Errorf("%w: %q", errRefTagMissing, tag)
		}
		ref, _ := stringField(object, "ref")
		refs = append(refs, ref)
		// The optional "family" selector pins agent-ref resolution to one IP
		// family. An unparsable value is a dead ref (direct fallback),
		// consistent with never-fail rendering; manual refs ignore it.
		family := FamilyAuto
		if familyRaw, exists := object["family"]; exists {
			var familyValue string
			if err := json.Unmarshal(familyRaw, &familyValue); err != nil {
				rendered = append(rendered, directFallback(tag))
				continue
			}
			parsed, err := ParseFamily(familyValue)
			if err != nil {
				rendered = append(rendered, directFallback(tag))
				continue
			}
			family = parsed
		}
		server := ""
		if serverRaw, exists := object["server"]; exists {
			var serverValue string
			if err := json.Unmarshal(serverRaw, &serverValue); err != nil {
				rendered = append(rendered, directFallback(tag))
				continue
			}
			normalized, err := NormalizeTLSAddress(serverValue)
			if err != nil || normalized == "" {
				rendered = append(rendered, directFallback(tag))
				continue
			}
			server = normalized
		}
		rendered = append(rendered, resolveRef(reg, source, tag, ref, family, server))
	}

	// No refs after all (the marker string appeared elsewhere): preserve the
	// input byte-for-byte instead of re-marshaling.
	if len(refs) == 0 {
		return logical, nil, nil
	}

	encodedOutbounds, err := json.Marshal(rendered)
	if err != nil {
		return nil, nil, fmt.Errorf("pool: encode rendered outbounds: %w", err)
	}
	document["outbounds"] = encodedOutbounds
	renderedDocument, err := json.Marshal(document)
	if err != nil {
		return nil, nil, fmt.Errorf("pool: encode rendered configuration: %w", err)
	}
	if len(renderedDocument) > MaxConfigBytes {
		return nil, nil, errRenderedLarge
	}
	return renderedDocument, refs, nil
}

// Refs scans a logical config and returns every pool ref string it contains,
// in order of appearance, without rendering. It is best-effort: configs that
// do not parse or carry no refs yield nil.
func Refs(logical []byte) []string {
	if !bytes.Contains(logical, poolRefTypeBytes) {
		return nil
	}
	document, err := parseLogicalDocument(logical)
	if err != nil {
		return nil
	}
	rawOutbounds, exists := document["outbounds"]
	if !exists {
		return nil
	}
	var outbounds []json.RawMessage
	if err := json.Unmarshal(rawOutbounds, &outbounds); err != nil {
		return nil
	}
	var refs []string
	for _, rawOutbound := range outbounds {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(rawOutbound, &object); err != nil {
			continue
		}
		outboundType, _ := stringField(object, "type")
		if outboundType != PoolRefType {
			continue
		}
		ref, _ := stringField(object, "ref")
		refs = append(refs, ref)
	}
	return refs
}

func parseLogicalDocument(logical []byte) (map[string]json.RawMessage, error) {
	if err := checkConfigStructure(logical); err != nil {
		return nil, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(logical, &document); err != nil {
		return nil, errConfigNotJSON
	}
	return document, nil
}

// resolveRef materializes one pool ref, falling back to a direct outbound
// with the ref object's tag whenever the ref cannot be resolved. family pins
// agent refs to one IP family (FamilyAuto walks v4 then v6); manual refs
// ignore it.
func resolveRef(
	reg *Registry,
	source DeriveSource,
	tag, ref string,
	family Family,
	server string,
) json.RawMessage {
	if materialized := resolveManualRef(reg, tag, ref); materialized != nil {
		return materialized
	}
	if materialized := resolveAgentRef(reg, source, tag, ref, family, server); materialized != nil {
		return materialized
	}
	return directFallback(tag)
}

func directFallback(tag string) json.RawMessage {
	encoded, err := json.Marshal(map[string]any{"type": "direct", "tag": tag})
	if err != nil {
		// tag passed validComponent, so marshaling cannot fail.
		panic(err)
	}
	return encoded
}

func resolveManualRef(reg *Registry, tag, ref string) json.RawMessage {
	name, ok := strings.CutPrefix(ref, "manual/")
	if !ok || !validComponent(name) {
		return nil
	}
	entry, exists := reg.ManualByName(name)
	if !exists {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(entry.Outbound, &object); err != nil {
		return nil
	}
	encodedTag, err := json.Marshal(tag)
	if err != nil {
		return nil
	}
	object["tag"] = encodedTag
	materialized, err := json.Marshal(object)
	if err != nil {
		return nil
	}
	return materialized
}

func resolveAgentRef(
	reg *Registry,
	source DeriveSource,
	tag, ref string,
	family Family,
	server string,
) json.RawMessage {
	agentID, inboundTag, userComponent, ok := parseAgentRef(ref)
	if !ok {
		return nil
	}
	address := server
	if address == "" {
		var hasAddress bool
		address, hasAddress = reg.AgentAddressForFamily(agentID, family)
		if !hasAddress {
			return nil
		}
		// Defensive: the resolved address must match the requested family.
		if family == FamilyIPv4 || family == FamilyIPv6 {
			parsed, err := netip.ParseAddr(address)
			if err != nil || parsed.Is4() != (family == FamilyIPv4) {
				return nil
			}
		}
	}
	if source == nil {
		return nil
	}
	record := source(agentID)
	if record == nil {
		return nil
	}
	config, err := parseDeployedConfig(record.ConfigJSON)
	if err != nil {
		return nil
	}
	for _, rawInbound := range config.Inbounds {
		inbound, err := parseInbound(rawInbound)
		if err != nil || inbound.Tag != inboundTag || !supportedInboundType(inbound.Type) {
			continue
		}
		// A DNS override is intentionally limited to TLS-capable protocols.
		// Shadowsocks pool refs continue to use the selected IP family.
		if server != "" && inbound.Type == "shadowsocks" {
			return nil
		}
		return materializeAgentInbound(config, inbound, tag, address, userComponent)
	}
	return nil
}

func parseAgentRef(ref string) (agentID, inboundTag, userComponent string, ok bool) {
	rest, found := strings.CutPrefix(ref, "agent/")
	if !found {
		return "", "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return "", "", "", false
	}
	if !validComponent(parts[0]) || !validComponent(parts[1]) || !validUserComponent(parts[2]) {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// materializeAgentInbound builds the concrete outbound for one resolved
// inbound. It returns nil (dead ref) when the inbound is not usable: bad
// port, missing credentials, or an unknown user.
func materializeAgentInbound(
	config *deployedConfig,
	inbound inboundConfig,
	tag, address, userComponent string,
) json.RawMessage {
	if inbound.ListenPort <= 0 || inbound.ListenPort > 65535 {
		return nil
	}
	user, serverKey, found := findUser(inbound, userComponent)
	if !found {
		return nil
	}

	var outbound map[string]any
	switch inbound.Type {
	case "shadowsocks":
		if inbound.Method == "" || inbound.Password == "" {
			return nil
		}
		password := inbound.Password
		if !serverKey {
			if user.Password == "" {
				return nil
			}
			// SIP022 EIH: server PSK and user PSK joined with a colon.
			password = inbound.Password + ":" + user.Password
		}
		outbound = map[string]any{
			"type":        "shadowsocks",
			"tag":         tag,
			"server":      address,
			"server_port": inbound.ListenPort,
			"method":      inbound.Method,
			"password":    password,
		}
	case "anytls":
		if user.Password == "" {
			return nil
		}
		outbound = map[string]any{
			"type":        "anytls",
			"tag":         tag,
			"server":      address,
			"server_port": inbound.ListenPort,
			"password":    user.Password,
			"tls":         outboundTLS(config, inbound),
		}
	case "hysteria2":
		if user.Password == "" {
			return nil
		}
		outbound = map[string]any{
			"type":        "hysteria2",
			"tag":         tag,
			"server":      address,
			"server_port": inbound.ListenPort,
			"password":    user.Password,
			"tls":         outboundTLS(config, inbound),
		}
		if inbound.UpMbps > 0 {
			outbound["up_mbps"] = inbound.UpMbps
		}
		if inbound.DownMbps > 0 {
			outbound["down_mbps"] = inbound.DownMbps
		}
		if inbound.Obfs != nil && inbound.Obfs.Type != "" {
			outbound["obfs"] = map[string]any{
				"type":     inbound.Obfs.Type,
				"password": inbound.Obfs.Password,
			}
		}
	default:
		return nil
	}
	materialized, err := json.Marshal(outbound)
	if err != nil {
		return nil
	}
	return materialized
}

// findUser resolves a ref user component against an inbound's users. The
// _server component matches an unnamed user, or — for shadowsocks — the
// server key alone (serverKey=true), which is the zero-user inbound case.
func findUser(inbound inboundConfig, userComponent string) (user inboundUser, serverKey, found bool) {
	for _, candidate := range inbound.Users {
		if candidate.Name == userComponent {
			return candidate, false, true
		}
	}
	if userComponent == serverKeyRefComponent {
		for _, candidate := range inbound.Users {
			if candidate.Name == "" {
				return candidate, false, true
			}
		}
		if inbound.Type == "shadowsocks" {
			return inboundUser{}, true, true
		}
	}
	return inboundUser{}, false, false
}

// outboundTLS builds the client-side TLS block for a materialized outbound.
// With an ACME certificate provider the server presents a publicly trusted
// certificate for the provider's domain. Otherwise (files mode or missing
// provider) the agent is assumed to serve a self-signed certificate, so
// verification is disabled and no server name is pinned.
func outboundTLS(config *deployedConfig, inbound inboundConfig) map[string]any {
	serverName := ""
	insecure := true
	if domain := config.acmeDomain(inbound); domain != "" {
		serverName = domain
		insecure = false
	}
	return map[string]any{
		"enabled":     true,
		"server_name": serverName,
		"insecure":    insecure,
	}
}
