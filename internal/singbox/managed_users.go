package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ManagedUserAPIListenPort = 19090
	ManagedUserAPIServiceTag = "tp-managed-users"
	managedUserAPITimeout    = 5 * time.Second
)

type managedUser struct {
	Username string `json:"username"`
	Password string `json:"uPSK"`
}

type managedUserReplacement struct {
	Users []managedUser `json:"users"`
}

type ManagedUserTraffic struct {
	InboundPath   string
	Username      string
	UplinkBytes   uint64
	DownlinkBytes uint64
}

type ManagedUserTrafficSnapshot struct {
	Users               []ManagedUserTraffic
	SuccessfulEndpoints int
	FailedEndpoints     int
}

type managedUserTrafficResponse struct {
	Users []struct {
		Username      string `json:"username"`
		UplinkBytes   uint64 `json:"uplinkBytes"`
		DownlinkBytes uint64 `json:"downlinkBytes"`
	} `json:"users"`
}

type managedUserEndpoint struct {
	Path  string
	Users []managedUser
}

type managedUserConfig struct {
	Document  map[string]any
	Endpoints []managedUserEndpoint
}

// reconcileManagedUsers applies a users-only configuration change through the
// loopback SSM API. Its boolean reports whether the change was users-only even
// when an API request fails, allowing the manager to restart immediately and
// repair any partially reconciled listeners.
func reconcileManagedUsers(
	ctx context.Context,
	previousConfig, candidateConfig []byte,
) (bool, error) {
	return reconcileManagedUsersWithClient(
		ctx,
		previousConfig,
		candidateConfig,
		managedUserHTTPClient(),
	)
}

func reconcileManagedUsersWithClient(
	ctx context.Context,
	previousConfig, candidateConfig []byte,
	client *http.Client,
) (bool, error) {
	previous, err := parseManagedUserConfig(previousConfig)
	if err != nil {
		return false, nil
	}
	candidate, err := parseManagedUserConfig(candidateConfig)
	if err != nil {
		return false, nil
	}
	if len(candidate.Endpoints) == 0 ||
		!reflect.DeepEqual(previous.Document, candidate.Document) ||
		!sameManagedUserEndpoints(previous.Endpoints, candidate.Endpoints) {
		return false, nil
	}

	for _, endpoint := range candidate.Endpoints {
		payload, marshalErr := json.Marshal(managedUserReplacement{Users: endpoint.Users})
		if marshalErr != nil {
			return true, errors.New("encode managed-user replacement")
		}
		requestContext, cancel := context.WithTimeout(ctx, managedUserAPITimeout)
		request, requestErr := http.NewRequestWithContext(
			requestContext,
			http.MethodPut,
			"http://127.0.0.1:"+strconv.Itoa(ManagedUserAPIListenPort)+
				endpoint.Path+"/server/v1/users",
			bytes.NewReader(payload),
		)
		if requestErr != nil {
			cancel()
			return true, errors.New("prepare managed-user replacement")
		}
		request.Header.Set("Content-Type", "application/json")
		response, requestErr := client.Do(request)
		if requestErr != nil {
			cancel()
			return true, errors.New("managed-user API is unavailable")
		}
		_, drainErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		closeErr := response.Body.Close()
		cancel()
		if requestErr != nil || drainErr != nil || closeErr != nil ||
			response.StatusCode != http.StatusNoContent {
			return true, errors.New("managed-user API rejected the replacement")
		}
	}
	return true, nil
}

func managedUserHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: managedUserAPITimeout}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "127.0.0.1:"+strconv.Itoa(ManagedUserAPIListenPort) {
					return nil, errors.New("managed-user API target is not loopback")
				}
				return dialer.DialContext(ctx, network, address)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("managed-user API redirects are not allowed")
		},
	}
}

// ManagedUserTraffic atomically reads and clears the interval counters from
// every loopback-only managed-user endpoint in the active configuration. The
// returned values are deliberately ephemeral deltas: the Agent does not keep
// a durable traffic ledger. It never accepts a URL from the network and never
// exposes the API listener beyond loopback.
func (m *Manager) ManagedUserTraffic(ctx context.Context) (ManagedUserTrafficSnapshot, error) {
	config, exists, err := m.loadActiveConfig()
	if err != nil {
		return ManagedUserTrafficSnapshot{}, err
	}
	if !exists {
		return ManagedUserTrafficSnapshot{}, nil
	}
	raw, err := collectManagedUserTrafficWithClient(ctx, config, managedUserHTTPClient())
	clear(config)
	return raw, err
}

func collectManagedUserTrafficWithClient(
	ctx context.Context,
	config []byte,
	client *http.Client,
) (ManagedUserTrafficSnapshot, error) {
	hasMemberships, err := managedConfigHasMemberships(config)
	if err != nil {
		return ManagedUserTrafficSnapshot{}, err
	}
	// Older applied profiles and relay-only Agents may legitimately have no
	// managed-user service. Accounting belongs exclusively to entrance
	// Memberships, so detect that authority before requiring or contacting the
	// loopback API. A profile that actually carries a Membership still fails
	// closed below when its service is absent or malformed.
	if !hasMemberships {
		return ManagedUserTrafficSnapshot{}, nil
	}
	parsed, err := parseManagedUserConfig(config)
	if err != nil {
		return ManagedUserTrafficSnapshot{}, err
	}
	result := ManagedUserTrafficSnapshot{}
	for _, endpoint := range parsed.Endpoints {
		membershipUsers := make(map[string]struct{})
		for _, user := range endpoint.Users {
			_, membership, identityErr := parseManagedMembershipIdentity(user.Username)
			if identityErr != nil {
				return result, identityErr
			}
			if membership {
				membershipUsers[user.Username] = struct{}{}
			}
		}
		// Link credentials use the same physical SSM service, but accounting is
		// owned exclusively by Proxy Node entrances. Do not query child-only
		// listeners at all.
		if len(membershipUsers) == 0 {
			continue
		}
		requestContext, cancel := context.WithTimeout(ctx, managedUserAPITimeout)
		request, requestErr := http.NewRequestWithContext(
			requestContext,
			http.MethodGet,
			"http://127.0.0.1:"+strconv.Itoa(ManagedUserAPIListenPort)+endpoint.Path+"/server/v1/stats?clear=true",
			nil,
		)
		if requestErr != nil {
			cancel()
			result.FailedEndpoints++
			continue
		}
		response, requestErr := client.Do(request)
		if requestErr != nil {
			cancel()
			result.FailedEndpoints++
			continue
		}
		limited := io.LimitReader(response.Body, 16<<20)
		var payload managedUserTrafficResponse
		decodeErr := json.NewDecoder(limited).Decode(&payload)
		closeErr := response.Body.Close()
		cancel()
		if response.StatusCode != http.StatusOK || decodeErr != nil || closeErr != nil {
			result.FailedEndpoints++
			continue
		}
		endpointUsers := make([]ManagedUserTraffic, 0, len(payload.Users))
		validEndpoint := true
		for _, user := range payload.Users {
			if _, membership := membershipUsers[user.Username]; !membership {
				continue
			}
			if strings.TrimSpace(user.Username) == "" || len(user.Username) > 128 || strings.ContainsRune(user.Username, '\x00') {
				validEndpoint = false
				break
			}
			endpointUsers = append(endpointUsers, ManagedUserTraffic{
				InboundPath: endpoint.Path, Username: user.Username,
				UplinkBytes: user.UplinkBytes, DownlinkBytes: user.DownlinkBytes,
			})
		}
		if !validEndpoint {
			result.FailedEndpoints++
			continue
		}
		result.SuccessfulEndpoints++
		result.Users = append(result.Users, endpointUsers...)
	}
	if result.FailedEndpoints > 0 {
		return result, errors.New("one or more entrance traffic endpoints failed")
	}
	return result, nil
}

func managedConfigHasMemberships(encoded []byte) (bool, error) {
	var document map[string]any
	if err := decodeManagedDocument(encoded, &document); err != nil {
		return false, err
	}
	_, count, err := managedMembershipIdentityIndexForNames(managedDocumentUserNames(document))
	return count > 0, err
}

func parseManagedUserConfig(encoded []byte) (managedUserConfig, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return managedUserConfig{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return managedUserConfig{}, errors.New("configuration contains trailing data")
	}

	servers, err := managedUserServers(document)
	if err != nil {
		return managedUserConfig{}, err
	}
	inbounds, ok := document["inbounds"].([]any)
	if !ok {
		return managedUserConfig{}, errors.New("configuration has no inbounds")
	}
	byTag := make(map[string]map[string]any, len(inbounds))
	for _, rawInbound := range inbounds {
		inbound, ok := rawInbound.(map[string]any)
		if !ok {
			return managedUserConfig{}, errors.New("configuration has an invalid inbound")
		}
		tag, _ := inbound["tag"].(string)
		if tag != "" {
			byTag[tag] = inbound
		}
	}

	paths := make([]string, 0, len(servers))
	for path := range servers {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	endpoints := make([]managedUserEndpoint, 0, len(paths))
	for _, path := range paths {
		if !validManagedUserPath(path) {
			return managedUserConfig{}, errors.New("configuration has an invalid managed-user path")
		}
		inbound := byTag[servers[path]]
		if inbound == nil || !managedInboundType(inbound["type"]) {
			return managedUserConfig{}, errors.New("managed-user service references an unsupported inbound")
		}
		users, err := extractManagedUsers(inbound["users"])
		if err != nil {
			return managedUserConfig{}, err
		}
		delete(inbound, "users")
		endpoints = append(endpoints, managedUserEndpoint{Path: path, Users: users})
	}
	return managedUserConfig{Document: document, Endpoints: endpoints}, nil
}

func managedUserServers(document map[string]any) (map[string]string, error) {
	services, ok := document["services"].([]any)
	if !ok {
		return nil, errors.New("configuration has no managed-user service")
	}
	for _, rawService := range services {
		service, ok := rawService.(map[string]any)
		if !ok || service["type"] != "ssm-api" || service["tag"] != ManagedUserAPIServiceTag {
			continue
		}
		port, ok := service["listen_port"].(json.Number)
		if !ok || port.String() != strconv.Itoa(ManagedUserAPIListenPort) ||
			service["listen"] != "127.0.0.1" {
			return nil, errors.New("managed-user service is not restricted to its reserved loopback endpoint")
		}
		rawServers, ok := service["servers"].(map[string]any)
		if !ok {
			return nil, errors.New("managed-user service has invalid servers")
		}
		servers := make(map[string]string, len(rawServers))
		for path, rawTag := range rawServers {
			tag, ok := rawTag.(string)
			if !ok || tag == "" {
				return nil, errors.New("managed-user service has an invalid inbound tag")
			}
			servers[path] = tag
		}
		return servers, nil
	}
	return nil, errors.New("configuration has no managed-user service")
}

func extractManagedUsers(raw any) ([]managedUser, error) {
	rawUsers, ok := raw.([]any)
	if !ok {
		return nil, errors.New("managed inbound has invalid users")
	}
	users := make([]managedUser, 0, len(rawUsers))
	seen := make(map[string]struct{}, len(rawUsers))
	for _, rawUser := range rawUsers {
		userObject, ok := rawUser.(map[string]any)
		if !ok {
			return nil, errors.New("managed inbound has an invalid user")
		}
		name, nameOK := userObject["name"].(string)
		password, passwordOK := userObject["password"].(string)
		if !nameOK || !passwordOK || name == "" || password == "" {
			return nil, errors.New("managed inbound has an incomplete user")
		}
		if _, exists := seen[name]; exists {
			return nil, errors.New("managed inbound has duplicate users")
		}
		seen[name] = struct{}{}
		users = append(users, managedUser{Username: name, Password: password})
	}
	sort.Slice(users, func(left, right int) bool { return users[left].Username < users[right].Username })
	return users, nil
}

func sameManagedUserEndpoints(left, right []managedUserEndpoint) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Path != right[index].Path {
			return false
		}
	}
	return true
}

func managedInboundType(raw any) bool {
	value, _ := raw.(string)
	return value == "shadowsocks" || value == "anytls" || value == "hysteria2"
}

func validManagedUserPath(path string) bool {
	if !strings.HasPrefix(path, "/tp-in-") || len(path) > 80 {
		return false
	}
	for _, character := range path[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// retainAuthorizedMemberships filters only generated end-user identities.
// Link identities remain topology-owned and therefore pass through unchanged.
// The stable membership suffix also permits a Proxy Node or username rename
// without treating the renamed identity as a newly authorized account.
func retainAuthorizedMemberships(activeConfig, candidateConfig []byte) ([]byte, error) {
	var candidate map[string]any
	if err := decodeManagedDocument(candidateConfig, &candidate); err != nil {
		return nil, err
	}
	candidateIdentities, candidateCount, err := managedMembershipIdentityIndexForNames(managedDocumentUserNames(candidate))
	if err != nil {
		return nil, err
	}
	if candidateCount == 0 {
		return append([]byte(nil), candidateConfig...), nil
	}
	authorized := newManagedMembershipIdentityIndex()
	var active map[string]any
	if len(bytes.TrimSpace(activeConfig)) > 0 && decodeManagedDocument(activeConfig, &active) == nil {
		for _, name := range managedDocumentUserNames(active) {
			identity, membership, identityErr := parseManagedMembershipIdentity(name)
			if identityErr != nil {
				return nil, identityErr
			}
			if membership {
				if err := authorized.add(identity); err != nil {
					return nil, err
				}
				continue
			}
			// Before the stable -m- marker, readable Membership labels ended in
			// -<12>. Retain that one-way active-profile compatibility until old
			// profiles have all been replaced; candidate identities remain strict.
			for legacyKey := range candidateIdentities.byLegacy {
				if !strings.HasSuffix(name, "-"+legacyKey) {
					continue
				}
				if err := authorized.add(managedMembershipIdentity{LegacyKey: legacyKey}); err != nil {
					return nil, err
				}
				break
			}
		}
	}
	inbounds, _ := candidate["inbounds"].([]any)
	for _, rawInbound := range inbounds {
		inbound, _ := rawInbound.(map[string]any)
		rawUsers, _ := inbound["users"].([]any)
		filtered := make([]any, 0, len(rawUsers))
		for _, rawUser := range rawUsers {
			user, _ := rawUser.(map[string]any)
			name, _ := user["name"].(string)
			identity, membership, identityErr := parseManagedMembershipIdentity(name)
			if identityErr != nil {
				return nil, identityErr
			}
			if membership {
				allowed, matchErr := authorized.authorizes(identity)
				if matchErr != nil {
					return nil, matchErr
				}
				if !allowed {
					continue
				}
			}
			filtered = append(filtered, rawUser)
		}
		inbound["users"] = filtered
	}
	encoded, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func decodeManagedDocument(encoded []byte, target *map[string]any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("configuration contains trailing data")
	}
	return nil
}

func managedDocumentUserNames(document map[string]any) []string {
	var result []string
	inbounds, _ := document["inbounds"].([]any)
	for _, rawInbound := range inbounds {
		inbound, _ := rawInbound.(map[string]any)
		rawUsers, _ := inbound["users"].([]any)
		for _, rawUser := range rawUsers {
			user, _ := rawUser.(map[string]any)
			if name, ok := user["name"].(string); ok {
				result = append(result, name)
			}
		}
	}
	return result
}
