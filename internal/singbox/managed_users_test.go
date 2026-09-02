package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

const testFullMembershipID = "mem_ABCDEFGHIJKLMMMMMMMMMMMM"

func testRollingMembershipLabel(fullID string) string {
	return fullID + "-m-" + fullID[len(managedMembershipIDPrefix):len(managedMembershipIDPrefix)+managedMembershipLegacyLen]
}

func TestManagedMembershipIdentityAcceptsLegacyAndRollingLabels(t *testing.T) {
	t.Parallel()
	legacy := "电影院-用户 一-m-ABCDEFGHIJKL"
	if key, ok := managedMembershipKey(legacy); !ok || key != "ABCDEFGHIJKL" {
		t.Fatalf("managedMembershipKey(%q) = %q, %v", legacy, key, ok)
	}
	rolling := testRollingMembershipLabel(testFullMembershipID)
	if len(rolling) != 43 {
		t.Fatalf("rolling Membership label length = %d, want 43", len(rolling))
	}
	if key, ok := managedMembershipKey(rolling); !ok || key != testFullMembershipID {
		t.Fatalf("managedMembershipKey(%q) = %q, %v", rolling, key, ok)
	}
	for _, fullID := range []string{
		"mem_ABCDEFGHIJKLmnopqrst",
		"mem_ABCDEFGHIJKLmnopqrst0123456789AB",
	} {
		if key, ok := managedMembershipKey(testRollingMembershipLabel(fullID)); !ok || key != fullID {
			t.Errorf("persisted-length managedMembershipKey(%q) = %q, %v", fullID, key, ok)
		}
	}
	identity, membership, err := parseManagedMembershipIdentity(
		testFullMembershipID + "-m-ZZZZZZZZZZZZ",
	)
	if err == nil || !membership || identity != (managedMembershipIdentity{}) {
		t.Fatalf("mismatched compatibility suffix = %#v, %v, %v; want malformed Membership", identity, membership, err)
	}
	if _, membership, err := parseManagedMembershipIdentity("cinema-link-l-ABCDEFGHIJKL"); err != nil || membership {
		t.Fatalf("Link label classified as Membership: membership=%v err=%v", membership, err)
	}
	if _, membership, err := parseManagedMembershipIdentity(testFullMembershipID); err == nil || !membership {
		t.Fatalf("markerless full Membership ID = membership=%v err=%v; want fail closed", membership, err)
	}
}

func TestManagedUserConfigRecognizesUsersOnlyChanges(t *testing.T) {
	t.Parallel()
	previous := managedUserTestConfig(`[{"name":"cinema-alice","password":"old-secret"}]`)
	candidate := managedUserTestConfig(`[{"name":"cinema-bob","password":"new-secret"}]`)
	oldConfig, err := parseManagedUserConfig(previous)
	if err != nil {
		t.Fatal(err)
	}
	newConfig, err := parseManagedUserConfig(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(oldConfig.Document, newConfig.Document) ||
		!sameManagedUserEndpoints(oldConfig.Endpoints, newConfig.Endpoints) {
		t.Fatal("users-only configs were classified as structural changes")
	}
	if len(newConfig.Endpoints) != 1 || len(newConfig.Endpoints[0].Users) != 1 ||
		newConfig.Endpoints[0].Users[0].Username != "cinema-bob" {
		t.Fatalf("managed users = %#v", newConfig.Endpoints)
	}
}

func TestReconcileManagedUsersReplacesCompleteDesiredSet(t *testing.T) {
	t.Parallel()
	previous := managedUserTestConfig(`[{"name":"cinema-alice","password":"old-secret"}]`)
	candidate := managedUserTestConfig(`[{"name":"cinema-bob","password":"new-secret"}]`)
	called := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		if request.Method != http.MethodPut ||
			request.URL.String() != "http://127.0.0.1:19090/tp-in-0123456789abcdef/server/v1/users" {
			t.Fatalf("managed-user request = %s %s", request.Method, request.URL)
		}
		var payload managedUserReplacement
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Users) != 1 || payload.Users[0].Username != "cinema-bob" ||
			payload.Users[0].Password != "new-secret" {
			t.Fatalf("replacement payload = %#v", payload)
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}
	applied, err := reconcileManagedUsersWithClient(
		context.Background(), previous, candidate, client,
	)
	if err != nil || !applied || !called {
		t.Fatalf("reconcileManagedUsersWithClient() = %v, %v, called=%v", applied, err, called)
	}
}

func TestManagedUserConfigRejectsPublicAPI(t *testing.T) {
	t.Parallel()
	config := managedUserTestConfig(`[]`)
	for index := range config {
		// The generated fixture contains this value exactly once.
		if index+len("127.0.0.1") <= len(config) && string(config[index:index+len("127.0.0.1")]) == "127.0.0.1" {
			copy(config[index:index+len("127.0.0.1")], "0.0.0.0  ")
			break
		}
	}
	if _, err := parseManagedUserConfig(config); err == nil {
		t.Fatal("public managed-user API binding was accepted")
	}
}

func TestCollectManagedUserTrafficUsesPublishedCounterSchema(t *testing.T) {
	t.Parallel()
	config := managedUserTestConfig(`[{"name":"cinema-alice-m-AAAAAAAAAAAA","password":"secret"}]`)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/tp-in-0123456789abcdef/server/v1/stats" ||
			request.URL.Query().Get("clear") != "true" {
			t.Fatalf("traffic request = %s %s", request.Method, request.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"users":[{"username":"cinema-alice-m-AAAAAAAAAAAA","uPSK":"secret","downlinkBytes":2048,"uplinkBytes":1024,"downlinkPackets":2,"uplinkPackets":1,"tcpSessions":1,"udpSessions":0}]}`,
			)),
			Header: make(http.Header),
		}, nil
	})}
	snapshot, err := collectManagedUserTrafficWithClient(context.Background(), config, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Users) != 1 ||
		snapshot.Users[0].InboundPath != "/tp-in-0123456789abcdef" ||
		snapshot.SuccessfulEndpoints != 1 || snapshot.FailedEndpoints != 0 ||
		snapshot.Users[0].Username != "cinema-alice-m-AAAAAAAAAAAA" ||
		snapshot.Users[0].UplinkBytes != 1024 || snapshot.Users[0].DownlinkBytes != 2048 {
		t.Fatalf("traffic snapshot = %#v", snapshot)
	}
}

func TestCollectManagedUserTrafficRecognizesRollingMembershipLabel(t *testing.T) {
	t.Parallel()
	username := testRollingMembershipLabel(testFullMembershipID)
	config := managedUserTestConfig(`[{"name":"` + username + `","password":"secret"}]`)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"users":[{"username":"` + username + `","uplinkBytes":10,"downlinkBytes":20}]}`,
			)),
			Header: make(http.Header),
		}, nil
	})}
	snapshot, err := collectManagedUserTrafficWithClient(context.Background(), config, client)
	if err != nil || snapshot.SuccessfulEndpoints != 1 || len(snapshot.Users) != 1 ||
		snapshot.Users[0].Username != username || snapshot.Users[0].UplinkBytes != 10 ||
		snapshot.Users[0].DownlinkBytes != 20 {
		t.Fatalf("rolling-label traffic snapshot = %#v, err=%v", snapshot, err)
	}
}

func TestCollectManagedUserTrafficPreservesSuccessfulEndpointsWhenAnotherFails(t *testing.T) {
	t.Parallel()
	config := []byte(`{
		"inbounds":[
			{"type":"anytls","tag":"tp-in-first","listen":"::","listen_port":443,"users":[{"name":"cinema-alice-m-AAAAAAAAAAAA","password":"secret"}]},
			{"type":"anytls","tag":"tp-in-second","listen":"::","listen_port":444,"users":[{"name":"cinema-bob-m-BBBBBBBBBBBB","password":"secret"}]}
		],
		"outbounds":[{"type":"direct","tag":"tp-direct"}],
		"route":{"rules":[],"final":"tp-direct"},
		"services":[{"type":"ssm-api","tag":"tp-managed-users","listen":"127.0.0.1","listen_port":19090,"servers":{
			"/tp-in-first":"tp-in-first","/tp-in-second":"tp-in-second"
		}}]
	}`)
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Query().Get("clear") != "true" {
			t.Fatalf("traffic request did not clear counters: %s", request.URL)
		}
		if requests == 1 {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(
					`{"users":[{"username":"cinema-alice-m-AAAAAAAAAAAA","uplinkBytes":10,"downlinkBytes":20}]}`,
				)),
				Header: make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(`{"error":"unavailable"}`)),
			Header:     make(http.Header),
		}, nil
	})}
	snapshot, err := collectManagedUserTrafficWithClient(context.Background(), config, client)
	if err == nil {
		t.Fatal("second endpoint failure was accepted")
	}
	if snapshot.SuccessfulEndpoints != 1 || snapshot.FailedEndpoints != 1 || len(snapshot.Users) != 1 ||
		snapshot.Users[0].Username != "cinema-alice-m-AAAAAAAAAAAA" || snapshot.Users[0].UplinkBytes != 10 {
		t.Fatalf("partial traffic snapshot = %#v", snapshot)
	}
}

func TestCollectManagedUserTrafficSkipsChildOnlyEndpoints(t *testing.T) {
	t.Parallel()
	config := []byte(`{
		"inbounds":[
			{"type":"anytls","tag":"tp-in-entrance","listen":"::","listen_port":443,"users":[{"name":"cinema-alice-m-AAAAAAAAAAAA","password":"secret"}]},
			{"type":"anytls","tag":"tp-in-child","listen":"::","listen_port":444,"users":[{"name":"cinema-link-l-LLLLLLLLLLLL","password":"secret"}]}
		],
		"outbounds":[{"type":"direct","tag":"tp-direct"}],
		"route":{"rules":[],"final":"tp-direct"},
		"services":[{"type":"ssm-api","tag":"tp-managed-users","listen":"127.0.0.1","listen_port":19090,"servers":{
			"/tp-in-entrance":"tp-in-entrance","/tp-in-child":"tp-in-child"
		}}]
	}`)
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Path != "/tp-in-entrance/server/v1/stats" {
			t.Fatalf("sampled child endpoint %q", request.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"users":[{"username":"cinema-alice-m-AAAAAAAAAAAA","uplinkBytes":10}]}`,
			)),
			Header: make(http.Header),
		}, nil
	})}
	snapshot, err := collectManagedUserTrafficWithClient(context.Background(), config, client)
	if err != nil || requests != 1 || snapshot.SuccessfulEndpoints != 1 || len(snapshot.Users) != 1 {
		t.Fatalf("entrance-only snapshot=%#v requests=%d err=%v", snapshot, requests, err)
	}
}

func TestCollectManagedUserTrafficAcceptsLegacyProfileWithoutEntranceMemberships(t *testing.T) {
	t.Parallel()
	config := []byte(`{
		"inbounds":[
			{"type":"anytls","tag":"tp-in-empty-entrance","listen":"::","listen_port":443,"users":[]},
			{"type":"shadowsocks","tag":"tp-in-child","listen":"::","listen_port":20048,"users":[{"name":"cinema-link-l-LLLLLLLLLLLL","password":"secret"}]}
		],
		"outbounds":[{"type":"direct","tag":"tp-direct"}],
		"route":{"rules":[],"final":"tp-direct"}
	}`)
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("unexpected accounting request")
	})}
	snapshot, err := collectManagedUserTrafficWithClient(context.Background(), config, client)
	if err != nil || requests != 0 || len(snapshot.Users) != 0 ||
		snapshot.SuccessfulEndpoints != 0 || snapshot.FailedEndpoints != 0 {
		t.Fatalf("legacy relay-only snapshot=%#v requests=%d err=%v", snapshot, requests, err)
	}
}

func TestCollectManagedUserTrafficRejectsLegacyProfileWithEntranceMembership(t *testing.T) {
	t.Parallel()
	config := []byte(`{
		"inbounds":[
			{"type":"anytls","tag":"tp-in-entrance","listen":"::","listen_port":443,"users":[{"name":"cinema-alice-m-AAAAAAAAAAAA","password":"secret"}]}
		],
		"outbounds":[{"type":"direct","tag":"tp-direct"}],
		"route":{"rules":[],"final":"tp-direct"}
	}`)
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("unexpected accounting request")
	})}
	if _, err := collectManagedUserTrafficWithClient(context.Background(), config, client); err == nil {
		t.Fatal("legacy entrance Membership was accepted without its accounting service")
	}
	if requests != 0 {
		t.Fatalf("legacy entrance made %d accounting requests without a service", requests)
	}
}

func TestTopologyRetainsOnlyAgentAuthorizedMemberships(t *testing.T) {
	t.Parallel()
	active := managedUserTestConfig(`[
		{"name":"cinema-alice-m-AAAAAAAAAAAA","password":"old-alice"},
		{"name":"cinema-link-l-LLLLLLLLLLLL","password":"old-link"}
	]`)
	candidate := managedUserTestConfig(`[
		{"name":"renamed-alice-m-AAAAAAAAAAAA","password":"rotated-alice"},
		{"name":"cinema-bob-m-BBBBBBBBBBBB","password":"stale-bob"},
		{"name":"cinema-link-l-NNNNNNNNNNNN","password":"new-link"}
	]`)
	filtered, err := retainAuthorizedMemberships(active, candidate)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseManagedUserConfig(filtered)
	if err != nil {
		t.Fatal(err)
	}
	users := parsed.Endpoints[0].Users
	if len(users) != 2 || users[0].Username != "cinema-link-l-NNNNNNNNNNNN" ||
		users[1].Username != "renamed-alice-m-AAAAAAAAAAAA" ||
		users[1].Password != "rotated-alice" {
		t.Fatalf("filtered topology users = %#v", users)
	}
}

func TestTopologyRetainsMembershipAcrossLegacyAndRollingLabels(t *testing.T) {
	t.Parallel()
	legacy := "cinema-alice-m-ABCDEFGHIJKL"
	rolling := testRollingMembershipLabel(testFullMembershipID)
	for _, testCase := range []struct {
		name         string
		active       string
		candidate    string
		wantUsername string
	}{
		{name: "legacy active to rolling candidate", active: legacy, candidate: rolling, wantUsername: rolling},
		{name: "rolling active to legacy candidate", active: rolling, candidate: legacy, wantUsername: legacy},
		{name: "pre-marker active to rolling candidate", active: "cinema-alice-ABCDEFGHIJKL", candidate: rolling, wantUsername: rolling},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			active := managedUserTestConfig(`[{"name":"` + testCase.active + `","password":"old"}]`)
			candidate := managedUserTestConfig(`[{"name":"` + testCase.candidate + `","password":"current"}]`)
			filtered, err := retainAuthorizedMemberships(active, candidate)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parseManagedUserConfig(filtered)
			if err != nil {
				t.Fatal(err)
			}
			if users := parsed.Endpoints[0].Users; len(users) != 1 || users[0].Username != testCase.wantUsername {
				t.Fatalf("retained users = %#v, want %q", users, testCase.wantUsername)
			}
		})
	}
}

func TestTopologyMembershipAliasCollisionsFailClosed(t *testing.T) {
	t.Parallel()
	otherFullID := "mem_ABCDEFGHIJKLNNNNNNNNNNNN"
	first := testRollingMembershipLabel(testFullMembershipID)
	second := testRollingMembershipLabel(otherFullID)

	active := managedUserTestConfig(`[{"name":"` + first + `","password":"first"}]`)
	candidate := managedUserTestConfig(`[{"name":"` + second + `","password":"second"}]`)
	if _, err := retainAuthorizedMemberships(active, candidate); !errors.Is(err, errAmbiguousManagedMembershipIdentity) {
		t.Fatalf("cross-generation alias collision error = %v", err)
	}

	candidate = managedUserTestConfig(`[
		{"name":"` + first + `","password":"first"},
		{"name":"` + second + `","password":"second"}
	]`)
	if _, err := retainAuthorizedMemberships(DisabledManagedConfig(), candidate); !errors.Is(err, errAmbiguousManagedMembershipIdentity) {
		t.Fatalf("candidate alias collision error = %v", err)
	}

	malformed := testFullMembershipID + "-m-ZZZZZZZZZZZZ"
	candidate = managedUserTestConfig(`[{"name":"` + malformed + `","password":"malformed"}]`)
	if _, err := retainAuthorizedMemberships(DisabledManagedConfig(), candidate); !errors.Is(err, errInvalidManagedMembershipIdentity) {
		t.Fatalf("malformed rolling identity error = %v", err)
	}
}

func TestTopologyWithoutActiveAuthorityCannotIntroduceMembership(t *testing.T) {
	t.Parallel()
	candidate := managedUserTestConfig(`[
		{"name":"cinema-alice-m-AAAAAAAAAAAA","password":"alice"},
		{"name":"cinema-link-l-LLLLLLLLLLLL","password":"link"}
	]`)
	filtered, err := retainAuthorizedMemberships(DisabledManagedConfig(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseManagedUserConfig(filtered)
	if err != nil {
		t.Fatal(err)
	}
	users := parsed.Endpoints[0].Users
	if len(users) != 1 || users[0].Username != "cinema-link-l-LLLLLLLLLLLL" {
		t.Fatalf("filtered first topology users = %#v", users)
	}
}

func TestManagedUserAuthorityReplacesMembershipsButPreservesLinkCredentials(t *testing.T) {
	t.Parallel()
	authoritative := managedUserTestConfig(`[
		{"name":"cinema-alice-m-AAAAAAAAAAAA","password":"alice-current"},
		{"name":"cinema-link-l-OLDLINK00000","password":"old-link"}
	]`)
	variant, err := BuildManagedUserAuthorityVariant(authoritative)
	if err != nil {
		t.Fatal(err)
	}
	candidate := managedUserTestConfig(`[
		{"name":"cinema-bob-m-BBBBBBBBBBBB","password":"stale-bob"},
		{"name":"cinema-link-l-NEWLINK00000","password":"new-link"}
	]`)
	overlaid, matched, err := applyManagedUserAuthority(candidate, []ManagedUserAuthorityVariant{variant})
	if err != nil || !matched {
		t.Fatalf("applyManagedUserAuthority() matched=%v err=%v", matched, err)
	}
	parsed, err := parseManagedUserConfig(overlaid)
	if err != nil {
		t.Fatal(err)
	}
	users := parsed.Endpoints[0].Users
	if len(users) != 2 || users[0].Username != "cinema-alice-m-AAAAAAAAAAAA" ||
		users[0].Password != "alice-current" || users[1].Username != "cinema-link-l-NEWLINK00000" ||
		users[1].Password != "new-link" {
		t.Fatalf("overlaid users = %#v", users)
	}
}

func TestManagedUserAuthorityRecognizesRollingMembershipLabel(t *testing.T) {
	t.Parallel()
	rolling := testRollingMembershipLabel(testFullMembershipID)
	variant, err := BuildManagedUserAuthorityVariant(managedUserTestConfig(`[
		{"name":"` + rolling + `","password":"membership"},
		{"name":"cinema-link-l-LLLLLLLLLLLL","password":"link"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(variant.Endpoints) != 1 || len(variant.Endpoints[0].Users) != 1 ||
		variant.Endpoints[0].Users[0].Username != rolling {
		t.Fatalf("rolling authority variant = %#v", variant)
	}
}

func managedUserTestConfig(users string) []byte {
	return []byte(`{
		"inbounds":[{"type":"anytls","tag":"tp-in-0123456789abcdef","listen":"::","listen_port":443,"users":` + users + `}],
		"outbounds":[{"type":"direct","tag":"tp-direct"}],
		"route":{"rules":[],"final":"tp-direct"},
		"services":[{"type":"ssm-api","tag":"tp-managed-users","listen":"127.0.0.1","listen_port":19090,"servers":{"/tp-in-0123456789abcdef":"tp-in-0123456789abcdef"}}]
	}`)
}
