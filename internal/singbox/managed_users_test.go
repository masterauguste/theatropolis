package singbox

import (
	"context"
	"encoding/json"
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

func managedUserTestConfig(users string) []byte {
	return []byte(`{
		"inbounds":[{"type":"anytls","tag":"tp-in-0123456789abcdef","listen":"::","listen_port":443,"users":` + users + `}],
		"outbounds":[{"type":"direct","tag":"tp-direct"}],
		"route":{"rules":[],"final":"tp-direct"},
		"services":[{"type":"ssm-api","tag":"tp-managed-users","listen":"127.0.0.1","listen_port":19090,"servers":{"/tp-in-0123456789abcdef":"tp-in-0123456789abcdef"}}]
	}`)
}
