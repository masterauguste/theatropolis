# Proxy Node Manager Design

Status: implemented product model.

This document defines the intended replacement for Theatropolis's current
per-agent sing-box configuration manager. It also records the proposed
cutover policy for installations that contain state from the old manager.

## Goals

Theatropolis manages logical proxy services rather than treating every enrolled
server as an independently configured sing-box instance.

A **Proxy Node** is a rooted routing tree. Traffic enters through exactly one
logical entrance, can branch through zero or more relay hops, and eventually
terminates at `direct` or `reject`. Every participating server remains an
unprivileged Agent controlled by the master.

The design must provide:

- independently configurable Proxy Nodes on the same Agent fleet;
- one entrance per Proxy Node, with branching but no merging or cycles;
- a configurable relay protocol on every link;
- global end users that can be assigned to multiple Proxy Nodes;
- automatically generated, membership-specific end-user credentials;
- automatically generated, link-specific relay credentials;
- optional sharing of a physical sing-box listener by compatible logical
  inbounds; and
- generated sing-box configuration which cannot route traffic from one Proxy
  Node into another except through an explicit link.

Importing or translating arbitrary configurations from the old configuration
manager is explicitly not a goal of the first Proxy Node release.

## Domain model

All persisted entities have an immutable, opaque internal ID. Human-readable
names may change and must never be used as database identity or foreign keys.

### Agent

An Agent is an enrolled physical or virtual server running the Theatropolis
agent and sing-box. Enrollment does not make an Agent a Proxy Node or assign it
any proxy role.

An Agent can host entrances and relay hops for any number of Proxy Nodes,
subject to listener compatibility and resource constraints.

### End User

An End User is a global administrator-managed identity. It exists above Proxy
Nodes and can be assigned to any number of them.

Deleting an End User revokes all of its Proxy Node memberships. Removing one
membership revokes access only to that Proxy Node.

### Proxy Node

A Proxy Node is an independently managed logical proxy service. It contains:

- a mutable, unique name;
- exactly one entrance;
- one or more logical hops;
- ordered links from each hop, with Link-owned match clauses;
- links from a hop to child hops; and
- terminal `direct` or `reject` outcomes.

The Proxy Node name is also the human-readable namespace used in generated
sing-box tags and authenticated-user labels. There is no separate immutable
slug exposed to administrators. The opaque Proxy Node ID remains stable across
renames.

### Entrance and logical inbounds

An inbound is not a top-level administrator-managed resource. It exists only
inside a Proxy Node:

- the root has one logical entrance inbound; and
- each incoming relay link causes a logical relay inbound to be rendered on
  the child hop.

Each logical inbound describes its Agent, protocol, listen address and port,
transport, TLS settings, and other protocol-specific options.

Several logical inbounds may compile into one physical sing-box inbound. For
example, two Proxy Nodes may both use a compatible AnyTLS listener on port 443
of the same Agent. Listener sharing is an implementation detail, not a
separately managed object in the product model.

Logical inbounds may be combined only when all socket- and protocol-level
settings are compatible. At minimum this includes the Agent, network, listen
address, port, protocol, transport, TLS behavior, and protocol options that
apply to the complete listener. An incompatible collision on the same socket is
a validation error and must not be resolved by silently changing either Proxy
Node.

### Hop

A Hop is a logical position in one Proxy Node's routing tree and is assigned to
an Agent. It is not the Agent itself.

The entrance is the root hop. Every other hop has exactly one incoming link,
which is what "one parent" means. A hop can have multiple outgoing links, so
branching is allowed. Two branches cannot converge on the same logical hop.

The initial topology is a strict rooted tree:

- exactly one root/entrance;
- every non-root hop has exactly one parent;
- a hop may have any number of children;
- no merges;
- no cycles; and
- all topology is configured manually by an administrator.

### Link

A Link connects one parent hop to one child hop. Its relay protocol and
protocol-specific options are configured independently.

Logical inbounds across one or more Proxy Nodes may share a physical listener
when their Agent, listen address, transport, protocol, and all administrator-
selected listener options are compatible. Listener-owned generated material is
reused automatically: the Shadowsocks 2022 server key and Hysteria2
obfuscation secret belong to the shared listener, while AnyTLS has no separate
generated listener secret. Membership and Link user credentials are never
shared. Shadowsocks claims both TCP and UDP for conflict detection; AnyTLS
claims TCP and Hysteria2 claims UDP, so AnyTLS and Hysteria2 may use the same
numeric port but neither can overlap a Shadowsocks listener on that address.
Existing state with compatible per-endpoint listener secrets is reconciled to
one stable listener identity when loaded. Listener lifetime is derived from its
logical references: deleting one Membership or Link removes only its user and
routing identity, while the physical listener remains for other references;
deleting the final reference removes the listener on the next deployment.

For a Shadowsocks Link with multiplexing enabled, the child inbound accepts
multiplexed sessions and the parent outbound explicitly selects `smux`.
Multiplex protocol selection is an outbound-only sing-box option; the child
inbound therefore carries the shared padding and TCP Brutal policy but no
`protocol` field.

Each Link also owns zero or more routing match clauses. Clauses on one Link are
ORed together, sibling Links are evaluated in administrator-defined order, and
the first matching Link wins. A Link with no clauses is inactive unless it is
explicitly the Hop's fallback Link. At most one fallback Link exists per Hop and
it is always ordered last.

Every Link receives its own automatically generated credentials. Those
credentials are shared by all end-user traffic traversing that Link, but are
never reused by another Link, including another Link in the same Proxy Node.
Compromise of one Link credential therefore does not grant access through a
different Link.

End-user identity is deliberately not propagated across a Link. Per-user
accounting and revocation are available at the entrance, but routing scope is
not configurable per user, inbound, or server. A downstream hop sees the
Link's authenticated identity.

### Terminal

A terminal outcome is always one of:

- `direct`: use that Agent's direct network connection; or
- `reject`: deny the traffic.

Other proxy protocols are not terminal types. Sending traffic to another
server is represented by a Link to another Hop.

### Membership and end-user credentials

A Membership assigns one global End User to one Proxy Node. The pair
`(end_user_id, proxy_node_id)` is unique.

Proxy Node access is granted and revoked from the End User's settings rather
than by adding users from a Proxy Node page. Creating a Membership
automatically generates fresh credentials compatible with the Proxy Node's
entrance protocol. Administrators cannot choose or reuse the secret.
Credentials are unique per Membership even when the same End User belongs to
several Proxy Nodes or the Proxy Nodes currently have distinct entrances.

The generated authenticated-user label follows:

```text
<proxy-node-name>-<end-user-name>
```

For example, global End User `alice` can have:

```text
cinema-alice  -> generated membership secret A
archive-alice -> generated membership secret B
```

Membership-specific credentials are required when compatible logical
entrances share a physical listener. For protocols such as AnyTLS, the client
sends the password but does not send the server-side user label. If two user
records on one listener had different labels but the same password, sing-box
could not determine which Proxy Node the client intended.

Credentials are protocol-shaped. A password, UUID, Shadowsocks key, or
username/password pair cannot be treated as one interchangeable value. The
Membership owns the appropriate generated credential material for its entrance
protocol.

Secrets are displayed only through an explicit administrator action and are
handled as sensitive state. Diagnostics, logs, topology exports, and ordinary
list views must not contain them.

## Routing and rendering

The master stores the logical model and compiles all affected Proxy Nodes into
one complete sing-box configuration per Agent. Administrators do not edit the
generated JSON as authoritative state.

At an entrance, authentication maps a connection to a Membership-specific
`auth_user` label. Generated rules use that label to select only that Proxy
Node's root routing tree. At a relay inbound, authentication maps the
connection to that Link's identity and selects the child Hop's routing tree.

Child Links at each Hop are ordered and their Link-owned match clauses apply to
all Proxy Node traffic which reaches that Hop. There is no separately
configurable routing scope. Multiple clauses on one Link are ORed. The first
matching Link wins; an optional unconditional fallback Link is evaluated last;
otherwise the Hop's required `direct` or `reject` terminal is used. The compiler
rejects missing targets, cycles, merges, listener conflicts, duplicate wire
credentials on a combined listener, and references outside the owning Proxy
Node.

A `direct` or `reject` terminal is compiled into the sing-box configuration of
the Agent hosting that Hop. A selected Link is compiled on the parent Agent and
hands traffic to the child Hop, whose own ordered Links and terminal then take
over. Consequently, the terminal action for a relayed path executes on that
path's final Hop, not on its entrance or an earlier relay.

The Proxy Node overview renders this model as a recursive routing tree. Hop
cards stay compact, and each Link-owned match clause appears as its own visible
branch labelled with the actual match type and values. These branches are only
distinct route presentations: clauses that target the same logical Link still
share its child Hop, endpoint, relay credential, and single sing-box
authenticated user. A fallback Link appears as one final fallback branch, and
a Link with no rule remains as a visibly inactive branch. Direct/Reject targets
identify the Agent on which they terminate. Selecting any route branch opens
the shared Link inspector with routing ownership, protocol, fallback state,
listener data, and controls.

The displayed tree propagates each selected rule and every earlier first-match
exclusion into the next Hop. Descendant branches that are provably
contradictory are omitted, including disjoint protocol/network values, domain
constraints, and IP CIDRs; a covered fallback is omitted as well. This is a
conservative three-state analysis. Relationships that depend on live DNS,
remote Geosite/GeoIP/custom Rule Set contents, or non-trivial regular
expressions remain visible with a runtime-dependent marker. The master never
performs DNS resolution for the tree because the answer observed by the Agent
can differ by location and time.

Generated sing-box tags must include opaque IDs or an equivalent collision-free
component. Human-readable names are included for clarity but are never relied
on for uniqueness.

Configuration activation remains atomic on each Agent. Fleet-wide changes are
not literally simultaneous, so operations that change both sides of a Link
must use a staged deployment which never exposes an unauthenticated or
unintended route.

Before preflight and queueing, fleet deployment compares each compiled Agent
configuration's SHA-256 digest with that Agent's latest successfully applied
rendered digest. Agents whose digest is already current are skipped: they do
not need to be online and their sing-box process is not restarted. Availability
checks and receiver-before-sender ordering apply to the remaining changed
Agents. A Membership-only change therefore normally restarts only the Proxy
Node's entrance Agent; an entirely unchanged deployment is a successful no-op.

## Renames

Proxy Node and End User names are mutable. A rename immediately changes the
desired generated labels and routing references; the old alias is not retained
as a routing alias after the new configuration is active.

The underlying secret remains unchanged when a protocol separates its local
user label from its wire credential, as AnyTLS, VLESS, and multi-user
Shadowsocks do. For protocols where the username itself is transmitted as part
of authentication, changing the generated username changes client-visible
credential material. The UI must warn the administrator and issue refreshed
client configuration for affected Memberships.

Link display labels and tags also follow Proxy Node renames. Link secrets remain
unchanged unless the chosen protocol makes the renamed username part of its
wire credential, in which case the change requires a safe receiver-first
rollout.

## Ownership and isolation invariants

The implementation must preserve all of the following:

1. A logical inbound belongs to exactly one Proxy Node.
2. An End User is global, while its credentials belong to a Membership.
3. A Membership credential is never reused by another Membership.
4. A Link credential is never reused by another Link.
5. A non-root Hop has exactly one incoming Link.
6. A routing match clause belongs to exactly one Link in the same Proxy Node.
7. A Proxy Node rename changes names, not immutable identity.
8. Removing a Proxy Node removes only its generated portion of every affected
   Agent configuration.
9. Revoking an Agent cannot silently turn a broken Link into `direct`; the
   affected route must fail closed until an administrator changes it.
10. Invalid or incomplete desired state is never deployed.

## Persistence requirements

The new master state must use an explicit versioned envelope. The schema
version and the Theatropolis build which last used the state are separate
fields with separate purposes. Conceptually:

```json
{
  "schema": "theatropolis/proxy-node-state",
  "schema_version": 2,
  "last_used_by": {
    "component": "master",
    "version": "v1.0.0",
    "commit": "0123456789abcdef",
    "recorded_at": "2027-01-02T03:04:05Z"
  },
  "data": {}
}
```

The actual storage may be split across files, but every authoritative store has
an unambiguous schema identifier, integer schema version, and `last_used_by`
record. `schema_version` governs data compatibility. `last_used_by.version`
records provenance and downgrade history; it must never be used as a substitute
for schema validation. Readers use bounded, strict JSON decoding, reject unknown
fields where appropriate, reject trailing data, validate all cross-references
and invariants, and fail closed on unsafe paths or permissions. Writes use the
project's atomic temp-file-and-rename pattern.

Official builds record their release version, commit, and component. Development
builds record an explicit development version plus their commit rather than
pretending to be an official release. Component identity matters because the
master owns logical topology while an Agent owns the generated configuration it
runs.

After an update or reinstall, the newly started component replaces
`last_used_by` with its own build information only after all of the following
have succeeded:

1. strict envelope and topology/deployment validation;
2. any supported schema migration;
3. initialization of the component's required runtime resources; and
4. successful readiness of the configuration it will use.

The root update helper and `install.sh` never write this field. A binary which
cannot successfully load and use the state must not claim that it did. For an
Agent with an active configuration, readiness includes successful sing-box
validation, process start, and the configured startup-grace check. If committing
the updated envelope fails, the component fails readiness and must not continue
serving the newly claimed state.

Updating `last_used_by` is provenance metadata only. It does not create a new
topology revision, rotate credentials, change generated sing-box JSON, or
trigger a fleet deployment. It lives outside the semantic configuration digest
and is atomically rewritten when the component version, commit, or role changes.
The `recorded_at` timestamp records that successful handoff; it need not be
rewritten on every restart by the same build.

An Agent also needs explicit deployment metadata or a versioned envelope which
binds its generated `sing-box/active.json` to the new manager schema, deployment
revision, Proxy Node set, and digest. Raw sing-box JSON alone is not a schema
marker: both old and new releases produce valid raw sing-box configurations.

## Major-version cutover from the old manager

### Policy

The first Proxy Node release does not translate old per-Agent configurations or
the old outbound pool into Proxy Nodes. Old-format proxy configuration is
removed from live use. A valid new-format state is preserved exactly, which
makes reinstalling the same or a later compatible release idempotent.

"Valid new-format" means all of the following:

- the explicit schema identifier is present and exact;
- the schema version is supported;
- the `last_used_by` build metadata is present and valid;
- strict decoding succeeds;
- size, permission, and path-safety checks succeed;
- all IDs, references, credentials, listeners, and topology invariants validate;
  and
- any generated Agent configuration matches its authenticated deployment
  metadata and digest.

Merely parsing as JSON or passing `sing-box check` is not sufficient.

### State classification

On startup, the application—not `install.sh`—classifies relevant state into
exactly one of these cases:

1. **No proxy-manager state:** initialize an empty new-format store.
2. **Valid supported new-format state:** preserve and load it.
3. **Recognized old-format state with no new-format marker:** remove it from
   live use, quarantine it for rollback, and initialize an empty new-format
   store.
4. **New-format marker with an older supported schema version:** run an
   explicit, tested schema migration and preserve the data.
5. **New-format marker with a newer unsupported schema version:** refuse to
   start; a downgrade must not rewrite or discard newer data.
6. **New-format marker but corrupt, incomplete, unsafe, or invalid data:**
   refuse to start and preserve the evidence. Never reinterpret this as legacy
   state and never silently reset it.
7. **Both old- and new-format authoritative state:** load the valid new state
   and quarantine the old state; if the new state is invalid, refuse to start.

This distinction prevents a reinstall from erasing current configuration and
prevents corruption from being mistaken for an intentional old-format cutover.

Even when its schema version is understood, state whose `last_used_by` official
release is newer than the running official binary is treated as a downgrade and
fails closed unless that downgrade is explicitly supported. This is a second
line of defense; the schema version remains the authoritative compatibility
mechanism. A `last_used_by` record never permits the reader to skip strict
validation.

### What is reset

The cutover resets only old proxy-manager configuration:

- per-Agent deployment records containing logical/raw sing-box configuration;
- `outbound-pool.json` and its generated references; and
- legacy Agent `sing-box/active.json` plus generated certificates which are
  referenced only by that discarded configuration.

These files leave live paths before the new service starts. The new master
begins with no Proxy Nodes, Memberships, Links, or generated proxy credentials.
sing-box must not continue serving a legacy configuration after an Agent has
completed the cutover.

### What is preserved

The following operational identity and access state is not old proxy-manager
configuration and should be preserved when valid:

- master web administrator credentials;
- enrolled Agent identities and pending enrollment records;
- each Agent's private Ed25519 identity and master connection settings;
- installer and release/update state needed for safe operation; and
- administrator-entered Agent metadata such as names, addresses, and TLS
  hostname preferences, if its new owner/schema is explicitly defined.

Web sessions may be invalidated at the major-version boundary without deleting
the administrator credential. Cached release and rule-set catalogs may be
discarded and rebuilt.

### Agent replacement and master transfer

Server-record IDs are private to one master and never cross the Agent protocol.
A normal token enrollment therefore transfers control based only on the
selected master address and token. The token selects the master's server
record and binds the Agent's public key to it. On later connections, the Agent
proves possession of its private key and the master reverse-resolves the public
key to that record. After token acceptance, the Agent removes
its inactive persisted `sing-box/active.json` and managed self-signed keys
before sing-box starts. Its first authenticated control session receives either
that master's retained logical deployment or a generated profile with no
inbounds and a rejecting final route.

Replacing hardware inside one master is explicit. A replacement token may be
created for an enrolled server record without deleting its latest deployment. The
current public key remains authorized until redemption. Redemption atomically
swaps the enrolled key and disconnects the old control session; the replacement
Agent then receives the retained deployment through the same connection-time
profile synchronization. Ordinary revocation remains deletion, not
replacement.

### Quarantine rather than immediate destruction

"Discard" means that legacy data is no longer authoritative or executable. It
should not mean irreversible deletion during the first startup.

Before changing live state, move recognized legacy files into one timestamped
quarantine directory on the same filesystem, owned by the relevant unprivileged
service account and mode `0700`. Files containing configuration or secrets
remain mode `0600`. The move and creation of the empty new store must be
crash-safe and guarded by an idempotent cutover record. The service must never
load or execute files from quarantine. Giving this job to the root update
helper would unnecessarily enlarge its authority and is not allowed.

Quarantine gives an administrator a rollback or manual-reference path if the
upgrade was accidental. Because it can contain credentials, the UI and release
notes must identify its location and provide an explicit, narrowly scoped way
to destroy it after verification. Automatic expiry should be implemented only
if its timing and failure behavior are clearly documented.

### Master and Agent sequencing

The master and Agents may be upgraded at different times. The new control
protocol must advertise the proxy-state generation/capability explicitly and
must not send new-format deployments to an old Agent.

An upgraded Agent must stop and quarantine a legacy active configuration before
claiming new-manager readiness. Until the master creates and deploys a Proxy
Node which includes that Agent, its sing-box process remains stopped. An old
Agent may continue running its old local configuration until it is upgraded, so
the UI must show it as **legacy configuration still active** rather than imply
that the master-side reset has already disabled it.

A recommended operator sequence is:

1. upgrade the master;
2. confirm the master classified or preserved its state as expected;
3. upgrade each Agent and confirm its legacy sing-box process stopped;
4. create new Proxy Nodes and Memberships; and
5. deploy and verify each new routing tree.

An optional coordinated maintenance command can be added later, but the normal
installer must remain safe and idempotent when rerun independently on either
role.

### Installer responsibilities

`install.sh` installs binaries, users, units, and administrator-supplied service
settings. It does not parse or delete application data formats. The master and
Agent binaries own state classification because they have the strict schema
validators and can produce precise diagnostics.

The installer must back up and roll back service/binary changes on installation
failure as it does today. Rerunning it over a valid new-format installation must
leave application state untouched.

## Implemented first-release decisions

- `proxy-node-state.json` is the authoritative strict versioned master store;
  its mutations are atomic and revisioned.
- Shadowsocks 2022, AnyTLS, and Hysteria2 are supported on entrances and Links.
- Link-owned clauses support protocol, domain, domain suffix, domain keyword,
  domain regex, IP/CIDR, geosite, geoip, custom Rule Set, and network matches.
  Each Hop has a Direct or Reject terminal, while an optional fallback Link is
  the final relay branch.
- Credentials are generated automatically. Membership import URIs are revealed
  only on the global user's detail page; Link secrets are never displayed.
- Agents advertise `proxy-node-config-v1`; an old Agent cannot receive a new
  fleet deployment.
- A single Agent may host multiple Hops and compatible shared listeners. The
  logical topology remains a rooted tree with branching, no merging, and no
  cycles.
- The relay map renders every conditional Rule as a separate branch. Selecting
  a branch edits only that Rule; adding, deleting, or reordering Rules is done
  from the map rather than from the Hop manager or relay endpoint form. A
  physical Link still owns the child endpoint and exactly one generated relay
  credential, even when several Rule branches select it.
- The shared Link inspector owns its conditional/fallback mode and transport
  settings. The Hop manager owns only Hop identity, its Direct/Reject terminal,
  and child-Link topology/order. This keeps routing intent visually attached to
  the exact branch it controls without multiplying sing-box users.
- Legacy master deployment records and Agent active configurations are moved to
  owner-only `legacy-config-quarantine/` directories. Destructive cleanup is
  intentionally not automated in this release.
