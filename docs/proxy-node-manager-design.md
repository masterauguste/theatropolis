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

New server records receive an opaque immutable `agt_...` ID and a separate
mutable display name. The display name may contain Unicode letters or numbers
(including Chinese), ordinary spaces, and `.`, `_`, or `-`; renaming it changes
only administrator-facing labels. Existing installations retain their prior
server-record IDs and use those IDs as a display fallback until renamed.

An Agent can host entrances and relay hops for any number of Proxy Nodes,
subject to listener compatibility and resource constraints.

### End User

An End User is a global administrator-managed identity. It exists above Proxy
Nodes and can be assigned to any number of them.

Its administrator-facing management name follows the same normalized Unicode
display-name rules as a Proxy Node. The immutable `usr_...` ID, subscription
token, Membership credentials, and separately claimed login username remain
independent of that display name.

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

The Proxy Node name is a normalized display name that may contain Unicode
letters or numbers (including Chinese), ordinary spaces, and `.`, `_`, or `-`;
it is not a path, resource identifier, sing-box tag, or authenticated-user
identity. There is no separate immutable slug exposed to administrators. The
opaque Proxy Node ID remains stable across renames.

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
Node. A Link's decision to use Shadowsocks multiplexing is the exception: it is
an outbound choice, so the shared inbound enables multiplex support whenever
any attached Link requests it while non-multiplexed Links continue to dial the
same listener normally.

### Hop

A Hop is a logical position in one Proxy Node's routing tree and is assigned to
an Agent. It is not the Agent itself. A Hop has no administrator-authored name;
its visible label is always derived from its assigned Agent, so Agent identity
changes cannot leave stale labels embedded in Proxy Node topology.

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
Every generated Hysteria2 listener explicitly uses the `aggressive` BBR profile.
Existing state with compatible per-endpoint listener secrets is reconciled to
one stable listener identity when loaded. Listener lifetime is derived from its
logical references: deleting one Membership or Link removes only its user and
routing identity, while the physical listener remains for other references;
deleting the final reference removes the listener on the next deployment.

For a Shadowsocks Link with multiplexing enabled, its parent outbound explicitly
selects `smux` with `max_connections: 4` and `min_streams: 4`. These managed
defaults are rendered for every enabled Link, including Links stored before the
policy was introduced. The child inbound enables multiplex support if at least one Link
attached to that physical listener requests it. Links that do not request mux
omit outbound multiplex configuration and continue to use ordinary sessions on
the same listener. Padding and TCP Brutal remain accepted in existing stored
state for compatibility but are not exposed by the guided editor; unlike the
per-Link mux usage toggle, their inbound policy remains listener-wide.

Each conditional Link owns exactly one routing Rule when active. A ruleless Link
is inactive unless it is explicitly the Hop's fallback Link. Sibling Rules are
evaluated in administrator-defined order and the first match wins. At most one
fallback Link exists per Hop and it is always ordered last. Adding another Rule
from an active branch creates a sibling Link, clones that branch's downstream
Hop tree, and generates fresh Link credentials throughout the clone.

A conditional Rule may instead choose `BLOCK`. This compiles to sing-box's
`reject` action on the Rule's parent Hop and creates no Link, listener,
credential, or child Hop. BLOCK and Link Rules share the same ordered
first-match priority space.

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

Proxy Node access can be granted and revoked from either the End User's settings
or the Proxy Node's user list. Both surfaces mutate the same Membership and
queue the same immediate user synchronization. Creating a Membership
automatically generates fresh credentials compatible with the currently active
entrance protocol. Administrators cannot choose or reuse the secret.
Credentials are unique per Membership even when the same End User belongs to
several Proxy Nodes or the Proxy Nodes currently have distinct entrances.

The generated authenticated-user label follows:

```text
<complete-membership-id>-m-<legacy-compatible-membership-suffix>
```

For example, two Memberships belonging to the same global End User can have:

```text
mem_AbCdEf012345MnOpQrStUvWx-m-AbCdEf012345 -> generated membership secret A
mem_ZyXwVu987654GhIjKlMnOpQr-m-ZyXwVu987654 -> generated membership secret B
```

The complete opaque Membership ID is always present and is never truncated.
The final 12-character marker is derived from that same ID and exists only for
rolling compatibility with older Agents. Proxy Node and End User display names
do not enter the label, so either may be renamed or contain multibyte text
without changing protocol identity. Relay users follow the equivalent complete
Link-ID form.

Membership-specific credentials are required when compatible logical
entrances share a physical listener. For protocols such as AnyTLS, the client
sends the password but does not send the server-side user label. If two user
records on one listener had different labels but the same password, sing-box
could not determine which Proxy Node the client intended.

Credentials are protocol-shaped. A password, UUID, Shadowsocks key, or
username/password pair cannot be treated as one interchangeable value. The
Membership owns the appropriate generated credential material for its entrance
protocol. An administrator may rotate that credential from either Membership
surface; rotation preserves quota and subscription state, immediately queues
the user authority, and invalidates the previous import credential.
The global End User surface can rotate every Membership credential owned by
that user in one atomic user-plane mutation without changing the subscription
bearer token. Resetting the subscription link is a wider atomic operation: it
rotates the bearer token and every Membership credential together, so a failure
cannot persist a new URL with only some Node credentials replaced. Revoking the
subscription link changes only the bearer token state.

A finite subscription may be granted in minutes, hours, days, or calendar
months. All billing, quota, expiration, and compensation references use the
fixed UTC+8 product clock. Minute/hour/day grants use exact durations. A calendar-month grant
keeps the established natural-month behavior: a grant created on March 4 for
one month remains active through April 4 and expires at April 5 00:00 UTC+8.
Administrators may extend a finite deadline using any supported unit. Extension
is strictly additive to the stored deadline while the Membership is active.
At the deadline, the Membership is removed atomically, its entrance credential
is revoked, and its accounting rows are deleted; restoring access requires a
new grant with a new Membership identity and credential. Proxy Node-wide
compensation takes a UTC+8 outage start and end, preselects active finite
Memberships whose current subscription interval overlaps that range, and
presents a searchable checklist for administrator overrides before applying one
extension to the checked Memberships. Unlimited or already-expired grants are
never candidates. Neither operation changes the quota period, anchor day, or
next traffic reset.

Secrets are displayed only through an explicit administrator action and are
handled as sensitive state. Diagnostics, logs, topology exports, and ordinary
list views must not contain them.

Membership state and topology state are independent configuration planes.
Creating, renaming, deleting, granting, revoking, expiring, quota-disabling, or
changing the allowance of an End User is persisted immediately and
automatically synchronized onto the last successfully applied topology. There
is no separate user Apply action. Routing Rules, Links, Hop placement, listener
settings, and Link credentials are changed as one completed operation at a
time. Each operation validates the complete topology and immediately starts an
atomic fleet deployment when every changed Agent is ready; there is no separate
topology Apply action. If a changed Agent is offline, its routable address is
temporarily unavailable, or its authoritative reconnect replay still occupies
the deployment slot, the valid desired revision remains saved as Pending while
the applied topology and managed-Agent set remain unchanged. Further edits
merge into that newest desired revision. A coalesced reconciler retries after
reconnect/address events and with a bounded backoff, including after master
restart; unchanged offline Agents do not block unrelated edits.

Topology comparison is compiled without end-user credentials. User authority
has its own revisioned control command and does not create, overwrite, or wait
behind a topology deployment record. Each command carries complete user sets
for the applied, desired, and (when present) in-flight topology shapes. The
Agent persists the newest authority in a private sidecar and serializes it with
local sing-box activation. Every topology candidate is overlaid with the newest
matching authority before validation; an unknown older shape can only retain
Membership IDs already active on that Agent. Consequently, delayed deployment
or rollback cannot resurrect a revoked credential. Once topology commits, the
master sends the latest user revision again so label renames and staged entrance
credentials follow the newly applied shape. If an entrance protocol change
requires a different credential shape, the replacement credential remains
pending until the new listener topology is active.

An authority-capable Agent must never treat an authority/topology digest
mismatch as a successful user synchronization. It immediately stops the
sing-box data plane while keeping its control connection available, persists
the newest authority, and reports the fixed non-sensitive mismatch diagnostic.
The master responds by rebuilding its last committed topology with the current
compiler and latest memberships, then sends it as a topology deployment; the
Agent overlays the persisted authority before validation and only then restarts
sing-box. Historical deployment JSON is only a fallback for Agents outside the
Proxy Node store, because replaying output from an older compiler can repeat the
same authority mismatch forever. Startup follows the same fail-closed rule, so
an old active file cannot briefly restore revoked credentials during
reconnection.

Topology deployment is a fleet transaction. Before the first Agent is touched,
the master writes a private atomic journal containing every affected Agent's
exact last-applied profile. Each Agent is marked before delivery. Any validation,
activation, revision, or persistence failure rolls every touched Agent back in
the previous topology's receiver-before-sender order; an interrupted master
resumes that same recorded order after restart. Rollback never discards the
accepted desired revision: after recovery it remains Pending and can be edited
again, while a structurally invalid mutation is the only case restored before
acceptance. A committing marker plus
the persisted applied topology revision distinguishes a completed transaction
from one requiring recovery. When a protocol replacement reuses a socket, the
old conflicting listener is removed in a separate first deployment while
unrelated listeners remain present, and only then is the new listener bound.

### Traffic accounting ownership

sing-box exposes process-local counters through an atomic read-and-clear
operation. A connected Agent samples every 15 seconds and sends that interval's
deltas directly to the master. Only SSM endpoints containing entrance
Membership identities are queried; Link credentials and child-only listeners
are excluded. Successful endpoint results are retained even if another
entrance endpoint fails, then sent before the bounded failure report. Immediately
before topology deployment replaces a changed Agent that
currently hosts an applied entrance, the master requests and persists a final
sample; changed child-only Agents are not sampled. The Agent creates no traffic
ledger and performs no accounting file write, `fsync`, or acknowledgement
pruning. The master adds each authenticated control frame exactly once to the
matching Membership's current-period usage in a private SQLite/WAL database,
keeps a bounded non-sensitive accounting-failure history there, and remains the
sole durable accounting authority. Topology and user policy remain in the
schema-v14 JSON store; SQL is authoritative for high-frequency totals and reset
boundaries. Schema-v7 JSON accounting values are imported once during upgrade,
and a corrupt accounting database fails closed instead of becoming an empty
ledger.

Low-frequency membership identity and policy mutations prepare their SQLite
reconciliation in an uncommitted transaction, atomically replace the JSON
authority, and only then commit SQLite. A JSON failure rolls the SQL transaction
back. A process interruption after the JSON rename but before the SQL commit is
recovered at startup by reconciling SQLite to the durable JSON authority. This
prevents a failed web mutation from silently changing user authority while
preserving SQLite as the sole authority for current traffic totals.

This intentionally follows an at-most-once polling model: a sing-box/Agent
crash before sampling, a response lost after counters were cleared, or a master
persistence failure can lose that interval. The system does not claim
audit-grade billing. Rolling quota resets clear master-owned Membership usage
in a serialized SQL transaction at UTC+8 midnight. Subscription deadlines are
checked once per minute; reaching one atomically removes the Membership and its
accounting rows before the independent user plane revokes the entrance credential.
An administrator-requested traffic reset first requests and persists an
entrance sample, then clears only the current-period total; it never moves the
quota period or subscription deadline. During rolling upgrades, legacy cumulative Agents retain their baseline
handling; reset-delta Agents advertise `managed-user-traffic-delta-v1` and use a
fresh compatibility epoch for each batch so an older master also adds it once.

Agents push a sample on connection and every 15 seconds. An Agent that cannot
collect a sample sends a bounded non-sensitive failure report. Agents
advertising `managed-user-traffic-request-v1` also accept a correlated
master-initiated sample request before an entrance-changing topology operation.
A failed destructive sample is recorded, but is not retried as though its
already-cleared counters still existed; the next periodic poll is the next
attempt. A requested report succeeds only after the master has persisted the
delta.

## Routing and rendering

The master stores the logical model and compiles all affected Proxy Nodes into
one complete sing-box configuration per Agent. Administrators do not edit the
generated JSON as authoritative state.

At an entrance, authentication maps a connection to a Membership-specific
`auth_user` label. Generated rules use that label to select only that Proxy
Node's root routing tree. At a relay inbound, authentication maps the
connection to that Link's identity and selects the child Hop's routing tree.

Each conditional Rule has an explicit priority among all Rules at its parent Hop
and applies to all Proxy Node traffic which reaches that Hop. There is no
separately configurable routing scope. A relay Rule owns a distinct Link,
credential, child Hop, and downstream routing context; a BLOCK Rule rejects on
the current Hop without relay artifacts. Compatible Links may still be
coalesced into one physical listener, where their different authenticated users
select their independent contexts. The first matching Rule wins; an optional
unconditional fallback Link is evaluated last; otherwise the
Hop's required `direct` or `reject` terminal is used. The Rule match selector
exposes `ALL` as that fallback choice. Selecting it creates or converts the
branch into the Hop's single fallback Link without storing a synthetic match
Rule, allowing unmatched traffic to relay to another Agent. The compiler
rejects missing targets, cycles, merges, listener conflicts, duplicate wire
credentials on a combined listener, and references outside the owning Proxy
Node.

A `direct` or `reject` terminal is compiled into the sing-box configuration of
the Agent hosting that Hop. A selected Link is compiled on the parent Agent and
hands traffic to the child Hop, whose own ordered Links and terminal then take
over. Consequently, the terminal action for a relayed path executes on that
path's final Hop, not on its entrance or an earlier relay.

The Proxy Node overview renders this model as a recursive routing tree. Hop
cards stay compact, and each Link-owned Rule appears as its own visible branch
labelled with the actual match type and values. BLOCK Rules appear in the same
ordered branch list and terminate in a visible BLOCK/Reject node on their
current Hop. A relay visual branch is also the
logical isolation boundary: it has its own child Hop tree, relay credential, and
sing-box authenticated user. Compatible endpoints can share a physical socket
without sharing those identities. A fallback Link appears as one final fallback branch, and
a Link with no rule remains as a visibly inactive branch. A Direct terminal is
implicit when its Hop has no other visible branch, but remains an explicit
fallback beside conditional branches; Reject is always an explicit terminal.
Selecting a Rule branch edits only that Rule, while dragging numbered sibling
branches changes their exact first-match priority in place without navigating
away from the map. Keyboard-accessible move
buttons remain available in the Rule inspector. The branch Link inspector owns
fallback state, the child terminal, deletion, and protocol/listener controls.
When a local Direct or Reject fallback terminal is visible in the tree, its
inspector edits that action in place and can open the branch wizard already set
to `ALL`, turning the fallback into a relay without detouring through the Hop
inspector.
Creating a branch is Rule-first: the administrator defines the match, then
chooses either a child Hop relay or BLOCK. A relay atomically creates the Link,
its unique identity, and its child Hop; BLOCK atomically creates only the local
terminal Rule. A failed validation therefore cannot leave an orphaned child
Hop, and deleting a relay branch deletes its child subtree. The Hop inspector
can move the Hop to another Agent while preserving its identity and complete
downstream subtree, edit that Hop's Direct/Reject terminal exit, or start this
branch wizard. The Link inspector also offers a destructive Replace Destination
operation: the selected Link, Rule, fallback state, and priority are retained,
but its old child Hop and entire downstream subtree are logically deleted, a
fresh terminal Hop is created on the selected Agent, and the Link credential is
rotated. This is one validated topology transaction rather than a staged live
teardown. Creating either a Proxy Node entrance or a child branch returns to
the relay map with the details window closed; selection is always an explicit
operator action.

The displayed tree propagates each selected rule and every earlier first-match
exclusion into the next Hop. Descendant branches that are provably contradictory
are omitted from that displayed path, including incompatible domain and domain
suffix combinations. A covered fallback is omitted as well. Dragging a
path-filtered branch list merges its visible order into the Hop's complete Rule
order, so omitted Rules retain their position. This is a
conservative three-state analysis. Relationships that depend on live DNS,
remote Geosite/GeoIP/custom Rule Set contents, or non-trivial regular
expressions remain visible with a runtime-dependent marker. The master never
performs DNS resolution for the tree because the answer observed by the Agent
can differ by location and time.

At runtime, the compiler inserts metadata actions only when ordered Rules first
need them. A `sniff` action appears immediately before the first domain,
Geosite/custom Rule Set, or protocol match; a `resolve` action appears
immediately before the first destination-IP, GeoIP/custom Rule Set match. A
custom Rule Set is opaque to the master and therefore conservatively requires
both. Generated configurations explicitly define one `local` DNS server backed
by the Agent's system resolver and set it as the default domain resolver; they
never rely on a zero-server implicit fallback. Earlier final Rules can still
terminate routing without incurring either operation.

Generated sing-box tags and authenticated-user labels use opaque IDs or an
equivalent collision-free component. Human-readable names remain UI metadata
and do not enter protocol identity.

Configuration activation remains atomic on each Agent. Fleet-wide changes are
not literally simultaneous, so operations that change both sides of a Link
must use a staged deployment which never exposes an unauthenticated or
unintended route.

Topology deployment compares user-agnostic candidate and applied views and skips
unchanged Agents. Availability checks and receiver-before-sender ordering apply
to the remaining changed Agents. Immediately before deployment, the restart
document is assembled from the selected topology and the current live
memberships; staged credentials are used for an entrance whose protocol shape
is changing. After it succeeds, automatic user synchronization sends the newest
revisioned authority independently. If only managed user arrays differ, the
Agent applies it through the loopback API without restarting sing-box. An
entirely unchanged operation is a successful no-op. Address-source changes use
a separate retrying refresh of the last applied topology and never publish a
candidate topology.

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
  "schema_version": 4,
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

When the hardware is permanently lost instead — a wiped or discarded machine
that will never reconnect — the ordinary retire-then-revoke order cannot run,
because the lost Agent can never acknowledge its empty retirement profile and
its stale applied references would otherwise block revocation forever. For an
enrolled Agent with no connected control session, the web UI therefore offers
an explicit forced removal: the master deletes the identity without delivering
a retirement profile, remaining topology references become ordinary
deleted-Server entries that the administrator redirects or deletes, and any
pending topology revision that was waiting on the lost Agent is reconciled
locally without a remote wipe. Forced removal is refused while a session is
connected; if the machine ever comes back, its Agent stays locked out and
must be reinstalled.

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

- `proxy-node-state.json` is the authoritative strict versioned topology and
  policy store; its mutations are atomic and revisioned. High-frequency traffic
  totals, reset boundaries, rolling-upgrade observations, and accounting errors
  are authoritative in the sibling private `proxy-node-accounting.sqlite` WAL
  database.
- Shadowsocks 2022, AnyTLS, and Hysteria2 are supported on entrances and Links.
- Conditional clauses support protocol, domain, domain suffix, domain keyword,
  domain regex, IP/CIDR, geosite, geoip, custom Rule Set, and network matches.
  Each clause can relay to a child Hop or BLOCK (sing-box Reject) on the current
  Hop. `ALL` creates the optional fallback Link as the final relay branch. Each
  Hop still has a Direct or Reject terminal for unmatched traffic.
- Credentials are generated automatically. Membership import URIs are revealed
  only on the global user's detail page; Link secrets are never displayed.
- Agents advertise `proxy-node-config-v1`; an old Agent cannot receive a new
  fleet deployment.
- A single Agent may host multiple Hops and compatible shared listeners. The
  logical topology remains a rooted tree with branching, no merging, and no
  cycles.
- A shared Shadowsocks listener enables inbound multiplex support when any
  attached Link requests it. Only those requesting Links receive `smux` on
  their parent outbounds, using four maximum physical connections and four
  streams before opening another; other Links on the listener remain non-multiplexed.
  Padding and TCP Brutal are intentionally absent from the current UI.
- The relay map renders every conditional Rule as a separate branch. Selecting
  a branch edits only that Rule; adding, deleting, or reordering Rules is done
  directly from the map. Relay branches own a distinct logical Link, child Hop
  context, generated credential, and authenticated user; BLOCK branches own no
  relay resources and end locally with Reject.
- Rule priority is explicit across the entire parent Hop, so Rules targeting
  different sibling Links can be interleaved. Dragging a numbered branch writes
  that exact order; the compiler emits it unchanged before the fallback Link
  and terminal.
- Duplicating an active branch copies its endpoint and full downstream subtree,
  assigns new Hop/Link/Rule IDs to the copy, and generates new Link credentials.
  Compatible copied endpoints remain eligible for physical listener sharing.
  A successful Rule save returns to the refreshed relay map without reopening
  the Rule dialog.
- The relay map is the only topology-management surface; there is no separate
  Hop manager. The Rule-first branch wizard atomically creates a Link and its
  child Hop, so a child cannot exist independently from its parent Link. Hops
  have no editable names and are displayed using their assigned Agent. A Hop
  inspector can create a branch, move that Hop and its intact subtree to another
  Agent, or change its Direct/Reject terminal exit. The branch Link inspector
  owns conditional/fallback mode, its child's terminal, deletion, transport
  settings, and destructive destination replacement. Replacement preserves the
  Link's routing Rule and priority, deletes the old destination subtree, rotates
  the Link credential, and creates a fresh terminal Hop. Deleting a branch
  removes its child subtree. Entrance terminal settings live with the entrance.
  This keeps routing intent visually attached to the exact branch and sing-box
  user it controls.
- Legacy master deployment records and Agent active configurations are moved to
  owner-only `legacy-config-quarantine/` directories. Destructive cleanup is
  intentionally not automated in this release.
- Every End User receives one rotatable bearer subscription token when created. Three public
  endpoints render Clash, Surge, and sing-box profiles from the same logical
  subscription. The token is private master state, responses are `no-store`,
  and rotation or revocation invalidates the old URL immediately.
- Public token lookup is indexed. Rendering operates on one consistent
  per-user projection rather than cloning the full fleet, and identical
  rendered profiles use a bounded in-memory content cache keyed by the complete
  projection.
- Subscription Nodes are derived rather than stored: each enabled Membership
  whose topology is applied and whose entrance has a routable address becomes
  one or two exported nodes. Each Proxy Node chooses IPv4 and IPv6, IPv4 only,
  or IPv6 only. Newly created Nodes default to IPv4 only; legacy Nodes without
  a saved choice retain the historical dual-stack behavior, and an unavailable
  selected family is omitted. This is master-side subscription
  metadata and never deploys topology. A quota-disabled Membership remains in
  the subscription with its stable credential, while the independent user plane
  removes that credential from the live entrance authority until reset. Expired
  Memberships are omitted. An empty Proxy group offers Direct first and Reject
  second.
- Subscription routing is independent of the Proxy Node topology plane. One
  universal ordered list of portable client-side matches is applied to every
  user export; its actions are Proxy,
  Direct, or Reject. Proxy is a selector containing every exported Node followed
  by explicit Direct and Reject choices. When no Node is available, the selector
  contains Direct followed by Reject, making Direct the default while retaining
  a manual fail-closed choice.
  Editing it never deploys an Agent or changes a Membership credential.
- Geosite and GeoIP are first-class universal matches. Clash receives native
  rules with pinned auto-updating MetaCubeX data URLs, sing-box receives the
  matching SagerNet binary rule set, and Surge receives master-hosted read-only
  `DOMAIN-SET` and CIDR `RULE-SET` views of the public MetaCubeX categories.
  Administrators do not create or manage remote rule-provider records.
- sing-box exports explicitly use the platform `local` DNS server, insert
  sniff/resolve actions at first use, enable a loopback-only Clash API for the
  `Proxy` selector, and enable its cache file so graphical clients can retain a
  selection. They include TUN transparent routing for the official Apple and
  desktop clients plus a loopback mixed-proxy fallback. Surge intentionally
  omits non-portable domain regular expressions
  instead of translating them to URL matching, and emits network values as
  uppercase `TCP`/`UDP`.
- The public Surge rule-set adapter permits 120 requests per client per minute
  under a 1,200-request global ceiling, caps each upstream body at 8 MiB,
  coalesces concurrent misses to four upstream
  fetches, and retains at most 128 converted entries / 64 MiB. Fresh results
  live for one hour and a last-known-good result may be served for 24 hours when
  upstream is unavailable.
