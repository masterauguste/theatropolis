# Theatropolis

Theatropolis is a master-agent sing-box manager for securely managing servers, users, inbounds, routing, versions, and usage from a local web interface. It is under active development.

## Install

Debian/Ubuntu on amd64 or arm64:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh | sudo sh -s -- master
```

The installer downloads the latest signed release and prompts for the master's public DNS name, the Caddy HTTPS port (`443` for standard HTTPS, default `8443`), and the local administrator credentials. After installation, sign in using the resulting HTTPS endpoint. Existing access-key installations keep working until they are explicitly migrated by rerunning the installer with `--admin-username operator` (or another lowercase username).

Add a server in the web interface, then run its generated command. The equivalent manual flow is `sudo theatropolis-master create-enrollment --server edge-1`, followed by:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh | sudo sh -s -- agent --master master.example.com:8443 --token TOKEN
```

The enrollment token identifies the server entry. The agent stores no server name or master-side ID: it sends its generated public key during enrollment, then proves possession of the corresponding private key whenever it reconnects. The master resolves that public key to its own private server record. After any successful enrollment, the agent removes its previous persisted sing-box profile and managed self-signed keys before starting. On the authenticated connection, the new master immediately deploys the profile retained for that server, or an explicit no-listener/reject profile when it has none. This prevents another master's profile from surviving a takeover.

To move an existing server record to replacement hardware, open that server's management dialog and create a replacement command. The existing agent remains authorized until the one-time token is redeemed; redemption swaps its public key, disconnects its old control session, and retains the master's last deployment for immediate replay. The equivalent local command is `sudo theatropolis-master create-enrollment --server edge-1 --replace-agent`.

The installer verifies release archives against RSA-PSS-signed SHA-256 manifests—no compiler or Go toolchain is installed. Agent installations include a pinned sing-box 1.14 release-candidate build published by [sing-box-v2ray-api-builds](https://github.com/masterauguste/sing-box-v2ray-api-builds), with V2Ray API plus Theatropolis-managed live user updates for Shadowsocks 2022, AnyTLS, and Hysteria2. The master accepts only signed `theatropolis.N` builds whose capability manifest declares the required managed-user and session-revocation patches.

The Servers page's Server settings dialog can update Agent software across the fleet or schedule one selected sing-box version across every connected compatible Agent. Offline Agents, Agents already running that version, and Agents with an update already pending are left unchanged and reported as skipped.

The master, agent, and sing-box all run as dedicated unprivileged users. A small root-only update helper has no listener and accepts updates only through fixed systemd units. Theatropolis releases must pass signature verification and cannot be downgraded; downloaded sing-box candidates are executed for validation only after dropping to the agent account. See [SECURITY.md](SECURITY.md) for the boundary and its limits.

## Proxy Nodes

Configuration is modeled as logical Proxy Nodes instead of editable per-server
sing-box files. Create a Proxy Node with one entrance, then create ordered
branches from its Hops. The guided branch editor defines the matching Rule
first, then atomically creates its relay Link and child Hop; a non-entrance Hop
cannot exist without that parent Link. Each conditional Rule is a separately
editable branch on the relay map. Every branch is its own logical Link, child routing context,
generated credential, and sing-box authenticated user. Duplicating a branch
copies its downstream chain and listener settings but creates fresh logical
identities and credentials. Numbered Rule branches can be dragged vertically on
the map to set their exact first-match priority without reloading the page. Links can
independently use Shadowsocks 2022, AnyTLS, or Hysteria2. An optional fallback
Link remains last, and otherwise traffic terminates as Direct or Reject on the
current Hop.
Compatible logical inbounds may share one Agent port across Proxy Nodes: the
listener-level material is reused while every Membership and branch Link retains
a distinct credential and authenticated-user routing identity.

Granting Proxy Node access from either the Node page or a global user's settings
uses a searchable picker and generates a unique membership credential. Each
grant has an independent monthly traffic allowance and calendar-month
subscription; either can be unlimited. Usage resets after the grant's monthly
anniversary, and an expiry date remains valid through that UTC day (for example,
an April 4 end date is disabled at April 5 00:00 UTC). Quota exhaustion and
expiration remove only that Node's credential, while end-of-day enforcement
keeps retrying if its entrance Agent is temporarily offline. Assigned Nodes
appear as compact tags whose detail dialogs reveal usage, allowance, and import
URIs. Every connected Agent samples only listeners carrying entrance
memberships, atomically reads and clears their per-user sing-box counters every
15 seconds, and sends the interval deltas to the master. Child Link listeners
are never sampled, and successful entrance results are retained even if another
entrance fails. Before replacing a changed Agent that currently hosts an
applied entrance, topology deployment requests and persists a final sample.
The master increments durable per-membership totals in a private SQLite/WAL
database and keeps a bounded, non-sensitive accounting-failure history. There
is no Agent traffic ledger or replay; after a destructive sample fails, the next
15-second poll is the next attempt, so a sing-box/Agent crash or an undelivered
reset response may lose that interval by design. Rolling usage periods reset in
a serialized SQL transaction at 00:10 UTC; subscription expiry is checked at
00:00 UTC. User grants, revocations, allowance changes, renames,
quota transitions, and subscription transitions synchronize automatically
against the last applied topology; there is no separate user deployment step.
Each completed topology operation—such as editing one Rule, Link, listener,
Hop, terminal, or branch order—is validated against the complete topology and
applied immediately; there is no separate topology Save step. A second
topology edit is rejected while that fleet transaction is active. Topology
comparison excludes end-user state. The agent
treats its currently active Membership IDs as authoritative during topology
activation, so a delayed topology payload can rotate an existing credential but
cannot resurrect a user already removed by a newer user sync. Each operation
journals the exact pre-change topology and last-applied profile for every
affected Agent; a failure or interrupted master process restores both the UI
topology and every touched Agent while preserving concurrent user-plane
changes. Incompatible listener
replacements retire the old listener before binding the new protocol while
leaving unrelated listeners active. Changed receiver Hops are still applied
before changed senders.

The full architecture and old-format cutover policy are recorded in
[docs/proxy-node-manager-design.md](docs/proxy-node-manager-design.md).
