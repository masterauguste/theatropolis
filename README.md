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

The installer verifies release archives against an RSA-PSS-signed SHA-256 manifest—no compiler or Go toolchain is installed. Agent installations include the pinned official sing-box 1.14.0-beta.2 binary for the detected architecture. After installation, the master can remotely select and install newer stable or prerelease Theatropolis versions published on GitHub.

The master, agent, and sing-box all run as dedicated unprivileged users. A small root-only update helper has no listener and accepts updates only through fixed systemd units. Theatropolis releases must pass signature verification and cannot be downgraded; downloaded sing-box candidates are executed for validation only after dropping to the agent account. See [SECURITY.md](SECURITY.md) for the boundary and its limits.

## Proxy Nodes

Configuration is modeled as logical Proxy Nodes instead of editable per-server
sing-box files. Create a Proxy Node with one entrance, then add ordered relay
Links to its Hops. Each Link owns its match clauses and can independently use
Shadowsocks 2022, AnyTLS, or Hysteria2. Sibling Links are evaluated in order;
the first Link with any matching clause wins, an optional fallback Link remains
last, and otherwise traffic terminates as Direct or Reject on the current Hop.
Compatible logical inbounds may share one Agent port across Proxy Nodes: the
listener-level material is reused while every Membership and Link retains a
distinct credential and authenticated-user routing identity.

Granting Proxy Node access from a global user's settings uses a searchable
picker and generates a unique membership credential. Assigned Nodes appear as
compact tags whose detail dialogs reveal the import URIs. The same page can
deploy pending access changes. Deployment compiles the complete desired fleet,
skips Agents whose applied configuration digest is already current, and applies
changed receiver Hops before changed senders.

The full architecture and old-format cutover policy are recorded in
[docs/proxy-node-manager-design.md](docs/proxy-node-manager-design.md).
