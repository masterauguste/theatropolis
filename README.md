# Theatropolis

Theatropolis is a master-agent sing-box manager for securely managing servers, users, inbounds, routing, versions, and usage from a local web interface. It is under active development.

## Install

Debian/Ubuntu on amd64 or arm64:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh | sudo sh -s -- master
```

The installer downloads the latest signed release and prompts for the master's public DNS name, the Caddy HTTPS port (`443` for standard HTTPS, default `8443`), and the local administrator credentials. After installation, sign in using the resulting HTTPS endpoint. Existing access-key installations keep working until they are explicitly migrated by rerunning the installer with `--admin-username operator` (or another lowercase username).

Add a server in the web interface, then run its generated command. The equivalent manual flow is `sudo theatropolis-master create-enrollment --agent-id edge-1`, followed by:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh | sudo sh -s -- agent --master master.example.com:8443 --token TOKEN
```

The enrollment token identifies the server entry; no agent ID is needed on the server. The installer verifies release archives against an RSA-PSS-signed SHA-256 manifest—no compiler or Go toolchain is installed. Agent installations include the pinned official sing-box 1.14.0-beta.2 binary for the detected architecture. After installation, the master can remotely select and install newer stable or prerelease Theatropolis versions published on GitHub.

The master, agent, and sing-box all run as dedicated unprivileged users. A small root-only update helper has no listener and accepts updates only through fixed systemd units. Theatropolis releases must pass signature verification and cannot be downgraded; downloaded sing-box candidates are executed for validation only after dropping to the agent account. See [SECURITY.md](SECURITY.md) for the boundary and its limits.

## Proxy Nodes

Configuration is modeled as logical Proxy Nodes instead of editable per-server
sing-box files. Create global users, create a Proxy Node with one entrance, then
add relay Links and ordered rules to its Hops. Each Link can independently use
Shadowsocks 2022, AnyTLS, or Hysteria2; unmatched traffic at a Hop can be sent
directly, rejected, or relayed through one of its child Links. Rules always
apply to all traffic for that Proxy Node which reaches the Hop—there is no
separate routing scope.

Assigning a global user to a Proxy Node generates a unique membership
credential. Import URIs are revealed only on that user's detail page. Deploying
compiles the complete desired fleet and applies receiver Hops before senders.

The full architecture and old-format cutover policy are recorded in
[docs/proxy-node-manager-design.md](docs/proxy-node-manager-design.md).
