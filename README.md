# Theatropolis

Theatropolis is a master-agent sing-box manager for securely managing servers, users, inbounds, routing, versions, and usage from a local web interface. It is under active development.

## Install

Debian/Ubuntu on amd64 or arm64:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh | sudo sh -s -- master --domain master.example.com
```

Replace `master.example.com` with the master's DNS name. The installer securely prompts for the local administrator username and password; sign in at `https://master.example.com:8443`. Existing access-key installations keep working until they are explicitly migrated by rerunning the installer with `--admin-username operator` (or another lowercase username).

Add a server in the web interface, then run its generated command. The equivalent manual flow is `sudo theatropolis-master create-enrollment --agent-id edge-1`, followed by:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh | sudo sh -s -- agent --master master.example.com:8443 --token TOKEN
```

The enrollment token identifies the server entry; no agent ID is needed on the server. The installer downloads SHA-256-verified release binaries—no compiler or Go toolchain is installed. Agent installations include the pinned official sing-box 1.14.0-beta.2 binary for the detected architecture. After installation, the master can remotely select and install any exact stable or prerelease Theatropolis version published on GitHub.
