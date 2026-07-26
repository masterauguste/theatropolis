# Theatropolis

Theatropolis is a master-agent sing-box manager for securely managing servers, users, inbounds, routing, versions, and usage from a local web interface. It is under active development.

## Install

Debian/Ubuntu on amd64 or arm64:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh | sudo sh -s -- master --domain master.example.com
```

Create a single-use token with `sudo theatropolis-master create-enrollment --agent-id edge-1`, then install the agent:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh | sudo sh -s -- agent --master master.example.com:8443 --agent-id edge-1 --token TOKEN
```

The installer downloads SHA-256-verified release binaries—no compiler or Go toolchain is installed.
