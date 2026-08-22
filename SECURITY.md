# Security model

The installed master and agent are network-facing, but neither runs as root. The agent supervises sing-box under the same dedicated unprivileged account. Its only ambient capability is `CAP_NET_BIND_SERVICE`, which permits binding low ports but does not grant general root access.

Privileged updates are isolated in `/usr/local/libexec/theatropolis/theatropolis-update-helper`. This helper:

- has no network listener or control-plane client;
- is started only by root-owned, fixed-argument systemd units;
- accepts bounded request files from the unprivileged service;
- installs Theatropolis archives only after RSA-PSS verification of the checksum manifest and SHA-256 verification of the archive;
- rejects Theatropolis downgrades;
- runs a downloaded sing-box candidate as `theatropolis-agent`, with a minimal environment and no inherited capabilities, before installing its already-verified bytes.

Consequently, compromise of the agent account can control the local proxy, read or modify agent-owned state, request an available update, and cause denial of service on that node. It should not provide a path to execute attacker-chosen code as root. Kernel vulnerabilities, compromise of the host's root-owned systemd configuration, and compromise of the offline release-signing key remain outside this boundary.

Web login failures are limited per client address so one remote client cannot lock out every operator. Argon2id derivation remains globally concurrency-limited to bound memory use. Unauthenticated gRPC streams have a ten-second first-frame deadline, and each HTTP/2 connection has a bounded concurrent-stream count.

## Existing installations

The privilege separation changes the update service commands and adds the dedicated helper. Existing installations must rerun the installer once after upgrading to a release that contains this change; the former privileged subcommands in the network-facing binaries fail closed.
