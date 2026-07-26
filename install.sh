#!/bin/sh

set -eu
umask 077

REPOSITORY="masterauguste/theatropolis"
INSTALL_DIRECTORY="/usr/local/bin"
MASTER_USER="theatropolis-master"
AGENT_USER="theatropolis-agent"
MASTER_STATE_DIRECTORY="/var/lib/theatropolis/master"
AGENT_STATE_DIRECTORY="/var/lib/theatropolis/agent"
CONFIG_DIRECTORY="/etc/theatropolis"
MASTER_ADMIN_SOCKET="/run/theatropolis/master-admin.sock"
DEFAULT_HTTPS_PORT="8443"

ROLE=""
VERSION="latest"
DOMAIN=""
HTTPS_PORT="$DEFAULT_HTTPS_PORT"
MASTER_ADDRESS=""
AGENT_ID=""
ENROLLMENT_TOKEN=""
CA_FILE=""
TEMP_DIRECTORY=""

usage() {
	printf '%s\n' \
		"Usage:" \
		"  install.sh master --domain <name> [--https-port <port>] [--version <tag>]" \
		"  install.sh agent --master <host:port> --agent-id <id> --token <token> [--ca-file <path>]" \
		"  install.sh all --domain <name> --agent-id <id> [--https-port <port>]" \
		"" \
		"Installs precompiled Linux amd64/arm64 release binaries. It never compiles locally."
}

fail() {
	printf 'theatropolis installer: %s\n' "$*" >&2
	exit 1
}

cleanup() {
	if [ -n "$TEMP_DIRECTORY" ] && [ -d "$TEMP_DIRECTORY" ]; then
		rm -rf -- "$TEMP_DIRECTORY"
	fi
}

trap cleanup EXIT HUP INT TERM

if [ "$#" -eq 0 ]; then
	usage
	exit 1
fi

case "$1" in
master | agent | all)
	ROLE="$1"
	shift
	;;
-h | --help)
	usage
	exit 0
	;;
*)
	fail "the first argument must be master, agent, or all"
	;;
esac

while [ "$#" -gt 0 ]; do
	case "$1" in
	--version)
		[ "$#" -ge 2 ] || fail "--version requires a value"
		VERSION="$2"
		shift 2
		;;
	--domain)
		[ "$#" -ge 2 ] || fail "--domain requires a value"
		DOMAIN="$2"
		shift 2
		;;
	--https-port)
		[ "$#" -ge 2 ] || fail "--https-port requires a value"
		HTTPS_PORT="$2"
		shift 2
		;;
	--master)
		[ "$#" -ge 2 ] || fail "--master requires a value"
		MASTER_ADDRESS="$2"
		shift 2
		;;
	--agent-id)
		[ "$#" -ge 2 ] || fail "--agent-id requires a value"
		AGENT_ID="$2"
		shift 2
		;;
	--token)
		[ "$#" -ge 2 ] || fail "--token requires a value"
		ENROLLMENT_TOKEN="$2"
		shift 2
		;;
	--ca-file)
		[ "$#" -ge 2 ] || fail "--ca-file requires a value"
		CA_FILE="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		fail "unknown argument: $1"
		;;
	esac
done

[ "$(id -u)" -eq 0 ] || fail "run this installer as root"
[ -r /etc/os-release ] || fail "cannot identify this operating system"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
debian | ubuntu) ;;
*) fail "only Debian and Ubuntu are currently supported" ;;
esac
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

case "$(uname -m)" in
x86_64 | amd64) ARCHITECTURE="amd64" ;;
aarch64 | arm64) ARCHITECTURE="arm64" ;;
*) fail "only amd64 and arm64 are supported" ;;
esac

if [ "$VERSION" != "latest" ]; then
	printf '%s' "$VERSION" |
		grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$' ||
		fail "invalid release tag"
fi

case "$ROLE" in
master | all)
	printf '%s' "$DOMAIN" |
		grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$' ||
		fail "--domain must be a valid public DNS name"
	case "$HTTPS_PORT" in
	*[!0-9]* | '') fail "--https-port must be numeric" ;;
	esac
	if [ "$HTTPS_PORT" -lt 1024 ] || [ "$HTTPS_PORT" -gt 65535 ]; then
		fail "--https-port must be between 1024 and 65535"
	fi
	;;
esac

case "$ROLE" in
agent | all)
	printf '%s' "$AGENT_ID" |
		grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' ||
		fail "--agent-id is invalid"
	if [ "$ROLE" = "all" ] && [ -z "$MASTER_ADDRESS" ]; then
		MASTER_ADDRESS="${DOMAIN}:${HTTPS_PORT}"
	fi
	printf '%s' "$MASTER_ADDRESS" |
		grep -Eq '^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}$' ||
		fail "--master must be a host:port pair"
	if [ -n "$ENROLLMENT_TOKEN" ]; then
		printf '%s' "$ENROLLMENT_TOKEN" |
			grep -Eq '^[A-Za-z0-9_-]{43}$' ||
			fail "--token is not a 32-byte base64url enrollment token"
	fi
	if [ -n "$CA_FILE" ]; then
		if [ ! -f "$CA_FILE" ] || [ -L "$CA_FILE" ]; then
			fail "--ca-file must be a regular file"
		fi
	fi
	;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl tar

TEMP_DIRECTORY="$(mktemp -d)"
ARCHIVE_NAME="theatropolis_linux_${ARCHITECTURE}.tar.gz"
if [ "$VERSION" = "latest" ]; then
	RELEASE_BASE="https://github.com/${REPOSITORY}/releases/latest/download"
else
	RELEASE_BASE="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
fi
CURL_OPTIONS="--fail --silent --show-error --location --proto =https --tlsv1.2 --retry 3"
# Word splitting is intentional for the constant curl option list.
# shellcheck disable=SC2086
curl $CURL_OPTIONS -o "$TEMP_DIRECTORY/$ARCHIVE_NAME" "$RELEASE_BASE/$ARCHIVE_NAME"
# shellcheck disable=SC2086
curl $CURL_OPTIONS -o "$TEMP_DIRECTORY/checksums.txt" "$RELEASE_BASE/checksums.txt"

EXPECTED_CHECKSUM="$(
	awk -v archive="$ARCHIVE_NAME" '$2 == archive { print $1 }' \
		"$TEMP_DIRECTORY/checksums.txt"
)"
printf '%s' "$EXPECTED_CHECKSUM" | grep -Eq '^[a-fA-F0-9]{64}$' ||
	fail "release checksum is missing or invalid"
ACTUAL_CHECKSUM="$(sha256sum "$TEMP_DIRECTORY/$ARCHIVE_NAME" | awk '{ print $1 }')"
[ "$ACTUAL_CHECKSUM" = "$EXPECTED_CHECKSUM" ] ||
	fail "release archive checksum verification failed"

mkdir "$TEMP_DIRECTORY/extracted"
ENTRY_COUNT=0
while IFS= read -r ENTRY; do
	case "$ENTRY" in
	theatropolis-master | theatropolis-agent) ;;
	*) fail "release archive contains an unexpected path: $ENTRY" ;;
	esac
	ENTRY_COUNT=$((ENTRY_COUNT + 1))
done <<EOF
$(tar -tzf "$TEMP_DIRECTORY/$ARCHIVE_NAME")
EOF
[ "$ENTRY_COUNT" -eq 2 ] || fail "release archive does not contain exactly two binaries"
tar --no-same-owner -xzf "$TEMP_DIRECTORY/$ARCHIVE_NAME" -C "$TEMP_DIRECTORY/extracted"
for COMPONENT in master agent; do
	BINARY="$TEMP_DIRECTORY/extracted/theatropolis-$COMPONENT"
	if [ ! -f "$BINARY" ] || [ -L "$BINARY" ]; then
		fail "release archive is missing the $COMPONENT binary"
	fi
done

install_binary() {
	COMPONENT="$1"
	install -o root -g root -m 0755 \
		"$TEMP_DIRECTORY/extracted/theatropolis-$COMPONENT" \
		"$INSTALL_DIRECTORY/theatropolis-$COMPONENT"
}

ensure_service_user() {
	USER_NAME="$1"
	HOME_DIRECTORY="$2"
	if ! id "$USER_NAME" >/dev/null 2>&1; then
		useradd \
			--system \
			--user-group \
			--home-dir "$HOME_DIRECTORY" \
			--shell /usr/sbin/nologin \
			"$USER_NAME"
	fi
	install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$HOME_DIRECTORY"
}

install_caddy() {
	if command -v caddy >/dev/null 2>&1; then
		return
	fi
	apt-get install -y \
		apt-transport-https \
		debian-archive-keyring \
		debian-keyring \
		gnupg
	# These are Caddy's official stable Debian repository endpoints.
	# shellcheck disable=SC2086
	curl $CURL_OPTIONS \
		-o "$TEMP_DIRECTORY/caddy.gpg" \
		"https://dl.cloudsmith.io/public/caddy/stable/gpg.key"
	gpg --dearmor --yes \
		-o /usr/share/keyrings/caddy-stable-archive-keyring.gpg \
		"$TEMP_DIRECTORY/caddy.gpg"
	# shellcheck disable=SC2086
	curl $CURL_OPTIONS \
		-o "$TEMP_DIRECTORY/caddy.list" \
		"https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt"
	install -o root -g root -m 0644 \
		"$TEMP_DIRECTORY/caddy.list" \
		/etc/apt/sources.list.d/caddy-stable.list
	chmod 0644 /usr/share/keyrings/caddy-stable-archive-keyring.gpg
	apt-get update
	apt-get install -y caddy
}

configure_caddy() {
	install_caddy
	install -d -o root -g root -m 0755 /etc/caddy/conf.d
	CADDYFILE="/etc/caddy/Caddyfile"
	SNIPPET="/etc/caddy/conf.d/theatropolis.caddy"
	[ -f "$CADDYFILE" ] || : >"$CADDYFILE"
	cp -a "$CADDYFILE" "$TEMP_DIRECTORY/Caddyfile.backup"
	HAD_SNIPPET="no"
	if [ -f "$SNIPPET" ]; then
		HAD_SNIPPET="yes"
		cp -a "$SNIPPET" "$TEMP_DIRECTORY/theatropolis.caddy.backup"
	fi
	if ! grep -Fqx 'import /etc/caddy/conf.d/*.caddy' "$CADDYFILE"; then
		printf '\nimport /etc/caddy/conf.d/*.caddy\n' >>"$CADDYFILE"
	fi
	cat >"$SNIPPET" <<EOF
https://${DOMAIN}:${HTTPS_PORT} {
	@agent protocol grpc

	handle @agent {
		reverse_proxy h2c://127.0.0.1:8081
	}

	handle {
		reverse_proxy 127.0.0.1:8080
	}

	tls {
		issuer acme https://acme-v02.api.letsencrypt.org/directory {
			disable_tlsalpn_challenge
		}
	}
}
EOF
	chmod 0644 "$CADDYFILE" "$SNIPPET"
	caddy fmt --overwrite "$SNIPPET"
	if ! caddy validate --config "$CADDYFILE" --adapter caddyfile; then
		cp -a "$TEMP_DIRECTORY/Caddyfile.backup" "$CADDYFILE"
		if [ "$HAD_SNIPPET" = "yes" ]; then
			cp -a "$TEMP_DIRECTORY/theatropolis.caddy.backup" "$SNIPPET"
		else
			rm -f -- "$SNIPPET"
		fi
		fail "Caddy rejected the generated configuration; the previous files were restored"
	fi
	systemctl enable --now caddy
	if ! systemctl reload caddy; then
		cp -a "$TEMP_DIRECTORY/Caddyfile.backup" "$CADDYFILE"
		if [ "$HAD_SNIPPET" = "yes" ]; then
			cp -a "$TEMP_DIRECTORY/theatropolis.caddy.backup" "$SNIPPET"
		else
			rm -f -- "$SNIPPET"
		fi
		systemctl reload caddy || true
		fail "Caddy could not load the generated configuration; the previous files were restored"
	fi
}

install_master() {
	install_binary master
	ensure_service_user "$MASTER_USER" "$MASTER_STATE_DIRECTORY"
	cat >/etc/systemd/system/theatropolis-master.service <<EOF
[Unit]
Description=Theatropolis master
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${MASTER_USER}
Group=${MASTER_USER}
UMask=0077
RuntimeDirectory=theatropolis
RuntimeDirectoryMode=0700
ExecStart=${INSTALL_DIRECTORY}/theatropolis-master serve
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=${MASTER_STATE_DIRECTORY} /run/theatropolis

[Install]
WantedBy=multi-user.target
EOF
	chmod 0644 /etc/systemd/system/theatropolis-master.service
	systemctl daemon-reload
	systemctl enable --now theatropolis-master
	systemctl restart theatropolis-master
	configure_caddy
}

write_agent_configuration() {
	install -d -o root -g root -m 0755 "$CONFIG_DIRECTORY"
	CONFIGURED_CA_FILE=""
	if [ -n "$CA_FILE" ]; then
		CONFIGURED_CA_FILE="${CONFIG_DIRECTORY}/agent-ca.pem"
	fi
	cat >"$CONFIG_DIRECTORY/agent.env" <<EOF
THEATROPOLIS_MASTER=${MASTER_ADDRESS}
THEATROPOLIS_AGENT_ID=${AGENT_ID}
THEATROPOLIS_CA_FILE=${CONFIGURED_CA_FILE}
EOF
	chmod 0600 "$CONFIG_DIRECTORY/agent.env"
	if [ -n "$CA_FILE" ]; then
		install -o root -g root -m 0644 "$CA_FILE" "$CONFIG_DIRECTORY/agent-ca.pem"
	else
		rm -f -- "$CONFIG_DIRECTORY/agent-ca.pem"
	fi
}

wait_for_master_socket() {
	ATTEMPTS=0
	while [ ! -S "$MASTER_ADMIN_SOCKET" ]; do
		ATTEMPTS=$((ATTEMPTS + 1))
		[ "$ATTEMPTS" -le 20 ] ||
			fail "the master administrative socket did not become ready"
		sleep 1
	done
}

install_agent() {
	install_binary agent
	ensure_service_user "$AGENT_USER" "$AGENT_STATE_DIRECTORY"
	if [ -z "$ENROLLMENT_TOKEN" ] && [ "$ROLE" = "all" ]; then
		wait_for_master_socket
		ENROLLMENT_TOKEN="$(
			"$INSTALL_DIRECTORY/theatropolis-master" create-enrollment \
				--agent-id "$AGENT_ID"
		)"
	fi
	if [ -n "$ENROLLMENT_TOKEN" ]; then
		printf '%s\n' "$ENROLLMENT_TOKEN" \
			>"$AGENT_STATE_DIRECTORY/enrollment.token"
		chown "$AGENT_USER:$AGENT_USER" "$AGENT_STATE_DIRECTORY/enrollment.token"
		chmod 0600 "$AGENT_STATE_DIRECTORY/enrollment.token"
	elif [ ! -f "$AGENT_STATE_DIRECTORY/identity.pem" ]; then
		fail "--token is required for a new agent installation"
	fi
	write_agent_configuration
	cat >/etc/systemd/system/theatropolis-agent.service <<EOF
[Unit]
Description=Theatropolis agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${AGENT_USER}
Group=${AGENT_USER}
UMask=0077
EnvironmentFile=${CONFIG_DIRECTORY}/agent.env
ExecStart=${INSTALL_DIRECTORY}/theatropolis-agent --master=\${THEATROPOLIS_MASTER} --agent-id=\${THEATROPOLIS_AGENT_ID} --state-dir=${AGENT_STATE_DIRECTORY} --enrollment-token-file=${AGENT_STATE_DIRECTORY}/enrollment.token --ca-file=\${THEATROPOLIS_CA_FILE}
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=${AGENT_STATE_DIRECTORY}

[Install]
WantedBy=multi-user.target
EOF
	chmod 0644 /etc/systemd/system/theatropolis-agent.service
	systemctl daemon-reload
	systemctl enable --now theatropolis-agent
	systemctl restart theatropolis-agent
}

case "$ROLE" in
master)
	install_master
	;;
agent)
	install_agent
	;;
all)
	install_master
	install_agent
	;;
esac

printf 'Installed precompiled Theatropolis binaries (%s, linux/%s).\n' \
	"$VERSION" "$ARCHITECTURE"
if [ "$ROLE" = "master" ] || [ "$ROLE" = "all" ]; then
	printf 'Master endpoint: https://%s:%s (HTTP-01 uses port 80).\n' \
		"$DOMAIN" "$HTTPS_PORT"
	if [ "$HTTPS_PORT" != "443" ]; then
		printf 'Port 443 remains available for a sing-box inbound.\n'
	fi
fi
