#!/bin/sh

set -eu
set +x
umask 077

REPOSITORY="masterauguste/theatropolis"
INSTALL_DIRECTORY="/usr/local/bin"
UPDATE_HELPER_DIRECTORY="/usr/local/libexec/theatropolis"
UPDATE_HELPER_PATH="${UPDATE_HELPER_DIRECTORY}/theatropolis-update-helper"
SING_BOX_VERSION=""
SING_BOX_TAG=""
SING_BOX_REPOSITORY="masterauguste/sing-box-v2ray-api-builds"
SING_BOX_LIBRARY_DIRECTORY="/usr/local/lib/theatropolis/sing-box"
MASTER_USER="theatropolis-master"
AGENT_USER="theatropolis-agent"
STATE_DIRECTORY="/var/lib/theatropolis"
MASTER_STATE_DIRECTORY="${STATE_DIRECTORY}/master"
AGENT_STATE_DIRECTORY="${STATE_DIRECTORY}/agent"
CONFIG_DIRECTORY="/etc/theatropolis"
MASTER_ADMIN_SOCKET="/run/theatropolis/master-admin.sock"
LEGACY_WEB_AUTH_FILE="${CONFIG_DIRECTORY}/web-auth.json"
WEB_AUTH_FILE="${MASTER_STATE_DIRECTORY}/web-auth.json"
MASTER_UNIT_FILE="/etc/systemd/system/theatropolis-master.service"
AGENT_UNIT_FILE="/etc/systemd/system/theatropolis-agent.service"
MASTER_UPDATE_SERVICE_FILE="/etc/systemd/system/theatropolis-master-update.service"
MASTER_UPDATE_PATH_FILE="/etc/systemd/system/theatropolis-master-update.path"
AGENT_UPDATE_SERVICE_FILE="/etc/systemd/system/theatropolis-agent-update.service"
AGENT_UPDATE_PATH_FILE="/etc/systemd/system/theatropolis-agent-update.path"
SING_BOX_UPDATE_SERVICE_FILE="/etc/systemd/system/theatropolis-sing-box-update.service"
SING_BOX_UPDATE_PATH_FILE="/etc/systemd/system/theatropolis-sing-box-update.path"
INSTALL_LOCK_FILE="/run/theatropolis-installer.lock"
DEFAULT_HTTPS_PORT="8443"
ACME_HTTP01_RELAY_PORT="19091"
ACME_HTTP01_RELAY_MARKER="${CONFIG_DIRECTORY}/acme-http01-master-relay"
CADDY_RELAY_SNIPPET="/etc/caddy/conf.d/theatropolis-agent-acme.caddy"

ROLE=""
RELEASE_TAG="latest"
DOMAIN=""
HTTPS_PORT="$DEFAULT_HTTPS_PORT"
MASTER_ADDRESS=""
MASTER_DIAL_ADDRESS=""
SERVER_NAME=""
ENROLLMENT_TOKEN=""
CA_FILE=""
TEMP_DIRECTORY=""
ADMIN_USERNAME=""
ADMIN_PASSWORD_FILE=""
ADMIN_PASSWORD_FILE_ID=""
ADMIN_PASSWORD_SNAPSHOT=""
WEB_ADMIN_PASSWORD=""
WEB_ADMIN_PASSWORD_CONFIRM=""
WEB_AUTH_EXISTED="no"
WEB_AUTH_CREATED="no"
WEB_AUTH_CREATED_ID=""
WEB_AUTH_RESET_APPLIED="no"
WEB_AUTH_BACKUP=""
WEB_AUTH_MIGRATED="no"
LEGACY_WEB_AUTH_PRESENT="no"
MASTER_UNIT_BACKUP=""
MASTER_UNIT_HAD="no"
MASTER_UNIT_TOUCHED="no"
MASTER_UNIT_TEMP=""
MASTER_WAS_ACTIVE="no"
MASTER_STOPPED="no"
INSTALL_SUCCEEDED="no"
CLEANUP_STARTED="no"
TTY_SETTINGS=""
ENROLLMENT_TOKEN_TEMP=""
AGENT_WAS_ACTIVE="no"
AGENT_STOPPED="no"
COLOCATED_AGENT_BINARY_BACKUP=""
RELAY_TOUCHED="no"
HAD_RELAY_SNIPPET="no"
HAD_RELAY_MARKER="no"
SING_BOX_BOOTSTRAP_REQUIRED="yes"

usage() {
	printf '%s\n' \
		"Usage:" \
		"  install.sh master [--version <tag>] [--admin-username <name> [--admin-password-file <path>]]" \
		"  install.sh agent --master <host:port> [--token <token>] [--ca-file <path>] [--version <tag>]" \
		"  install.sh all --server <name> [--version <tag>] [--admin-username <name> [--admin-password-file <path>]]" \
		"" \
		"Master and all installations prompt for the public domain and Caddy HTTPS port." \
		"Installs precompiled Linux amd64/arm64 release binaries. It never compiles locally."
}

fail() {
	printf 'theatropolis installer: %s\n' "$*" >&2
	exit 1
}

cleanup() {
	CLEANUP_STATUS="$?"
	if [ "$CLEANUP_STARTED" = "yes" ]; then
		return
	fi
	CLEANUP_STARTED="yes"
	trap - EXIT HUP INT TERM
	set +e

	if [ -n "$TTY_SETTINGS" ]; then
		stty "$TTY_SETTINGS" </dev/tty >/dev/null 2>&1 || true
		TTY_SETTINGS=""
	fi
	WEB_ADMIN_PASSWORD=""
	WEB_ADMIN_PASSWORD_CONFIRM=""
	if [ -n "$ADMIN_PASSWORD_SNAPSHOT" ] &&
		[ -f "$ADMIN_PASSWORD_SNAPSHOT" ] &&
		[ ! -L "$ADMIN_PASSWORD_SNAPSHOT" ]; then
		rm -f -- "$ADMIN_PASSWORD_SNAPSHOT"
	fi
	if [ -n "$MASTER_UNIT_TEMP" ] &&
		[ -f "$MASTER_UNIT_TEMP" ] &&
		[ ! -L "$MASTER_UNIT_TEMP" ]; then
		rm -f -- "$MASTER_UNIT_TEMP"
	fi

	if [ "$INSTALL_SUCCEEDED" != "yes" ] &&
		{ [ "$WEB_AUTH_RESET_APPLIED" = "yes" ] ||
			[ "$WEB_AUTH_CREATED" = "yes" ] ||
			[ "$MASTER_UNIT_TOUCHED" = "yes" ] ||
			[ "$MASTER_STOPPED" = "yes" ]; }; then
		MASTER_STOPPED="yes"
		systemctl stop theatropolis-master >/dev/null 2>&1 || true
	fi

	if [ "$INSTALL_SUCCEEDED" != "yes" ] &&
		[ "$WEB_AUTH_MIGRATED" = "yes" ] &&
		[ -f "$WEB_AUTH_FILE" ] &&
		[ ! -L "$WEB_AUTH_FILE" ]; then
		rm -f -- "$WEB_AUTH_FILE"
	elif [ "$INSTALL_SUCCEEDED" != "yes" ] &&
		[ "$WEB_AUTH_RESET_APPLIED" = "yes" ] &&
		[ -n "$WEB_AUTH_BACKUP" ]; then
		AUTH_RESTORE="${WEB_AUTH_FILE}.restore.$$"
		rm -f -- "$AUTH_RESTORE"
		if cp -a "$WEB_AUTH_BACKUP" "$AUTH_RESTORE" &&
			mv -fT -- "$AUTH_RESTORE" "$WEB_AUTH_FILE"; then
			:
		else
			rm -f -- "$AUTH_RESTORE"
			printf '%s\n' \
				'theatropolis installer: could not restore the previous web admin credential' >&2
		fi
	elif [ "$INSTALL_SUCCEEDED" != "yes" ] &&
		[ "$WEB_AUTH_CREATED" = "yes" ] &&
		[ -n "$WEB_AUTH_CREATED_ID" ] &&
		[ -f "$WEB_AUTH_FILE" ] &&
		[ ! -L "$WEB_AUTH_FILE" ] &&
		[ "$(stat -c '%d:%i' "$WEB_AUTH_FILE" 2>/dev/null || true)" = "$WEB_AUTH_CREATED_ID" ]; then
		rm -f -- "$WEB_AUTH_FILE"
	fi

	if [ "$INSTALL_SUCCEEDED" != "yes" ] &&
		[ "$MASTER_UNIT_TOUCHED" = "yes" ]; then
		if [ "$MASTER_UNIT_HAD" = "yes" ] &&
			[ -n "$MASTER_UNIT_BACKUP" ]; then
			UNIT_RESTORE="${MASTER_UNIT_FILE}.restore.$$"
			rm -f -- "$UNIT_RESTORE"
			if cp -a "$MASTER_UNIT_BACKUP" "$UNIT_RESTORE" &&
				mv -fT -- "$UNIT_RESTORE" "$MASTER_UNIT_FILE"; then
				:
			else
				rm -f -- "$UNIT_RESTORE"
				printf '%s\n' \
					'theatropolis installer: could not restore the previous master service unit' >&2
			fi
		elif [ "$MASTER_UNIT_HAD" = "no" ]; then
			rm -f -- "$MASTER_UNIT_FILE"
		fi
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi

	if [ "$INSTALL_SUCCEEDED" != "yes" ] &&
		[ "$MASTER_WAS_ACTIVE" = "yes" ] &&
		[ "$MASTER_STOPPED" = "yes" ]; then
		if ! systemctl start theatropolis-master; then
			printf '%s\n' \
				'theatropolis installer: the previous master could not be restarted after rollback' >&2
		fi
		MASTER_STOPPED="no"
	fi
	if [ "$INSTALL_SUCCEEDED" != "yes" ]; then
		if [ -n "$COLOCATED_AGENT_BINARY_BACKUP" ]; then
			cp -a "$COLOCATED_AGENT_BINARY_BACKUP" "$INSTALL_DIRECTORY/theatropolis-agent"
		fi
		if [ "$RELAY_TOUCHED" = "yes" ]; then
			if [ "$HAD_RELAY_SNIPPET" = "yes" ]; then
				cp -a "$TEMP_DIRECTORY/theatropolis-agent-acme.caddy.backup" "$CADDY_RELAY_SNIPPET"
			else
				rm -f -- "$CADDY_RELAY_SNIPPET"
			fi
			if [ "$HAD_RELAY_MARKER" = "yes" ]; then
				cp -a "$TEMP_DIRECTORY/acme-relay-marker.backup" "$ACME_HTTP01_RELAY_MARKER"
			else
				rm -f -- "$ACME_HTTP01_RELAY_MARKER"
			fi
			systemctl reload caddy || true
		fi
	fi
	if [ -n "$TEMP_DIRECTORY" ] && [ -d "$TEMP_DIRECTORY" ]; then
		rm -rf -- "$TEMP_DIRECTORY"
	fi
	if [ -n "$ENROLLMENT_TOKEN_TEMP" ] &&
		[ -f "$ENROLLMENT_TOKEN_TEMP" ] &&
		[ ! -L "$ENROLLMENT_TOKEN_TEMP" ]; then
		rm -f -- "$ENROLLMENT_TOKEN_TEMP"
	fi
	if [ "$INSTALL_SUCCEEDED" != "yes" ] &&
		[ "$AGENT_WAS_ACTIVE" = "yes" ] &&
		[ "$AGENT_STOPPED" = "yes" ]; then
		if ! systemctl start theatropolis-agent; then
			printf '%s\n' \
				'theatropolis installer: the previous agent could not be restarted after installation failed' >&2
		fi
		AGENT_STOPPED="no"
	fi
	exit "$CLEANUP_STATUS"
}

handle_signal() {
	exit "$1"
}

trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

validate_enrollment_token() {
	printf '%s' "$ENROLLMENT_TOKEN" |
		grep -Eq '^[A-Za-z0-9_-]{43}$' ||
		fail "the enrollment token is not a 32-byte base64url value"
}

prompt_for_enrollment_token() {
	if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
		fail "a terminal is required to enter the enrollment token; use --token only for secured automation"
	fi
	TTY_SETTINGS="$(stty -g </dev/tty)" ||
		fail "could not read terminal settings for the enrollment token prompt"
	stty -echo </dev/tty ||
		fail "could not disable terminal echo for the enrollment token prompt"
	printf 'Enrollment token: ' >/dev/tty
	if ! IFS= read -r ENROLLMENT_TOKEN </dev/tty; then
		stty "$TTY_SETTINGS" </dev/tty >/dev/null 2>&1 || true
		TTY_SETTINGS=""
		printf '\n' >/dev/tty
		fail "could not read the enrollment token from the terminal"
	fi
	stty "$TTY_SETTINGS" </dev/tty ||
		fail "could not restore terminal settings after reading the enrollment token"
	TTY_SETTINGS=""
	printf '\n' >/dev/tty
	validate_enrollment_token
}

sing_box_output_has_tag() {
	printf '%s\n' "$1" |
		awk -v expected="$2" '
			/^Tags:[[:space:]]*/ {
				line = $0
				sub(/^Tags:[[:space:]]*/, "", line)
				count = split(line, tags, ",")
				for (position = 1; position <= count; position++) {
					sub(/^[[:space:]]*/, "", tags[position])
					sub(/[[:space:]\r]*$/, "", tags[position])
					if (tags[position] == expected) found = 1
				}
			}
			END { exit found ? 0 : 1 }
		'
}

installed_sing_box_usable() {
	SING_BOX_INSTALLED_BINARY="$INSTALL_DIRECTORY/sing-box"
	SING_BOX_INSTALLED_LIBRARY="$SING_BOX_LIBRARY_DIRECTORY/libcronet.so"
	for SING_BOX_INSTALLED_COMPONENT in \
		"$SING_BOX_INSTALLED_BINARY" \
		"$SING_BOX_INSTALLED_LIBRARY"; do
		if [ ! -f "$SING_BOX_INSTALLED_COMPONENT" ] ||
			[ -L "$SING_BOX_INSTALLED_COMPONENT" ]; then
			return 1
		fi
	done
	[ -x "$SING_BOX_INSTALLED_BINARY" ] || return 1
	SING_BOX_INSTALLED_VERSION_OUTPUT="$(
		LD_LIBRARY_PATH="$SING_BOX_LIBRARY_DIRECTORY" \
			"$SING_BOX_INSTALLED_BINARY" version 2>/dev/null
	)" || return 1
	printf '%s\n' "$SING_BOX_INSTALLED_VERSION_OUTPUT" |
		grep -Eq '^sing-box version (1\.(1[4-9]|[2-9][0-9])|([2-9]|[1-9][0-9]+)\.[0-9]+)\.[0-9]+([-+][0-9A-Za-z.-]+)?$' ||
		return 1
	sing_box_output_has_tag \
		"$SING_BOX_INSTALLED_VERSION_OUTPUT" \
		with_v2ray_api || return 1
	sing_box_output_has_tag \
		"$SING_BOX_INSTALLED_VERSION_OUTPUT" \
		with_theatropolis_managed_users || return 1
	return 0
}

validate_master_endpoint() {
	printf '%s' "$DOMAIN" |
		grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$' ||
		fail "the public domain must be a valid DNS name"
	case "$HTTPS_PORT" in
	*[!0-9]* | '') fail "the Caddy HTTPS port must be numeric" ;;
	??????*) fail "the Caddy HTTPS port must be 443 or between 1024 and 65535" ;;
	esac
	if [ "$HTTPS_PORT" != "443" ] &&
		{ [ "$HTTPS_PORT" -lt 1024 ] || [ "$HTTPS_PORT" -gt 65535 ]; }; then
		fail "the Caddy HTTPS port must be 443 or between 1024 and 65535"
	fi
}

prompt_for_master_endpoint() {
	if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
		fail "a terminal is required to configure the public domain and Caddy HTTPS port"
	fi
	printf 'Public domain name: ' >/dev/tty
	if ! IFS= read -r DOMAIN </dev/tty; then
		fail "could not read the public domain from the terminal"
	fi
	printf 'Caddy HTTPS port [%s]: ' "$DEFAULT_HTTPS_PORT" >/dev/tty
	if ! IFS= read -r CADDY_HTTPS_PORT_INPUT </dev/tty; then
		fail "could not read the Caddy HTTPS port from the terminal"
	fi
	if [ -n "$CADDY_HTTPS_PORT_INPUT" ]; then
		HTTPS_PORT="$CADDY_HTTPS_PORT_INPUT"
	fi
	CADDY_HTTPS_PORT_INPUT=""
	validate_master_endpoint
}

validate_admin_username() {
	printf '%s' "$ADMIN_USERNAME" |
		grep -Eq '^[a-z0-9][a-z0-9._-]{0,63}$' ||
		fail "the admin username is invalid"
}

validate_admin_password_file() {
	if [ -L "$ADMIN_PASSWORD_FILE" ] || [ ! -f "$ADMIN_PASSWORD_FILE" ]; then
		fail "--admin-password-file must be a regular file, not a symbolic link"
	fi
	FILE_OWNER="$(stat -c '%u' -- "$ADMIN_PASSWORD_FILE")" ||
		fail "could not inspect --admin-password-file ownership"
	[ "$FILE_OWNER" = "0" ] ||
		fail "--admin-password-file must be owned by root"
	FILE_MODE="$(stat -c '%a' -- "$ADMIN_PASSWORD_FILE")" ||
		fail "could not inspect --admin-password-file permissions"
	case "$FILE_MODE" in
	400 | 600) ;;
	*) fail "--admin-password-file permissions must be 0400 or 0600" ;;
	esac
	ADMIN_PASSWORD_FILE_ID="$(stat -c '%d:%i' -- "$ADMIN_PASSWORD_FILE")" ||
		fail "could not inspect --admin-password-file identity"
}

snapshot_admin_password_file() {
	[ -n "$TEMP_DIRECTORY" ] ||
		fail "cannot snapshot --admin-password-file before temporary storage is ready"
	ADMIN_PASSWORD_SNAPSHOT="$TEMP_DIRECTORY/admin-password"
	if ! cp -p --no-dereference -- \
		"$ADMIN_PASSWORD_FILE" \
		"$ADMIN_PASSWORD_SNAPSHOT"; then
		fail "could not securely snapshot --admin-password-file"
	fi
	if [ -L "$ADMIN_PASSWORD_SNAPSHOT" ] ||
		[ ! -f "$ADMIN_PASSWORD_SNAPSHOT" ]; then
		fail "--admin-password-file changed while it was being read"
	fi
	SNAPSHOT_OWNER="$(stat -c '%u' "$ADMIN_PASSWORD_SNAPSHOT")" ||
		fail "could not inspect the admin password snapshot ownership"
	[ "$SNAPSHOT_OWNER" = "0" ] ||
		fail "--admin-password-file changed while it was being read"
	SNAPSHOT_MODE="$(stat -c '%a' "$ADMIN_PASSWORD_SNAPSHOT")" ||
		fail "could not inspect the admin password snapshot permissions"
	case "$SNAPSHOT_MODE" in
	400 | 600) ;;
	*) fail "--admin-password-file changed while it was being read" ;;
	esac
	CURRENT_PASSWORD_FILE_ID="$(
		stat -c '%d:%i' -- "$ADMIN_PASSWORD_FILE" 2>/dev/null || true
	)"
	[ "$CURRENT_PASSWORD_FILE_ID" = "$ADMIN_PASSWORD_FILE_ID" ] ||
		fail "--admin-password-file changed while it was being read"
}

prompt_for_admin_credentials() {
	if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
		fail "a terminal is required to choose web admin credentials; use --admin-username with --admin-password-file for secured automation"
	fi
	if [ -z "$ADMIN_USERNAME" ]; then
		printf 'Admin username [admin]: ' >/dev/tty
		if ! IFS= read -r ADMIN_USERNAME </dev/tty; then
			fail "could not read the admin username from the terminal"
		fi
		if [ -z "$ADMIN_USERNAME" ]; then
			ADMIN_USERNAME="admin"
		fi
	fi
	validate_admin_username

	TTY_SETTINGS="$(stty -g </dev/tty)" ||
		fail "could not read terminal settings for the admin password prompt"
	stty -echo </dev/tty ||
		fail "could not disable terminal echo for the admin password prompt"
	printf 'Admin password (15-128 characters): ' >/dev/tty
	if ! IFS= read -r WEB_ADMIN_PASSWORD </dev/tty; then
		stty "$TTY_SETTINGS" </dev/tty >/dev/null 2>&1 || true
		TTY_SETTINGS=""
		printf '\n' >/dev/tty
		fail "could not read the admin password from the terminal"
	fi
	printf '\nConfirm admin password: ' >/dev/tty
	if ! IFS= read -r WEB_ADMIN_PASSWORD_CONFIRM </dev/tty; then
		stty "$TTY_SETTINGS" </dev/tty >/dev/null 2>&1 || true
		TTY_SETTINGS=""
		WEB_ADMIN_PASSWORD=""
		printf '\n' >/dev/tty
		fail "could not read the admin password confirmation from the terminal"
	fi
	stty "$TTY_SETTINGS" </dev/tty ||
		fail "could not restore terminal settings after reading the admin password"
	TTY_SETTINGS=""
	printf '\n' >/dev/tty
	if [ "$WEB_ADMIN_PASSWORD" != "$WEB_ADMIN_PASSWORD_CONFIRM" ]; then
		WEB_ADMIN_PASSWORD=""
		WEB_ADMIN_PASSWORD_CONFIRM=""
		fail "the admin password confirmation did not match"
	fi
	WEB_ADMIN_PASSWORD_CONFIRM=""
}

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
		RELEASE_TAG="$2"
		shift 2
		;;
	--master)
		[ "$#" -ge 2 ] || fail "--master requires a value"
		MASTER_ADDRESS="$2"
		shift 2
		;;
	--server)
		[ "$#" -ge 2 ] || fail "--server requires a value"
		SERVER_NAME="$2"
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
	--admin-username)
		[ "$#" -ge 2 ] || fail "--admin-username requires a value"
		ADMIN_USERNAME="$2"
		shift 2
		;;
	--admin-password-file)
		[ "$#" -ge 2 ] || fail "--admin-password-file requires a value"
		ADMIN_PASSWORD_FILE="$2"
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
command -v flock >/dev/null 2>&1 || fail "util-linux flock is required"
[ -x /usr/bin/setpriv ] || fail "util-linux setpriv is required"
exec 9>"$INSTALL_LOCK_FILE" ||
	fail "could not open the installer lock file"
flock -n 9 ||
	fail "another Theatropolis installer is already running"

case "$(uname -m)" in
x86_64 | amd64)
	ARCHITECTURE="amd64"
	;;
aarch64 | arm64)
	ARCHITECTURE="arm64"
	;;
*) fail "only amd64 and arm64 are supported" ;;
esac

if [ "$RELEASE_TAG" != "latest" ]; then
	printf '%s' "$RELEASE_TAG" |
		grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$' ||
		fail "invalid release tag"
fi

case "$ROLE" in
master | all)
	prompt_for_master_endpoint
	if [ -n "$ADMIN_USERNAME" ]; then
		validate_admin_username
	fi
	if [ -n "$ADMIN_PASSWORD_FILE" ]; then
		[ -n "$ADMIN_USERNAME" ] ||
			fail "--admin-password-file requires --admin-username"
		validate_admin_password_file
	fi
	;;
esac

if [ "$ROLE" = "agent" ] &&
	{ [ -n "$ADMIN_USERNAME" ] || [ -n "$ADMIN_PASSWORD_FILE" ]; }; then
	fail "--admin-username and --admin-password-file are only valid for master or all"
fi
if [ "$ROLE" != "all" ] && [ -n "$SERVER_NAME" ]; then
	fail "--server is only valid for an all-in-one installation"
fi

case "$ROLE" in
agent | all)
	if [ "$ROLE" = "all" ]; then
		[ -n "$SERVER_NAME" ] || fail "--server is required"
		SERVER_NAME_BYTES="$(printf '%s' "$SERVER_NAME" | LC_ALL=C wc -c | tr -d ' ')"
		[ "$SERVER_NAME_BYTES" -le 240 ] || fail "--server exceeds the display-name size limit"
		printf '%s' "$SERVER_NAME" | LC_ALL=C grep -q '[[:cntrl:]]' &&
			fail "--server contains a control character"
	fi
	if [ "$ROLE" = "all" ] && [ -z "$MASTER_ADDRESS" ]; then
		MASTER_ADDRESS="${DOMAIN}:${HTTPS_PORT}"
	fi
	printf '%s' "$MASTER_ADDRESS" |
		grep -Eq '^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}$' ||
		fail "--master must be a host:port pair"
	IDENTITY_FILE="$AGENT_STATE_DIRECTORY/identity.pem"
	if [ -L "$IDENTITY_FILE" ] ||
		{ [ -e "$IDENTITY_FILE" ] && [ ! -f "$IDENTITY_FILE" ]; }; then
		fail "the existing agent identity is not a regular file"
	fi
	if [ -n "$ENROLLMENT_TOKEN" ]; then
		validate_enrollment_token
	elif [ "$ROLE" = "agent" ] &&
		[ ! -f "$IDENTITY_FILE" ]; then
		prompt_for_enrollment_token
	fi
	if [ -f "$IDENTITY_FILE" ] && installed_sing_box_usable; then
		# A working managed-user sing-box has its own independent signed update
		# plane. Reinstalling the Agent must not silently replace it.
		SING_BOX_BOOTSTRAP_REQUIRED="no"
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
apt-get install -y ca-certificates curl openssl tar

TEMP_DIRECTORY="$(mktemp -d)"
ARCHIVE_NAME="theatropolis_linux_${ARCHITECTURE}.tar.gz"
if [ "$RELEASE_TAG" = "latest" ]; then
	RELEASE_BASE="https://github.com/${REPOSITORY}/releases/latest/download"
else
	RELEASE_BASE="https://github.com/${REPOSITORY}/releases/download/${RELEASE_TAG}"
fi
CURL_OPTIONS="--fail --silent --show-error --location --proto =https --tlsv1.2 --retry 3"
# Word splitting is intentional for the constant curl option list.
# shellcheck disable=SC2086
curl $CURL_OPTIONS -o "$TEMP_DIRECTORY/$ARCHIVE_NAME" "$RELEASE_BASE/$ARCHIVE_NAME"
# shellcheck disable=SC2086
curl $CURL_OPTIONS -o "$TEMP_DIRECTORY/checksums.txt" "$RELEASE_BASE/checksums.txt"
# shellcheck disable=SC2086
curl $CURL_OPTIONS -o "$TEMP_DIRECTORY/checksums.txt.sig" "$RELEASE_BASE/checksums.txt.sig"

cat >"$TEMP_DIRECTORY/release-signing-public.pem" <<'EOF'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAwjM8e7oVpp1jdwmpJvzO
4RGSauhfzcVYe4G5eJFgi14B4aaFBtI47KLWhaqR9mQqHum6n93Rx+GykWQLy44s
7cd45BeBU2REExZPaFsmVMVZcz7YtiCrkgx7IpuKWxOWaDXdFFrCOj4Dj5GhKe63
UxrrYeIYYKQcXLnfHkFm3vmVAbgMfwmfZhc7fV6WsleNumvJrGTsvMQpYV6q6Rg/
PSdnjSBryfd4Tnqisa8ddq7E4MSMpkYQ6d48VDGpCp0xMk41yAef65kfvuPz3Shf
xoMYIQdVhTHEDLCKOw2bDb+7axqSOXC++EETPCbu0r0lXTlDtaPErow1VcJMv18h
hxpGzDZWJQeLlwXOrLqMRN1mADGr8v02W1JfW6rRAnJVBP8Amn0fK3f0fNUvSltJ
yrCvAulMOVYoQt7TQUWzBSHFTny7O7U1vVCzqJ8aCaRRwpUvVKgiBEh9EMpzg16X
WZPwbJF9uiw1LFQTdqgFR/MswrS/i2umtOYdf34kfWF/AgMBAAE=
-----END PUBLIC KEY-----
EOF
if ! openssl dgst -sha256 \
	-verify "$TEMP_DIRECTORY/release-signing-public.pem" \
	-signature "$TEMP_DIRECTORY/checksums.txt.sig" \
	-sigopt rsa_padding_mode:pss \
	-sigopt rsa_pss_saltlen:32 \
	"$TEMP_DIRECTORY/checksums.txt" >/dev/null; then
	fail "release checksum manifest signature verification failed"
fi

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
	theatropolis-master | theatropolis-agent | theatropolis-update-helper) ;;
	*) fail "release archive contains an unexpected path: $ENTRY" ;;
	esac
	ENTRY_COUNT=$((ENTRY_COUNT + 1))
done <<EOF
$(tar -tzf "$TEMP_DIRECTORY/$ARCHIVE_NAME")
EOF
[ "$ENTRY_COUNT" -eq 3 ] || fail "release archive does not contain exactly three binaries"
tar --no-same-owner -xzf "$TEMP_DIRECTORY/$ARCHIVE_NAME" -C "$TEMP_DIRECTORY/extracted"
for COMPONENT in master agent update-helper; do
	BINARY="$TEMP_DIRECTORY/extracted/theatropolis-$COMPONENT"
	if [ ! -f "$BINARY" ] || [ -L "$BINARY" ]; then
		fail "release archive is missing the $COMPONENT binary"
	fi
done

prepare_sing_box() {
	SING_BOX_PACKAGE="sing-box-${SING_BOX_VERSION}-linux-${ARCHITECTURE}"
	SING_BOX_ARCHIVE="${SING_BOX_PACKAGE}.tar.gz"
	SING_BOX_RELEASE_BASE="https://github.com/${SING_BOX_REPOSITORY}/releases/download/v${SING_BOX_VERSION}"
	SING_BOX_ARCHIVE_PATH="$TEMP_DIRECTORY/$SING_BOX_ARCHIVE"
	SING_BOX_MANIFEST_PATH="$TEMP_DIRECTORY/sing-box-checksums.txt"
	SING_BOX_SIGNATURE_PATH="$TEMP_DIRECTORY/sing-box-checksums.txt.sig"
	SING_BOX_BUILD_MANIFEST_PATH="$TEMP_DIRECTORY/sing-box-build-manifest.json"
	SING_BOX_PUBLIC_KEY_PATH="$TEMP_DIRECTORY/sing-box-release-signing-public.pem"
	# Word splitting is intentional for the constant curl option list.
	# shellcheck disable=SC2086
	curl $CURL_OPTIONS \
		-o "$SING_BOX_MANIFEST_PATH" \
		"$SING_BOX_RELEASE_BASE/checksums.txt"
	# shellcheck disable=SC2086
	curl $CURL_OPTIONS \
		-o "$SING_BOX_SIGNATURE_PATH" \
		"$SING_BOX_RELEASE_BASE/checksums.txt.sig"
	# shellcheck disable=SC2086
	curl $CURL_OPTIONS \
		-o "$SING_BOX_BUILD_MANIFEST_PATH" \
		"$SING_BOX_RELEASE_BASE/build-manifest.json"

	cat >"$SING_BOX_PUBLIC_KEY_PATH" <<'EOF'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyfM82BiyFd5HnGrCDVWz
cbNsmNVt4gRudcg+aF4rtZeHQ6a0+NA18MjwWqAxGDyjd1Zbh1RSV/SneSMoQs7r
0JgyTirWp+iqhQFVuSgwSIaC+p8rcLJ/g09wADBOwJJJJK8xlLwiRa1TTlKGS7Q8
f3x/g/1DeD72oIyEwC4Sr06aefv0kjzPQ4NvN4ArCakWeRf1+LNDirWwCFdYTaU7
p4azubUGlopolqPSI5NYHqICSGoi1KOkQWbH8A4dH7u87TbRrd3k9hBy2oTbYZrH
ztukFC5x4iWEnAW94P1CxHWPIL/E4QELSoD/bfm9t4zSsqZAOoHzjqSRkPyMqVOP
EgT8WenoIQV2jJsNYacpG+HdBOHxw7KHlutl1kojuBIXB4+sLRGnZ9KsU6uPZJqA
E8ytHGgU3PKNx/cDrPzElJ/4NXFkEL6xwAVzbJVgLP3Ik53QREvqgL4ifAwH+gQ0
Td2bRXboqG6wtCBLGSk6FM2SJJrAej2vvItY78x75t5tAgMBAAE=
-----END PUBLIC KEY-----
EOF
	if ! openssl dgst -sha256 \
		-verify "$SING_BOX_PUBLIC_KEY_PATH" \
		-signature "$SING_BOX_SIGNATURE_PATH" \
		-sigopt rsa_padding_mode:pss \
		-sigopt rsa_pss_saltlen:32 \
		"$SING_BOX_MANIFEST_PATH" >/dev/null; then
		fail "sing-box checksum manifest signature verification failed"
	fi

	SING_BOX_SIGNED_SHA256="$(
		awk -v archive="$SING_BOX_ARCHIVE" '
			$2 == archive { matches++; checksum = $1 }
			END { if (matches == 1) print checksum }
		' "$SING_BOX_MANIFEST_PATH"
	)"
	printf '%s' "$SING_BOX_SIGNED_SHA256" |
		grep -Eq '^[a-f0-9]{64}$' ||
		fail "sing-box release checksum is missing or invalid"
	SING_BOX_SIGNED_BUILD_MANIFEST_SHA256="$(
		awk '
			$2 == "build-manifest.json" { matches++; checksum = $1 }
			END { if (matches == 1) print checksum }
		' "$SING_BOX_MANIFEST_PATH"
	)"
	printf '%s' "$SING_BOX_SIGNED_BUILD_MANIFEST_SHA256" |
		grep -Eq '^[a-f0-9]{64}$' ||
		fail "sing-box build manifest checksum is missing or invalid"
	SING_BOX_ACTUAL_BUILD_MANIFEST_SHA256="$(
		sha256sum "$SING_BOX_BUILD_MANIFEST_PATH" |
			awk '{ print $1 }'
	)"
	[ "$SING_BOX_ACTUAL_BUILD_MANIFEST_SHA256" = "$SING_BOX_SIGNED_BUILD_MANIFEST_SHA256" ] ||
		fail "sing-box build manifest checksum verification failed"
	if ! "$TEMP_DIRECTORY/extracted/theatropolis-master" \
		validate-sing-box-build-manifest \
		--version "$SING_BOX_TAG" \
		--file "$SING_BOX_BUILD_MANIFEST_PATH"; then
		fail "sing-box build manifest lacks required managed-user capabilities"
	fi
	# shellcheck disable=SC2086
	curl $CURL_OPTIONS \
		-o "$SING_BOX_ARCHIVE_PATH" \
		"$SING_BOX_RELEASE_BASE/$SING_BOX_ARCHIVE"

	SING_BOX_ACTUAL_SHA256="$(
		sha256sum "$SING_BOX_ARCHIVE_PATH" |
			awk '{ print $1 }'
	)"
	[ "$SING_BOX_ACTUAL_SHA256" = "$SING_BOX_SIGNED_SHA256" ] ||
		fail "sing-box archive checksum verification failed"

	SING_BOX_ENTRY_COUNT=0
	while IFS= read -r SING_BOX_ENTRY; do
		case "$SING_BOX_ENTRY" in
		"$SING_BOX_PACKAGE/" | \
			"$SING_BOX_PACKAGE/sing-box" | \
			"$SING_BOX_PACKAGE/libcronet.so" | \
			"$SING_BOX_PACKAGE/LICENSE") ;;
		*) fail "sing-box archive contains an unexpected path: $SING_BOX_ENTRY" ;;
		esac
		SING_BOX_ENTRY_COUNT=$((SING_BOX_ENTRY_COUNT + 1))
	done <<EOF
$(tar --quoting-style=escape -tzf "$SING_BOX_ARCHIVE_PATH")
EOF
	[ "$SING_BOX_ENTRY_COUNT" -eq 4 ] ||
		fail "sing-box archive does not contain exactly the expected files"

	SING_BOX_TYPED_ENTRY_COUNT=0
	while IFS=' ' read -r SING_BOX_ENTRY_TYPE SING_BOX_ENTRY_PATH; do
		case "$SING_BOX_ENTRY_TYPE:$SING_BOX_ENTRY_PATH" in
		"d:$SING_BOX_PACKAGE/" | \
			"-:$SING_BOX_PACKAGE/sing-box" | \
			"-:$SING_BOX_PACKAGE/libcronet.so" | \
			"-:$SING_BOX_PACKAGE/LICENSE") ;;
		*) fail "sing-box archive contains an unsafe entry type" ;;
		esac
		SING_BOX_TYPED_ENTRY_COUNT=$((SING_BOX_TYPED_ENTRY_COUNT + 1))
	done <<EOF
$(tar --quoting-style=escape -tvzf "$SING_BOX_ARCHIVE_PATH" |
		awk '{ print substr($1, 1, 1), $NF }')
EOF
	[ "$SING_BOX_TYPED_ENTRY_COUNT" -eq 4 ] ||
		fail "sing-box archive does not contain exactly the expected entry types"

	SING_BOX_EXTRACT_DIRECTORY="$TEMP_DIRECTORY/sing-box"
	mkdir "$SING_BOX_EXTRACT_DIRECTORY"
	tar \
		--no-same-owner \
		--no-same-permissions \
		--keep-directory-symlink \
		-xzf "$SING_BOX_ARCHIVE_PATH" \
		-C "$SING_BOX_EXTRACT_DIRECTORY" \
		"$SING_BOX_PACKAGE/sing-box" \
		"$SING_BOX_PACKAGE/libcronet.so" \
		"$SING_BOX_PACKAGE/LICENSE"
	for SING_BOX_COMPONENT in sing-box libcronet.so LICENSE; do
		SING_BOX_COMPONENT_PATH="$SING_BOX_EXTRACT_DIRECTORY/$SING_BOX_PACKAGE/$SING_BOX_COMPONENT"
		if [ ! -f "$SING_BOX_COMPONENT_PATH" ] ||
			[ -L "$SING_BOX_COMPONENT_PATH" ]; then
			fail "sing-box archive did not extract a regular $SING_BOX_COMPONENT file"
		fi
	done
	SING_BOX_VERSION_OUTPUT="$("$SING_BOX_EXTRACT_DIRECTORY/$SING_BOX_PACKAGE/sing-box" version 2>/dev/null)" ||
		fail "sing-box candidate version could not be verified"
	printf '%s\n' "$SING_BOX_VERSION_OUTPUT" |
		grep -Fqx "sing-box version $SING_BOX_VERSION" ||
		fail "sing-box candidate reported an unexpected version"
	sing_box_output_has_tag "$SING_BOX_VERSION_OUTPUT" with_v2ray_api ||
		fail "sing-box candidate lacks V2Ray API support"
	sing_box_output_has_tag \
		"$SING_BOX_VERSION_OUTPUT" \
		with_theatropolis_managed_users ||
		fail "sing-box candidate lacks Theatropolis managed-user support"
}

resolve_sing_box_version() {
	SING_BOX_TAG="$(
		"$TEMP_DIRECTORY/extracted/theatropolis-master" latest-sing-box-version
	)" || fail "could not resolve the latest supported sing-box release"
	printf '%s' "$SING_BOX_TAG" |
		grep -Eq '^v(1\.(1[4-9]|[2-9][0-9])|([2-9]|[1-9][0-9]+)\.[0-9]+)\.[0-9]+(-rc\.[0-9]+\.theatropolis\.[1-9][0-9]*|-theatropolis\.[1-9][0-9]*)$' ||
		fail "the latest sing-box release has an invalid version"
	SING_BOX_VERSION="${SING_BOX_TAG#v}"
}

case "$ROLE" in
agent | all)
	if [ "$SING_BOX_BOOTSTRAP_REQUIRED" = "yes" ]; then
		resolve_sing_box_version
		prepare_sing_box
	fi
	;;
esac

case "$ROLE" in
master | all)
	COMPATIBILITY_STATE="$TEMP_DIRECTORY/master-compatibility"
	mkdir "$COMPATIBILITY_STATE"
	if ! printf '%s\n' 'theatropolis-compatibility-password' |
		"$TEMP_DIRECTORY/extracted/theatropolis-master" set-web-admin \
			--state-dir "$COMPATIBILITY_STATE" \
			--username compatibility \
			--password-stdin >/dev/null 2>&1; then
		fail "the selected release does not support password-based web administration; choose a newer version"
	fi
	if [ ! -f "$COMPATIBILITY_STATE/web-auth.json" ] ||
		[ -L "$COMPATIBILITY_STATE/web-auth.json" ]; then
		fail "the selected release did not create a valid web admin credential"
	fi
	COMPATIBILITY_AUTH_FILE="$WEB_AUTH_FILE"
	if [ ! -e "$COMPATIBILITY_AUTH_FILE" ] && [ ! -L "$COMPATIBILITY_AUTH_FILE" ] &&
		{ [ -e "$LEGACY_WEB_AUTH_FILE" ] || [ -L "$LEGACY_WEB_AUTH_FILE" ]; }; then
		COMPATIBILITY_AUTH_FILE="$LEGACY_WEB_AUTH_FILE"
	fi
	if [ -e "$COMPATIBILITY_AUTH_FILE" ] || [ -L "$COMPATIBILITY_AUTH_FILE" ]; then
		if [ -L "$COMPATIBILITY_AUTH_FILE" ] || [ ! -f "$COMPATIBILITY_AUTH_FILE" ]; then
			fail "the web access file exists but is not a regular file"
		fi
		COMPATIBILITY_EXISTING="$TEMP_DIRECTORY/master-existing-compatibility"
		mkdir "$COMPATIBILITY_EXISTING"
		cp -a "$COMPATIBILITY_AUTH_FILE" "$COMPATIBILITY_EXISTING/web-auth.json"
		if ! printf '%s\n' 'theatropolis-compatibility-password' |
			"$TEMP_DIRECTORY/extracted/theatropolis-master" set-web-admin \
				--state-dir "$COMPATIBILITY_EXISTING" \
				--username compatibility \
				--password-stdin \
				--replace >/dev/null 2>&1; then
			fail "the selected release cannot migrate the existing web admin credential"
		fi
	fi
	;;
esac

install_binary() {
	COMPONENT="$1"
	install -o root -g root -m 0755 \
		"$TEMP_DIRECTORY/extracted/theatropolis-$COMPONENT" \
		"$INSTALL_DIRECTORY/theatropolis-$COMPONENT"
}

install_update_helper() {
	install -d -o root -g root -m 0755 "$UPDATE_HELPER_DIRECTORY"
	install -o root -g root -m 0755 \
		"$TEMP_DIRECTORY/extracted/theatropolis-update-helper" \
		"$UPDATE_HELPER_PATH"
}

install_sing_box() {
	SING_BOX_LIBRARY_PARENT="${SING_BOX_LIBRARY_DIRECTORY%/*}"
	for SING_BOX_DIRECTORY in \
		"$SING_BOX_LIBRARY_PARENT" \
		"$SING_BOX_LIBRARY_DIRECTORY"; do
		if [ -L "$SING_BOX_DIRECTORY" ] ||
			{ [ -e "$SING_BOX_DIRECTORY" ] && [ ! -d "$SING_BOX_DIRECTORY" ]; }; then
			fail "sing-box library path is not a directory: $SING_BOX_DIRECTORY"
		fi
	done
	for SING_BOX_TARGET in \
		"$SING_BOX_LIBRARY_DIRECTORY/libcronet.so" \
		"$INSTALL_DIRECTORY/sing-box"; do
		if [ -L "$SING_BOX_TARGET" ] ||
			{ [ -e "$SING_BOX_TARGET" ] && [ ! -f "$SING_BOX_TARGET" ]; }; then
			fail "sing-box install target is not a regular file: $SING_BOX_TARGET"
		fi
	done
	install -d -o root -g root -m 0755 "$SING_BOX_LIBRARY_DIRECTORY"
	install -o root -g root -m 0644 \
		"$SING_BOX_EXTRACT_DIRECTORY/$SING_BOX_PACKAGE/libcronet.so" \
		"$SING_BOX_LIBRARY_DIRECTORY/libcronet.so"
	install -o root -g root -m 0755 \
		"$SING_BOX_EXTRACT_DIRECTORY/$SING_BOX_PACKAGE/sing-box" \
		"$INSTALL_DIRECTORY/sing-box"
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
	if [ -L "$HOME_DIRECTORY" ] ||
		{ [ -e "$HOME_DIRECTORY" ] && [ ! -d "$HOME_DIRECTORY" ]; }; then
		fail "service state path is not a directory: $HOME_DIRECTORY"
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
	header Strict-Transport-Security "max-age=31536000"

	@agent {
		protocol grpc
		path /theatropolis.control.v1.AgentControlService/*
	}

	handle @agent {
		reverse_proxy h2c://127.0.0.1:8081 {
			header_up -Authorization
			header_up -Cookie
		}
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

configure_acme_http01_relay() {
	# An explicit named HTTP site must precede Caddy's automatic HTTPS
	# redirect for the Master hostname. The catch-all alone cannot do that.
	detect_local_master_dial_address
	case "$LOCAL_MASTER_ADDRESS" in
		'' | *[!A-Za-z0-9.:-]*) fail "cannot determine the local Master's ACME relay hostname" ;;
	esac
	printf '%s\n' "$LOCAL_MASTER_ADDRESS" | grep -Eq '^[A-Za-z0-9.-]+:[0-9]{1,5}$' ||
		fail "cannot determine the local Master's ACME relay hostname"
	RELAY_MASTER_HOST="${LOCAL_MASTER_ADDRESS%:*}"
	install_caddy
	install -d -o root -g root -m 0755 /etc/caddy/conf.d "$CONFIG_DIRECTORY"
	if [ "$RELAY_TOUCHED" = "no" ]; then
		if [ -e "$CADDY_RELAY_SNIPPET" ] || [ -L "$CADDY_RELAY_SNIPPET" ]; then
			[ -f "$CADDY_RELAY_SNIPPET" ] && [ ! -L "$CADDY_RELAY_SNIPPET" ] ||
				fail "the ACME relay Caddy entry is not a regular file"
			HAD_RELAY_SNIPPET="yes"
			cp -a "$CADDY_RELAY_SNIPPET" "$TEMP_DIRECTORY/theatropolis-agent-acme.caddy.backup"
		fi
		if [ -e "$ACME_HTTP01_RELAY_MARKER" ] || [ -L "$ACME_HTTP01_RELAY_MARKER" ]; then
			[ -f "$ACME_HTTP01_RELAY_MARKER" ] && [ ! -L "$ACME_HTTP01_RELAY_MARKER" ] ||
				fail "the ACME relay marker is not a regular file"
			cp -a "$ACME_HTTP01_RELAY_MARKER" "$TEMP_DIRECTORY/acme-relay-marker.backup"
			HAD_RELAY_MARKER="yes"
		fi
		RELAY_TOUCHED="yes"
	fi
	cat >"$CADDY_RELAY_SNIPPET" <<EOF
(theatropolis_agent_acme_relay) {
	@theatropolis_agent_acme {
		method GET HEAD
		path /.well-known/acme-challenge/*
	}

	handle @theatropolis_agent_acme {
		reverse_proxy 127.0.0.1:${ACME_HTTP01_RELAY_PORT}
	}
}

http://${RELAY_MASTER_HOST} {
	import theatropolis_agent_acme_relay
	handle {
		redir https://${LOCAL_MASTER_ADDRESS}{uri} 308
	}
}

:80 {
	import theatropolis_agent_acme_relay
}
EOF
	chmod 0644 "$CADDY_RELAY_SNIPPET"
	caddy fmt --overwrite "$CADDY_RELAY_SNIPPET"
	if ! caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile; then
		if [ "$HAD_RELAY_SNIPPET" = "yes" ]; then
			cp -a "$TEMP_DIRECTORY/theatropolis-agent-acme.caddy.backup" "$CADDY_RELAY_SNIPPET"
		else
			rm -f -- "$CADDY_RELAY_SNIPPET"
		fi
		fail "Caddy rejected the co-located Agent ACME relay; the previous entry was restored"
	fi
	if ! systemctl reload caddy; then
		if [ "$HAD_RELAY_SNIPPET" = "yes" ]; then
			cp -a "$TEMP_DIRECTORY/theatropolis-agent-acme.caddy.backup" "$CADDY_RELAY_SNIPPET"
		else
			rm -f -- "$CADDY_RELAY_SNIPPET"
		fi
		systemctl reload caddy || true
		fail "Caddy could not load the co-located Agent ACME relay; the previous entry was restored"
	fi
	printf '%s\n' "$ACME_HTTP01_RELAY_PORT" >"$ACME_HTTP01_RELAY_MARKER"
	chown root:root "$ACME_HTTP01_RELAY_MARKER"
	chmod 0644 "$ACME_HTTP01_RELAY_MARKER"
}

run_set_web_admin() {
	ADMIN_BINARY="$1"
	REPLACE_ADMIN="$2"
	ADMIN_STATUS=0
	if [ -n "$ADMIN_PASSWORD_FILE" ]; then
		[ -n "$ADMIN_PASSWORD_SNAPSHOT" ] ||
			fail "the admin password file was not securely snapshotted"
		if [ "$REPLACE_ADMIN" = "yes" ]; then
			"$ADMIN_BINARY" set-web-admin \
				--state-dir "$MASTER_STATE_DIRECTORY" \
				--username "$ADMIN_USERNAME" \
				--password-stdin \
				--replace <"$ADMIN_PASSWORD_SNAPSHOT" ||
				ADMIN_STATUS="$?"
		else
			"$ADMIN_BINARY" set-web-admin \
				--state-dir "$MASTER_STATE_DIRECTORY" \
				--username "$ADMIN_USERNAME" \
				--password-stdin <"$ADMIN_PASSWORD_SNAPSHOT" ||
				ADMIN_STATUS="$?"
		fi
	else
		if [ "$REPLACE_ADMIN" = "yes" ]; then
			printf '%s\n' "$WEB_ADMIN_PASSWORD" |
				"$ADMIN_BINARY" set-web-admin \
					--state-dir "$MASTER_STATE_DIRECTORY" \
					--username "$ADMIN_USERNAME" \
					--password-stdin \
					--replace ||
				ADMIN_STATUS="$?"
		else
			printf '%s\n' "$WEB_ADMIN_PASSWORD" |
				"$ADMIN_BINARY" set-web-admin \
					--state-dir "$MASTER_STATE_DIRECTORY" \
					--username "$ADMIN_USERNAME" \
					--password-stdin ||
				ADMIN_STATUS="$?"
		fi
	fi
	WEB_ADMIN_PASSWORD=""
	WEB_ADMIN_PASSWORD_CONFIRM=""
	if [ -n "$ADMIN_PASSWORD_SNAPSHOT" ]; then
		rm -f -- "$ADMIN_PASSWORD_SNAPSHOT"
		ADMIN_PASSWORD_SNAPSHOT=""
	fi
	return "$ADMIN_STATUS"
}

install_master() {
	install -d -o root -g root -m 0755 "$STATE_DIRECTORY"
	ensure_service_user "$MASTER_USER" "$MASTER_STATE_DIRECTORY"
	install -d -o root -g "$MASTER_USER" -m 0750 "$CONFIG_DIRECTORY"
	if [ -e "$LEGACY_WEB_AUTH_FILE" ] || [ -L "$LEGACY_WEB_AUTH_FILE" ]; then
		if [ -L "$LEGACY_WEB_AUTH_FILE" ] || [ ! -f "$LEGACY_WEB_AUTH_FILE" ]; then
			fail "the legacy web access file exists but is not a regular file"
		fi
		LEGACY_WEB_AUTH_PRESENT="yes"
	fi
	if [ -e "$WEB_AUTH_FILE" ] || [ -L "$WEB_AUTH_FILE" ]; then
		if [ -L "$WEB_AUTH_FILE" ] || [ ! -f "$WEB_AUTH_FILE" ]; then
			fail "the web access file exists but is not a regular file"
		fi
		WEB_AUTH_EXISTED="yes"
	elif [ "$LEGACY_WEB_AUTH_PRESENT" = "yes" ]; then
		WEB_AUTH_CREATED="yes"
		WEB_AUTH_MIGRATED="yes"
		install -o "$MASTER_USER" -g "$MASTER_USER" -m 0600 \
			"$LEGACY_WEB_AUTH_FILE" "$WEB_AUTH_FILE"
		WEB_AUTH_CREATED_ID="$(stat -c '%d:%i' "$WEB_AUTH_FILE")" ||
			fail "could not inspect the migrated web admin credential"
		WEB_AUTH_EXISTED="yes"
	else
		WEB_AUTH_EXISTED="no"
	fi
	if [ -e "$MASTER_UNIT_FILE" ] || [ -L "$MASTER_UNIT_FILE" ]; then
		if [ -L "$MASTER_UNIT_FILE" ] || [ ! -f "$MASTER_UNIT_FILE" ]; then
			fail "the master service unit exists but is not a regular file"
		fi
		MASTER_UNIT_HAD="yes"
		MASTER_UNIT_BACKUP="$TEMP_DIRECTORY/theatropolis-master.service.backup"
		cp -a "$MASTER_UNIT_FILE" "$MASTER_UNIT_BACKUP"
	fi
	for UPDATE_UNIT_FILE in \
		"$MASTER_UPDATE_SERVICE_FILE" \
		"$MASTER_UPDATE_PATH_FILE"; do
		if [ -L "$UPDATE_UNIT_FILE" ] ||
			{ [ -e "$UPDATE_UNIT_FILE" ] && [ ! -f "$UPDATE_UNIT_FILE" ]; }; then
			fail "a master update unit exists but is not a regular file"
		fi
	done
	if systemctl is-active --quiet theatropolis-master; then
		MASTER_WAS_ACTIVE="yes"
	fi
	if [ -f "$AGENT_UNIT_FILE" ] && [ ! -L "$AGENT_UNIT_FILE" ] &&
		systemctl is-active --quiet theatropolis-agent; then
		AGENT_WAS_ACTIVE="yes"
		AGENT_STOPPED="yes"
		systemctl stop theatropolis-agent
	fi

	if [ "$WEB_AUTH_EXISTED" = "no" ] || [ -n "$ADMIN_USERNAME" ]; then
		if [ -z "$ADMIN_PASSWORD_FILE" ]; then
			prompt_for_admin_credentials
		else
			snapshot_admin_password_file
		fi
		validate_admin_username
	fi

	if [ "$WEB_AUTH_EXISTED" = "yes" ] && [ -n "$ADMIN_USERNAME" ]; then
		WEB_AUTH_BACKUP="$TEMP_DIRECTORY/web-auth.backup"
		cp -a "$WEB_AUTH_FILE" "$WEB_AUTH_BACKUP"
		if [ "$MASTER_WAS_ACTIVE" = "yes" ]; then
			MASTER_STOPPED="yes"
			if ! systemctl stop theatropolis-master; then
				fail "could not stop the active master before replacing its web admin credential"
			fi
		fi
		WEB_AUTH_RESET_APPLIED="yes"
		if ! run_set_web_admin \
			"$TEMP_DIRECTORY/extracted/theatropolis-master" yes; then
			fail "could not replace the web admin credential"
		fi
	elif [ "$WEB_AUTH_EXISTED" = "no" ]; then
		WEB_AUTH_CREATED="yes"
		if ! run_set_web_admin \
			"$TEMP_DIRECTORY/extracted/theatropolis-master" no; then
			if [ -f "$WEB_AUTH_FILE" ] && [ ! -L "$WEB_AUTH_FILE" ]; then
				WEB_AUTH_CREATED_ID="$(
					stat -c '%d:%i' "$WEB_AUTH_FILE" 2>/dev/null || true
				)"
			fi
			fail "could not initialize the web admin credential"
		fi
		WEB_AUTH_CREATED_ID="$(stat -c '%d:%i' "$WEB_AUTH_FILE")" ||
			fail "could not inspect the new web admin credential"
	fi

	install_binary master
	install_update_helper
	if [ "$WEB_AUTH_CREATED" = "yes" ] ||
		[ "$WEB_AUTH_RESET_APPLIED" = "yes" ]; then
		chown "$MASTER_USER:$MASTER_USER" "$WEB_AUTH_FILE"
		chmod 0600 "$WEB_AUTH_FILE"
	fi
	MASTER_UNIT_TEMP="$(mktemp "${MASTER_UNIT_FILE}.tmp.XXXXXX")" ||
		fail "could not create a temporary master service unit"
	cat >"$MASTER_UNIT_TEMP" <<EOF
[Unit]
Description=Theatropolis master
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${MASTER_USER}
Group=${MASTER_USER}
UMask=0077
Environment=THEATROPOLIS_PUBLIC_ADDRESS=${DOMAIN}:${HTTPS_PORT}
RuntimeDirectory=theatropolis
RuntimeDirectoryMode=0700
ExecStart=${INSTALL_DIRECTORY}/theatropolis-master serve --public-url https://${DOMAIN}:${HTTPS_PORT} --web-auth-file ${WEB_AUTH_FILE}
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
	chmod 0644 "$MASTER_UNIT_TEMP"
	MASTER_UNIT_TOUCHED="yes"
	if ! mv -fT -- "$MASTER_UNIT_TEMP" "$MASTER_UNIT_FILE"; then
		fail "could not atomically install the master service unit"
	fi
	MASTER_UNIT_TEMP=""
	cat >"$MASTER_UPDATE_SERVICE_FILE" <<EOF
[Unit]
Description=Apply a verified Theatropolis master update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStartPre=/bin/sleep 2
ExecStart=${UPDATE_HELPER_PATH} apply-theatropolis --component=master --state-dir=${MASTER_STATE_DIRECTORY} --install-path=${INSTALL_DIRECTORY}/theatropolis-master --helper-install-path=${UPDATE_HELPER_PATH}
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
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER
ReadWritePaths=${INSTALL_DIRECTORY} ${UPDATE_HELPER_DIRECTORY} ${MASTER_STATE_DIRECTORY}
EOF
	cat >"$MASTER_UPDATE_PATH_FILE" <<EOF
[Unit]
Description=Watch for verified Theatropolis master update requests

[Path]
PathExists=${MASTER_STATE_DIRECTORY}/update-request.json
PathExists=${MASTER_STATE_DIRECTORY}/.update-request.processing.json
Unit=theatropolis-master-update.service

[Install]
WantedBy=multi-user.target
EOF
	chmod 0644 "$MASTER_UPDATE_SERVICE_FILE" "$MASTER_UPDATE_PATH_FILE"
	systemctl daemon-reload
	systemctl enable --now theatropolis-master-update.path
	systemctl enable --now theatropolis-master
	systemctl restart theatropolis-master
	configure_caddy
	if [ -f "$AGENT_UNIT_FILE" ] && [ ! -L "$AGENT_UNIT_FILE" ]; then
		if [ "$ROLE" = "master" ]; then
			# Old Agent units do not carry the relay flag and old binaries do
			# not understand it. Upgrade only the verified binary, preserving
			# enrollment, environment, sing-box, and the existing service unit.
			[ -f "$INSTALL_DIRECTORY/theatropolis-agent" ] &&
				[ ! -L "$INSTALL_DIRECTORY/theatropolis-agent" ] ||
				fail "the existing Agent binary is not a regular file; reinstall the Agent first"
			COLOCATED_AGENT_BINARY_BACKUP="$TEMP_DIRECTORY/colocated-agent.backup"
			cp -a "$INSTALL_DIRECTORY/theatropolis-agent" "$COLOCATED_AGENT_BINARY_BACKUP"
			install_binary agent
		fi
		configure_acme_http01_relay
		if [ "$ROLE" = "master" ] && [ "$AGENT_WAS_ACTIVE" = "yes" ]; then
			systemctl restart theatropolis-agent
			AGENT_STOPPED="no"
		fi
	fi
}

write_enrollment_token() {
	TOKEN_TARGET="$AGENT_STATE_DIRECTORY/enrollment.token"
	if [ -L "$TOKEN_TARGET" ] ||
		{ [ -e "$TOKEN_TARGET" ] && [ ! -f "$TOKEN_TARGET" ]; }; then
		fail "the existing enrollment token path is not a regular file"
	fi
	STATE_DEVICE="$(stat -c '%d' "$STATE_DIRECTORY")"
	AGENT_DEVICE="$(stat -c '%d' "$AGENT_STATE_DIRECTORY")"
	[ "$STATE_DEVICE" = "$AGENT_DEVICE" ] ||
		fail "agent state must share a filesystem with $STATE_DIRECTORY for secure token installation"

	ENROLLMENT_TOKEN_TEMP="$(mktemp "$STATE_DIRECTORY/.enrollment-token.XXXXXX")"
	printf '%s\n' "$ENROLLMENT_TOKEN" >"$ENROLLMENT_TOKEN_TEMP"
	chown "root:$AGENT_USER" "$ENROLLMENT_TOKEN_TEMP"
	chmod 0640 "$ENROLLMENT_TOKEN_TEMP"
	mv -fT -- "$ENROLLMENT_TOKEN_TEMP" "$TOKEN_TARGET"
	ENROLLMENT_TOKEN_TEMP=""
}

write_agent_configuration() {
	install -d -o root -g root -m 0755 "$CONFIG_DIRECTORY"
	CONFIGURED_CA_FILE=""
	if [ -n "$CA_FILE" ]; then
		CONFIGURED_CA_FILE="${CONFIG_DIRECTORY}/agent-ca.pem"
	fi
	cat >"$CONFIG_DIRECTORY/agent.env" <<EOF
THEATROPOLIS_MASTER=${MASTER_ADDRESS}
THEATROPOLIS_MASTER_DIAL=${MASTER_DIAL_ADDRESS}
THEATROPOLIS_CA_FILE=${CONFIGURED_CA_FILE}
EOF
	chmod 0600 "$CONFIG_DIRECTORY/agent.env"
	if [ -n "$CA_FILE" ]; then
		install -o root -g root -m 0644 "$CA_FILE" "$CONFIG_DIRECTORY/agent-ca.pem"
	else
		rm -f -- "$CONFIG_DIRECTORY/agent-ca.pem"
	fi
}

detect_local_master_dial_address() {
	MASTER_DIAL_ADDRESS=""
	if [ ! -f "$MASTER_UNIT_FILE" ] || [ -L "$MASTER_UNIT_FILE" ]; then
		return
	fi
	LOCAL_MASTER_METADATA_COUNT="$(
		grep -Ec '^Environment=THEATROPOLIS_PUBLIC_ADDRESS=[A-Za-z0-9.-]+:[0-9]{1,5}$' \
			"$MASTER_UNIT_FILE" || true
	)"
	if [ "$LOCAL_MASTER_METADATA_COUNT" -eq 1 ]; then
		LOCAL_MASTER_ADDRESS="$(
			sed -n 's/^Environment=THEATROPOLIS_PUBLIC_ADDRESS=//p' \
				"$MASTER_UNIT_FILE"
		)"
	else
		# Units written before the explicit metadata line can still be
		# recognized from the installer's fixed ExecStart shape. Do not
		# evaluate or source the unit: extract only a strict DNS host:port.
		LOCAL_MASTER_ADDRESS="$(
			sed -n \
				's#^ExecStart=[^ ]* serve --public-url https://\([A-Za-z0-9.-][A-Za-z0-9.-]*:[0-9][0-9]*\) .*$#\1#p' \
				"$MASTER_UNIT_FILE"
		)"
	fi
	if [ "$LOCAL_MASTER_ADDRESS" != "$MASTER_ADDRESS" ]; then
		return 0
	fi
	LOCAL_MASTER_PORT="${MASTER_ADDRESS##*:}"
	MASTER_DIAL_ADDRESS="127.0.0.1:${LOCAL_MASTER_PORT}"
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
	if systemctl is-active --quiet theatropolis-agent; then
		AGENT_WAS_ACTIVE="yes"
		AGENT_STOPPED="yes"
		systemctl stop theatropolis-agent
	fi
	if [ "$SING_BOX_BOOTSTRAP_REQUIRED" = "yes" ]; then
		install_sing_box
	fi
	install_binary agent
	install_update_helper
	install -d -o root -g root -m 0755 "$STATE_DIRECTORY"
	ensure_service_user "$AGENT_USER" "$AGENT_STATE_DIRECTORY"
	if [ -z "$ENROLLMENT_TOKEN" ] && [ "$ROLE" = "all" ]; then
		wait_for_master_socket
		ENROLLMENT_TOKEN="$(
			"$INSTALL_DIRECTORY/theatropolis-master" create-enrollment \
				--server "$SERVER_NAME"
		)"
	fi
	if [ -n "$ENROLLMENT_TOKEN" ]; then
		write_enrollment_token
	elif [ ! -f "$AGENT_STATE_DIRECTORY/identity.pem" ]; then
		fail "--token is required for a new agent installation"
	fi
	detect_local_master_dial_address
	write_agent_configuration
	cat >"$AGENT_UNIT_FILE" <<EOF
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
Environment=LD_LIBRARY_PATH=${SING_BOX_LIBRARY_DIRECTORY}
Environment=HOME=${AGENT_STATE_DIRECTORY}
Environment=XDG_DATA_HOME=${AGENT_STATE_DIRECTORY}/data
WorkingDirectory=${AGENT_STATE_DIRECTORY}
ExecStart=${INSTALL_DIRECTORY}/theatropolis-agent --master=\${THEATROPOLIS_MASTER} --master-dial-address=\${THEATROPOLIS_MASTER_DIAL} --state-dir=${AGENT_STATE_DIRECTORY} --enrollment-token-file=${AGENT_STATE_DIRECTORY}/enrollment.token --ca-file=\${THEATROPOLIS_CA_FILE} --acme-http01-relay-marker=${ACME_HTTP01_RELAY_MARKER}
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
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictRealtime=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ReadWritePaths=${AGENT_STATE_DIRECTORY}

[Install]
WantedBy=multi-user.target
EOF
	cat >"$AGENT_UPDATE_SERVICE_FILE" <<EOF
[Unit]
Description=Apply a verified Theatropolis agent update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=${UPDATE_HELPER_PATH} apply-theatropolis --component=agent --state-dir=${AGENT_STATE_DIRECTORY} --install-path=${INSTALL_DIRECTORY}/theatropolis-agent --helper-install-path=${UPDATE_HELPER_PATH}
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
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER
ReadWritePaths=${INSTALL_DIRECTORY} ${UPDATE_HELPER_DIRECTORY} ${AGENT_STATE_DIRECTORY}
EOF
	cat >"$AGENT_UPDATE_PATH_FILE" <<EOF
[Unit]
Description=Watch for verified Theatropolis agent update requests

[Path]
PathExists=${AGENT_STATE_DIRECTORY}/update-request.json
Unit=theatropolis-agent-update.service

[Install]
WantedBy=multi-user.target
EOF
	cat >"$SING_BOX_UPDATE_SERVICE_FILE" <<EOF
[Unit]
Description=Apply a verified sing-box update requested by Theatropolis
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=${UPDATE_HELPER_PATH} apply-sing-box --state-dir=${AGENT_STATE_DIRECTORY} --install-path=${INSTALL_DIRECTORY}/sing-box --library-path=${SING_BOX_LIBRARY_DIRECTORY}/libcronet.so --validation-user=${AGENT_USER}
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
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictRealtime=true
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID
AmbientCapabilities=CAP_SETGID CAP_SETUID
ReadWritePaths=${INSTALL_DIRECTORY} ${SING_BOX_LIBRARY_DIRECTORY} ${AGENT_STATE_DIRECTORY}
EOF
	cat >"$SING_BOX_UPDATE_PATH_FILE" <<EOF
[Unit]
Description=Watch for verified sing-box update requests

[Path]
PathExists=${AGENT_STATE_DIRECTORY}/sing-box-update-request.json
Unit=theatropolis-sing-box-update.service

[Install]
WantedBy=multi-user.target
EOF
	chmod 0644 "$AGENT_UNIT_FILE"
	chmod 0644 "$AGENT_UPDATE_SERVICE_FILE" "$AGENT_UPDATE_PATH_FILE"
	chmod 0644 "$SING_BOX_UPDATE_SERVICE_FILE" "$SING_BOX_UPDATE_PATH_FILE"
	if [ -f "$MASTER_UNIT_FILE" ] && [ ! -L "$MASTER_UNIT_FILE" ]; then
		configure_acme_http01_relay
	fi
	systemctl daemon-reload
	systemctl enable --now theatropolis-agent-update.path
	systemctl enable --now theatropolis-sing-box-update.path
	systemctl enable --now theatropolis-agent
	systemctl restart theatropolis-agent
	AGENT_STOPPED="no"
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
	"$RELEASE_TAG" "$ARCHITECTURE"
if [ "$ROLE" = "master" ] || [ "$ROLE" = "all" ]; then
	printf 'Master endpoint: https://%s:%s (HTTP-01 uses port 80).\n' \
		"$DOMAIN" "$HTTPS_PORT"
	if [ "$HTTPS_PORT" != "443" ]; then
		printf 'Port 443 remains available for a sing-box inbound.\n'
	fi
	if { [ "$WEB_AUTH_CREATED" = "yes" ] && [ "$WEB_AUTH_MIGRATED" != "yes" ]; } ||
		[ "$WEB_AUTH_RESET_APPLIED" = "yes" ]; then
		printf 'Web admin username: %s\n' "$ADMIN_USERNAME"
		printf '%s\n' \
			'The admin password was not printed or stored in plaintext.'
	else
		printf '%s\n' \
			'The existing web admin credential was preserved.'
	fi
fi
INSTALL_SUCCEEDED="yes"
if [ "$LEGACY_WEB_AUTH_PRESENT" = "yes" ]; then
	if ! rm -f -- "$LEGACY_WEB_AUTH_FILE"; then
		printf '%s\n' \
			'theatropolis installer: warning: the obsolete web credential copy could not be removed' >&2
	fi
fi
