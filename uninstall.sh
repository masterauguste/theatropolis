#!/bin/sh

set -eu
set +x
umask 077

INSTALL_DIRECTORY="/usr/local/bin"
UPDATE_HELPER_DIRECTORY="/usr/local/libexec/theatropolis"
UPDATE_HELPER_PATH="${UPDATE_HELPER_DIRECTORY}/theatropolis-update-helper"
SING_BOX_LIBRARY_DIRECTORY="/usr/local/lib/theatropolis/sing-box"
STATE_DIRECTORY="/var/lib/theatropolis"
MASTER_STATE_DIRECTORY="${STATE_DIRECTORY}/master"
AGENT_STATE_DIRECTORY="${STATE_DIRECTORY}/agent"
CONFIG_DIRECTORY="/etc/theatropolis"
SYSTEMD_DIRECTORY="/etc/systemd/system"
CADDYFILE="/etc/caddy/Caddyfile"
CADDY_SNIPPET="/etc/caddy/conf.d/theatropolis.caddy"
INSTALL_LOCK_FILE="/run/theatropolis-installer.lock"
MASTER_USER="theatropolis-master"
AGENT_USER="theatropolis-agent"

MASTER_UNIT="theatropolis-master.service"
MASTER_UPDATE_SERVICE="theatropolis-master-update.service"
MASTER_UPDATE_PATH="theatropolis-master-update.path"
AGENT_UNIT="theatropolis-agent.service"
AGENT_UPDATE_SERVICE="theatropolis-agent-update.service"
AGENT_UPDATE_PATH="theatropolis-agent-update.path"
SING_BOX_UPDATE_SERVICE="theatropolis-sing-box-update.service"
SING_BOX_UPDATE_PATH="theatropolis-sing-box-update.path"

ROLE=""
ASSUME_YES="no"
KEEP_DATA="no"
CADDY_BACKUP=""
CADDY_REMOVAL_COMMITTED="no"

usage() {
	printf '%s\n' \
		"Usage:" \
		"  uninstall.sh master [--yes] [--keep-data]" \
		"  uninstall.sh agent [--yes] [--keep-data]" \
		"  uninstall.sh child [--yes] [--keep-data]" \
		"  uninstall.sh all [--yes] [--keep-data]" \
		"" \
		"The child role is an alias for agent." \
		"By default, the selected role's state is permanently removed." \
		"Use --keep-data to retain state and its service account for recovery." \
		"Master removal deletes only Theatropolis' Caddy snippet; it does not uninstall Caddy."
}

fail() {
	printf 'theatropolis uninstaller: %s\n' "$*" >&2
	exit 1
}

cleanup() {
	STATUS="$?"
	trap - EXIT HUP INT TERM
	set +e
	if [ -n "$CADDY_BACKUP" ] &&
		[ "$CADDY_REMOVAL_COMMITTED" != "yes" ] &&
		{ [ -e "$CADDY_BACKUP" ] || [ -L "$CADDY_BACKUP" ]; }; then
		mv -f -- "$CADDY_BACKUP" "$CADDY_SNIPPET"
		if systemctl is-active --quiet caddy; then
			systemctl reload caddy >/dev/null 2>&1 || true
		fi
	fi
	exit "$STATUS"
}

handle_signal() {
	exit "$1"
}

trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

if [ "$#" -eq 0 ]; then
	usage
	exit 1
fi

case "$1" in
master | agent | all)
	ROLE="$1"
	shift
	;;
child)
	ROLE="agent"
	shift
	;;
-h | --help)
	usage
	exit 0
	;;
*)
	fail "the first argument must be master, agent, child, or all"
	;;
esac

while [ "$#" -gt 0 ]; do
	case "$1" in
	--yes)
		ASSUME_YES="yes"
		shift
		;;
	--keep-data)
		KEEP_DATA="yes"
		shift
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

[ "$(id -u)" -eq 0 ] || fail "run this uninstaller as root"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"
command -v flock >/dev/null 2>&1 || fail "util-linux flock is required"
exec 9>"$INSTALL_LOCK_FILE" || fail "could not open the installer lock file"
flock -n 9 || fail "another Theatropolis installer or uninstaller is already running"

confirm_uninstall() {
	[ "$ASSUME_YES" = "yes" ] && return
	if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
		fail "a terminal is required for confirmation; use --yes for secured automation"
	fi
	printf 'Uninstall Theatropolis role: %s\n' "$ROLE" >/dev/tty
	if [ "$KEEP_DATA" = "yes" ]; then
		printf 'Runtime state will be preserved.\n' >/dev/tty
	else
		printf 'The selected role state will be permanently deleted.\n' >/dev/tty
	fi
	if [ "$ROLE" = "master" ] || [ "$ROLE" = "all" ]; then
		printf 'The Theatropolis Caddy entry will also be removed.\n' >/dev/tty
	fi
	printf 'Type uninstall to continue: ' >/dev/tty
	CONFIRMATION=""
	IFS= read -r CONFIRMATION </dev/tty || fail "could not read confirmation"
	[ "$CONFIRMATION" = "uninstall" ] || fail "confirmation did not match; nothing was removed"
}

remove_path() {
	TARGET="$1"
	case "$TARGET" in
	"$INSTALL_DIRECTORY/theatropolis-master"|\
		"$INSTALL_DIRECTORY/theatropolis-agent"|\
		"$INSTALL_DIRECTORY/sing-box"|\
		"$UPDATE_HELPER_PATH"|\
		"$CONFIG_DIRECTORY/agent.env"|\
		"$CONFIG_DIRECTORY/agent-ca.pem"|\
		"$CONFIG_DIRECTORY/web-auth.json"|\
		"$SYSTEMD_DIRECTORY/$MASTER_UNIT"|\
		"$SYSTEMD_DIRECTORY/$MASTER_UPDATE_SERVICE"|\
		"$SYSTEMD_DIRECTORY/$MASTER_UPDATE_PATH"|\
		"$SYSTEMD_DIRECTORY/$AGENT_UNIT"|\
		"$SYSTEMD_DIRECTORY/$AGENT_UPDATE_SERVICE"|\
		"$SYSTEMD_DIRECTORY/$AGENT_UPDATE_PATH"|\
		"$SYSTEMD_DIRECTORY/$SING_BOX_UPDATE_SERVICE"|\
		"$SYSTEMD_DIRECTORY/$SING_BOX_UPDATE_PATH")
		rm -f -- "$TARGET"
		;;
	*)
		fail "refusing to remove unexpected path: $TARGET"
		;;
	esac
}

remove_tree() {
	TARGET="$1"
	case "$TARGET" in
	"$MASTER_STATE_DIRECTORY"|\
		"$AGENT_STATE_DIRECTORY"|\
		"$SING_BOX_LIBRARY_DIRECTORY"|\
		"$SYSTEMD_DIRECTORY/$MASTER_UNIT.d"|\
		"$SYSTEMD_DIRECTORY/$MASTER_UPDATE_SERVICE.d"|\
		"$SYSTEMD_DIRECTORY/$MASTER_UPDATE_PATH.d"|\
		"$SYSTEMD_DIRECTORY/$AGENT_UNIT.d"|\
		"$SYSTEMD_DIRECTORY/$AGENT_UPDATE_SERVICE.d"|\
		"$SYSTEMD_DIRECTORY/$AGENT_UPDATE_PATH.d"|\
		"$SYSTEMD_DIRECTORY/$SING_BOX_UPDATE_SERVICE.d"|\
		"$SYSTEMD_DIRECTORY/$SING_BOX_UPDATE_PATH.d")
		if [ -L "$TARGET" ]; then
			rm -f -- "$TARGET"
		elif [ -e "$TARGET" ]; then
			rm -rf -- "$TARGET"
		fi
		;;
	*)
		fail "refusing to remove unexpected directory: $TARGET"
		;;
	esac
}

disable_unit() {
	UNIT="$1"
	systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
	systemctl stop "$UNIT" >/dev/null 2>&1 || true
}

remove_service_user() {
	USER_NAME="$1"
	if id "$USER_NAME" >/dev/null 2>&1; then
		userdel "$USER_NAME" || fail "could not remove service user $USER_NAME"
	fi
	if command -v getent >/dev/null 2>&1 &&
		getent group "$USER_NAME" >/dev/null 2>&1; then
		if ! groupdel "$USER_NAME"; then
			printf 'theatropolis uninstaller: warning: service group %s was retained\n' \
				"$USER_NAME" >&2
		fi
	fi
}

remove_master_caddy_entry() {
	if [ ! -e "$CADDY_SNIPPET" ] && [ ! -L "$CADDY_SNIPPET" ]; then
		return
	fi
	if [ ! -f "$CADDY_SNIPPET" ] && [ ! -L "$CADDY_SNIPPET" ]; then
		fail "the Theatropolis Caddy entry is not a regular file or symbolic link"
	fi
	CADDY_BACKUP="${CADDY_SNIPPET}.uninstall.$$"
	[ ! -e "$CADDY_BACKUP" ] && [ ! -L "$CADDY_BACKUP" ] ||
		fail "temporary Caddy backup path already exists: $CADDY_BACKUP"
	mv -- "$CADDY_SNIPPET" "$CADDY_BACKUP"

	if [ -f "$CADDYFILE" ] && command -v caddy >/dev/null 2>&1; then
		if ! caddy validate --config "$CADDYFILE" --adapter caddyfile; then
			fail "Caddy rejected the configuration without Theatropolis; the entry was restored"
		fi
	fi
	if systemctl is-active --quiet caddy; then
		if ! systemctl reload caddy; then
			fail "Caddy could not reload without Theatropolis; the entry was restored"
		fi
	fi
	rm -f -- "$CADDY_BACKUP"
	CADDY_BACKUP=""
	CADDY_REMOVAL_COMMITTED="yes"
}

uninstall_master() {
	disable_unit "$MASTER_UPDATE_PATH"
	disable_unit "$MASTER_UPDATE_SERVICE"
	disable_unit "$MASTER_UNIT"
	remove_path "$SYSTEMD_DIRECTORY/$MASTER_UNIT"
	remove_path "$SYSTEMD_DIRECTORY/$MASTER_UPDATE_SERVICE"
	remove_path "$SYSTEMD_DIRECTORY/$MASTER_UPDATE_PATH"
	remove_tree "$SYSTEMD_DIRECTORY/$MASTER_UNIT.d"
	remove_tree "$SYSTEMD_DIRECTORY/$MASTER_UPDATE_SERVICE.d"
	remove_tree "$SYSTEMD_DIRECTORY/$MASTER_UPDATE_PATH.d"
	remove_path "$INSTALL_DIRECTORY/theatropolis-master"
	remove_path "$CONFIG_DIRECTORY/web-auth.json"
	if [ "$KEEP_DATA" != "yes" ]; then
		remove_tree "$MASTER_STATE_DIRECTORY"
		remove_service_user "$MASTER_USER"
	fi
}

uninstall_agent() {
	disable_unit "$AGENT_UPDATE_PATH"
	disable_unit "$SING_BOX_UPDATE_PATH"
	disable_unit "$AGENT_UPDATE_SERVICE"
	disable_unit "$SING_BOX_UPDATE_SERVICE"
	disable_unit "$AGENT_UNIT"
	remove_path "$SYSTEMD_DIRECTORY/$AGENT_UNIT"
	remove_path "$SYSTEMD_DIRECTORY/$AGENT_UPDATE_SERVICE"
	remove_path "$SYSTEMD_DIRECTORY/$AGENT_UPDATE_PATH"
	remove_path "$SYSTEMD_DIRECTORY/$SING_BOX_UPDATE_SERVICE"
	remove_path "$SYSTEMD_DIRECTORY/$SING_BOX_UPDATE_PATH"
	remove_tree "$SYSTEMD_DIRECTORY/$AGENT_UNIT.d"
	remove_tree "$SYSTEMD_DIRECTORY/$AGENT_UPDATE_SERVICE.d"
	remove_tree "$SYSTEMD_DIRECTORY/$AGENT_UPDATE_PATH.d"
	remove_tree "$SYSTEMD_DIRECTORY/$SING_BOX_UPDATE_SERVICE.d"
	remove_tree "$SYSTEMD_DIRECTORY/$SING_BOX_UPDATE_PATH.d"
	remove_path "$INSTALL_DIRECTORY/theatropolis-agent"
	remove_path "$INSTALL_DIRECTORY/sing-box"
	remove_tree "$SING_BOX_LIBRARY_DIRECTORY"
	remove_path "$CONFIG_DIRECTORY/agent.env"
	remove_path "$CONFIG_DIRECTORY/agent-ca.pem"
	if [ "$KEEP_DATA" != "yes" ]; then
		remove_tree "$AGENT_STATE_DIRECTORY"
		remove_service_user "$AGENT_USER"
	fi
}

remove_shared_files_if_unused() {
	if [ ! -e "$INSTALL_DIRECTORY/theatropolis-master" ] &&
		[ ! -L "$INSTALL_DIRECTORY/theatropolis-master" ] &&
		[ ! -e "$INSTALL_DIRECTORY/theatropolis-agent" ] &&
		[ ! -L "$INSTALL_DIRECTORY/theatropolis-agent" ] &&
		[ ! -e "$SYSTEMD_DIRECTORY/$MASTER_UNIT" ] &&
		[ ! -L "$SYSTEMD_DIRECTORY/$MASTER_UNIT" ] &&
		[ ! -e "$SYSTEMD_DIRECTORY/$AGENT_UNIT" ] &&
		[ ! -L "$SYSTEMD_DIRECTORY/$AGENT_UNIT" ]; then
		remove_path "$UPDATE_HELPER_PATH"
		rmdir "$UPDATE_HELPER_DIRECTORY" >/dev/null 2>&1 || true
	fi
	rmdir "${SING_BOX_LIBRARY_DIRECTORY%/*}" >/dev/null 2>&1 || true
	rmdir "$CONFIG_DIRECTORY" >/dev/null 2>&1 || true
	if [ "$KEEP_DATA" != "yes" ]; then
		rmdir "$STATE_DIRECTORY" >/dev/null 2>&1 || true
	fi
}

confirm_uninstall

case "$ROLE" in
master)
	remove_master_caddy_entry
	uninstall_master
	;;
agent)
	uninstall_agent
	;;
all)
	remove_master_caddy_entry
	uninstall_agent
	uninstall_master
	;;
esac

remove_shared_files_if_unused
systemctl daemon-reload

printf 'Uninstalled Theatropolis %s role.\n' "$ROLE"
if [ "$KEEP_DATA" = "yes" ]; then
	printf 'Preserved role state under %s.\n' "$STATE_DIRECTORY"
fi
