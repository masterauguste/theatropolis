#!/bin/sh

set -eu

INSTALLER_INPUT="${1:-./install.sh}"
case "$INSTALLER_INPUT" in
/*) INSTALLER="$INSTALLER_INPUT" ;;
*) INSTALLER="$(pwd)/$INSTALLER_INPUT" ;;
esac

TEST_DIRECTORY="$(mktemp -d)"
TEST_ROOT="$TEST_DIRECTORY/root"
MOCK_BIN="$TEST_DIRECTORY/bin"
RELEASE_DIRECTORY="$TEST_DIRECTORY/release"
RELEASE_STAGE="$TEST_DIRECTORY/release-stage"
MASTER_LOG="$TEST_DIRECTORY/master.log"
INIT_STATE_LOG="$TEST_DIRECTORY/init-state.log"
SYSTEMCTL_LOG="$TEST_DIRECTORY/systemctl.log"
CADDY_LOG="$TEST_DIRECTORY/caddy.log"
INSTALL_LOG="$TEST_DIRECTORY/install.log"
APT_LOG="$TEST_DIRECTORY/apt.log"
CURL_LOG="$TEST_DIRECTORY/curl.log"
COMPILER_LOG="$TEST_DIRECTORY/compiler.log"
MASTER_STATE_FILE="$TEST_DIRECTORY/master-service-state"
INITIAL_PASSWORD_FILE="$TEST_DIRECTORY/initial-password"
RESET_PASSWORD_FILE="$TEST_DIRECTORY/reset-password"
FAILED_RESET_PASSWORD_FILE="$TEST_DIRECTORY/failed-reset-password"
BAD_MODE_PASSWORD_FILE="$TEST_DIRECTORY/bad-mode-password"
INTERACTIVE_PASSWORD="Interactive-Celestial-Harbor-753"
INITIAL_PASSWORD="initial-admin-password-123"
RESET_PASSWORD="replacement-admin-password-456"
FAILED_RESET_PASSWORD="rollback-admin-password-789"
DOMAIN="control.example.com"
HTTPS_PORT="443"
RELEASE_TAG="v9.9.9"

cleanup() {
	rm -rf -- "$TEST_DIRECTORY"
}

fail() {
	printf 'master installer test: %s\n' "$*" >&2
	exit 1
}

trap cleanup EXIT HUP INT TERM

command -v script >/dev/null 2>&1 ||
	fail "the util-linux script command is required"

mkdir -p \
	"$MOCK_BIN" \
	"$RELEASE_DIRECTORY" \
	"$RELEASE_STAGE" \
	"$TEST_ROOT/etc/caddy/conf.d" \
	"$TEST_ROOT/etc/systemd/system" \
	"$TEST_ROOT/run" \
	"$TEST_ROOT/usr/local/bin"

printf '%s\n' \
	'ID=debian' \
	'VERSION_ID=13' \
	>"$TEST_ROOT/etc/os-release"
printf '%s\n' "$INITIAL_PASSWORD" >"$INITIAL_PASSWORD_FILE"
printf '%s\n' "$RESET_PASSWORD" >"$RESET_PASSWORD_FILE"
printf '%s\n' "$FAILED_RESET_PASSWORD" >"$FAILED_RESET_PASSWORD_FILE"
printf '%s\n' "$INITIAL_PASSWORD" >"$BAD_MODE_PASSWORD_FILE"
chmod 0600 \
	"$INITIAL_PASSWORD_FILE" \
	"$RESET_PASSWORD_FILE" \
	"$FAILED_RESET_PASSWORD_FILE"
chmod 0644 "$BAD_MODE_PASSWORD_FILE"
printf 'inactive\n' >"$MASTER_STATE_FILE"

# Relocate the installer's fixed system paths into the temporary test root.
# This leaves its behavior intact while avoiding writes to the CI host.
sed \
	-e "s#/usr/local/#$TEST_ROOT/usr/local/#g" \
	-e "s#/usr/share/#$TEST_ROOT/usr/share/#g" \
	-e "s#/var/lib/#$TEST_ROOT/var/lib/#g" \
	-e "s#/etc/#$TEST_ROOT/etc/#g" \
	-e "s#/run/#$TEST_ROOT/run/#g" \
	"$INSTALLER" >"$TEST_DIRECTORY/install.sh"
chmod +x "$TEST_DIRECTORY/install.sh"

# A release-compatible master accepts a password only on stdin and writes a
# credential document without echoing or logging the secret.
cat >"$RELEASE_STAGE/theatropolis-master" <<'EOF'
#!/bin/sh
set -eu

printf '%s\n' "$*" >>"$TEST_MASTER_LOG"

case "${1:-}" in
set-web-admin)
	shift
	STATE_DIRECTORY=""
	USERNAME=""
	PASSWORD_STDIN="no"
	REPLACE="no"
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--state-dir)
			[ "$#" -ge 2 ] || exit 64
			STATE_DIRECTORY="$2"
			shift 2
			;;
		--username)
			[ "$#" -ge 2 ] || exit 64
			USERNAME="$2"
			shift 2
			;;
		--password-stdin)
			PASSWORD_STDIN="yes"
			shift
			;;
		--replace)
			REPLACE="yes"
			shift
			;;
		*)
			exit 64
			;;
		esac
	done
	[ -n "$STATE_DIRECTORY" ] || exit 64
	[ -n "$USERNAME" ] || exit 64
	[ "$PASSWORD_STDIN" = "yes" ] || exit 64
	IFS= read -r PASSWORD || exit 64
	[ "${#PASSWORD}" -ge 15 ] || exit 64
	mkdir -p "$STATE_DIRECTORY"
	AUTH_FILE="$STATE_DIRECTORY/web-auth.json"
	if [ "$REPLACE" = "yes" ]; then
		[ -f "$AUTH_FILE" ] || exit 73
	else
		[ ! -e "$AUTH_FILE" ] || exit 73
	fi
	PASSWORD_HASH="$(
		printf '%s' "$PASSWORD" |
			sha256sum |
			awk '{ print $1 }'
	)"
	AUTH_TEMP="$STATE_DIRECTORY/.web-auth.test.$$"
	printf '{"version":2,"username":"%s","password_sha256":"%s"}\n' \
		"$USERNAME" \
		"$PASSWORD_HASH" \
		>"$AUTH_TEMP"
	chmod 0600 "$AUTH_TEMP"
	mv -f -- "$AUTH_TEMP" "$AUTH_FILE"
	printf '%s|%s|%s\n' \
		"$STATE_DIRECTORY" \
		"$REPLACE" \
		"$USERNAME" \
		>>"$TEST_INIT_STATE_LOG"
	PASSWORD=""
	case "$USERNAME" in
	fresh-commit-fail | reset-commit-fail) exit 74 ;;
	esac
	;;
version)
	printf 'v9.9.9 (commit fixture, built fixture)\n'
	;;
*)
	exit 64
	;;
esac
EOF

cat >"$RELEASE_STAGE/theatropolis-agent" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"$RELEASE_STAGE/theatropolis-update-helper" <<'EOF'
#!/bin/sh
exit 0
EOF

chmod +x \
	"$RELEASE_STAGE/theatropolis-master" \
	"$RELEASE_STAGE/theatropolis-agent" \
	"$RELEASE_STAGE/theatropolis-update-helper"

tar -czf "$RELEASE_DIRECTORY/theatropolis_linux_amd64.tar.gz" \
	-C "$RELEASE_STAGE" \
	theatropolis-master \
	theatropolis-agent \
	theatropolis-update-helper
(
	cd "$RELEASE_DIRECTORY"
	ARCHIVE_CHECKSUM="$(
		sha256sum theatropolis_linux_amd64.tar.gz |
			awk '{ print $1 }'
	)"
	printf '%s  %s\n' \
		"$ARCHIVE_CHECKSUM" \
		theatropolis_linux_amd64.tar.gz \
		>checksums.txt
	: >checksums.txt.sig
)

cat >"$MOCK_BIN/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-u" ]; then
	printf '0\n'
	exit 0
fi
case "${1:-}" in
theatropolis-master | theatropolis-agent) exit 0 ;;
esac
exec /usr/bin/id "$@"
EOF

cat >"$MOCK_BIN/uname" <<'EOF'
#!/bin/sh
printf 'x86_64\n'
EOF

cat >"$MOCK_BIN/apt-get" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$TEST_APT_LOG"
exit 0
EOF

cat >"$MOCK_BIN/curl" <<'EOF'
#!/bin/sh
set -eu

printf '%s\n' "$*" >>"$TEST_CURL_LOG"
OUTPUT=""
SOURCE=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	-o)
		[ "$#" -ge 2 ] || exit 64
		OUTPUT="$2"
		shift 2
		;;
	http://* | https://*)
		SOURCE="$1"
		shift
		;;
	*)
		shift
		;;
	esac
done

[ -n "$OUTPUT" ] || exit 64
case "$SOURCE" in
*/theatropolis_linux_amd64.tar.gz)
	cp "$TEST_RELEASE_DIRECTORY/theatropolis_linux_amd64.tar.gz" "$OUTPUT"
	;;
*/checksums.txt)
	cp "$TEST_RELEASE_DIRECTORY/checksums.txt" "$OUTPUT"
	;;
*/checksums.txt.sig)
	cp "$TEST_RELEASE_DIRECTORY/checksums.txt.sig" "$OUTPUT"
	;;
*)
	printf 'unexpected mock curl source: %s\n' "$SOURCE" >&2
	exit 65
	;;
esac
EOF

cat >"$MOCK_BIN/openssl" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"$MOCK_BIN/install" <<'EOF'
#!/bin/sh
set -eu

printf '%s\n' "$*" >>"$TEST_INSTALL_LOG"
DIRECTORY="no"
MODE=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	-d)
		DIRECTORY="yes"
		shift
		;;
	-o | -g)
		[ "$#" -ge 2 ] || exit 64
		shift 2
		;;
	-m)
		[ "$#" -ge 2 ] || exit 64
		MODE="$2"
		shift 2
		;;
	--)
		shift
		break
		;;
	-*)
		exit 64
		;;
	*)
		break
		;;
	esac
done

if [ "$DIRECTORY" = "yes" ]; then
	[ "$#" -ge 1 ] || exit 64
	for TARGET in "$@"; do
		mkdir -p "$TARGET"
		if [ -n "$MODE" ]; then
			chmod "$MODE" "$TARGET"
		fi
	done
else
	[ "$#" -eq 2 ] || exit 64
	cp "$1" "$2"
	if [ -n "$MODE" ]; then
		chmod "$MODE" "$2"
	fi
fi
EOF

cat >"$MOCK_BIN/chown" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"$MOCK_BIN/flock" <<'EOF'
#!/bin/sh
[ "${TEST_FLOCK_BUSY:-no}" != "yes" ] || exit 1
exit 0
EOF

cat >"$MOCK_BIN/mv" <<'EOF'
#!/bin/sh
if [ "${TEST_FAIL_UNIT_RENAME:-no}" = "yes" ]; then
	for ARGUMENT in "$@"; do
		case "$ARGUMENT" in
		*.service.tmp.*) exit 44 ;;
		esac
	done
fi
exec /usr/bin/mv "$@"
EOF

cat >"$MOCK_BIN/stat" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-c" ]; then
	STAT_FORMAT="$2"
	shift 2
	if [ "${1:-}" = "--" ]; then
		shift
	fi
	if [ "$#" -eq 1 ]; then
		STAT_PATH="$1"
		case "$STAT_FORMAT:$STAT_PATH" in
		"%u:$TEST_INITIAL_PASSWORD_FILE" | \
		"%u:$TEST_RESET_PASSWORD_FILE" | \
		"%u:$TEST_FAILED_RESET_PASSWORD_FILE" | \
		"%u:$TEST_BAD_MODE_PASSWORD_FILE" | \
		"%u:"*"/admin-password")
			printf '0\n'
			exit 0
			;;
		"%a:$TEST_INITIAL_PASSWORD_FILE" | \
		"%a:$TEST_RESET_PASSWORD_FILE" | \
		"%a:$TEST_FAILED_RESET_PASSWORD_FILE" | \
		"%a:"*"/admin-password")
			printf '600\n'
			exit 0
			;;
		"%a:$TEST_BAD_MODE_PASSWORD_FILE")
			printf '644\n'
			exit 0
			;;
		esac
		exec /usr/bin/stat -c "$STAT_FORMAT" -- "$STAT_PATH"
	fi
fi
exec /usr/bin/stat "$@"
EOF

cat >"$MOCK_BIN/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$TEST_SYSTEMCTL_LOG"
case "$*" in
"is-active --quiet theatropolis-master")
	grep -Fqx active "$TEST_MASTER_STATE_FILE"
	;;
"stop theatropolis-master")
	printf 'inactive\n' >"$TEST_MASTER_STATE_FILE"
	if [ "${TEST_FAIL_MASTER_STOP:-no}" = "yes" ]; then
		exit 43
	fi
	;;
"start theatropolis-master" | \
"restart theatropolis-master" | \
"enable --now theatropolis-master")
	printf 'active\n' >"$TEST_MASTER_STATE_FILE"
	;;
"reload caddy")
	if [ "${TEST_FAIL_CADDY_RELOAD:-no}" = "yes" ]; then
		exit 42
	fi
	;;
"restart theatropolis-agent")
	if [ "${TEST_FAIL_AGENT_RESTART:-no}" = "yes" ]; then
		exit 44
	fi
	;;
esac
exit 0
EOF

cat >"$MOCK_BIN/caddy" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$TEST_CADDY_LOG"
case "${1:-}" in
fmt | validate) exit 0 ;;
*) exit 64 ;;
esac
EOF

cat >"$MOCK_BIN/compiler-block" <<'EOF'
#!/bin/sh
printf '%s: %s\n' "$0" "$*" >>"$TEST_COMPILER_LOG"
exit 99
EOF

chmod +x \
	"$MOCK_BIN/id" \
	"$MOCK_BIN/uname" \
	"$MOCK_BIN/apt-get" \
	"$MOCK_BIN/curl" \
	"$MOCK_BIN/openssl" \
	"$MOCK_BIN/install" \
	"$MOCK_BIN/chown" \
	"$MOCK_BIN/flock" \
	"$MOCK_BIN/mv" \
	"$MOCK_BIN/stat" \
	"$MOCK_BIN/systemctl" \
	"$MOCK_BIN/caddy" \
	"$MOCK_BIN/compiler-block"

for COMPILER in go gcc cc clang make cmake cargo rustc; do
	cp "$MOCK_BIN/compiler-block" "$MOCK_BIN/$COMPILER"
done

run_installer() {
	FAIL_CADDY_RELOAD="$1"
	shift
	TEST_ADMIN_USERNAME=""
	TEST_ADMIN_PASSWORD_FILE=""
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--admin-username)
			[ "$#" -ge 2 ] || fail "test --admin-username requires a value"
			TEST_ADMIN_USERNAME="$2"
			shift 2
			;;
		--admin-password-file)
			[ "$#" -ge 2 ] || fail "test --admin-password-file requires a value"
			TEST_ADMIN_PASSWORD_FILE="$2"
			shift 2
			;;
		*) fail "unexpected test installer argument: $1" ;;
		esac
	done
	# The command string is intentionally expanded by script's child shell.
	# shellcheck disable=SC2016
	printf '%s\n%s\n' "$DOMAIN" "$HTTPS_PORT" |
		PATH="$MOCK_BIN:$PATH" \
		TEST_RELEASE_DIRECTORY="$RELEASE_DIRECTORY" \
		TEST_MASTER_LOG="$MASTER_LOG" \
		TEST_INIT_STATE_LOG="$INIT_STATE_LOG" \
		TEST_SYSTEMCTL_LOG="$SYSTEMCTL_LOG" \
		TEST_CADDY_LOG="$CADDY_LOG" \
		TEST_INSTALL_LOG="$INSTALL_LOG" \
		TEST_APT_LOG="$APT_LOG" \
		TEST_CURL_LOG="$CURL_LOG" \
		TEST_COMPILER_LOG="$COMPILER_LOG" \
		TEST_MASTER_STATE_FILE="$MASTER_STATE_FILE" \
		TEST_FAIL_CADDY_RELOAD="$FAIL_CADDY_RELOAD" \
		TEST_FAIL_AGENT_RESTART="${TEST_FAIL_AGENT_RESTART:-no}" \
		TEST_FLOCK_BUSY="${TEST_FLOCK_BUSY:-no}" \
		TEST_FAIL_MASTER_STOP="${TEST_FAIL_MASTER_STOP:-no}" \
		TEST_FAIL_UNIT_RENAME="${TEST_FAIL_UNIT_RENAME:-no}" \
		TEST_INITIAL_PASSWORD_FILE="$INITIAL_PASSWORD_FILE" \
		TEST_RESET_PASSWORD_FILE="$RESET_PASSWORD_FILE" \
		TEST_FAILED_RESET_PASSWORD_FILE="$FAILED_RESET_PASSWORD_FILE" \
		TEST_BAD_MODE_PASSWORD_FILE="$BAD_MODE_PASSWORD_FILE" \
		TEST_INSTALLER_UNDER_TEST="$TEST_DIRECTORY/install.sh" \
		TEST_RELEASE_TAG="$RELEASE_TAG" \
		TEST_ADMIN_USERNAME="$TEST_ADMIN_USERNAME" \
		TEST_ADMIN_PASSWORD_FILE="$TEST_ADMIN_PASSWORD_FILE" \
		script -q -e -c \
		'set -- master --version "$TEST_RELEASE_TAG"; if [ -n "$TEST_ADMIN_USERNAME" ]; then set -- "$@" --admin-username "$TEST_ADMIN_USERNAME"; fi; if [ -n "$TEST_ADMIN_PASSWORD_FILE" ]; then set -- "$@" --admin-password-file "$TEST_ADMIN_PASSWORD_FILE"; fi; exec sh "$TEST_INSTALLER_UNDER_TEST" "$@"' \
		/dev/null
}

set +e
LEGACY_ENDPOINT_OUTPUT="$(
	sh "$TEST_DIRECTORY/install.sh" master \
		--domain "$DOMAIN" 2>&1
)"
LEGACY_ENDPOINT_STATUS="$?"
set -e
[ "$LEGACY_ENDPOINT_STATUS" -ne 0 ] ||
	fail "installer still accepted the removed --domain option"
printf '%s' "$LEGACY_ENDPOINT_OUTPUT" | grep -Fq 'unknown argument: --domain' ||
	fail "removed endpoint options did not produce an unknown-argument diagnostic"

set +e
LEGACY_PORT_OUTPUT="$(
	sh "$TEST_DIRECTORY/install.sh" master \
		--https-port "$HTTPS_PORT" 2>&1
)"
LEGACY_PORT_STATUS="$?"
set -e
[ "$LEGACY_PORT_STATUS" -ne 0 ] ||
	fail "installer still accepted the removed --https-port option"
printf '%s' "$LEGACY_PORT_OUTPUT" | grep -Fq 'unknown argument: --https-port' ||
	fail "removed Caddy port option did not produce an unknown-argument diagnostic"

# The process-wide installer lock prevents fresh/reset rollback state from
# racing another installer.
set +e
LOCK_OUTPUT="$(
	TEST_FLOCK_BUSY=yes \
		run_installer no \
		--admin-username locked-admin \
		--admin-password-file "$INITIAL_PASSWORD_FILE" 2>&1
)"
LOCK_STATUS="$?"
set -e
[ "$LOCK_STATUS" -ne 0 ] ||
	fail "installer continued while its exclusive lock was busy"
printf '%s' "$LOCK_OUTPUT" |
	grep -Fq 'another Theatropolis installer is already running' ||
	fail "busy installer lock did not produce a safe diagnostic"

# Unsafe automation password files must be rejected before any installation
# mutation or network/download work.
set +e
BAD_MODE_OUTPUT="$(
	run_installer no \
		--admin-username bad-mode-admin \
		--admin-password-file "$BAD_MODE_PASSWORD_FILE" 2>&1
)"
BAD_MODE_STATUS="$?"
set -e
[ "$BAD_MODE_STATUS" -ne 0 ] ||
	fail "group/world-readable admin password file was accepted"
printf '%s' "$BAD_MODE_OUTPUT" |
	grep -Fq 'permissions must be 0400 or 0600' ||
	fail "bad admin password file mode did not produce a safe diagnostic"

SYMLINK_PASSWORD_FILE="$TEST_DIRECTORY/symlink-password"
if ln -s "$INITIAL_PASSWORD_FILE" "$SYMLINK_PASSWORD_FILE" 2>/dev/null &&
	[ -L "$SYMLINK_PASSWORD_FILE" ]; then
	set +e
	SYMLINK_OUTPUT="$(
		run_installer no \
			--admin-username symlink-admin \
			--admin-password-file "$SYMLINK_PASSWORD_FILE" 2>&1
	)"
	SYMLINK_STATUS="$?"
	set -e
	[ "$SYMLINK_STATUS" -ne 0 ] ||
		fail "symbolic-link admin password file was accepted"
	printf '%s' "$SYMLINK_OUTPUT" |
		grep -Fq 'regular file, not a symbolic link' ||
		fail "symbolic-link admin password file did not produce a safe diagnostic"
fi

# A fresh interactive install defaults the username to admin and reads the
# password twice with terminal echo disabled. Force a later failure so the
# remaining scenarios still begin without a credential.
AUTH_FILE="$TEST_ROOT/var/lib/theatropolis/master/web-auth.json"
# Git for Windows exposes script(1), but its pseudo-terminal cannot reliably
# drive this Linux installer prompt. Linux CI exercises the interactive path.
if [ -z "${MSYSTEM:-}" ] && command -v script >/dev/null 2>&1; then
	INTERACTIVE_OUTPUT_FILE="$TEST_DIRECTORY/interactive-output.log"
	INTERACTIVE_INPUT_FIFO="$TEST_DIRECTORY/interactive-input"
	: >"$INTERACTIVE_OUTPUT_FILE"
	mkfifo "$INTERACTIVE_INPUT_FIFO"
	(
		exec 3>"$INTERACTIVE_INPUT_FIFO"
		ATTEMPTS=0
		until grep -Fq 'Public domain name:' "$INTERACTIVE_OUTPUT_FILE"; do
			ATTEMPTS=$((ATTEMPTS + 1))
			[ "$ATTEMPTS" -le 600 ] || exit 1
			sleep 0.1
		done
		printf '%s\n' "$DOMAIN" >&3
		ATTEMPTS=0
		until grep -Fq 'Caddy HTTPS port [8443]:' "$INTERACTIVE_OUTPUT_FILE"; do
			ATTEMPTS=$((ATTEMPTS + 1))
			[ "$ATTEMPTS" -le 600 ] || exit 1
			sleep 0.1
		done
		printf '%s\n' "$HTTPS_PORT" >&3
		ATTEMPTS=0
		until grep -Fq 'Admin username [admin]:' "$INTERACTIVE_OUTPUT_FILE"; do
			ATTEMPTS=$((ATTEMPTS + 1))
			[ "$ATTEMPTS" -le 600 ] || exit 1
			sleep 0.1
		done
		printf '\n' >&3
		ATTEMPTS=0
		until grep -Fq 'Admin password (15-128 characters):' "$INTERACTIVE_OUTPUT_FILE"; do
			ATTEMPTS=$((ATTEMPTS + 1))
			[ "$ATTEMPTS" -le 600 ] || exit 1
			sleep 0.1
		done
		printf '%s\n%s\n' \
			"$INTERACTIVE_PASSWORD" \
			"$INTERACTIVE_PASSWORD" >&3
		exec 3>&-
	) &
	INTERACTIVE_WRITER_PID="$!"
	set +e
	# The command string is intentionally expanded by script's child shell.
	# shellcheck disable=SC2016
	PATH="$MOCK_BIN:$PATH" \
		TEST_RELEASE_DIRECTORY="$RELEASE_DIRECTORY" \
		TEST_MASTER_LOG="$MASTER_LOG" \
		TEST_INIT_STATE_LOG="$INIT_STATE_LOG" \
		TEST_SYSTEMCTL_LOG="$SYSTEMCTL_LOG" \
		TEST_CADDY_LOG="$CADDY_LOG" \
		TEST_INSTALL_LOG="$INSTALL_LOG" \
		TEST_APT_LOG="$APT_LOG" \
		TEST_CURL_LOG="$CURL_LOG" \
		TEST_COMPILER_LOG="$COMPILER_LOG" \
		TEST_MASTER_STATE_FILE="$MASTER_STATE_FILE" \
		TEST_FAIL_CADDY_RELOAD="yes" \
		TEST_INITIAL_PASSWORD_FILE="$INITIAL_PASSWORD_FILE" \
		TEST_RESET_PASSWORD_FILE="$RESET_PASSWORD_FILE" \
		TEST_FAILED_RESET_PASSWORD_FILE="$FAILED_RESET_PASSWORD_FILE" \
		TEST_INSTALLER_UNDER_TEST="$TEST_DIRECTORY/install.sh" \
		TEST_DOMAIN="$DOMAIN" \
		TEST_HTTPS_PORT="$HTTPS_PORT" \
		TEST_RELEASE_TAG="$RELEASE_TAG" \
		script -q -e -c \
		'sh "$TEST_INSTALLER_UNDER_TEST" master --version "$TEST_RELEASE_TAG"' \
		/dev/null \
		<"$INTERACTIVE_INPUT_FIFO" \
		>"$INTERACTIVE_OUTPUT_FILE" 2>&1
	INTERACTIVE_STATUS="$?"
	wait "$INTERACTIVE_WRITER_PID"
	INTERACTIVE_WRITER_STATUS="$?"
	set -e
	INTERACTIVE_OUTPUT="$(cat "$INTERACTIVE_OUTPUT_FILE")"
	[ "$INTERACTIVE_WRITER_STATUS" -eq 0 ] ||
		fail "timed out waiting for the interactive admin prompt"
	[ "$INTERACTIVE_STATUS" -ne 0 ] ||
		fail "interactive installation unexpectedly succeeded when Caddy reload failed"
	printf '%s' "$INTERACTIVE_OUTPUT" | grep -Fq 'Public domain name:' ||
		fail "interactive installation did not prompt for the public domain"
	printf '%s' "$INTERACTIVE_OUTPUT" | grep -Fq 'Caddy HTTPS port [8443]:' ||
		fail "interactive installation did not prompt for the Caddy HTTPS port"
	printf '%s' "$INTERACTIVE_OUTPUT" | grep -Fq 'Admin username [admin]:' ||
		fail "interactive installation did not prompt for an admin username"
	printf '%s' "$INTERACTIVE_OUTPUT" | grep -Fq 'Admin password (15-128 characters):' ||
		fail "interactive installation did not prompt for an admin password"
	printf '%s' "$INTERACTIVE_OUTPUT" | grep -Fq 'Confirm admin password:' ||
		fail "interactive installation did not request password confirmation"
	if printf '%s' "$INTERACTIVE_OUTPUT" | grep -Fq "$INTERACTIVE_PASSWORD"; then
		fail "interactive terminal echoed the admin password"
	fi
	[ ! -e "$AUTH_FILE" ] ||
		fail "failed interactive installation retained its new credential"
	[ "$(grep -Fxc "$TEST_ROOT/var/lib/theatropolis/master|no|admin" "$INIT_STATE_LOG")" -eq 1 ] ||
		fail "interactive installation did not initialize the default admin username"
fi

# Even when credential creation commits and then reports a durability error,
# a failed fresh install must remove only the credential it just created.
set +e
FRESH_COMMIT_FAILURE_OUTPUT="$(
	run_installer no \
		--admin-username fresh-commit-fail \
		--admin-password-file "$INITIAL_PASSWORD_FILE" 2>&1
)"
FRESH_COMMIT_FAILURE_STATUS="$?"
set -e
[ "$FRESH_COMMIT_FAILURE_STATUS" -ne 0 ] ||
	fail "commit-then-fail fresh initialization unexpectedly succeeded"
[ ! -e "$AUTH_FILE" ] ||
	fail "commit-then-fail fresh initialization retained its credential"
if printf '%s' "$FRESH_COMMIT_FAILURE_OUTPUT" | grep -Fq "$INITIAL_PASSWORD"; then
	fail "commit-then-fail fresh output exposed the admin password"
fi

# A later failure must also remove a freshly-created credential. The secret
# must never appear in output or any command invocation log.
set +e
FRESH_FAILURE_OUTPUT="$(
	run_installer yes \
		--admin-username first-admin \
		--admin-password-file "$INITIAL_PASSWORD_FILE" 2>&1
)"
FRESH_FAILURE_STATUS="$?"
set -e
[ "$FRESH_FAILURE_STATUS" -ne 0 ] ||
	fail "fresh installation unexpectedly succeeded when Caddy reload failed"
[ ! -e "$AUTH_FILE" ] ||
	fail "failed fresh installation retained its newly created web credential"
if printf '%s' "$FRESH_FAILURE_OUTPUT" | grep -Fq "$INITIAL_PASSWORD"; then
	fail "fresh installation failure output exposed the admin password"
fi

set +e
FIRST_OUTPUT="$(
	run_installer no \
		--admin-username first-admin \
		--admin-password-file "$INITIAL_PASSWORD_FILE" 2>&1
)"
FIRST_STATUS="$?"
set -e
[ "$FIRST_STATUS" -eq 0 ] ||
	fail "initial installation failed (status $FIRST_STATUS): $FIRST_OUTPUT"
[ -f "$AUTH_FILE" ] ||
	fail "initial installation did not create the web access file"
if printf '%s' "$FIRST_OUTPUT" | grep -Fq "$INITIAL_PASSWORD"; then
	fail "initial installation output exposed the admin password"
fi
printf '%s' "$FIRST_OUTPUT" | grep -Fq 'Web admin username: first-admin' ||
	fail "initial installation did not confirm the selected admin username"
AUTH_HASH_BEFORE="$(sha256sum "$AUTH_FILE" | awk '{ print $1 }')"

set +e
SECOND_OUTPUT="$(run_installer no 2>&1)"
SECOND_STATUS="$?"
set -e
[ "$SECOND_STATUS" -eq 0 ] ||
	fail "reinstallation failed (status $SECOND_STATUS): $SECOND_OUTPUT"
printf '%s' "$SECOND_OUTPUT" | grep -Fq 'existing web admin credential was preserved' ||
	fail "reinstallation did not report credential preservation"

AUTH_HASH_AFTER="$(sha256sum "$AUTH_FILE" | awk '{ print $1 }')"
[ "$AUTH_HASH_AFTER" = "$AUTH_HASH_BEFORE" ] ||
	fail "reinstallation replaced or modified the web access file"
[ "$(grep -Fxc "$TEST_ROOT/var/lib/theatropolis/master|no|first-admin" "$INIT_STATE_LOG")" -eq 2 ] ||
	fail "fresh-failure and successful initialization calls were not both exercised"

set +e
RESET_OUTPUT="$(
	run_installer no \
		--admin-username replacement-admin \
		--admin-password-file "$RESET_PASSWORD_FILE" 2>&1
)"
RESET_STATUS="$?"
set -e
[ "$RESET_STATUS" -eq 0 ] ||
	fail "explicit admin reset failed (status $RESET_STATUS): $RESET_OUTPUT"
if printf '%s' "$RESET_OUTPUT" | grep -Fq "$RESET_PASSWORD"; then
	fail "explicit reset output exposed the admin password"
fi
AUTH_HASH_RESET="$(sha256sum "$AUTH_FILE" | awk '{ print $1 }')"
[ "$AUTH_HASH_RESET" != "$AUTH_HASH_AFTER" ] ||
	fail "explicit reset did not replace the web admin credential"
[ "$(grep -Fxc "$TEST_ROOT/var/lib/theatropolis/master|yes|replacement-admin" "$INIT_STATE_LOG")" -eq 1 ] ||
	fail "explicit reset did not invoke the candidate in replacement mode"

UNIT="$TEST_ROOT/etc/systemd/system/theatropolis-master.service"
UNIT_HASH_RESET="$(sha256sum "$UNIT" | awk '{ print $1 }')"
grep -Fqx "Environment=THEATROPOLIS_PUBLIC_ADDRESS=$DOMAIN:$HTTPS_PORT" "$UNIT" ||
	fail "master unit does not publish its canonical address for co-located Agent detection"

set +e
STOP_FAILURE_OUTPUT="$(
	TEST_FAIL_MASTER_STOP=yes \
		run_installer no \
		--admin-username stop-failure-admin \
		--admin-password-file "$FAILED_RESET_PASSWORD_FILE" 2>&1
)"
STOP_FAILURE_STATUS="$?"
set -e
[ "$STOP_FAILURE_STATUS" -ne 0 ] ||
	fail "explicit reset unexpectedly succeeded after an uncertain master stop"
if printf '%s' "$STOP_FAILURE_OUTPUT" | grep -Fq "$FAILED_RESET_PASSWORD"; then
	fail "uncertain-stop output exposed the admin password"
fi
[ "$(sha256sum "$AUTH_FILE" | awk '{ print $1 }')" = "$AUTH_HASH_RESET" ] ||
	fail "uncertain-stop failure changed the previous web admin credential"
[ "$(sha256sum "$UNIT" | awk '{ print $1 }')" = "$UNIT_HASH_RESET" ] ||
	fail "uncertain-stop failure changed the previous master service unit"
grep -Fqx active "$MASTER_STATE_FILE" ||
	fail "uncertain-stop failure did not recover the previously active master"

set +e
UNIT_RENAME_FAILURE_OUTPUT="$(
	TEST_FAIL_UNIT_RENAME=yes \
		run_installer no \
		--admin-username unit-rename-failure \
		--admin-password-file "$FAILED_RESET_PASSWORD_FILE" 2>&1
)"
UNIT_RENAME_FAILURE_STATUS="$?"
set -e
[ "$UNIT_RENAME_FAILURE_STATUS" -ne 0 ] ||
	fail "explicit reset unexpectedly succeeded when unit installation failed"
if printf '%s' "$UNIT_RENAME_FAILURE_OUTPUT" | grep -Fq "$FAILED_RESET_PASSWORD"; then
	fail "unit-install failure output exposed the admin password"
fi
[ "$(sha256sum "$AUTH_FILE" | awk '{ print $1 }')" = "$AUTH_HASH_RESET" ] ||
	fail "unit-install failure did not restore the previous web admin credential"
[ "$(sha256sum "$UNIT" | awk '{ print $1 }')" = "$UNIT_HASH_RESET" ] ||
	fail "unit-install failure did not preserve the previous master service unit"
grep -Fqx active "$MASTER_STATE_FILE" ||
	fail "unit-install failure did not restart the previous master"
if find "$(dirname "$UNIT")" \
	-name 'theatropolis-master.service.tmp.*' \
	-print -quit |
	grep -q .; then
	fail "unit-install failure retained a temporary master service unit"
fi

set +e
RESET_COMMIT_FAILURE_OUTPUT="$(
	run_installer no \
		--admin-username reset-commit-fail \
		--admin-password-file "$FAILED_RESET_PASSWORD_FILE" 2>&1
)"
RESET_COMMIT_FAILURE_STATUS="$?"
set -e
[ "$RESET_COMMIT_FAILURE_STATUS" -ne 0 ] ||
	fail "commit-then-fail explicit reset unexpectedly succeeded"
if printf '%s' "$RESET_COMMIT_FAILURE_OUTPUT" | grep -Fq "$FAILED_RESET_PASSWORD"; then
	fail "commit-then-fail reset output exposed the admin password"
fi
[ "$(sha256sum "$AUTH_FILE" | awk '{ print $1 }')" = "$AUTH_HASH_RESET" ] ||
	fail "commit-then-fail reset did not restore the previous credential"
[ "$(sha256sum "$UNIT" | awk '{ print $1 }')" = "$UNIT_HASH_RESET" ] ||
	fail "commit-then-fail reset modified the master service unit"
grep -Fqx active "$MASTER_STATE_FILE" ||
	fail "commit-then-fail reset did not restart the previous master"

set +e
ROLLBACK_OUTPUT="$(
	run_installer yes \
		--admin-username rollback-admin \
		--admin-password-file "$FAILED_RESET_PASSWORD_FILE" 2>&1
)"
ROLLBACK_STATUS="$?"
set -e
[ "$ROLLBACK_STATUS" -ne 0 ] ||
	fail "reset installation unexpectedly succeeded when Caddy reload failed"
if printf '%s' "$ROLLBACK_OUTPUT" | grep -Fq "$FAILED_RESET_PASSWORD"; then
	fail "failed reset output exposed the admin password"
fi
[ "$(sha256sum "$AUTH_FILE" | awk '{ print $1 }')" = "$AUTH_HASH_RESET" ] ||
	fail "failed reset did not restore the previous web admin credential"
[ "$(sha256sum "$UNIT" | awk '{ print $1 }')" = "$UNIT_HASH_RESET" ] ||
	fail "failed reset did not restore the previous master service unit"
grep -Fqx active "$MASTER_STATE_FILE" ||
	fail "failed reset did not restore the previously active master service"

[ -f "$UNIT" ] ||
	fail "master systemd unit was not generated"
grep -Fq -- \
	"--public-url https://${DOMAIN}:${HTTPS_PORT}" \
	"$UNIT" ||
	fail "master unit does not contain the canonical public URL"
grep -Fq -- \
	"--web-auth-file $AUTH_FILE" \
	"$UNIT" ||
	fail "master unit does not contain the persistent web access path"

UPDATE_UNIT="$TEST_ROOT/etc/systemd/system/theatropolis-master-update.service"
UPDATE_PATH="$TEST_ROOT/etc/systemd/system/theatropolis-master-update.path"
[ -f "$UPDATE_UNIT" ] ||
	fail "master update systemd unit was not generated"
[ -f "$UPDATE_PATH" ] ||
	fail "master update path unit was not generated"
grep -Fq -- \
	"theatropolis-update-helper apply-theatropolis --component=master --state-dir=$TEST_ROOT/var/lib/theatropolis/master --install-path=$TEST_ROOT/usr/local/bin/theatropolis-master" \
	"$UPDATE_UNIT" ||
	fail "master update unit does not invoke the verified self-updater"
grep -Fq -- \
	"PathExists=$TEST_ROOT/var/lib/theatropolis/master/update-request.json" \
	"$UPDATE_PATH" ||
	fail "master update path does not watch the master's request file"
grep -Fq -- \
	"PathExists=$TEST_ROOT/var/lib/theatropolis/master/.update-request.processing.json" \
	"$UPDATE_PATH" ||
	fail "master update path does not recover a claimed request after interruption"
grep -Fq -- \
	"enable --now theatropolis-master-update.path" \
	"$SYSTEMCTL_LOG" ||
	fail "master update path unit was not enabled"

# An installation that predates the writable master state path keeps its web
# credential under /etc. Migration must retain that source until the full
# install succeeds, remove a failed target copy during rollback, and delete the
# obsolete source only after the new service has started successfully.
LEGACY_AUTH_FILE="$TEST_ROOT/etc/theatropolis/web-auth.json"
mv "$AUTH_FILE" "$LEGACY_AUTH_FILE"
LEGACY_AUTH_HASH="$(sha256sum "$LEGACY_AUTH_FILE" | awk '{ print $1 }')"
set +e
run_installer yes >/dev/null 2>&1
MIGRATION_FAILURE_STATUS="$?"
set -e
[ "$MIGRATION_FAILURE_STATUS" -ne 0 ] ||
	fail "legacy credential migration unexpectedly succeeded when Caddy reload failed"
[ ! -e "$AUTH_FILE" ] ||
	fail "failed legacy credential migration retained its target copy"
[ -f "$LEGACY_AUTH_FILE" ] ||
	fail "failed legacy credential migration removed its rollback source"
[ "$(sha256sum "$LEGACY_AUTH_FILE" | awk '{ print $1 }')" = "$LEGACY_AUTH_HASH" ] ||
	fail "failed legacy credential migration changed its rollback source"

set +e
MIGRATION_OUTPUT="$(run_installer no 2>&1)"
MIGRATION_STATUS="$?"
set -e
[ "$MIGRATION_STATUS" -eq 0 ] ||
	fail "legacy credential migration failed (status $MIGRATION_STATUS): $MIGRATION_OUTPUT"
[ -f "$AUTH_FILE" ] ||
	fail "legacy credential migration did not create the writable state file"
[ ! -e "$LEGACY_AUTH_FILE" ] ||
	fail "successful legacy credential migration retained the obsolete /etc copy"
[ "$(sha256sum "$AUTH_FILE" | awk '{ print $1 }')" = "$LEGACY_AUTH_HASH" ] ||
	fail "legacy credential migration changed the credential"
printf '%s' "$MIGRATION_OUTPUT" | grep -Fq 'existing web admin credential was preserved' ||
	fail "legacy credential migration did not report credential preservation"

SNIPPET="$TEST_ROOT/etc/caddy/conf.d/theatropolis.caddy"
[ -f "$SNIPPET" ] ||
	fail "Caddy snippet was not generated"
[ "$(grep -Ec '^[[:space:]]*protocol grpc$' "$SNIPPET")" -eq 1 ] ||
	fail "Caddy snippet does not use one exact gRPC protocol matcher"
[ "$(grep -Fxc '		path /theatropolis.control.v1.AgentControlService/*' "$SNIPPET")" -eq 1 ] ||
	fail "Caddy snippet does not restrict gRPC traffic to the control service"
grep -Eq '^[[:space:]]*handle \{$' "$SNIPPET" ||
	fail "Caddy snippet does not include an unmatched-request UI handler"
grep -Eq '^[[:space:]]*reverse_proxy 127\.0\.0\.1:8080$' "$SNIPPET" ||
	fail "Caddy snippet does not route unmatched requests to the web UI"

CADDYFILE="$TEST_ROOT/etc/caddy/Caddyfile"
[ "$(grep -Fxc "import $TEST_ROOT/etc/caddy/conf.d/*.caddy" "$CADDYFILE")" -eq 1 ] ||
	fail "reinstallation duplicated or omitted the Caddy import"

# Installing or upgrading the Master beside an existing Agent enables the
# loopback-only challenge relay and restarts that Agent after Caddy accepts it.
AGENT_UNIT="$TEST_ROOT/etc/systemd/system/theatropolis-agent.service"
printf '%s\n' '[Service]' 'ExecStart=/usr/local/bin/theatropolis-agent --master old.example.com:443' >"$AGENT_UNIT"
cp "$AGENT_UNIT" "$TEST_DIRECTORY/legacy-agent-unit"
printf '%s\n' 'old Agent binary without ACME relay support' >"$TEST_ROOT/usr/local/bin/theatropolis-agent"
mkdir -p "$TEST_ROOT/var/lib/theatropolis/agent"
printf '%s\n' 'preserved identity' >"$TEST_ROOT/var/lib/theatropolis/agent/identity.pem"
printf '%s\n' 'THEATROPOLIS_MASTER=old.example.com:443' >"$TEST_ROOT/etc/theatropolis/agent.env"
set +e
COLOCATED_OUTPUT="$(run_installer no 2>&1)"
COLOCATED_STATUS="$?"
set -e
[ "$COLOCATED_STATUS" -eq 0 ] ||
	fail "co-located Master reinstall failed (status $COLOCATED_STATUS): $COLOCATED_OUTPUT"
RELAY_SNIPPET="$TEST_ROOT/etc/caddy/conf.d/theatropolis-agent-acme.caddy"
RELAY_MARKER="$TEST_ROOT/etc/theatropolis/acme-http01-master-relay"
grep -Fq 'reverse_proxy 127.0.0.1:19091' "$RELAY_SNIPPET" ||
	fail "Master reinstall beside an Agent did not configure the ACME relay"
grep -Fqx "http://${DOMAIN} {" "$RELAY_SNIPPET" ||
	fail "relay does not override the Master's automatic HTTP redirect"
grep -Fq "redir https://${DOMAIN}:${HTTPS_PORT}{uri} 308" "$RELAY_SNIPPET" ||
	fail "relay does not preserve the Master's ordinary HTTPS redirect"
cmp -s "$RELEASE_STAGE/theatropolis-agent" "$TEST_ROOT/usr/local/bin/theatropolis-agent" ||
	fail "Master reinstall left an old Agent binary without relay support"
cmp -s "$AGENT_UNIT" "$TEST_DIRECTORY/legacy-agent-unit" ||
	fail "Master reinstall replaced the existing Agent service configuration"
grep -Fqx 'preserved identity' "$TEST_ROOT/var/lib/theatropolis/agent/identity.pem" ||
	fail "Master reinstall replaced the Agent identity"
grep -Fqx 'THEATROPOLIS_MASTER=old.example.com:443' "$TEST_ROOT/etc/theatropolis/agent.env" ||
	fail "Master reinstall changed the Agent's enrolled Master"
grep -Fqx '19091' "$RELAY_MARKER" ||
	fail "Master reinstall beside an Agent did not enable the ACME relay marker"
grep -Fqx 'restart theatropolis-agent' "$SYSTEMCTL_LOG" ||
	fail "Master reinstall did not restart the co-located Agent after enabling the relay"

# A failed paired upgrade restores both the old executable and the exact relay
# configuration before restarting the surviving Agent.
printf '%s\n' 'previous Agent binary' >"$TEST_ROOT/usr/local/bin/theatropolis-agent"
cp "$RELAY_SNIPPET" "$TEST_DIRECTORY/relay-before-failure"
cp "$RELAY_MARKER" "$TEST_DIRECTORY/marker-before-failure"
set +e
FAILED_COLOCATED_OUTPUT="$(TEST_FAIL_AGENT_RESTART=yes run_installer no 2>&1)"
FAILED_COLOCATED_STATUS="$?"
set -e
[ "$FAILED_COLOCATED_STATUS" -ne 0 ] ||
	fail "paired upgrade ignored the failed Agent restart"
grep -Fqx 'previous Agent binary' "$TEST_ROOT/usr/local/bin/theatropolis-agent" ||
	fail "failed paired upgrade did not restore the previous Agent binary"
cmp -s "$RELAY_SNIPPET" "$TEST_DIRECTORY/relay-before-failure" ||
	fail "failed paired upgrade did not restore the relay entry"
cmp -s "$RELAY_MARKER" "$TEST_DIRECTORY/marker-before-failure" ||
	fail "failed paired upgrade did not restore the relay marker"

[ ! -s "$COMPILER_LOG" ] ||
	fail "installer invoked a compiler: $(tr '\n' ' ' <"$COMPILER_LOG")"
[ -x "$TEST_ROOT/usr/local/bin/theatropolis-master" ] ||
	fail "precompiled master binary was not installed"
[ -x "$TEST_ROOT/usr/local/libexec/theatropolis/theatropolis-update-helper" ] ||
	fail "dedicated update helper was not installed"
[ -s "$APT_LOG" ] ||
	fail "mocked package installation was not exercised"
[ -s "$SYSTEMCTL_LOG" ] ||
	fail "mocked systemd integration was not exercised"
[ -s "$CADDY_LOG" ] ||
	fail "mocked Caddy validation was not exercised"

for SECRET in \
	"$INTERACTIVE_PASSWORD" \
	"$INITIAL_PASSWORD" \
	"$RESET_PASSWORD" \
	"$FAILED_RESET_PASSWORD"; do
	if grep -Fq "$SECRET" \
		"$MASTER_LOG" \
		"$SYSTEMCTL_LOG" \
		"$CADDY_LOG" \
		"$INSTALL_LOG" \
		"$APT_LOG" \
		"$CURL_LOG"; then
		fail "an admin password appeared in an installer command log"
	fi
done
