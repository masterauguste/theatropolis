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
ACCESS_KEY="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
DOMAIN="control.example.com"
HTTPS_PORT="8443"
RELEASE_TAG="v9.9.9"

cleanup() {
	rm -rf -- "$TEST_DIRECTORY"
}

fail() {
	printf 'master installer test: %s\n' "$*" >&2
	exit 1
}

trap cleanup EXIT HUP INT TERM

mkdir -p \
	"$MOCK_BIN" \
	"$RELEASE_DIRECTORY" \
	"$RELEASE_STAGE" \
	"$TEST_ROOT/etc/caddy/conf.d" \
	"$TEST_ROOT/etc/systemd/system" \
	"$TEST_ROOT/usr/local/bin"

printf '%s\n' \
	'ID=debian' \
	'VERSION_ID=13' \
	>"$TEST_ROOT/etc/os-release"

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

# A release-compatible master creates a digest file and prints a new access
# key. The state-directory log lets the test distinguish compatibility probes
# from initialization of the persistent installation.
cat >"$RELEASE_STAGE/theatropolis-master" <<'EOF'
#!/bin/sh
set -eu

printf '%s\n' "$*" >>"$TEST_MASTER_LOG"

case "${1:-}" in
init-web-admin)
	shift
	STATE_DIRECTORY=""
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--state-dir)
			[ "$#" -ge 2 ] || exit 64
			STATE_DIRECTORY="$2"
			shift 2
			;;
		*)
			exit 64
			;;
		esac
	done
	[ -n "$STATE_DIRECTORY" ] || exit 64
	printf '%s\n' "$STATE_DIRECTORY" >>"$TEST_INIT_STATE_LOG"
	mkdir -p "$STATE_DIRECTORY"
	[ ! -e "$STATE_DIRECTORY/web-auth.json" ] || exit 73
	printf '{"version":1,"key_sha256":"fixture-digest"}\n' \
		>"$STATE_DIRECTORY/web-auth.json"
	printf '%s\n' "$TEST_ACCESS_KEY"
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

chmod +x \
	"$RELEASE_STAGE/theatropolis-master" \
	"$RELEASE_STAGE/theatropolis-agent"

tar -czf "$RELEASE_DIRECTORY/theatropolis_linux_amd64.tar.gz" \
	-C "$RELEASE_STAGE" \
	theatropolis-master \
	theatropolis-agent
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
*)
	printf 'unexpected mock curl source: %s\n' "$SOURCE" >&2
	exit 65
	;;
esac
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

cat >"$MOCK_BIN/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$TEST_SYSTEMCTL_LOG"
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
	"$MOCK_BIN/install" \
	"$MOCK_BIN/chown" \
	"$MOCK_BIN/systemctl" \
	"$MOCK_BIN/caddy" \
	"$MOCK_BIN/compiler-block"

for COMPILER in go gcc cc clang make cmake cargo rustc; do
	cp "$MOCK_BIN/compiler-block" "$MOCK_BIN/$COMPILER"
done

run_installer() {
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
		TEST_ACCESS_KEY="$ACCESS_KEY" \
		sh "$TEST_DIRECTORY/install.sh" master \
		--domain "$DOMAIN" \
		--https-port "$HTTPS_PORT" \
		--version "$RELEASE_TAG"
}

set +e
FIRST_OUTPUT="$(run_installer 2>&1)"
FIRST_STATUS="$?"
set -e
[ "$FIRST_STATUS" -eq 0 ] ||
	fail "initial installation failed (status $FIRST_STATUS): $FIRST_OUTPUT"
printf '%s' "$FIRST_OUTPUT" | grep -Fq "Access key: $ACCESS_KEY" ||
	fail "initial installation did not display the new operator access key"

AUTH_FILE="$TEST_ROOT/etc/theatropolis/web-auth.json"
[ -f "$AUTH_FILE" ] ||
	fail "initial installation did not create the web access file"
AUTH_HASH_BEFORE="$(sha256sum "$AUTH_FILE" | awk '{ print $1 }')"

set +e
SECOND_OUTPUT="$(run_installer 2>&1)"
SECOND_STATUS="$?"
set -e
[ "$SECOND_STATUS" -eq 0 ] ||
	fail "reinstallation failed (status $SECOND_STATUS): $SECOND_OUTPUT"
if printf '%s' "$SECOND_OUTPUT" | grep -Fq 'Access key:'; then
	fail "reinstallation unexpectedly displayed a new operator access key"
fi

AUTH_HASH_AFTER="$(sha256sum "$AUTH_FILE" | awk '{ print $1 }')"
[ "$AUTH_HASH_AFTER" = "$AUTH_HASH_BEFORE" ] ||
	fail "reinstallation replaced or modified the web access file"
[ "$(grep -Fxc "$TEST_ROOT/etc/theatropolis" "$INIT_STATE_LOG")" -eq 1 ] ||
	fail "persistent web access was initialized more than once"

UNIT="$TEST_ROOT/etc/systemd/system/theatropolis-master.service"
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

[ ! -s "$COMPILER_LOG" ] ||
	fail "installer invoked a compiler: $(tr '\n' ' ' <"$COMPILER_LOG")"
[ -x "$TEST_ROOT/usr/local/bin/theatropolis-master" ] ||
	fail "precompiled master binary was not installed"
[ -s "$APT_LOG" ] ||
	fail "mocked package installation was not exercised"
[ -s "$SYSTEMCTL_LOG" ] ||
	fail "mocked systemd integration was not exercised"
[ -s "$CADDY_LOG" ] ||
	fail "mocked Caddy validation was not exercised"
