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
SING_BOX_VERSION="1.14.0-rc.1.theatropolis.2"
SING_BOX_PACKAGE="sing-box-${SING_BOX_VERSION}-linux-amd64"
SING_BOX_ARCHIVE="${SING_BOX_PACKAGE}.tar.gz"
SING_BOX_STAGE="$TEST_DIRECTORY/sing-box-stage"
MV_LOG="$TEST_DIRECTORY/mv.log"
CHOWN_LOG="$TEST_DIRECTORY/chown.log"
SYSTEMCTL_LOG="$TEST_DIRECTORY/systemctl.log"
TEST_PLATFORM="$(uname -s)"
VALID_TOKEN="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
STALE_TOKEN="stale-enrollment-token"
RELEASE_TAG="v9.9.9"

cleanup() {
	rm -rf -- "$TEST_DIRECTORY"
}

fail() {
	printf 'agent token installer test: %s\n' "$*" >&2
	exit 1
}

trap cleanup EXIT HUP INT TERM

mkdir -p \
	"$MOCK_BIN" \
	"$RELEASE_DIRECTORY" \
	"$RELEASE_STAGE" \
	"$SING_BOX_STAGE/$SING_BOX_PACKAGE" \
	"$TEST_ROOT/etc/systemd/system" \
	"$TEST_ROOT/run" \
	"$TEST_ROOT/usr/local/bin" \
	"$TEST_ROOT/var/lib/theatropolis/agent"

printf '%s\n' \
	'ID=debian' \
	'VERSION_ID=13' \
	>"$TEST_ROOT/etc/os-release"

# Relocate every fixed system path so the installer cannot write to the host.
sed \
	-e "s#/usr/bin/setpriv#$MOCK_BIN/setpriv#g" \
	-e "s#/usr/local/#$TEST_ROOT/usr/local/#g" \
	-e "s#/usr/share/#$TEST_ROOT/usr/share/#g" \
	-e "s#/var/lib/#$TEST_ROOT/var/lib/#g" \
	-e "s#/etc/#$TEST_ROOT/etc/#g" \
	-e "s#/run/#$TEST_ROOT/run/#g" \
	"$INSTALLER" >"$TEST_DIRECTORY/install.sh"
chmod +x "$TEST_DIRECTORY/install.sh"

cat >"$RELEASE_STAGE/theatropolis-master" <<'EOF'
#!/bin/sh
case "${1:-}" in
latest-sing-box-version)
	printf '%s\n' 'v1.14.0-rc.1.theatropolis.2'
	;;
validate-sing-box-build-manifest) ;;
*) exit 64 ;;
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

cat >"$SING_BOX_STAGE/$SING_BOX_PACKAGE/sing-box" <<'EOF'
#!/bin/sh
printf '%s\n' 'sing-box version 1.14.0-rc.1.theatropolis.2' 'Tags: with_v2ray_api,with_theatropolis_managed_users'
EOF
printf '%s\n' 'mock cronet library' \
	>"$SING_BOX_STAGE/$SING_BOX_PACKAGE/libcronet.so"
printf '%s\n' 'mock sing-box license' \
	>"$SING_BOX_STAGE/$SING_BOX_PACKAGE/LICENSE"
chmod +x "$SING_BOX_STAGE/$SING_BOX_PACKAGE/sing-box"

tar -czf "$RELEASE_DIRECTORY/theatropolis_linux_amd64.tar.gz" \
	-C "$RELEASE_STAGE" \
	theatropolis-master \
	theatropolis-agent \
	theatropolis-update-helper
tar -czf "$RELEASE_DIRECTORY/$SING_BOX_ARCHIVE" \
	-C "$SING_BOX_STAGE" \
	"$SING_BOX_PACKAGE"
cat >"$RELEASE_DIRECTORY/build-manifest.json" <<EOF
{"schema_version":2,"release":{"tag":"v$SING_BOX_VERSION","version":"$SING_BOX_VERSION"},"patchset":{"capabilities":["managed-users-v1","anytls-live-users","hysteria2-live-users","session-revocation-v1","traffic-reset-v1"]},"build":{"tags":["with_v2ray_api","with_theatropolis_managed_users"]}}
EOF
(
	cd "$RELEASE_DIRECTORY"
	BUILD_MANIFEST_CHECKSUM="$(sha256sum build-manifest.json | awk '{ print $1 }')"
	printf '%s  %s\n%s  %s\n' \
		'5d1ebf727af665dd433f7661583b6087eee9b162b5be1df0795a3ab0686f2122' \
		"$SING_BOX_ARCHIVE" \
		"$BUILD_MANIFEST_CHECKSUM" \
		build-manifest.json \
		>sing-box-checksums.txt
)
: >"$RELEASE_DIRECTORY/sing-box-checksums.txt.sig"
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
theatropolis-agent) exit 0 ;;
esac
exec /usr/bin/id "$@"
EOF

cat >"$MOCK_BIN/uname" <<'EOF'
#!/bin/sh
printf 'x86_64\n'
EOF

cat >"$MOCK_BIN/apt-get" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"$MOCK_BIN/curl" <<'EOF'
#!/bin/sh
set -eu

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
*/sing-box-v2ray-api-builds/releases/download/v1.14.0-rc.1.theatropolis.2/checksums.txt)
	cp "$TEST_RELEASE_DIRECTORY/sing-box-checksums.txt" "$OUTPUT"
	;;
*/sing-box-v2ray-api-builds/releases/download/v1.14.0-rc.1.theatropolis.2/checksums.txt.sig)
	cp "$TEST_RELEASE_DIRECTORY/sing-box-checksums.txt.sig" "$OUTPUT"
	;;
*/sing-box-v2ray-api-builds/releases/download/v1.14.0-rc.1.theatropolis.2/build-manifest.json)
	cp "$TEST_RELEASE_DIRECTORY/build-manifest.json" "$OUTPUT"
	;;
*/checksums.txt)
	cp "$TEST_RELEASE_DIRECTORY/checksums.txt" "$OUTPUT"
	;;
*/checksums.txt.sig)
	cp "$TEST_RELEASE_DIRECTORY/checksums.txt.sig" "$OUTPUT"
	;;
*/sing-box-1.14.0-rc.1.theatropolis.2-linux-amd64.tar.gz)
	cp "$TEST_RELEASE_DIRECTORY/sing-box-1.14.0-rc.1.theatropolis.2-linux-amd64.tar.gz" "$OUTPUT"
	;;
*)
	printf 'unexpected mock curl source: %s\n' "$SOURCE" >&2
	exit 65
	;;
esac
EOF

cat >"$MOCK_BIN/openssl" <<'EOF'
#!/bin/sh
case "$*" in
*sing-box-release-signing-public.pem*)
	[ "${TEST_SING_BOX_SIGNATURE_FAIL:-no}" != "yes" ] || exit 1
	;;
esac
exit 0
EOF

cat >"$MOCK_BIN/sha256sum" <<'EOF'
#!/bin/sh
case "${1:-}" in
*"/sing-box-1.14.0-rc.1.theatropolis.2-linux-amd64.tar.gz")
	printf '%s  %s\n' \
		'5d1ebf727af665dd433f7661583b6087eee9b162b5be1df0795a3ab0686f2122' \
		"$1"
	;;
*) exec /usr/bin/sha256sum "$@" ;;
esac
EOF

cat >"$MOCK_BIN/install" <<'EOF'
#!/bin/sh
set -eu

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
printf '%s\n' "$*" >>"$TEST_CHOWN_LOG"
exit 0
EOF

cat >"$MOCK_BIN/flock" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"$MOCK_BIN/setpriv" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"$MOCK_BIN/mv" <<'EOF'
#!/bin/sh
set -eu

[ "$#" -eq 4 ] || exit 64
[ "$1" = "-fT" ] || exit 64
[ "$2" = "--" ] || exit 64
[ -f "$3" ] || exit 65
[ ! -L "$3" ] || exit 65
printf '%s\n' \
	"$3" \
	"$4" \
	"$(stat -c '%a' "$3")" \
	"$(cat "$3")" \
	>>"$TEST_MV_LOG"
exec /bin/mv "$@"
EOF

cat >"$MOCK_BIN/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$TEST_SYSTEMCTL_LOG"
case "${1:-}" in
is-active) exit 3 ;;
*) exit 0 ;;
esac
EOF

chmod +x "$MOCK_BIN"/*

run_installer() {
	TEST_SING_BOX_SIGNATURE_FAIL_VALUE="${1:-no}"
	PATH="$MOCK_BIN:$PATH" \
		TEST_RELEASE_DIRECTORY="$RELEASE_DIRECTORY" \
		TEST_MV_LOG="$MV_LOG" \
		TEST_CHOWN_LOG="$CHOWN_LOG" \
		TEST_SYSTEMCTL_LOG="$SYSTEMCTL_LOG" \
		TEST_SING_BOX_SIGNATURE_FAIL="$TEST_SING_BOX_SIGNATURE_FAIL_VALUE" \
		sh "$TEST_DIRECTORY/install.sh" agent \
		--master master.example.com:8443 \
		--token "$VALID_TOKEN" \
		--version "$RELEASE_TAG"
}

STATE_DIRECTORY="$TEST_ROOT/var/lib/theatropolis"
AGENT_STATE_DIRECTORY="$STATE_DIRECTORY/agent"
TOKEN_PATH="$AGENT_STATE_DIRECTORY/enrollment.token"
OLD_TOKEN_LINK="$TEST_DIRECTORY/old-enrollment-token"
EXPECTED_TOKEN_FILE="$TEST_DIRECTORY/expected-enrollment-token"

# Begin with an ordinary token file and keep a hard link to its old inode. An
# atomic rename must replace the pathname rather than truncate that inode.
printf '%s\n' "$STALE_TOKEN" >"$TOKEN_PATH"
ln "$TOKEN_PATH" "$OLD_TOKEN_LINK"
printf '%s\n' "$VALID_TOKEN" >"$EXPECTED_TOKEN_FILE"

set +e
NORMAL_OUTPUT="$(run_installer 2>&1)"
NORMAL_STATUS="$?"
set -e

[ "$NORMAL_STATUS" -eq 0 ] ||
	fail "normal token installation failed (status $NORMAL_STATUS): $NORMAL_OUTPUT"
AGENT_UNIT="$TEST_ROOT/etc/systemd/system/theatropolis-agent.service"
[ -f "$AGENT_UNIT" ] ||
	fail "agent systemd unit was not generated"
UPDATE_SERVICE="$TEST_ROOT/etc/systemd/system/theatropolis-agent-update.service"
UPDATE_PATH="$TEST_ROOT/etc/systemd/system/theatropolis-agent-update.path"
SING_BOX_UPDATE_SERVICE="$TEST_ROOT/etc/systemd/system/theatropolis-sing-box-update.service"
SING_BOX_UPDATE_PATH="$TEST_ROOT/etc/systemd/system/theatropolis-sing-box-update.path"
if [ ! -f "$UPDATE_SERVICE" ] || [ ! -f "$UPDATE_PATH" ]; then
	fail "root update helper units were not generated"
fi
if [ ! -f "$SING_BOX_UPDATE_SERVICE" ] ||
	[ ! -f "$SING_BOX_UPDATE_PATH" ]; then
	fail "root sing-box update helper units were not generated"
fi
grep -Fq 'theatropolis-update-helper apply-theatropolis --component=agent' "$UPDATE_SERVICE" ||
	fail "update unit does not invoke the dedicated root helper"
grep -Fqx "PathExists=$AGENT_STATE_DIRECTORY/update-request.json" "$UPDATE_PATH" ||
	fail "update watcher does not monitor the agent request file"
grep -Fq 'theatropolis-update-helper apply-sing-box ' "$SING_BOX_UPDATE_SERVICE" ||
	fail "sing-box update unit does not invoke the dedicated root helper"
grep -Fqx 'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK' "$SING_BOX_UPDATE_SERVICE" ||
	fail "sing-box candidate sandbox does not match the Agent network-monitoring policy"
grep -Fqx 'CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID' "$SING_BOX_UPDATE_SERVICE" ||
	fail "sing-box update helper does not bound its privilege-drop capabilities"
grep -Fqx 'AmbientCapabilities=CAP_SETGID CAP_SETUID' "$SING_BOX_UPDATE_SERVICE" ||
	fail "sing-box update helper cannot retain the capabilities required to drop privileges"
[ -x "$TEST_ROOT/usr/local/libexec/theatropolis/theatropolis-update-helper" ] ||
	fail "dedicated update helper was not installed"
grep -Fqx "PathExists=$AGENT_STATE_DIRECTORY/sing-box-update-request.json" "$SING_BOX_UPDATE_PATH" ||
	fail "sing-box update watcher does not monitor its request file"
if grep -Fq -- '--agent-id' "$AGENT_UNIT"; then
	fail "agent systemd unit still requires a master-assigned agent ID"
fi
grep -Fqx 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' "$AGENT_UNIT" ||
	fail "agent unit does not bound low-port access to CAP_NET_BIND_SERVICE"
grep -Fqx 'AmbientCapabilities=CAP_NET_BIND_SERVICE' "$AGENT_UNIT" ||
	fail "agent unit does not grant sing-box low-port binding capability"
grep -Fqx "Environment=LD_LIBRARY_PATH=$TEST_ROOT/usr/local/lib/theatropolis/sing-box" "$AGENT_UNIT" ||
	fail "agent unit does not configure the trusted sing-box library path"
grep -Fqx "Environment=HOME=$AGENT_STATE_DIRECTORY" "$AGENT_UNIT" ||
	fail "agent unit does not give ACME a writable home"
grep -Fqx "Environment=XDG_DATA_HOME=$AGENT_STATE_DIRECTORY/data" "$AGENT_UNIT" ||
	fail "agent unit does not give ACME a writable data directory"
grep -Fq -- "--master-dial-address=\${THEATROPOLIS_MASTER_DIAL}" "$AGENT_UNIT" ||
	fail "agent unit does not pass the installer-managed local dial address"
AGENT_ENV="$TEST_ROOT/etc/theatropolis/agent.env"
grep -Fqx 'THEATROPOLIS_MASTER_DIAL=' "$AGENT_ENV" ||
	fail "ordinary remote Agent unexpectedly received a local Master dial override"
[ -x "$TEST_ROOT/usr/local/bin/sing-box" ] ||
	fail "resolved sing-box binary was not installed"
[ -f "$TEST_ROOT/usr/local/lib/theatropolis/sing-box/libcronet.so" ] ||
	fail "resolved sing-box libcronet library was not installed"
[ "$(stat -c '%a' "$TEST_ROOT/usr/local/bin/sing-box")" = "755" ] ||
	fail "installed sing-box binary does not have mode 0755"
[ "$(stat -c '%a' "$TEST_ROOT/usr/local/lib/theatropolis/sing-box/libcronet.so")" = "644" ] ||
	fail "installed sing-box libcronet library does not have mode 0644"
if [ ! -f "$TOKEN_PATH" ] || [ -L "$TOKEN_PATH" ]; then
	fail "normal token installation did not leave a regular file"
fi
cmp -s "$EXPECTED_TOKEN_FILE" "$TOKEN_PATH" ||
	fail "installed token does not exactly match the enrollment token"
printf '%s\n' "$STALE_TOKEN" | cmp -s - "$OLD_TOKEN_LINK" ||
	fail "installer modified the old token inode instead of replacing it"
[ "$(stat -c '%i' "$TOKEN_PATH")" != "$(stat -c '%i' "$OLD_TOKEN_LINK")" ] ||
	fail "installer did not atomically replace the old token inode"

[ "$(wc -l <"$MV_LOG")" -eq 4 ] ||
	fail "token installation did not perform exactly one logged replacement"
STAGED_TOKEN="$(sed -n '1p' "$MV_LOG")"
LOGGED_TARGET="$(sed -n '2p' "$MV_LOG")"
LOGGED_MODE="$(sed -n '3p' "$MV_LOG")"
LOGGED_VALUE="$(sed -n '4p' "$MV_LOG")"
case "$STAGED_TOKEN" in
"$STATE_DIRECTORY"/.enrollment-token.*) ;;
*) fail "token was not staged inside the root-controlled state directory" ;;
esac
[ "$LOGGED_TARGET" = "$TOKEN_PATH" ] ||
	fail "atomic replacement targeted an unexpected path"
case "$TEST_PLATFORM" in
MINGW* | MSYS*)
	# Git Bash maps POSIX group permissions onto Windows ACLs and can report
	# the mktemp mode even after a successful chmod. Linux CI checks exactly.
	;;
*)
	[ "$LOGGED_MODE" = "640" ] ||
		fail "staged token did not have mode 0640 before replacement"
	;;
esac
[ "$LOGGED_VALUE" = "$VALID_TOKEN" ] ||
	fail "staged token did not contain the exact enrollment token"
grep -Fqx "root:theatropolis-agent $STAGED_TOKEN" "$CHOWN_LOG" ||
	fail "staged token was not assigned root ownership before replacement"
if find "$STATE_DIRECTORY" -maxdepth 1 \
	-name '.enrollment-token.*' -print | grep -q .; then
	fail "successful installation left a staged token behind"
fi

# Once an Agent identity exists, reinstalling Theatropolis must not download,
# validate, or replace sing-box. Its independently managed release channel may
# be temporarily unavailable or intentionally newer than the bootstrap pin.
printf '%s\n' 'existing agent identity' >"$AGENT_STATE_DIRECTORY/identity.pem"
cat >"$TEST_ROOT/etc/systemd/system/theatropolis-master.service" <<EOF
[Service]
Environment=THEATROPOLIS_PUBLIC_ADDRESS=master.example.com:8443
EOF
SING_BOX_BEFORE_REINSTALL="$TEST_DIRECTORY/sing-box-before-reinstall"
cp "$TEST_ROOT/usr/local/bin/sing-box" "$SING_BOX_BEFORE_REINSTALL"
set +e
REINSTALL_OUTPUT="$(run_installer yes 2>&1)"
REINSTALL_STATUS="$?"
set -e
[ "$REINSTALL_STATUS" -eq 0 ] ||
	fail "existing Agent reinstall was blocked by sing-box (status $REINSTALL_STATUS): $REINSTALL_OUTPUT"
cmp -s "$SING_BOX_BEFORE_REINSTALL" "$TEST_ROOT/usr/local/bin/sing-box" ||
	fail "existing Agent reinstall replaced independently managed sing-box"
grep -Fqx 'THEATROPOLIS_MASTER_DIAL=127.0.0.1:8443' "$AGENT_ENV" ||
	fail "Agent did not detect its matching co-located Master"

# Existing Master units from before the explicit address metadata also carry
# the canonical address in the installer's fixed ExecStart line.
cat >"$TEST_ROOT/etc/systemd/system/theatropolis-master.service" <<EOF
[Service]
ExecStart=$TEST_ROOT/usr/local/bin/theatropolis-master serve --public-url https://master.example.com:8443 --web-auth-file $TEST_ROOT/var/lib/theatropolis/master/web-auth.json
EOF
set +e
LEGACY_LOCAL_OUTPUT="$(run_installer yes 2>&1)"
LEGACY_LOCAL_STATUS="$?"
set -e
[ "$LEGACY_LOCAL_STATUS" -eq 0 ] ||
	fail "legacy local Master detection failed (status $LEGACY_LOCAL_STATUS): $LEGACY_LOCAL_OUTPUT"
grep -Fqx 'THEATROPOLIS_MASTER_DIAL=127.0.0.1:8443' "$AGENT_ENV" ||
	fail "Agent did not detect an existing pre-metadata local Master unit"

cat >"$TEST_ROOT/etc/systemd/system/theatropolis-master.service" <<EOF
[Service]
Environment=THEATROPOLIS_PUBLIC_ADDRESS=other.example.com:8443
EOF
set +e
REMOTE_WITH_LOCAL_OUTPUT="$(run_installer yes 2>&1)"
REMOTE_WITH_LOCAL_STATUS="$?"
set -e
[ "$REMOTE_WITH_LOCAL_STATUS" -eq 0 ] ||
	fail "different local Master reinstall failed (status $REMOTE_WITH_LOCAL_STATUS): $REMOTE_WITH_LOCAL_OUTPUT"
grep -Fqx 'THEATROPOLIS_MASTER_DIAL=' "$AGENT_ENV" ||
	fail "Agent incorrectly redirected a different Master address to loopback"
rm -f -- "$AGENT_STATE_DIRECTORY/identity.pem"

set +e
SING_BOX_SIGNATURE_OUTPUT="$(run_installer yes 2>&1)"
SING_BOX_SIGNATURE_STATUS="$?"
set -e
[ "$SING_BOX_SIGNATURE_STATUS" -ne 0 ] ||
	fail "installer unexpectedly accepted an invalid sing-box signature"
printf '%s' "$SING_BOX_SIGNATURE_OUTPUT" |
	grep -Fq 'sing-box checksum manifest signature verification failed' ||
	fail "sing-box signature rejection did not provide a useful diagnostic"

# Git Bash cannot reliably create a native Windows symlink without optional
# host privileges. The Linux CI run below remains authoritative for this case.
case "$TEST_PLATFORM" in
MINGW* | MSYS*) exit 0 ;;
esac

# The resolved V2Ray-API archive is rejected before extraction if any expected
# member is a symbolic link, even when its path and checksum otherwise pass.
rm -f -- "$SING_BOX_STAGE/$SING_BOX_PACKAGE/libcronet.so"
ln -s /etc/shadow "$SING_BOX_STAGE/$SING_BOX_PACKAGE/libcronet.so"
tar -czf "$RELEASE_DIRECTORY/$SING_BOX_ARCHIVE" \
	-C "$SING_BOX_STAGE" \
	"$SING_BOX_PACKAGE"

set +e
SING_BOX_SYMLINK_OUTPUT="$(run_installer 2>&1)"
SING_BOX_SYMLINK_STATUS="$?"
set -e

[ "$SING_BOX_SYMLINK_STATUS" -ne 0 ] ||
	fail "installer unexpectedly accepted a symlink in the sing-box archive"
printf '%s' "$SING_BOX_SYMLINK_OUTPUT" |
	grep -Eiq '(unsafe entry type|sing-box archive)' ||
	fail "sing-box archive symlink rejection did not provide a useful diagnostic"

# Restore the valid archive fixture before testing an unrelated local-path
# rejection. Otherwise prepare_sing_box correctly rejects the malicious
# archive again before write_enrollment_token can inspect TOKEN_PATH.
rm -f -- "$SING_BOX_STAGE/$SING_BOX_PACKAGE/libcronet.so"
printf '%s\n' 'mock cronet library' \
	>"$SING_BOX_STAGE/$SING_BOX_PACKAGE/libcronet.so"
tar -czf "$RELEASE_DIRECTORY/$SING_BOX_ARCHIVE" \
	-C "$SING_BOX_STAGE" \
	"$SING_BOX_PACKAGE"

# A pre-existing symlink must be rejected without touching its referent or
# reaching the atomic move.
SENTINEL="$TEST_DIRECTORY/symlink-referent"
printf '%s\n' 'do-not-overwrite' >"$SENTINEL"
rm -f -- "$TOKEN_PATH" "$MV_LOG" "$CHOWN_LOG"
ln -s "$SENTINEL" "$TOKEN_PATH"

set +e
SYMLINK_OUTPUT="$(run_installer 2>&1)"
SYMLINK_STATUS="$?"
set -e

[ "$SYMLINK_STATUS" -ne 0 ] ||
	fail "installer unexpectedly accepted a pre-existing token symlink"
[ -L "$TOKEN_PATH" ] ||
	fail "installer replaced or removed the pre-existing token symlink"
[ "$(readlink "$TOKEN_PATH")" = "$SENTINEL" ] ||
	fail "installer changed the pre-existing token symlink"
printf '%s\n' 'do-not-overwrite' | cmp -s - "$SENTINEL" ||
	fail "installer followed the token symlink and overwrote its referent"
[ ! -s "$MV_LOG" ] ||
	fail "installer attempted an atomic move after detecting the symlink"
printf '%s' "$SYMLINK_OUTPUT" |
	grep -Eiq '(enrollment token path|not a regular file|symlink)' ||
	fail "symlink rejection did not provide a useful diagnostic"
if find "$STATE_DIRECTORY" -maxdepth 1 \
	-name '.enrollment-token.*' -print | grep -q .; then
	fail "rejected symlink installation left a staged token behind"
fi
