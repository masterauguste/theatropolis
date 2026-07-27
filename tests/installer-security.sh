#!/bin/sh

set -eu

INSTALLER="${1:-./install.sh}"
TEST_DIRECTORY="$(mktemp -d)"
VALID_TOKEN="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

cleanup() {
	rm -rf -- "$TEST_DIRECTORY"
}

fail() {
	printf 'installer security test: %s\n' "$*" >&2
	exit 1
}

trap cleanup EXIT HUP INT TERM

command -v script >/dev/null 2>&1 ||
	fail "the util-linux script command is required"

PROMPT_BIN="$TEST_DIRECTORY/prompt-bin"
PROMPT_APT_LOG="$TEST_DIRECTORY/prompt-apt.log"
PROMPT_ARGV_LOG="$TEST_DIRECTORY/prompt-argv.log"
mkdir "$PROMPT_BIN"

# Report root only for the installer's privilege check.
# shellcheck disable=SC2016
printf '%s\n' \
	'#!/bin/sh' \
	'if [ "${1:-}" = "-u" ]; then' \
	'	printf "0\n"' \
	'	exit 0' \
	'fi' \
	'exec /usr/bin/id "$@"' \
	>"$PROMPT_BIN/id"
# Stop immediately after argument validation and record the parent installer
# command line. The enrollment token must not appear there.
# shellcheck disable=SC2016
printf '%s\n' \
	'#!/bin/sh' \
	'printf "%s\n" "$*" >>"$TEST_APT_LOG"' \
	'if [ -r "/proc/$PPID/cmdline" ]; then' \
	'	tr "\000" " " <"/proc/$PPID/cmdline" >>"$TEST_ARGV_LOG"' \
	'	printf "\n" >>"$TEST_ARGV_LOG"' \
	'fi' \
	'exit 42' \
	>"$PROMPT_BIN/apt-get"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$PROMPT_BIN/systemctl"
chmod +x "$PROMPT_BIN/id" "$PROMPT_BIN/apt-get" "$PROMPT_BIN/systemctl"

PROMPT_PATH="$PROMPT_BIN:$PATH"
set +e
# INSTALLER_UNDER_TEST is intentionally expanded by script's child shell.
# shellcheck disable=SC2016
PROMPT_OUTPUT="$(
	{
		# Wait until the child has disabled terminal echo and displayed its
		# prompt before sending the credential through the pseudoterminal.
		sleep 1
		printf '%s\n' "$VALID_TOKEN"
	} |
		PATH="$PROMPT_PATH" \
			TEST_APT_LOG="$PROMPT_APT_LOG" \
			TEST_ARGV_LOG="$PROMPT_ARGV_LOG" \
			INSTALLER_UNDER_TEST="$INSTALLER" \
			script -q -e -c \
			'sh "$INSTALLER_UNDER_TEST" agent --master master.example.com:8443 --agent-id edge-1' \
			/dev/null 2>&1
)"
PROMPT_STATUS="$?"
set -e

[ "$PROMPT_STATUS" -eq 42 ] ||
	fail "interactive prompt did not reach the mocked package step (status $PROMPT_STATUS): $PROMPT_OUTPUT"
printf '%s' "$PROMPT_OUTPUT" | grep -Eiq 'enrollment[ -]token' ||
	fail "interactive installation did not display an enrollment-token prompt"
if printf '%s' "$PROMPT_OUTPUT" | grep -Fq "$VALID_TOKEN"; then
	fail "interactive terminal echoed the enrollment token"
fi
[ -s "$PROMPT_APT_LOG" ] ||
	fail "interactive installation did not continue after reading the token"
if [ -s "$PROMPT_ARGV_LOG" ] &&
	grep -Fq "$VALID_TOKEN" "$PROMPT_ARGV_LOG"; then
	fail "installer process arguments exposed the enrollment token"
fi

# The prompted value must flow through the same strict token validation. This
# also prevents an implementation from prompting but then continuing with an
# empty or discarded credential.
INVALID_TOKEN="invalid_token_marker"
rm -f -- "$PROMPT_APT_LOG" "$PROMPT_ARGV_LOG"
set +e
# INSTALLER_UNDER_TEST is intentionally expanded by script's child shell.
# shellcheck disable=SC2016
INVALID_OUTPUT="$(
	{
		sleep 1
		printf '%s\n' "$INVALID_TOKEN"
	} |
		PATH="$PROMPT_PATH" \
			TEST_APT_LOG="$PROMPT_APT_LOG" \
			TEST_ARGV_LOG="$PROMPT_ARGV_LOG" \
			INSTALLER_UNDER_TEST="$INSTALLER" \
			script -q -e -c \
			'sh "$INSTALLER_UNDER_TEST" agent --master master.example.com:8443 --agent-id edge-1' \
			/dev/null 2>&1
)"
INVALID_STATUS="$?"
set -e

[ "$INVALID_STATUS" -ne 0 ] ||
	fail "installer unexpectedly accepted an invalid prompted token"
[ "$INVALID_STATUS" -ne 42 ] ||
	fail "invalid prompted token reached package installation"
[ ! -s "$PROMPT_APT_LOG" ] ||
	fail "invalid prompted token performed package work"
if printf '%s' "$INVALID_OUTPUT" | grep -Fq "$INVALID_TOKEN"; then
	fail "terminal echoed an invalid enrollment token"
fi
printf '%s' "$INVALID_OUTPUT" | grep -Eiq '(invalid|32-byte|base64url|enrollment[ -]token)' ||
	fail "invalid prompted token did not produce a useful diagnostic"

# Without a controlling terminal the installer must fail closed before doing
# package or network work; it must not silently accept an empty credential.
rm -f -- "$PROMPT_APT_LOG" "$PROMPT_ARGV_LOG"
set +e
NONINTERACTIVE_OUTPUT="$(
	PATH="$PROMPT_PATH" \
		TEST_APT_LOG="$PROMPT_APT_LOG" \
		TEST_ARGV_LOG="$PROMPT_ARGV_LOG" \
		sh "$INSTALLER" agent \
		--master master.example.com:8443 \
		--agent-id edge-1 </dev/null 2>&1
)"
NONINTERACTIVE_STATUS="$?"
set -e

[ "$NONINTERACTIVE_STATUS" -ne 0 ] ||
	fail "agent installation without a terminal unexpectedly succeeded"
[ "$NONINTERACTIVE_STATUS" -ne 42 ] ||
	fail "agent installation without a terminal reached package installation"
[ ! -s "$PROMPT_APT_LOG" ] ||
	fail "agent installation without a terminal performed package work"
printf '%s' "$NONINTERACTIVE_OUTPUT" |
	grep -Eiq '(terminal|tty|enrollment[ -]token)' ||
	fail "noninteractive failure did not explain how enrollment input is obtained"

RELEASE_DIRECTORY="$TEST_DIRECTORY/release"
RELEASE_STAGE="$TEST_DIRECTORY/release-stage"
COMPAT_BIN="$TEST_DIRECTORY/compat-bin"
MASTER_INVOCATIONS="$TEST_DIRECTORY/master-invocations.log"
INSTALL_INVOCATIONS="$TEST_DIRECTORY/install-invocations.log"
mkdir "$RELEASE_DIRECTORY" "$RELEASE_STAGE" "$COMPAT_BIN"

# Model the published v0.0.1 master: it can report its version but does not
# implement the init-web-admin command required by the web-enabled installer.
# shellcheck disable=SC2016
printf '%s\n' \
	'#!/bin/sh' \
	'printf "%s\n" "$*" >>"$TEST_MASTER_INVOCATIONS"' \
	'case "${1:-}" in' \
	'version)' \
	'	printf "v0.0.1 (commit test, built test)\n"' \
	'	exit 0' \
	';;' \
	'init-web-admin)' \
	'	printf "unknown command %s\n" "$1" >&2' \
	'	exit 64' \
	';;' \
	'*)' \
	'	exit 64' \
	';;' \
	'esac' \
	>"$RELEASE_STAGE/theatropolis-master"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$RELEASE_STAGE/theatropolis-agent"
chmod +x \
	"$RELEASE_STAGE/theatropolis-master" \
	"$RELEASE_STAGE/theatropolis-agent"
tar -czf "$RELEASE_DIRECTORY/theatropolis_linux_amd64.tar.gz" \
	-C "$RELEASE_STAGE" \
	theatropolis-master \
	theatropolis-agent
(
	cd "$RELEASE_DIRECTORY"
	sha256sum theatropolis_linux_amd64.tar.gz >checksums.txt
)

# shellcheck disable=SC2016
printf '%s\n' \
	'#!/bin/sh' \
	'if [ "${1:-}" = "-u" ]; then' \
	'	printf "0\n"' \
	'	exit 0' \
	'fi' \
	'exec /usr/bin/id "$@"' \
	>"$COMPAT_BIN/id"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$COMPAT_BIN/apt-get"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$COMPAT_BIN/systemctl"
printf '%s\n' '#!/bin/sh' 'printf "x86_64\n"' >"$COMPAT_BIN/uname"
# shellcheck disable=SC2016
printf '%s\n' \
	'#!/bin/sh' \
	'OUTPUT=""' \
	'SOURCE=""' \
	'while [ "$#" -gt 0 ]; do' \
	'	case "$1" in' \
	'	-o)' \
	'		OUTPUT="$2"' \
	'		shift 2' \
	'		;;' \
	'	*)' \
	'		SOURCE="$1"' \
	'		shift' \
	'		;;' \
	'	esac' \
	'done' \
	'case "$SOURCE" in' \
	'*/theatropolis_linux_amd64.tar.gz)' \
	'	cp "$TEST_RELEASE_DIRECTORY/theatropolis_linux_amd64.tar.gz" "$OUTPUT"' \
	'	;;' \
	'*/checksums.txt)' \
	'	cp "$TEST_RELEASE_DIRECTORY/checksums.txt" "$OUTPUT"' \
	'	;;' \
	'*)' \
	'	printf "unexpected mock curl source: %s\n" "$SOURCE" >&2' \
	'	exit 65' \
	'	;;' \
	'esac' \
	>"$COMPAT_BIN/curl"
# Any attempt to install the incompatible candidate is a test failure.
# shellcheck disable=SC2016
printf '%s\n' \
	'#!/bin/sh' \
	'printf "%s\n" "$*" >>"$TEST_INSTALL_INVOCATIONS"' \
	'exit 91' \
	>"$COMPAT_BIN/install"
chmod +x "$COMPAT_BIN"/*

set +e
COMPAT_OUTPUT="$(
	PATH="$COMPAT_BIN:$PATH" \
		TEST_RELEASE_DIRECTORY="$RELEASE_DIRECTORY" \
		TEST_MASTER_INVOCATIONS="$MASTER_INVOCATIONS" \
		TEST_INSTALL_INVOCATIONS="$INSTALL_INVOCATIONS" \
		sh "$INSTALLER" master \
		--domain master.example.com \
		--version v0.0.1 2>&1
)"
COMPAT_STATUS="$?"
set -e

[ "$COMPAT_STATUS" -ne 0 ] ||
	fail "installer unexpectedly accepted the v0.0.1 master"
[ ! -s "$INSTALL_INVOCATIONS" ] ||
	fail "installer attempted to install the incompatible v0.0.1 master"
[ -s "$MASTER_INVOCATIONS" ] ||
	fail "installer did not probe the candidate master for compatibility"
grep -Eq '(version|init-web-admin)' "$MASTER_INVOCATIONS" ||
	fail "installer compatibility probe did not inspect the required master capability"
printf '%s' "$COMPAT_OUTPUT" |
	grep -Eiq '(incompat|does not support|requires|newer|too old|minimum|web interface|init-web-admin)' ||
	fail "v0.0.1 rejection did not provide a compatibility diagnostic"
