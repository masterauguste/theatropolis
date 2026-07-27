#!/bin/sh

set -eu

INSTALLER_SOURCE="${1:-./install.sh}"
TEST_DIRECTORY="$(mktemp -d)"
INSTALLER="$TEST_DIRECTORY/install.sh"

cleanup() {
	rm -rf -- "$TEST_DIRECTORY"
}

trap cleanup EXIT HUP INT TERM

mkdir "$TEST_DIRECTORY/bin"
sed \
	"s#INSTALL_LOCK_FILE=\"/run/theatropolis-installer.lock\"#INSTALL_LOCK_FILE=\"$TEST_DIRECTORY/installer.lock\"#" \
	"$INSTALLER_SOURCE" >"$INSTALLER"
chmod +x "$INSTALLER"
# This text is written verbatim into the mock executable.
# shellcheck disable=SC2016
printf '%s\n' \
	'#!/bin/sh' \
	'if [ "${1:-}" = "-u" ]; then' \
	'	printf "0\n"' \
	'	exit 0' \
	'fi' \
	'exec /usr/bin/id "$@"' \
	>"$TEST_DIRECTORY/bin/id"
printf '%s\n' \
	'#!/bin/sh' \
	'exit 42' \
	>"$TEST_DIRECTORY/bin/apt-get"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$TEST_DIRECTORY/bin/flock"
chmod +x \
	"$TEST_DIRECTORY/bin/id" \
	"$TEST_DIRECTORY/bin/apt-get" \
	"$TEST_DIRECTORY/bin/flock"

run_case() {
	description="$1"
	shift

	set +e
	output="$(
		PATH="$TEST_DIRECTORY/bin:$PATH" sh "$INSTALLER" agent \
			--master master.example.com:8443 \
			--agent-id edge-1 \
			--token AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
			"$@" 2>&1
	)"
	status="$?"
	set -e

	if [ "$status" -ne 42 ]; then
		printf 'case %s: expected mocked apt-get status 42, got %s\n%s\n' \
			"$description" "$status" "$output" >&2
		exit 1
	fi
}

# /etc/os-release defines VERSION on Debian and Ubuntu. Both cases must retain
# the installer release selection after that file is sourced.
run_case default-latest
run_case explicit-tag --version v0.0.1
