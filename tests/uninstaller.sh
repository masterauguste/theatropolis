#!/bin/sh

set -eu

PROJECT_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
TEST_DIRECTORY="$(mktemp -d)"
trap 'rm -rf -- "$TEST_DIRECTORY"' EXIT HUP INT TERM
MOCK_BIN="$TEST_DIRECTORY/bin"
mkdir -p "$MOCK_BIN"

fail() {
	printf 'uninstaller test: %s\n' "$*" >&2
	exit 1
}

cat >"$MOCK_BIN/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-u" ]; then
	printf '0\n'
	exit 0
fi
[ -n "${UNINSTALL_TEST_ROOT:-}" ] || exit 1
[ -f "$UNINSTALL_TEST_ROOT/users/${1:-}" ]
EOF

cat >"$MOCK_BIN/userdel" <<'EOF'
#!/bin/sh
printf 'userdel %s\n' "$1" >>"$UNINSTALL_TEST_ROOT/accounts.log"
rm -f -- "$UNINSTALL_TEST_ROOT/users/$1"
EOF

cat >"$MOCK_BIN/getent" <<'EOF'
#!/bin/sh
[ "${1:-}" = "group" ] || exit 1
[ -f "$UNINSTALL_TEST_ROOT/groups/${2:-}" ]
EOF

cat >"$MOCK_BIN/groupdel" <<'EOF'
#!/bin/sh
printf 'groupdel %s\n' "$1" >>"$UNINSTALL_TEST_ROOT/accounts.log"
rm -f -- "$UNINSTALL_TEST_ROOT/groups/$1"
EOF

cat >"$MOCK_BIN/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$UNINSTALL_TEST_ROOT/systemctl.log"
if [ "${1:-}" = "is-active" ] && [ "${2:-}" = "--quiet" ] && [ "${3:-}" = "caddy" ]; then
	[ -f "$UNINSTALL_TEST_ROOT/caddy-active" ]
	exit
fi
if [ "${1:-}" = "is-active" ] && [ "${3:-}" = "theatropolis-agent" ]; then
	[ ! -f "$UNINSTALL_TEST_ROOT/agent-inactive" ]
	exit
fi
if [ "${1:-}" = "reload" ] && [ "${2:-}" = "caddy" ] &&
	[ -f "$UNINSTALL_TEST_ROOT/caddy-reload-fails" ]; then
	exit 1
fi
exit 0
EOF

cat >"$MOCK_BIN/caddy" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$UNINSTALL_TEST_ROOT/caddy.log"
[ ! -f "$UNINSTALL_TEST_ROOT/caddy-validation-fails" ]
EOF

cat >"$MOCK_BIN/flock" <<'EOF'
#!/bin/sh
exit 0
EOF

chmod 0755 "$MOCK_BIN"/*

prepare_case() {
	CASE_NAME="$1"
	CASE_ROOT="$TEST_DIRECTORY/$CASE_NAME"
	mkdir -p \
		"$CASE_ROOT/etc/caddy/conf.d" \
		"$CASE_ROOT/etc/systemd/system" \
		"$CASE_ROOT/etc/theatropolis" \
		"$CASE_ROOT/run" \
		"$CASE_ROOT/usr/local/bin" \
		"$CASE_ROOT/usr/local/lib/theatropolis/sing-box" \
		"$CASE_ROOT/usr/local/libexec/theatropolis" \
		"$CASE_ROOT/var/lib/theatropolis/master" \
		"$CASE_ROOT/var/lib/theatropolis/agent" \
		"$CASE_ROOT/users" \
		"$CASE_ROOT/groups"

	for FILE in \
		theatropolis-master \
		theatropolis-agent \
		sing-box; do
		printf '%s\n' "$FILE" >"$CASE_ROOT/usr/local/bin/$FILE"
	done
	printf '%s\n' 'helper' >"$CASE_ROOT/usr/local/libexec/theatropolis/theatropolis-update-helper"
	printf '%s\n' 'cronet' >"$CASE_ROOT/usr/local/lib/theatropolis/sing-box/libcronet.so"
	printf '%s\n' 'master-data' >"$CASE_ROOT/var/lib/theatropolis/master/state.json"
	printf '%s\n' 'agent-data' >"$CASE_ROOT/var/lib/theatropolis/agent/identity.pem"
	printf '%s\n' \
		'THEATROPOLIS_MASTER=example.test:443' \
		'THEATROPOLIS_MASTER_DIAL=127.0.0.1:443' \
		>"$CASE_ROOT/etc/theatropolis/agent.env"
	printf '%s\n' 'ca' >"$CASE_ROOT/etc/theatropolis/agent-ca.pem"
	printf '%s\n' 'legacy-auth' >"$CASE_ROOT/etc/theatropolis/web-auth.json"
	printf '%s\n' 'import conf.d/*.caddy' >"$CASE_ROOT/etc/caddy/Caddyfile"
	printf '%s\n' 'https://example.test {}' >"$CASE_ROOT/etc/caddy/conf.d/theatropolis.caddy"
	printf '%s\n' ':80 { reverse_proxy /.well-known/acme-challenge/* 127.0.0.1:19091 }' \
		>"$CASE_ROOT/etc/caddy/conf.d/theatropolis-agent-acme.caddy"
	printf '%s\n' '19091' >"$CASE_ROOT/etc/theatropolis/acme-http01-master-relay"
	touch \
		"$CASE_ROOT/users/theatropolis-master" \
		"$CASE_ROOT/users/theatropolis-agent" \
		"$CASE_ROOT/groups/theatropolis-master" \
		"$CASE_ROOT/groups/theatropolis-agent"

	for UNIT in \
		theatropolis-master.service \
		theatropolis-master-update.service \
		theatropolis-master-update.path \
		theatropolis-agent.service \
		theatropolis-agent-update.service \
		theatropolis-agent-update.path \
		theatropolis-sing-box-update.service \
		theatropolis-sing-box-update.path; do
		: >"$CASE_ROOT/etc/systemd/system/$UNIT"
		mkdir -p "$CASE_ROOT/etc/systemd/system/$UNIT.d"
		: >"$CASE_ROOT/etc/systemd/system/$UNIT.d/override.conf"
	done
	printf '%s\n' \
		'[Service]' \
		'Environment=THEATROPOLIS_PUBLIC_ADDRESS=example.test:443' \
		>"$CASE_ROOT/etc/systemd/system/theatropolis-master.service"

	PATCHED_SCRIPT="$CASE_ROOT/uninstall.sh"
	sed \
		-e "s#INSTALL_DIRECTORY=\"/usr/local/bin\"#INSTALL_DIRECTORY=\"$CASE_ROOT/usr/local/bin\"#" \
		-e "s#UPDATE_HELPER_DIRECTORY=\"/usr/local/libexec/theatropolis\"#UPDATE_HELPER_DIRECTORY=\"$CASE_ROOT/usr/local/libexec/theatropolis\"#" \
		-e "s#SING_BOX_LIBRARY_DIRECTORY=\"/usr/local/lib/theatropolis/sing-box\"#SING_BOX_LIBRARY_DIRECTORY=\"$CASE_ROOT/usr/local/lib/theatropolis/sing-box\"#" \
		-e "s#STATE_DIRECTORY=\"/var/lib/theatropolis\"#STATE_DIRECTORY=\"$CASE_ROOT/var/lib/theatropolis\"#" \
		-e "s#CONFIG_DIRECTORY=\"/etc/theatropolis\"#CONFIG_DIRECTORY=\"$CASE_ROOT/etc/theatropolis\"#" \
		-e "s#SYSTEMD_DIRECTORY=\"/etc/systemd/system\"#SYSTEMD_DIRECTORY=\"$CASE_ROOT/etc/systemd/system\"#" \
		-e "s#CADDYFILE=\"/etc/caddy/Caddyfile\"#CADDYFILE=\"$CASE_ROOT/etc/caddy/Caddyfile\"#" \
		-e "s#CADDY_SNIPPET=\"/etc/caddy/conf.d/theatropolis.caddy\"#CADDY_SNIPPET=\"$CASE_ROOT/etc/caddy/conf.d/theatropolis.caddy\"#" \
		-e "s#CADDY_RELAY_SNIPPET=\"/etc/caddy/conf.d/theatropolis-agent-acme.caddy\"#CADDY_RELAY_SNIPPET=\"$CASE_ROOT/etc/caddy/conf.d/theatropolis-agent-acme.caddy\"#" \
		-e "s#INSTALL_LOCK_FILE=\"/run/theatropolis-installer.lock\"#INSTALL_LOCK_FILE=\"$CASE_ROOT/run/installer.lock\"#" \
		"$PROJECT_ROOT/uninstall.sh" >"$PATCHED_SCRIPT"
	chmod 0755 "$PATCHED_SCRIPT"
	: >"$CASE_ROOT/systemctl.log"
	: >"$CASE_ROOT/caddy.log"
	: >"$CASE_ROOT/accounts.log"
}

run_uninstaller() {
	UNINSTALL_TEST_ROOT="$CASE_ROOT" \
		PATH="$MOCK_BIN:$PATH" \
		sh "$PATCHED_SCRIPT" "$@"
}

prepare_case master_only
touch "$CASE_ROOT/caddy-active"
run_uninstaller master --yes
[ ! -e "$CASE_ROOT/usr/local/bin/theatropolis-master" ] || fail "master binary was retained"
[ ! -e "$CASE_ROOT/var/lib/theatropolis/master" ] || fail "master state was retained"
[ ! -e "$CASE_ROOT/etc/systemd/system/theatropolis-master.service" ] || fail "master address metadata unit was retained"
[ ! -e "$CASE_ROOT/etc/caddy/conf.d/theatropolis.caddy" ] || fail "Caddy entry was retained"
[ ! -e "$CASE_ROOT/etc/caddy/conf.d/theatropolis-agent-acme.caddy" ] || fail "Agent ACME relay entry was retained"
[ ! -e "$CASE_ROOT/etc/theatropolis/acme-http01-master-relay" ] || fail "Agent ACME relay marker was retained"
[ ! -e "$CASE_ROOT/users/theatropolis-master" ] || fail "master user was retained"
[ -e "$CASE_ROOT/usr/local/bin/theatropolis-agent" ] || fail "agent binary was removed with master"
[ -e "$CASE_ROOT/var/lib/theatropolis/agent/identity.pem" ] || fail "agent state was removed with master"
[ -e "$CASE_ROOT/usr/local/libexec/theatropolis/theatropolis-update-helper" ] || fail "shared helper was removed while agent remains"
[ -e "$CASE_ROOT/etc/theatropolis/agent.env" ] || fail "agent configuration was removed with master"
grep -Fqx 'validate --config '"$CASE_ROOT"'/etc/caddy/Caddyfile --adapter caddyfile' "$CASE_ROOT/caddy.log" ||
	fail "Caddy validation was not performed"
grep -Fqx 'reload caddy' "$CASE_ROOT/systemctl.log" || fail "Caddy was not reloaded"
grep -Fqx 'restart theatropolis-agent' "$CASE_ROOT/systemctl.log" ||
	fail "surviving Agent did not re-read its removed relay marker"

prepare_case master_with_inactive_agent
touch "$CASE_ROOT/agent-inactive"
run_uninstaller master --yes
if grep -Fqx 'restart theatropolis-agent' "$CASE_ROOT/systemctl.log"; then
	fail "removing Master started an inactive Agent"
fi

prepare_case child_keep_data
run_uninstaller child --yes --keep-data
[ ! -e "$CASE_ROOT/usr/local/bin/theatropolis-agent" ] || fail "agent binary was retained"
[ ! -e "$CASE_ROOT/usr/local/bin/sing-box" ] || fail "sing-box binary was retained"
[ ! -e "$CASE_ROOT/usr/local/lib/theatropolis/sing-box" ] || fail "sing-box library was retained"
[ ! -e "$CASE_ROOT/etc/theatropolis/agent.env" ] || fail "agent environment was retained"
[ ! -e "$CASE_ROOT/etc/systemd/system/theatropolis-agent.service" ] || fail "Agent local dial unit was retained"
[ -e "$CASE_ROOT/var/lib/theatropolis/agent/identity.pem" ] || fail "--keep-data removed agent state"
[ -e "$CASE_ROOT/users/theatropolis-agent" ] || fail "--keep-data removed the state-owning Agent account"
[ -e "$CASE_ROOT/usr/local/bin/theatropolis-master" ] || fail "master binary was removed with child"
[ -e "$CASE_ROOT/etc/caddy/conf.d/theatropolis.caddy" ] || fail "child uninstall changed Caddy"
[ ! -e "$CASE_ROOT/etc/caddy/conf.d/theatropolis-agent-acme.caddy" ] || fail "child uninstall retained Agent ACME relay"
[ ! -e "$CASE_ROOT/etc/theatropolis/acme-http01-master-relay" ] || fail "child uninstall retained Agent ACME relay marker"
[ -e "$CASE_ROOT/usr/local/libexec/theatropolis/theatropolis-update-helper" ] || fail "shared helper was removed while master remains"

prepare_case remove_all
touch "$CASE_ROOT/caddy-active"
run_uninstaller all --yes
for TARGET in \
	"$CASE_ROOT/usr/local/bin/theatropolis-master" \
	"$CASE_ROOT/usr/local/bin/theatropolis-agent" \
	"$CASE_ROOT/usr/local/bin/sing-box" \
	"$CASE_ROOT/usr/local/libexec/theatropolis/theatropolis-update-helper" \
	"$CASE_ROOT/var/lib/theatropolis/master" \
	"$CASE_ROOT/var/lib/theatropolis/agent" \
	"$CASE_ROOT/etc/systemd/system/theatropolis-master.service" \
	"$CASE_ROOT/etc/systemd/system/theatropolis-agent.service" \
	"$CASE_ROOT/etc/theatropolis/agent.env" \
	"$CASE_ROOT/etc/theatropolis/acme-http01-master-relay" \
	"$CASE_ROOT/etc/caddy/conf.d/theatropolis.caddy" \
	"$CASE_ROOT/etc/caddy/conf.d/theatropolis-agent-acme.caddy"; do
	[ ! -e "$TARGET" ] || fail "all uninstall retained $TARGET"
done
[ ! -e "$CASE_ROOT/users/theatropolis-master" ] || fail "all uninstall retained master user"
[ ! -e "$CASE_ROOT/users/theatropolis-agent" ] || fail "all uninstall retained agent user"
grep -Fqx 'daemon-reload' "$CASE_ROOT/systemctl.log" || fail "systemd was not reloaded"

prepare_case caddy_rollback
touch "$CASE_ROOT/caddy-active" "$CASE_ROOT/caddy-validation-fails"
if run_uninstaller master --yes >"$CASE_ROOT/stdout.log" 2>"$CASE_ROOT/stderr.log"; then
	fail "master uninstall succeeded after Caddy validation failed"
fi
[ -e "$CASE_ROOT/etc/caddy/conf.d/theatropolis.caddy" ] || fail "failed Caddy removal was not rolled back"
[ -e "$CASE_ROOT/etc/caddy/conf.d/theatropolis-agent-acme.caddy" ] || fail "failed Agent ACME relay removal was not rolled back"
[ -e "$CASE_ROOT/etc/theatropolis/acme-http01-master-relay" ] || fail "failed Agent ACME relay removal deleted its marker"
[ -e "$CASE_ROOT/usr/local/bin/theatropolis-master" ] || fail "master was removed despite Caddy rollback"
[ -e "$CASE_ROOT/var/lib/theatropolis/master/state.json" ] || fail "master state was removed despite Caddy rollback"
[ -e "$CASE_ROOT/users/theatropolis-master" ] || fail "master user was removed despite Caddy rollback"
grep -Eq 'the entr(y|ies) (was|were) restored' "$CASE_ROOT/stderr.log" || fail "Caddy rollback diagnostic was omitted"

prepare_case idempotent_agent
rm -f -- \
	"$CASE_ROOT/usr/local/bin/theatropolis-agent" \
	"$CASE_ROOT/usr/local/bin/sing-box" \
	"$CASE_ROOT/etc/systemd/system/theatropolis-agent.service"
rm -rf -- "$CASE_ROOT/var/lib/theatropolis/agent"
run_uninstaller agent --yes
[ -e "$CASE_ROOT/usr/local/bin/theatropolis-master" ] || fail "idempotent agent uninstall changed master"

printf '%s\n' 'uninstaller tests passed'
