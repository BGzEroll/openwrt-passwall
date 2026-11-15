#!/bin/sh

[ "$1" = url_test_node ] || exit 1
node=$2
[ "$(uci -q get "passwall.$node")" = nodes ] || exit 1
PASSWALL_TEST_DIR=$(mktemp -d /tmp/passwall-urltest.XXXXXX) || exit 1
export PASSWALL_TEST_DIR
export PASSWALL_TMP_PATH=$PASSWALL_TEST_DIR
cleanup() {
	if [ -f "$PASSWALL_TEST_DIR/pids" ]; then
		for pid in $(cat "$PASSWALL_TEST_DIR/pids"); do
			if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$PASSWALL_TEST_DIR"; then
				kill "$pid" 2>/dev/null || :
			fi
		done
	fi
	rm -rf "$PASSWALL_TEST_DIR"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
port=$(/usr/share/passwall/app.sh get_new_port 61080 tcp) || exit 1
/usr/share/passwall/app.sh run_socks "flag=url_test_$node" "node=$node" bind=127.0.0.1 "socks_port=$port" config_file=test.json || exit 1
sleep 1
curl --connect-timeout 3 --max-time 10 -o /dev/null -I -skL -w '%{http_code}:%{time_starttransfer}' \
	-x "socks5h://127.0.0.1:$port" https://www.google.com/generate_204
