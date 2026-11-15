#!/bin/sh

APP_PATH=/usr/share/passwall
STATE_PATH=/var/run/passwall
SCRIPT_PATH=/tmp/etc/passwall/script_func
exec 9>/var/lock/passwall.lock

while [ -f "$STATE_PATH/running" ]; do
	sleep 58
	flock -x 9 || exit 1
	if [ ! -f "$STATE_PATH/running" ]; then
		flock -u 9
		break
	fi
	for file in "$SCRIPT_PATH"/*; do
		[ -f "$file" ] || continue
		cmd=$(cat "$file")
		check=${cmd%%>*}
		case "$check" in *dns2socks*) check=$(echo "$check" | sed 's/:/ /g') ;; esac
		if ! pgrep -f "$check" >/dev/null; then
			eval "$cmd 9>&- 2>&1 &"
			echo $! >> "$STATE_PATH/pids"
		fi
	done
	flock -u 9
done
