#!/bin/sh
# Downloads have their own lock; only publication takes the lifecycle lock.
APP=/usr/share/passwall
mkdir -p /var/lock /var/run/passwall || exit 1
exec 8>/var/lock/passwall-rule-update.lock
case "$1" in
	status)
		if flock -n 8; then
			lua "$APP/rule_update.lua" status-idle
		else
			lua "$APP/rule_update.lua" status
		fi
		exit $?
		;;
	start|run) ;;
	*) exit 2 ;;
esac
if ! flock -n 8; then
	lua "$APP/rule_update.lua" busy
	exit 75
fi
: >/var/run/passwall/rule-update.error || exit 1
if [ "$1" = start ]; then
	lua "$APP/rule_update.lua" prepare "$2" >/dev/null || exit 1
else
	lua "$APP/rule_update.lua" prepare >/dev/null || exit 1
fi
export PASSWALL_RULE_UPDATE_LOCKED=1
run_worker() {
	lua "$APP/rule_update.lua" "$@" 2>/var/run/passwall/rule-update.error

	local result=$?

	if [ "$result" = 0 ]; then
		(
			flock -x 9 || exit 1

			for backup in "$APP"/rules/.update.??????; do
				[ -d "$backup" ] || continue
				rm -rf -- "$backup" || exit 1
			done
		) 9>/var/lock/passwall.lock ||
			logger -t passwall "历史规则备份清理失败"
	else
		lua "$APP/rule_update.lua" failed >/dev/null
	fi

	return "$result"
}
if [ "$1" = start ]; then
	# Both the worker and curl retain fd 8 until the task ends.
	run_worker "$2" </dev/null >/dev/null 2>&1 &
	lua "$APP/rule_update.lua" status

elif [ -n "$2" ]; then
	run_worker "$2"
else
	run_worker
fi
