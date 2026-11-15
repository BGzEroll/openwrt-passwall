local _M = {}

_M.xray = {
	path = "/usr/bin/xray",
	cmd_version = "version | awk '{print $2}' | sed -n 1P"
}

_M["chinadns-ng"] = {
	path = "/usr/bin/chinadns-ng",
	cmd_version = "-V | awk '{print $2}'"
}

return _M
