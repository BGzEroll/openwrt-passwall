local api = require 'luci.passwall.api'
local cases = {
 {'printf hello', 0, 'hello'},
 {'printf "first\\nsecond\\n"', 0, 'first\nsecond'},
 {'printf failure; exit 7', 7, 'failure'},
 {'printf left | tr a-z A-Z', 0, 'LEFT'},
 {'true', 0, ''}
}
for _, case in ipairs(cases) do
 local code, output = api.exec_call(case[1])
 assert(code == case[2] and output == case[3], tostring(code) .. ': ' .. tostring(output))
end
for _ = 1, 50 do
 local code, output = api.exec_call('printf ok')
 assert(code == 0 and output == 'ok')
end
local ids = {}
for _ = 1, 100 do
 local id = api.gen_short_uuid()
 assert(type(id) == 'string' and id:match('^%x+$') and not ids[id])
 ids[id] = true
end
print('native command capture, exit codes and node IDs passed')
