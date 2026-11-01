-- wrk script: send DEPTH requests back to back per write (HTTP pipelining)
local depth = tonumber(os.getenv("DEPTH") or "16")
init = function(args)
  local r = {}
  for i = 1, depth do r[i] = wrk.format() end
  req = table.concat(r)
end
request = function() return req end
