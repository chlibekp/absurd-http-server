#!/bin/sh
# Runs inside the bench container: server on CPUs 0-2, wrk on CPUs 3-5.
set -e
DUR=${DUR:-10s}
taskset -c 0-2 /src/build/absurd 8080 >/dev/null &
taskset -c 0-2 nginx -c /src/bench/nginx.conf &
sleep 1
run() { # name port extra...
  name=$1; port=$2; shift 2
  printf '%-28s ' "$name"
  taskset -c 3-5 wrk -t3 -c256 -d"$DUR" "$@" http://127.0.0.1:$port/ \
    | awk '/Requests\/sec/{rps=$2} /Latency/{lat=$2} END{printf "%12s req/s   avg latency %s\n", rps, lat}'
}
run "nginx      keep-alive"     8081
run "absurd     keep-alive"     8080
DEPTH=16 run "nginx      pipelined x16" 8081 -s /src/bench/pipeline.lua
DEPTH=16 run "absurd     pipelined x16" 8080 -s /src/bench/pipeline.lua
kill %1 %2 2>/dev/null || true
