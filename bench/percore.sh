#!/bin/sh
# One server core (CPU 0) vs five wrk threads (CPUs 1-5): measures per-core server throughput.
DUR=${DUR:-8s}
sed -e 's/worker_processes 3;/worker_processes 1;/' -e 's/worker_cpu_affinity .*;/worker_cpu_affinity 1;/' \
  /src/bench/nginx.conf > /tmp/nginx1.conf
taskset -c 0 /src/build/absurd 8080 1 >/dev/null &
taskset -c 0 nginx -c /tmp/nginx1.conf &
sleep 1
snap() { awk '/^cpu0 /{print $2+$3+$4+$7+$8, $5+$6}' /proc/stat; }
run() {
  name=$1; port=$2; shift 2
  taskset -c 1-5 wrk -t5 -c250 -d"$DUR" "$@" http://127.0.0.1:$port/ > /tmp/w &
  sleep 3; a=$(snap); sleep 3; b=$(snap); wait $!
  printf '%-26s %12s req/s   server cpu0 %s%%\n' "$name" \
    "$(awk '/Requests\/sec/{print $2}' /tmp/w)" \
    "$(echo $a $b | awk '{b=$3-$1; i=$4-$2; printf "%d", 100*b/(b+i)}')"
}
run "nginx   keep-alive"      8081
run "absurd  keep-alive"      8080
DEPTH=16 run "nginx   pipelined x16" 8081 -s /src/bench/pipeline.lua
DEPTH=16 run "absurd  pipelined x16" 8080 -s /src/bench/pipeline.lua
