#!/bin/sh
# Per-core throughput on this machine, without Docker: absurd with one worker
# pinned to CPU 0, wrk on the other CPUs. Prints the median of three runs,
# without pipelining and pipelined 16 deep.
#   make && bench/local.sh            (needs wrk, python3, taskset, 2+ CPUs)
set -e
R=$(cd "$(dirname "$0")/.." && pwd)
PORT=${PORT:-18099}
SITE=$(mktemp -d)
trap 'kill $PID 2>/dev/null || true; rm -rf "$SITE"' EXIT
python3 "$R/test/run.py" fixture "$SITE"
taskset -c 0 "$R/build/absurd" -t 1 -p "$PORT" "$SITE" > /dev/null &
PID=$!
sleep 0.5
N=$(nproc)
LOAD="1-$((N - 1))"
T=$((N - 1)); [ "$T" -gt 4 ] && T=4
for d in 1 16; do
  runs=""
  for i in 1 2 3; do
    x=$(DEPTH=$d taskset -c "$LOAD" wrk -t"$T" -c96 -d4s -s "$R/bench/pipeline.lua" "http://127.0.0.1:$PORT/" |
        awk '/Requests\/sec/{print int($2)}')
    runs="$runs $x"
  done
  median=$(echo $runs | tr ' ' '\n' | sort -n | sed -n 2p)
  printf 'pipeline depth %-2d  %9d req/s on one core   (runs:%s)\n' "$d" "$median" "$runs"
done
