#!/bin/sh
# usage: cpu.sh <port> [wrk args...]  -> req/s plus busy% of server CPUs (0-2) and client CPUs (3-5)
port=$1; shift
snap() { awk '/^cpu[0-9]/{print $1, $2+$3+$4+$7+$8, $5+$6}' /proc/stat; }
taskset -c 3-5 wrk -t3 -c256 -d8s "$@" http://127.0.0.1:$port/ > /tmp/w &
sleep 3; snap > /tmp/a; sleep 3; snap > /tmp/b; wait
awk '/Requests\/sec/{printf "%s req/s  ", $2}' /tmp/w
paste /tmp/a /tmp/b | awk '{b=$5-$2; i=$6-$3; printf "%s:%d%% ", $1, 100*b/(b+i)} END{print ""}'
