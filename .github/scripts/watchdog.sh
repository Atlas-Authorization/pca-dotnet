#!/bin/bash
# usage: watchdog.sh <kill-log>   run in the background of a mutation step; stops when the step's shell ends (job cleanup) or is killed.
# Every 20 s: log memory, load, thread count and the biggest processes; SIGKILL any dotnet process over 9 GB RSS and append a
# "WATCHDOG epoch=.. pid=.. rss_kb=.. cwd=.." line to <kill-log> (stryker-isolate.py turns a mutant whose test run saw such a kill into a RunError).
LOG="$1"
while sleep 20; do
  echo "watch $(date -u +%H:%M:%S) $(free -m | awk '/Mem:/ {printf "used=%s avail=%s ", $3, $7}')load=$(cut -d' ' -f1-3 /proc/loadavg) threads=$(ps -eLf | wc -l) top: $(ps -eo pid=,rss=,comm= --sort=-rss | head -3 | tr -s ' \n' ' ')"
  ps -eo pid=,rss=,comm= | awk '$2 > 9000000 && $3 == "dotnet" { print $1, $2 }' | while read -r p rss; do
    line="WATCHDOG epoch=$(date +%s) pid=$p rss_kb=$rss cwd=$(readlink "/proc/$p/cwd" 2>/dev/null) cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | cut -c1-160)"
    echo "$line"; echo "$line" >> "$LOG"
    kill -9 "$p" 2>/dev/null || true
  done
done
