#!/usr/bin/env python3
"""Selftest of the isolate helpers (run in every shard before any mutant): the process-group kill returns promptly and leaves nothing,
and a watchdog kill turns even a 'Killed' result into a RunError. Exits non-zero on the first broken property."""
import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stryker_procs import sh, watchdog_hits, reclassify

# 1. a timed-out command and its grandchild (which holds the pipe) are killed together, promptly
t = time.time()
rc, out, _ = sh(["bash", "-c", "echo start; (sleep 300; echo late) & sleep 300"], "/tmp", timeout=3)
assert rc is None and "start" in out and time.time() - t < 20, (rc, out, time.time() - t)
assert sh(["bash", "-c", "echo hi; exit 4"], "/tmp", timeout=5)[:2] == (4, "hi\n")
# ... and a child a command that exited normally left running (an orphaned test host) is killed with its group
with tempfile.TemporaryDirectory() as d:
    pf = os.path.join(d, "pid")
    assert sh(["bash", "-c", f"sleep 300 >/dev/null 2>&1 & echo $! > {pf}"], "/tmp", timeout=10)[0] == 0
    left, gone = int(open(pf).read()), False
    for _ in range(50):
        try:
            os.kill(left, 0)
            st = open(f"/proc/{left}/stat").read().split(") ")[-1][0] if os.path.exists(f"/proc/{left}/stat") else "Z"
            if st == "Z":
                gone = True; break
        except ProcessLookupError:
            gone = True; break
        time.sleep(0.1)
    assert gone, f"pid {left} outlived its run"

# 2. watchdog attribution: only a kill under THIS worker dir, at or after the run start, counts
now = int(time.time())
with tempfile.TemporaryDirectory() as d:
    log = os.path.join(d, "watchdog.log")
    open(log, "w").write(
        f"WATCHDOG epoch={now} pid=10 rss_kb=9500000 cwd=/work/w0/AtlasPca.Corpus.Tests/bin cmd=dotnet testhost\n"
        f"WATCHDOG epoch={now - 600} pid=11 rss_kb=9500000 cwd=/work/w0/AtlasPca.Corpus.Tests/bin cmd=old\n"
        f"WATCHDOG epoch={now} pid=12 rss_kb=9500000 cwd=/work/w1/AtlasPca.Corpus.Tests/bin cmd=other worker\n"
        f"WATCHDOG epoch={now} pid=13 rss_kb=9500000 cwd=/work/w01/x cmd=prefix lookalike\n")
    hits = watchdog_hits(log, "/work/w0", now - 5)
    assert len(hits) == 1 and "pid=10" in hits[0], hits
    assert watchdog_hits(log, "/work/w0", now + 100) == []
    assert watchdog_hits(os.path.join(d, "missing.log"), "/work/w0", 0) == []

# 3. a watchdog kill is a RunError, never Killed, whatever the run said; no kill leaves the result alone
for st in ("Killed", "Survived", "Timeout"):
    got = reclassify(st, "d", ["WATCHDOG epoch=1 pid=2 rss_kb=3 cwd=/w0/x"])
    assert got[0] == "RunError" and "WATCHDOG" in got[1], got
assert reclassify("Killed", "T.x", []) == ("Killed", "T.x")
print("stryker-isolate selftest ok")
