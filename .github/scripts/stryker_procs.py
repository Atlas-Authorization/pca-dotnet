"""Process helpers shared by stryker-isolate.py and its selftest: a command run in its own process group (killed whole on a timeout) and
the attribution of watchdog kills to a mutant's test run."""
import os, re, signal, subprocess, time


def sh(cmd, cwd, timeout=None, env=None):
    """Run cmd in its own process group; on timeout kill the WHOLE group (dotnet test, testhost and their children), never
    waiting on a pipe a surviving grandchild still holds. Returns (returncode | None on timeout, output, seconds)."""
    t = time.time()
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out or "", time.time() - t
    except subprocess.TimeoutExpired as e:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            out, _ = p.communicate(timeout=30)
        except Exception:
            out = e.stdout if isinstance(e.stdout, str) else (e.stdout or b"").decode(errors="replace")
        return None, out or "", time.time() - t


WD = re.compile(r"^WATCHDOG epoch=(\d+) pid=(\d+) rss_kb=(\d+) cwd=(\S*)", re.M)


def watchdog_hits(log_path, wdir, since):
    """The watchdog kill lines (scripts/watchdog.sh) of a dotnet process that lived under wdir, at or after `since` (epoch seconds, 2 s slack)."""
    if not log_path or not os.path.exists(log_path):
        return []
    text = open(log_path, errors="replace").read()
    return [m.group(0)[:200] for m in WD.finditer(text) if int(m.group(1)) >= int(since) - 2 and m.group(4).startswith(wdir.rstrip("/") + "/")]


def reclassify(status, detail, hits):
    """A test host killed by the watchdog is a RunError whatever the test run then said (a crash can look like a kill): the evidence is the
    watchdog's own line, and the mutant is never Killed."""
    if hits:
        return "RunError", ("watchdog killed a test host: " + hits[0])[:300]
    return status, detail
