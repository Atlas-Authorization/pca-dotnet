#!/usr/bin/env python3
"""Test Stryker.NET mutants ONE AT A TIME, each compiled alone into the verifier: the honest status of a mutant Stryker could
not test (and a fast way to re-test a chosen list of mutants).

Why: Stryker.NET compiles every mutant of the project into one assembly. When a mutant breaks the build (C# definite
assignment after `is not T x` -> `is T x`, `List.Count` -> `Sum`, ...) Stryker rolls back the mutants it maps the error to,
and the error's location often lies inside a DIFFERENT, compilable mutant of the same statement or expression. Those
collateral mutants are reported CompileError and never tested (about a quarter of the CompileErrors of AtlasPca). Here each
mutant is applied alone to a clean copy of the source, built, and run against the oracle test project.

  python3 stryker-isolate.py --src <dotnet-pca dir> --mutants <json> --out <json> [--jobs 4] [--filter <dotnet test filter>]
                             [--timeout <s>] [--work <dir>] [--stop-on-fail] [--deadline <unix time>]

<json>: [{id, file: "AtlasPca/X.cs", start: {line, column}, end: {line, column}, replacement, ...}] (1-based columns, end
exclusive: the Stryker report's location). Output: the same records plus "status": CompileError | Killed | Survived | Timeout
(and "detail": the first compiler error / failing test), RunError (the tests failed but no assertion decided the mutant: the
test host crashed or aborted, or every failing test hit OutOfMemoryException under the 3 GiB heap cap - the oracle's
RunErrorProbe logs each OOM to $PCA_RUNERR_LOG; "detail" = the evidence; a run error needs a per-mutant ledger reason), or
Untested: a mutant not started before --deadline (the caller must count it as not passed). Worker copies live in <work>/w<k> (default <src>/.mutwork), which
must sit below the monorepo root (the oracle finds packages/pca/conformance by walking up from its bin directory).
A test host is capped at a 3 GiB GC heap (DOTNET_GCHeapHardLimit), so an unbounded-allocation mutant dies alone - as a RunError,
never a kill."""
import argparse, json, os, re, shutil, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

ap = argparse.ArgumentParser()
ap.add_argument("--src", required=True)
ap.add_argument("--mutants", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--jobs", type=int, default=4)
ap.add_argument("--filter", default="Category!=Huge")
ap.add_argument("--timeout", type=int, default=0, help="per-mutant test timeout in seconds (0 = 3x the baseline run + 60)")
ap.add_argument("--work", default=None)
ap.add_argument("--deadline", type=float, default=0, help="unix time after which no mutant is started (they are Untested)")
ap.add_argument("--stop-on-fail", action="store_true", help="xUnit.StopOnFail: a killed mutant stops at its first failing test")
a = ap.parse_args()

src = os.path.abspath(a.src)
work = os.path.abspath(a.work or os.path.join(src, ".mutwork"))
TEST = "AtlasPca.Corpus.Tests"
# the kill set: the corpus project plus the Authorize / executor / middleware tests (they exercise Authorize.cs, Executor.cs, ...)
TESTS = [TEST, "AtlasPca.AspNetCore.Tests"]
muts = json.load(open(a.mutants))
for m in muts:
    for k in ("file", "start", "end", "replacement"):
        if k not in m:
            sys.exit(f"mutant without '{k}': {json.dumps(m)[:200]}")

def sh(cmd, cwd, timeout=None, env=None):
    t = time.time()
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout + r.stderr, time.time() - t
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return None, out, time.time() - t

def copy_tree(dst):
    if os.path.exists(dst):
        shutil.rmtree(dst)
    os.makedirs(dst)
    for d in ("AtlasPca", "AtlasPca.AspNetCore", *TESTS):
        shutil.copytree(os.path.join(src, d), os.path.join(dst, d), ignore=shutil.ignore_patterns("bin", "obj", "StrykerOutput", ".mutwork"))
    for f in ("global.json",):
        if os.path.exists(os.path.join(src, f)):
            shutil.copy(os.path.join(src, f), dst)

TEST_ENV = dict(os.environ, DOTNET_GCHeapHardLimit="0xC0000000")
test_cmd = ["dotnet", "test", "-c", "Release", "--no-build", "--nologo", "--filter", a.filter]
full_cmd = list(test_cmd)
if a.stop_on_fail:
    test_cmd += ["--", "xUnit.StopOnFail=true"]

def build_all(w, extra):
    for t in TESTS:
        rc, out, _ = sh(["dotnet", "build", "-c", "Release", "--nologo", "-v", "q"] + extra, os.path.join(w, t))
        if rc != 0:
            return rc, out
    return 0, ""

def runerr_log(w):
    return os.path.join(w, "runerr.log")

def test_all(w, timeout=None, cmd=None):
    """Run every test project; the first failure (or timeout) decides. OOM evidence goes to <w>/runerr.log (truncated first)."""
    total = 0.0
    open(runerr_log(w), "w").close()
    env = dict(TEST_ENV, PCA_RUNERR_LOG=runerr_log(w))
    for t in TESTS:
        rc, out, secs = sh(cmd or test_cmd, os.path.join(w, t), timeout=timeout, env=env)
        total += secs
        if rc != 0:
            return rc, out, total
    return 0, "", total

FAILED = re.compile(r"^\s*Failed (\S+?)(?:\(.*)? \[", re.M)
def failures(out):
    """{failed test -> its VSTest block}: the test's 'Failed' line up to the next one."""
    ms = list(FAILED.finditer(out))
    return {m.group(1): out[m.start(): ms[i + 1].start() if i + 1 < len(ms) else len(out)] for i, m in enumerate(ms)}

def classify(w, rc, out, timeout):
    """Killed only when some test failed on its own assertion; RunError when the host crashed / aborted (no failed test) or
    every failed test is an OutOfMemoryException one (the heap cap, not a test, decided). Re-run without StopOnFail first, so
    an OOM test that stopped the run early cannot hide a later assertion failure."""
    fails = failures(out)
    oom = {l.split(" ", 1)[1].strip() for l in open(runerr_log(w)).read().splitlines() if l.startswith("OOM ")}
    if fails and not oom and not any("OutOfMemoryException" in b for b in fails.values()):
        return "Killed", next(iter(fails))[:200]
    if a.stop_on_fail:
        rc2, out2, _ = test_all(w, timeout, full_cmd)
        if rc2 is None:
            return "Timeout", f">{timeout}s (full re-run)"
        if rc2 == 0:
            return "RunError", "flaky: failed with StopOnFail, passed on the full re-run"
        fails = failures(out2)
        oom = {l.split(" ", 1)[1].strip() for l in open(runerr_log(w)).read().splitlines() if l.startswith("OOM ")}
        out = out2
    real = [t for t, b in fails.items() if "OutOfMemoryException" not in b and not any(t == o or t.startswith(o + ".") for o in oom)]
    if real:
        return "Killed", real[0][:200]
    if not fails:
        crash = next((l.strip() for l in out.split("\n") if re.search(r"(?i)test host process crashed|test run aborted|stack overflow|aborted", l)), "no failed test")
        return "RunError", ("crash: " + crash)[:200]
    return "RunError", ("OutOfMemoryException: " + ", ".join(sorted(fails)))[:200]

late = lambda: a.deadline and time.time() > a.deadline
if late():
    json.dump([dict(m, status="Untested", detail="deadline") for m in muts], open(a.out, "w"), indent=1)
    sys.exit(print(f"{len(muts)} mutant(s) Untested: the deadline passed before the one-by-one tests started", flush=True))
jobs = max(1, min(a.jobs, len(muts))) if muts else 0
workers = [os.path.join(work, f"w{k}") for k in range(jobs)]
base_secs = []
def prepare(w):
    copy_tree(w)
    rc, out = build_all(w, [])
    if rc != 0:
        sys.exit(f"{w}: the unmutated source does not build:\n{out[-3000:]}")
    rc, out, secs = test_all(w)
    if rc != 0:
        sys.exit(f"{w}: the oracle fails on the unmutated source:\n{out[-3000:]}")
    if os.path.getsize(runerr_log(w)):
        sys.exit(f"{w}: the unmutated source hits OutOfMemoryException under the heap cap:\n{open(runerr_log(w)).read()[:2000]}")
    base_secs.append(secs)
with ThreadPoolExecutor(jobs or 1) as ex:
    list(ex.map(prepare, workers))
timeout = a.timeout or int(3 * max(base_secs or [60]) + 60)
print(f"{len(muts)} mutant(s), {jobs} worker(s), baseline {max(base_secs or [0]):.0f}s, timeout {timeout}s", flush=True)

def offset(lines, line, col):
    return sum(len(x) + 1 for x in lines[: line - 1]) + col - 1

free = list(workers)
lock = threading.Lock()
done = [0]
def run(m):
    if late():
        return dict(m, status="Untested", detail="deadline")
    with lock:
        w = free.pop()
    try:
        p = os.path.join(w, m["file"])
        orig = open(p, encoding="utf-8").read()
        lines = orig.split("\n")
        s, e = offset(lines, m["start"]["line"], m["start"]["column"]), offset(lines, m["end"]["line"], m["end"]["column"])
        try:
            open(p, "w", encoding="utf-8").write(orig[:s] + m["replacement"] + orig[e:])
            rc, out = build_all(w, ["--no-restore"])
            if rc != 0:
                err = next((l.strip() for l in out.split("\n") if ": error " in l), "?")
                st, det = "CompileError", re.sub(r"\s*\[[^\]]*\.csproj\]$", "", err)[-200:]
            else:
                rc, out, secs = test_all(w, timeout)
                if rc is None:
                    st, det = "Timeout", f">{timeout}s"
                elif rc != 0:
                    st, det = classify(w, rc, out, timeout)
                else:
                    st, det = "Survived", f"{secs:.0f}s"
        finally:
            open(p, "w", encoding="utf-8").write(orig)
        r = dict(m, status=st, detail=det)
    finally:
        with lock:
            free.append(w)
            done[0] += 1
            n = done[0]
    print(f"[{n}/{len(muts)}] {r['status']:12} {m['file']}:{m['start']['line']} {m.get('mutatorName', '')}: {m['replacement'][:60]!r} | {r['detail'][:120]}", flush=True)
    return r

with ThreadPoolExecutor(jobs or 1) as ex:
    res = list(ex.map(run, muts))
json.dump(res, open(a.out, "w"), indent=1)
from collections import Counter
print(dict(Counter(r["status"] for r in res)), flush=True)
