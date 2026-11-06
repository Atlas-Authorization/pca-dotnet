#!/usr/bin/env python3
"""One shard's Stryker.NET result -> the shard report inputs, in two steps around stryker-isolate.py.

  collect: python3 stryker-report.py collect --scope <scope.json> [--report <mutation-report.json>] [--carried <json>]
                                             [--runerr-log <file>] --all <all.json> --retest <retest.json>
     Every IN-SCOPE mutant of the Stryker report (scope.json from stryker-spans.py; line numbers of the original file: the
     shard's `// Stryker ...` directive lines are dropped again), plus the carried baseline mutants of a targeted run (a
     mutant Stryker reported again wins). retest.json = the mutants stryker-isolate.py must test one by one:
       - a CompileError not yet tested alone: Stryker compiles all mutants into one assembly and, when one breaks the build,
         rolls back every mutant the error maps to, often a DIFFERENT, compilable mutant of the same statement. Those
         collateral mutants were never tested (a hidden Survived is possible), so each is built and tested alone;
       - every Survived / NoCoverage: Stryker runs coverage-analysis perTest (only the tests that cover a mutant; "all"
         ran the whole suite per mutant and a shard outgrew the 340-minute job limit), and per-test capture can
         mis-attribute coverage, so each survivor is confirmed alone against both full test projects (a carried one also
         because the tests changed since the baseline);
       - every Killed mutant whose killing test hit OutOfMemoryException under the heap cap during the Stryker run (the
         oracle's RunErrorProbe wrote "OOM <test>" to --runerr-log): it is re-tested alone, where a kill by the memory cap
         rather than an assertion becomes a RunError (an OOM line naming no test fails the shard: unattributable).
       (A test-host crash during the Stryker run is reported Timeout by Stryker, never Killed.)
  finish:  python3 stryker-report.py finish --all <all.json> [--isolated <isolated.json>] --sources <dotnet-pca root>
                                            --scope <scope.json> --counts <counts.json> --survivors <survivors.json>
                                            --baseline <baseline.json> --runerrors <run-errors.json>
     Applies the isolated statuses, writes the shard's counts and survivors (Survived + NoCoverage + Untested, the
     mutants stryker-isolate.py's --deadline left unstarted, named "UNTESTED <mutant>" so no ledger entry matches; in the ledger's site
     format: mutant = '<Mutator>: <replacement>', line = the trimmed source line, occurrence) and the baseline the next
     targeted run of this shard starts from (sources, scope, every in-scope mutant with its status), and the RunError mutants
     (no assertion decided them: crash / OutOfMemoryException) for the merge job's run-error ledger check."""
import collections, json, os, re, sys

def opt(name, required=True):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    if required:
        sys.exit(f"stryker-report.py: {name} is required")
    return None

def key(m):
    return (m["file"], m["start"]["line"], m["start"]["column"], m["end"]["line"], m["end"]["column"], m["mutatorName"], m["replacement"])

cmd = sys.argv[1]
scope = json.load(open(opt("--scope")))
if cmd == "collect":
    out, rep = [], opt("--report", False)
    rl = opt("--runerr-log", False)
    oom = set()
    if rl and os.path.exists(rl):
        oom = {l[4:].strip() for l in open(rl).read().splitlines() if l.startswith("OOM ")}
        if "?" in oom:
            print(open(rl).read()[-4000:])
            sys.exit("an OutOfMemoryException during the Stryker run names no test: the kills cannot be told from run errors")
    if rep:
        d = json.load(open(rep))
        tname = {}
        for tf in (d.get("testFiles") or d.get("TestFiles") or {}).values():
            for t in tf.get("tests") or tf.get("Tests") or []:
                tname[str(t.get("id") or t.get("Id"))] = t.get("name") or t.get("Name") or ""
        def by_oom(m):
            kb = m.get("killedBy") or m.get("KilledBy")
            if kb is None:
                return True  # no attribution: test it alone
            return any(any(tname.get(str(i), "") == o or tname.get(str(i), "").startswith(o + "(") or tname.get(str(i), "").startswith(o + ".") for o in oom) for i in kb)
        for f, v in d["files"].items():
            m_ = re.search(r"(?:^|/)(AtlasPca(?:\.AspNetCore)?/.*)$", f.replace("\\", "/"))
            rel = m_.group(1) if m_ else f
            if rel not in scope:
                continue
            a, b = scope[rel]
            raw = v["source"].split("\n")
            keep = [i for i, l in enumerate(raw, 1) if not l.strip().startswith("// Stryker ")]
            orig = {r: j for j, r in enumerate(keep, 1)}
            for m in v["mutants"]:
                s, e = m["location"]["start"], m["location"]["end"]
                if s["line"] not in orig or not (a <= orig[s["line"]] <= b):
                    continue
                # an end on a directive line cannot happen (a directive line sits before a declaration, outside any
                # mutated node); map it to the next original line all the same
                el = orig.get(e["line"]) or orig[min(x for x in keep if x > e["line"])]
                out.append({"file": rel, "start": {"line": orig[s["line"]], "column": s["column"]},
                            "end": {"line": el, "column": e["column"]}, "mutatorName": m["mutatorName"],
                            "replacement": str(m.get("replacement", "")), "status": m["status"],
                            "isolated": False, **({"oom": True} if oom and m["status"] == "Killed" and by_oom(m) else {})})
    car = json.load(open(opt("--carried", False))) if opt("--carried", False) else []
    # an Ignored mutant of a fenced member (targeted mode) is the carried one; any other in-scope Ignored mutant (a Stryker
    # filter, not this shard's fencing) is tested alone like a survivor, never dropped
    ck = {key(m) for m in car}
    out = [m for m in out if not (m["status"] == "Ignored" and key(m) in ck)]
    seen = {key(m) for m in out}
    out += [m for m in car if key(m) not in seen]
    for i, m in enumerate(out):
        m["id"] = i
    # every Survived / NoCoverage too: per-test coverage can mis-attribute a test, so no survivor stands on it
    retest = [m for m in out if (m["status"] == "CompileError" and not m.get("isolated"))
              or m["status"] in ("Survived", "NoCoverage", "Untested", "Ignored") or m.get("oom")]
    json.dump(out, open(opt("--all"), "w"))
    json.dump(retest, open(opt("--retest"), "w"))
    c = collections.Counter(m["status"] for m in out)
    print(f"{len(out)} in-scope mutant(s) ({sum(1 for m in out if m.get('carried'))} carried): {dict(c)}; "
          f"{len(retest)} to test one by one", flush=True)
elif cmd == "finish":
    allm = json.load(open(opt("--all")))
    iso = opt("--isolated", False)
    if iso and os.path.exists(iso):
        byid = {r["id"]: r for r in json.load(open(iso))}
        for m in allm:
            r = byid.get(m["id"])
            if r is not None:
                m["status"], m["isolated"], m["detail"] = r["status"], True, r.get("detail", "")
    srcdir = opt("--sources")
    srcs = {}
    def src(rel):
        if rel not in srcs:
            srcs[rel] = open(os.path.join(srcdir, rel), encoding="utf-8").read().split("\n")
        return srcs[rel]
    c, surv, rerr = collections.Counter(), [], []
    for m in sorted(allm, key=lambda m: (m["file"], m["start"]["line"], m["start"]["column"], m["mutatorName"], m["replacement"])):
        c[m["status"]] += 1
        if m["status"] == "RunError":
            lines, ln = src(m["file"]), m["start"]["line"]
            occ = [i + 1 for i, l in enumerate(lines) if l.strip() == lines[ln - 1].strip()].index(ln) + 1
            rerr.append({"crate": "dotnet-pca", "file": m["file"], "mutant": f"{m['mutatorName']}: {' '.join(m['replacement'].split())[:160]}",
                         "line": lines[ln - 1].strip(), "occurrence": occ, "lineno": ln, "evidence": m.get("detail", "")})
        if m["status"] in ("Survived", "NoCoverage", "Untested", "Ignored"):
            lines, ln = src(m["file"]), m["start"]["line"]
            rep = " ".join(m["replacement"].split())[:160]
            occ = [i + 1 for i, l in enumerate(lines) if l.strip() == lines[ln - 1].strip()].index(ln) + 1
            # an Untested mutant (time budget) is listed under a name no ledger entry can carry: it always fails the merge
            pre = "UNTESTED " if m["status"] in ("Untested", "Ignored") else ""
            surv.append({"crate": "dotnet-pca", "file": m["file"], "mutant": f"{pre}{m['mutatorName']}: {rep}",
                         "line": lines[ln - 1].strip(), "occurrence": occ, "lineno": ln})
    # every in-scope mutant a compile error = the shard tested nothing (a directive / filter problem): a tool failure
    if not any(c[x] for x in ("Killed", "Survived", "Timeout", "NoCoverage", "RunError")):
        sys.exit(f"no mutant was tested: {dict(c)}")
    json.dump(dict(c), open(opt("--counts"), "w"))
    json.dump(surv, open(opt("--survivors"), "w"), indent=1)
    json.dump(rerr, open(opt("--runerrors"), "w"), indent=1)
    base = {"scope": scope, "sources": {rel: "\n".join(src(rel)) for rel in scope},
            "mutants": [{k: m[k] for k in ("file", "start", "end", "mutatorName", "replacement", "status", "isolated")} for m in allm]}
    if rerr:
        print(f"{len(rerr)} RunError mutant(s) (no assertion decided them):", *(f"  {r['file']}:{r['lineno']} {r['mutant'][:80]} | {r['evidence'][:100]}" for r in rerr), sep="\n", flush=True)
    json.dump(base, open(opt("--baseline"), "w"))
    print(dict(c), len(surv), "survivor(s)", flush=True)
else:
    sys.exit("stryker-report.py collect|finish ...")
