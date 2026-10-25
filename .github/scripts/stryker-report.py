#!/usr/bin/env python3
"""One shard's Stryker.NET result -> the shard report inputs, in two steps around stryker-isolate.py.

  collect: python3 stryker-report.py collect --scope <scope.json> [--report <mutation-report.json>] [--carried <json>]
                                             --all <all.json> --retest <retest.json>
     Every IN-SCOPE mutant of the Stryker report (scope.json from stryker-spans.py; line numbers of the original file: the
     shard's `// Stryker ...` directive lines are dropped again), plus the carried baseline mutants of a targeted run (a
     mutant Stryker reported again wins). retest.json = the mutants stryker-isolate.py must test one by one:
       - a CompileError not yet tested alone: Stryker compiles all mutants into one assembly and, when one breaks the build,
         rolls back every mutant the error maps to, often a DIFFERENT, compilable mutant of the same statement. Those
         collateral mutants were never tested (a hidden Survived is possible), so each is built and tested alone;
       - a carried Survived / NoCoverage (targeted mode): the tests changed since the baseline.
  finish:  python3 stryker-report.py finish --all <all.json> [--isolated <isolated.json>] --sources <AtlasPca dir>
                                            --scope <scope.json> --counts <counts.json> --survivors <survivors.json>
                                            --baseline <baseline.json>
     Applies the isolated statuses, writes the shard's counts and survivors (Survived + NoCoverage, in the ledger's site
     format: mutant = '<Mutator>: <replacement>', line = the trimmed source line, occurrence) and the baseline the next
     targeted run of this shard starts from (sources, scope, every in-scope mutant with its status)."""
import collections, json, os, sys

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
    if rep:
        d = json.load(open(rep))
        for f, v in d["files"].items():
            rel = "AtlasPca/" + f.replace("\\", "/").split("/AtlasPca/")[-1]
            if rel not in scope:
                continue
            a, b = scope[rel]
            raw = v["source"].split("\n")
            keep = [i for i, l in enumerate(raw, 1) if not l.strip().startswith("// Stryker ")]
            orig = {r: j for j, r in enumerate(keep, 1)}
            for m in v["mutants"]:
                if m["status"] == "Ignored":
                    continue
                s, e = m["location"]["start"], m["location"]["end"]
                if s["line"] not in orig or not (a <= orig[s["line"]] <= b):
                    continue
                # an end on a directive line cannot happen (a directive line sits before a declaration, outside any
                # mutated node); map it to the next original line all the same
                el = orig.get(e["line"]) or orig[min(x for x in keep if x > e["line"])]
                out.append({"file": rel, "start": {"line": orig[s["line"]], "column": s["column"]},
                            "end": {"line": el, "column": e["column"]}, "mutatorName": m["mutatorName"],
                            "replacement": str(m.get("replacement", "")), "status": m["status"],
                            "isolated": False})
    seen = {key(m) for m in out}
    car = json.load(open(opt("--carried", False))) if opt("--carried", False) else []
    out += [m for m in car if key(m) not in seen]
    for i, m in enumerate(out):
        m["id"] = i
    retest = [m for m in out if (m["status"] == "CompileError" and not m.get("isolated"))
              or (m.get("carried") and m["status"] in ("Survived", "NoCoverage"))]
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
            srcs[rel] = open(os.path.join(srcdir, rel.split("/", 1)[1]), encoding="utf-8").read().split("\n")
        return srcs[rel]
    c, surv = collections.Counter(), []
    for m in sorted(allm, key=lambda m: (m["file"], m["start"]["line"], m["start"]["column"], m["mutatorName"], m["replacement"])):
        c[m["status"]] += 1
        if m["status"] in ("Survived", "NoCoverage"):
            lines, ln = src(m["file"]), m["start"]["line"]
            rep = " ".join(m["replacement"].split())[:160]
            occ = [i + 1 for i, l in enumerate(lines) if l.strip() == lines[ln - 1].strip()].index(ln) + 1
            surv.append({"crate": "dotnet-pca", "file": m["file"], "mutant": f"{m['mutatorName']}: {rep}",
                         "line": lines[ln - 1].strip(), "occurrence": occ, "lineno": ln})
    # every in-scope mutant a compile error = the shard tested nothing (a directive / filter problem): a tool failure
    if not any(c[x] for x in ("Killed", "Survived", "Timeout", "NoCoverage")):
        sys.exit(f"no mutant was tested: {dict(c)}")
    json.dump(dict(c), open(opt("--counts"), "w"))
    json.dump(surv, open(opt("--survivors"), "w"), indent=1)
    base = {"scope": scope, "sources": {rel: "\n".join(src(rel)) for rel in scope},
            "mutants": [{k: m[k] for k in ("file", "start", "end", "mutatorName", "replacement", "status", "isolated")} for m in allm]}
    json.dump(base, open(opt("--baseline"), "w"))
    print(dict(c), len(surv), "survivor(s)", flush=True)
else:
    sys.exit("stryker-report.py collect|finish ...")
