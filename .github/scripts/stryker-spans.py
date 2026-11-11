#!/usr/bin/env python3
"""Shard K of N of the Stryker.NET run over AtlasPca/: prints one --mutate glob per line, fences the shard's files (CI copy
only) with Stryker comment directives so only the wanted members are mutated, and writes the shard's scope.

   python3 stryker-spans.py <k> <n> <AtlasPca dir> --scope <scope.json> [--baseline <baseline.json> --carry <carried.json>]

A shard whose file set changed still works against an old targeted baseline: the baseline is read per file (sources / scope
keyed by file), so a file that moved into a shard has no baseline entry there and is mutated whole, a file that moved out is
simply not in scope, and the files that stayed keep their carried results.

PLAN lists every .cs file of AtlasPca/ exactly once: whole, or as spans "File.cs#i/n" (n near-equal line spans cut only at
member declarations, indent 0 or 4 in the file-scoped namespace, so no mutant crosses a cut and the spans partition the
file). A .cs file missing from PLAN (or a planned file that is gone, or spans that do not partition a file) fails the
shard, so a new source file is never silently left out.

FENCING: a `// Stryker disable all` comment only disables the syntax node it is attached to (the declaration right below
it): it does NOT run on to a later `// Stryker restore all` across sibling members (0.4.2 run 38330673581: every Pca.cs
shard tested the whole file, 3x the work, and every Pca.cs survivor was reported three times). So a top-level type with no
live line gets its own directive line, and inside a type with live lines every member declaration (indent 4, its attribute
lines included) without one gets one. Live = the shard's span (full mode), or the lines that changed since the
baseline (targeted mode). A `--mutate Pca.cs{a..b}` line filter is not used: with it Stryker.NET 4.8 reported every in-span
mutant as a compile error. The inserted directive lines are whole lines `// Stryker disable all`; the report step drops
them again (line numbers of the original file).

--scope: {"AtlasPca/<file>.cs" | "AtlasPca.AspNetCore/<file>.cs": [first, last]} (original-file lines the shard owns). The report step counts and lists only
in-scope mutants: Stryker compiles (and reports CompileError for) the mutants of EVERY file of the project in every shard
(run 38330673581: ~1,489 CompileErrors in each of the 12 shards, 17,834 in all, whatever the shard mutated).

TARGETED mode (--baseline = the stryker-baseline.json the same shard uploaded in an earlier run: its sources, scope and
every in-scope mutant with its status): the lines of the current sources that are not an unchanged copy of an in-scope
baseline line are live (edited, added, next to a deletion, or newly in scope). Only the members holding a live line are
mutated by Stryker (none: no glob is printed and Stryker is skipped). Every baseline mutant that lies, unchanged, in a
fenced member is written to --carry with its line numbers moved to the current source; the report step keeps its
Killed / Timeout / tested CompileError result and re-tests the others (Survived, NoCoverage, untested CompileError) one by
one with stryker-isolate.py, so new kill tests are seen without re-running Stryker over the whole shard."""
import collections, difflib, json, os, re, sys

# One shard per entry: "File.cs" (the whole file) or "File.cs#i/n" (line span i of n, cut at member declarations); paths are
# relative to AtlasPca/ (the middleware's start with ../AtlasPca.AspNetCore/, its own Stryker project: never mixed in a shard).
# Balanced on run 41748042249's per-shard Stryker minutes plus its survivor / CompileError counts (each is tested alone
# afterwards), Attest/ Ext/ and the middleware by size; the suite has since become ~6x faster (Ed25519 check).
PLAN = [
    ["Pca.cs#1/2"],
    ["Passport.cs"],
    ["ActionSchema.cs", "Ext/Optimistic.cs"],
    ["Authorize.cs#1/2", "MissingContext.cs"],
    ["Authorize.cs#2/2", "FreshAt.cs"],
    ["Ext/Mesh.cs", "Ext/PcaInternals.cs"],
    ["ActionsRegistry.cs", "Undo.cs"],
    ["Workflow.cs", "IntentRevocation.cs"],
    ["Attest/AttestNvidiaCollateral.cs"],
    ["Sigstore.cs#1/2", "Attest/AttestMaa.cs"],
    ["Sigstore.cs#2/2", "Keys.cs"],
    ["Predicates.cs", "Attest/AttestAmd.cs"],
    ["Actions.cs#1/6"],
    ["Actions.cs#3/6"],
    ["Attest/AttestCert.cs#1/2"],
    ["Issue.cs", "StoreConformance.cs"],
    ["K3.cs"],
    ["PolicyAuthoring.cs", "ArgProvenance.cs"],
    ["ReadSide.cs", "CaveatLang.cs"],
    ["Attest/AttestIntelCollateral.cs"],
    ["IntentV2.cs"],
    ["../AtlasPca.AspNetCore/PcaMiddleware.cs", "../AtlasPca.AspNetCore/PcaOptions.cs", "../AtlasPca.AspNetCore/PcaProtect.cs", "../AtlasPca.AspNetCore/PcaExtensions.cs"],
    ["IntentSession.cs", "Decision.cs", "Assurance.cs", "PcaDomainSig.cs"],
    ["Lease.cs", "Attest/AttestGcp.cs", "StepUp.cs", "ParamProvenance.cs"],
    ["Operations.cs", "ReadVault.cs", "RevocationFreshness.cs", "BreakGlass.cs"],
    ["ProvenanceGate.cs", "Ext/Ledger.cs", "IntentAcc.cs", "OracleFacts.cs", "IntentClassifier.cs"],
    ["A2a.cs", "IntentMap.cs", "IntentHistory.cs", "Attest/AttestCommon.cs", "K4.cs", "Agent.cs"],
    ["Blueprint.cs", "IntentJs.cs", "PcaGrant.cs", "Ext/JsCanon.cs", "IntentPrimitives.cs", "Escalation.cs", "IntentArtifacts.cs", "Refusals.cs", "Caveats.cs"],
    ["AtomicKv.cs", "Attest/AttestFactory.cs", "IntentWB.cs", "LessNative.cs", "Rx.cs"],
    # run 41937170925: these shards passed their budget (12 in Stryker, 8/13/14/20 with mutants left untested); new ones go last, so the other numbers stay
    ["PlanLifecycle.cs"],
    ["Actions.cs#5/6"],
    ["Attest/AttestDer.cs"],
    ["Attest/AttestJws.cs"],
    ["Approval.cs"],
    ["Attest/AttestXml.cs#1/2"],
    ["Obligations.cs", "Attest/AttestCertExts.cs"],
    # run 42149070759: Pca, Actions and AttestXml ran out of budget, AttestCert came near it
    ["Pca.cs#2/2"],
    ["Actions.cs#2/6"],
    ["Actions.cs#4/6"],
    ["Actions.cs#6/6"],
    ["Attest/AttestCert.cs#2/2"],
    ["Attest/AttestXml.cs#2/2"],
    ["RuntimeClaim.cs"],
    # run 42441751689: shard 17 (K3 + AttestIntel + PolicyClasses, 138 mutants untested) and shard 6 (3 untested) overran the budget: one file each, the old slots keep their numbers
    ["Attest/AttestIntel.cs"],
    ["PolicyClasses.cs"],
    ["Attest/AttestNvidia.cs"],
    # run 42636647633: shard 20 lost its runner a third time (shutdown signal after 90 min at 2 workers): one file each, the old slot keeps AttestIntelCollateral
    ["SafeRegex.cs#1/3"],
    ["Executor.cs"],
    # run 42720114305: SafeRegex alone lost its runner again (shutdown at 38 min): three spans, one worker each, so the span that does it is named
    ["SafeRegex.cs#2/3"],
    ["SafeRegex.cs#3/3"],
]

def opt(name):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    return None

k, n, d = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
scope_out, baseline_in, carry_out = opt("--scope"), opt("--baseline"), opt("--carry")
if not scope_out or bool(baseline_in) != bool(carry_out):
    sys.exit("usage: stryker-spans.py <k> <n> <AtlasPca dir> --scope <json> [--baseline <json> --carry <json>]")
if n != len(PLAN):
    sys.exit(f"the workflow runs {n} shards but the plan has {len(PLAN)}: keep SHARDS in step with stryker-spans.py")
# every .cs file of the verifier (subdirectories included: Ext/, Attest/) and of the ASP.NET Core middleware project, as paths
# relative to AtlasPca/ (the middleware's start with ../AtlasPca.AspNetCore/)
SKIP = {"bin", "obj", "StrykerOutput", ".mutwork"}
files = sorted(os.path.relpath(os.path.join(r, f), d) for top in (d, os.path.join(d, "..", "AtlasPca.AspNetCore"))
               for r, ds, fs in os.walk(top) if not ds.__setitem__(slice(None), [x for x in ds if x not in SKIP])
               for f in fs if f.endswith(".cs"))
key = lambda f: os.path.normpath("AtlasPca/" + f)  # scope / ledger path: AtlasPca/Ext/Mesh.cs, AtlasPca.AspNetCore/PcaMiddleware.cs
parts = collections.defaultdict(list)  # file -> [(i, n)] of its plan entries
for it in (x for sh in PLAN for x in sh):
    f, _, sp = it.partition("#")
    parts[f].append(tuple(map(int, sp.split("/"))) if sp else (1, 1))
if sorted(parts) != files:
    sys.exit(f"AtlasPca/ has {files}, the plan covers {sorted(parts)}: update PLAN in stryker-spans.py")
for f, ps in parts.items():
    if sorted(ps) != [(i, ps[0][1]) for i in range(1, ps[0][1] + 1)]:
        sys.exit(f"{f}: plan spans {sorted(ps)} do not partition the file")

def read(f):
    return open(os.path.join(d, f), encoding="utf-8").read().split("\n")

def units(lines):
    """[(type_start, type_end, [(member_start, member_end), ...])]: top-level types (indent 0) and their members (indent 4);
    attribute lines belong to the declaration below them. Ranges are 1-based and inclusive; a member runs to the line
    before the next declaration of indent 0 or 4."""
    cand = [i + 1 for i, l in enumerate(lines) if re.match(r"^( {4})?[A-Za-z\[]", l) and not l.startswith(("using ", "namespace "))]
    starts = []
    for x in cand:
        prev = starts[-1] if starts else None
        ind = len(lines[x - 1]) - len(lines[x - 1].lstrip(" "))
        # a declaration right below its own attribute lines (same indent, only attributes / blanks / comments between)
        if prev is not None and lines[prev - 1].lstrip().startswith("[") and len(lines[prev - 1]) - len(lines[prev - 1].lstrip(" ")) == ind \
                and all(re.match(r"^\s*(\[.*|//.*)?$", lines[j - 1]) for j in range(prev, x)):
            continue
        starts.append(x)
    out = []
    for j, s in enumerate(starts):
        end = starts[j + 1] - 1 if j + 1 < len(starts) else len(lines)
        if not lines[s - 1].startswith(" "):
            out.append([s, None, []])
        elif out:
            out[-1][2].append((s, end))
    for j, u in enumerate(out):
        u[1] = out[j + 1][0] - 1 if j + 1 < len(out) else len(lines)
        u[2] = [(a, min(b, u[1])) for a, b in u[2]]
    return out

def fence(lines, live):
    """(directive lines to insert before, fenced line ranges) for a file whose `live` lines are mutated."""
    ins, fenced = set(), []
    for t, end, members in units(lines):
        if not any(t <= x <= end for x in live):
            ins.add(t); fenced.append((t, end))
            continue
        for a, b in members:
            if not any(a <= x <= b for x in live):
                ins.add(a); fenced.append((a, b))
    return ins, fenced

def write_fenced(f, lines, ins):
    out = []
    for i, l in enumerate(lines, 1):
        if i in ins:
            out.append("// Stryker disable all")
        out.append(l)
    open(os.path.join(d, f), "w", encoding="utf-8").write("\n".join(out))

for f in files:
    if any(l.strip().startswith("// Stryker") for l in read(f)):
        sys.exit(f"{f} already has Stryker directives")

def span(f, i, n):
    """Lines [a, b] of span i of n of f: n near-equal parts cut only at member declarations (indent 0 or 4)."""
    lines = read(f)
    if n == 1:
        return [1, len(lines)]
    starts = [t for t, _, ms in units(lines) for t in [t] + [a for a, _ in ms]]
    cuts = []
    for j in range(1, n):
        target = j * len(lines) / n
        cuts.append(min((x for x in starts if x > (cuts[-1] if cuts else 1)), key=lambda x: abs(x - target)))
    bounds = [1] + cuts + [len(lines) + 1]
    return [bounds[i - 1], bounds[i] - 1]

# the shard's scope (original-file lines); one Stryker project per shard
if len({key(it.partition("#")[0]).split("/")[0] for it in PLAN[k - 1]}) != 1:
    sys.exit(f"shard {k} mixes projects: {PLAN[k - 1]}")
scope = {}
for it in PLAN[k - 1]:
    f, _, sp = it.partition("#")
    scope[key(f)] = span(f, *map(int, sp.split("/"))) if sp else [1, len(read(f))]
json.dump(scope, open(scope_out, "w"))

base = json.load(open(baseline_in)) if baseline_in else None
carried, globs = [], []
for rel, (a, b) in scope.items():
    f = os.path.relpath(rel, "AtlasPca")
    lines = read(f)
    whole = (a, b) == (1, len(lines))
    if base is None:
        if whole:
            globs.append(f)  # the whole file: no fencing
            continue
        live = set(range(a, b + 1))
    else:
        old = base.get("sources", {}).get(rel)
        olds = base.get("scope", {}).get(rel)
        same = {}  # old line -> current line, for unchanged in-scope baseline lines
        live = set()
        if old is not None and olds is not None:
            old = old.split("\n")
            sm = difflib.SequenceMatcher(None, old, lines, autojunk=False)
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == "equal":
                    for o, c in zip(range(i1, i2), range(j1, j2)):
                        if olds[0] <= o + 1 <= olds[1]:
                            same[o + 1] = c + 1
                elif tag == "delete":
                    live.update({j1, j1 + 1})  # the lines around a deletion
        cur_same = set(same.values())
        live |= {x for x in range(a, b + 1) if x not in cur_same}
        live = {x for x in live if a <= x <= b}
        _, fenced = fence(lines, live)
        infence = lambda x: any(p <= x <= q for p, q in fenced) and a <= x <= b
        for m in base.get("mutants", []):
            if m["file"] != rel:
                continue
            s, e = same.get(m["start"]["line"]), same.get(m["end"]["line"])
            if s is None or e is None or not (infence(s) and infence(e)):
                continue  # changed, or in a member Stryker mutates again
            carried.append(dict(m, start=dict(m["start"], line=s), end=dict(m["end"], line=e), carried=True))
        if not live:
            continue  # nothing to mutate in this file: every in-scope mutant is carried
    ins, _ = fence(lines, live)
    write_fenced(f, lines, ins)
    print(f"{f}: lines {a}..{b}, {len(live)} live line(s), {len(ins)} directive(s)", file=sys.stderr)
    globs.append(f)
if carry_out:
    json.dump(carried, open(carry_out, "w"))
    print(f"targeted: {len(carried)} baseline mutant(s) carried forward", file=sys.stderr)
for f in globs:
    print(f"**/{key(f)}")
