#!/usr/bin/env python3
"""Shard K of N of the Stryker.NET run over AtlasPca/: prints one --mutate glob per line, fences the shard's files (CI copy
only) with Stryker comment directives so only the wanted members are mutated, and writes the shard's scope.

   python3 stryker-spans.py <k> <n> <AtlasPca dir> --scope <scope.json> [--baseline <baseline.json> --carry <carried.json>]

PLAN lists every .cs file of AtlasPca/ exactly once (balanced by size, ~500-600 lines a shard); Pca.cs is split into
PCA_SPANS line spans cut only at member declarations (indent 0 or 4 in the file-scoped namespace), so no mutant crosses a
cut and the spans partition the file. A .cs file missing from PLAN (or a planned file that is gone) fails the shard, so a
new source file is never silently left out.

FENCING: a `// Stryker disable all` comment only disables the syntax node it is attached to (the declaration right below
it): it does NOT run on to a later `// Stryker restore all` across sibling members (0.4.2 run 38330673581: every Pca.cs
shard tested the whole file, 3x the work, and every Pca.cs survivor was reported three times). So a top-level type with no
live line gets its own directive line, and inside a type with live lines every member declaration (indent 4, its attribute
lines included) without one gets one. Live = the shard's Pca.cs span (full mode), or the lines that changed since the
baseline (targeted mode). A `--mutate Pca.cs{a..b}` line filter is not used: with it Stryker.NET 4.8 reported every in-span
mutant as a compile error. The inserted directive lines are whole lines `// Stryker disable all`; the report step drops
them again (line numbers of the original file).

--scope: {"AtlasPca/<file>.cs": [first, last]} (original-file lines the shard owns). The report step counts and lists only
in-scope mutants: Stryker compiles (and reports CompileError for) the mutants of EVERY file of the project in every shard
(run 38330673581: ~1,489 CompileErrors in each of the 12 shards, 17,834 in all, whatever the shard mutated).

TARGETED mode (--baseline = the stryker-baseline.json the same shard uploaded in an earlier run: its sources, scope and
every in-scope mutant with its status): the lines of the current sources that are not an unchanged copy of an in-scope
baseline line are live (edited, added, next to a deletion, or newly in scope). Only the members holding a live line are
mutated by Stryker (none: no glob is printed and Stryker is skipped). Every baseline mutant that lies, unchanged, in a
fenced member is written to --carry with its line numbers moved to the current source; the report step keeps its
Killed / Timeout / tested CompileError result and re-tests the others (Survived, NoCoverage, untested CompileError) one by
one with stryker-isolate.py, so new kill tests are seen without re-running Stryker over the whole shard."""
import difflib, json, os, re, sys

PCA_SPANS = 3
PLAN = [
    ["SafeRegex.cs"],
    ["IntentV2.cs"],
    ["IntentAcc.cs", "Caveats.cs"],
    ["IntentMap.cs", "IntentWB.cs"],
    ["Predicates.cs", "IntentSession.cs"],
    ["OracleFacts.cs", "IntentJs.cs"],
    ["ActionSchema.cs", "IntentRevocation.cs"],
    ["ParamProvenance.cs", "IntentPrimitives.cs", "LessNative.cs"],
    ["IntentClassifier.cs", "IntentArtifacts.cs"],
    ["Authorize.cs"],
    ["Operations.cs", "AtomicKv.cs", "Executor.cs"],
    ["PlanLifecycle.cs", "Escalation.cs", "RevocationFreshness.cs"],
    ["Assurance.cs", "StepUp.cs"],
    ["StoreConformance.cs", "Decision.cs"],
    ["Passport.cs", "IntentHistory.cs"],
]

def opt(name):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    return None

k, n, d = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
scope_out, baseline_in, carry_out = opt("--scope"), opt("--baseline"), opt("--carry")
if not scope_out or bool(baseline_in) != bool(carry_out):
    sys.exit("usage: stryker-spans.py <k> <n> <AtlasPca dir> --scope <json> [--baseline <json> --carry <json>]")
if n != PCA_SPANS + len(PLAN):
    sys.exit(f"the workflow runs {n} shards but the plan has {PCA_SPANS + len(PLAN)}: keep SHARDS in step with stryker-spans.py")
files = sorted(f for f in os.listdir(d) if f.endswith(".cs"))
planned = sorted(["Pca.cs"] + [f for s in PLAN for f in s])
if files != planned:
    sys.exit(f"AtlasPca/ has {files}, the plan covers {planned}: update PLAN in stryker-spans.py")

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

# the shard's scope (original-file lines)
if k > PCA_SPANS:
    scope = {f"AtlasPca/{f}": [1, len(read(f))] for f in PLAN[k - PCA_SPANS - 1]}
else:
    lines = read("Pca.cs")
    starts = [t for t, _, ms in units(lines) for t in [t] + [a for a, _ in ms]]
    cuts = []
    for j in range(1, PCA_SPANS):
        target = j * len(lines) / PCA_SPANS
        cuts.append(min((x for x in starts if x > (cuts[-1] if cuts else 1)), key=lambda x: abs(x - target)))
    bounds = [1] + cuts + [len(lines) + 1]
    scope = {"AtlasPca/Pca.cs": [bounds[k - 1], bounds[k] - 1]}
json.dump(scope, open(scope_out, "w"))

base = json.load(open(baseline_in)) if baseline_in else None
carried, globs = [], []
for rel, (a, b) in scope.items():
    f = rel.split("/", 1)[1]
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
    print(f"**/AtlasPca/{f}")
