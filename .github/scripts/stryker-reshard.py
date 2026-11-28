#!/usr/bin/env python3
"""Re-shard stryker-spans.py's PLAN by measured cost: shard k becomes p pieces (the first keeps number k, the rest are appended).

  python3 stryker-reshard.py <stryker-spans.py> <AtlasPca dir> <pieces.json | dir of cost-<k>.json> [<comment for the new rows>]
     pieces.json: {"<shard>": <pieces>, ...}; a directory: the shards' measured cost files, cut by the model below (at most 4 each)

Prints {"<shard>": [<its new shard numbers>]} and rewrites PLAN in place. A shard's entries are cut (each cut keeps the plan a
partition: a whole file becomes spans 1..2 of 2, a span gets slices 1..2 of 2, and a slice j of m of a span re-slices that whole
span into 2m, every other shard holding a slice of it keeping its share as two slices) until it has at least p of them or none can be
cut again at a member declaration, then packed into p shards by code lines. The workflow's shard count and matrix lists must follow."""
import ast, json, math, os, re, sys

# Cost model (run 45873188747 after its fixes): ~17 min fixed, ~3.6 min per survivor / NoCoverage (one full-suite run beside 3 other
# workers), ~0.4 min per other retest; a shard gets 33 of its 50 minutes for mutants. Stryker's own per-mutant time is not in cost-<k>.json.
FIXED, BUDGET, SURV, OTHER = 17, 50, 3.6, 0.4
def pieces_of(cost):
    r = cost.get("retest", {})
    surv = r.get("Survived", 0) + r.get("NoCoverage", 0)
    return max(1, math.ceil((surv * SURV + (sum(r.values()) - surv) * OTHER) / (BUDGET - FIXED)))
assert pieces_of({"retest": {"Survived": 9, "CompileError": 10}}) == 2 and pieces_of({}) == 1

spans_py, d, src3 = sys.argv[1], sys.argv[2], sys.argv[3]
if os.path.isdir(src3):  # the cost-<k>.json files of a run's shard-<k> artifacts
    pieces = {int(f[5:-5]): pieces_of(json.load(open(os.path.join(src3, f)))) for f in os.listdir(src3) if re.fullmatch(r"cost-\d+\.json", f)}
    pieces = {k: min(4, v) for k, v in pieces.items() if v > 1}
else:
    pieces = {int(k): v for k, v in json.load(open(src3)).items()}
src = open(spans_py).read()
ns = {"re": re, "sys": sys}
for name in ("parse", "units", "cut"):
    i = src.index("\ndef " + name + "(") + 1
    exec(src[i: i + re.search(r"\n(?=\S)", src[i:]).start()], ns)  # the function only, up to the next top-level line
i0 = src.index("PLAN = [")
i1 = src.index("\n]\n", i0) + 2
plan = ast.literal_eval(src[i0 + 7: i1])
cache = {}
def starts(f):
    if f not in cache:
        lines = open(os.path.join(d, f), encoding="utf-8").read().split("\n")
        cache[f] = (lines, [t for t, _, ms in ns["units"](lines) for t in [t] + [a for a, _ in ms]])
    return cache[f]
def lines_of(it):
    """Code lines of an entry, or None when it cannot be cut there (no member declaration left)."""
    f, (i, n), (j, m) = ns["parse"](it)
    lines, st = starts(f)
    try:
        a, b = ns["cut"](st, 1, len(lines), n, i)
        a, b = ns["cut"](st, a, b, m, j)
    except SystemExit:
        return None
    return sum(1 for l in lines[a - 1: b] if l.strip() and not l.strip().startswith("//"))
def fmt(f, i, n, j, m):
    return f + ("" if n == 1 else f"#{i}/{n}") + ("" if m == 1 else f"@{j}/{m}")

def split(it):
    """{entry: [its replacement entries]} for cutting `it` in two (the other shards' slices of the same span included), or None."""
    f, (i, n), (j, m) = ns["parse"](it)
    if n == 1 and m == 1:
        rep = {it: [fmt(f, 1, 2, 1, 1), fmt(f, 2, 2, 1, 1)]}
    elif m == 1:
        rep = {it: [fmt(f, i, n, 1, 2), fmt(f, i, n, 2, 2)]}
    else:
        rep = {fmt(f, i, n, jj, m): [fmt(f, i, n, 2 * jj - 1, 2 * m), fmt(f, i, n, 2 * jj, 2 * m)] for jj in range(1, m + 1)}
    return rep if all(lines_of(x) is not None for v in rep.values() for x in v) else None

out = {}
for k in sorted(pieces):
    p = pieces[k]
    while len(plan[k - 1]) < p:
        # cut the biggest entry only: cutting a small one to reach p shards saves nothing (a span that is one long member stops here)
        big = max(plan[k - 1], key=lambda x: lines_of(x) or 0)
        rep = split(big)
        if rep is None or min(lines_of(x) or 0 for x in rep[big]) < (lines_of(big) or 0) / 5:
            break
        plan = [[y for x in sh for y in rep.get(x, [x])] for sh in plan]
    p = min(p, len(plan[k - 1]))
    bins = [[] for _ in range(p)]
    for it in sorted(plan[k - 1], key=lambda x: -(lines_of(x) or 0)):
        min(bins, key=lambda b: sum(lines_of(x) or 0 for x in b)).append(it)
    plan[k - 1] = bins[0]
    out[k] = [k] + list(range(len(plan) + 1, len(plan) + p))
    plan += bins[1:]

# the result must still partition every file (the check stryker-spans.py runs in every shard)
parts = {}
for it in (x for sh in plan for x in sh):
    f, (i, n), (j, m) = ns["parse"](it)
    parts.setdefault(f, []).append((i, n, j, m))
for f, ps in parts.items():
    n = ps[0][1]
    assert all(q[1] == n for q in ps), f
    for i in range(1, n + 1):
        sl = sorted((j, m) for (i2, _, j, m) in ps if i2 == i)
        assert sl and sl == [(j, sl[0][1]) for j in range(1, sl[0][1] + 1)], (f, sorted(ps))
# rewrite the rows in place (one row per line; the plan's comments stay), the new rows go last
row = lambda sh: "    [" + ", ".join(json.dumps(x) for x in sh) + "],"
body = src[i0: i1].split("\n")
at = [n for n, l in enumerate(body) if l.strip().startswith("[")]
assert len(at) == len(old_len := ast.literal_eval(src[i0 + 7: i1])), "one PLAN row per line"
for n, sh in zip(at, plan):
    body[n] = row(sh)
end = max(n for n, l in enumerate(body) if l.strip() == "]")
note = f"    # {sys.argv[4]}" if len(sys.argv) > 4 else "    # re-sharded by measured cost (stryker-reshard.py)"
body[end:end] = [note] + [row(sh) for sh in plan[len(at):]] if len(plan) > len(at) else []
open(spans_py, "w").write(src[:i0] + "\n".join(body) + src[i1:])
print(json.dumps({str(k): v for k, v in out.items()}))
