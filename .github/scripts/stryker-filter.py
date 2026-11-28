#!/usr/bin/env python3
"""Narrow a shard's Stryker pass to the test classes that ran (or killed) its mutants in an earlier run.

  python3 stryker-filter.py <stryker-config.json> <stryker-baseline.json of an earlier run of this shard>

The baseline's "classes" (stryker-report.py: the classes that covered an in-scope mutant, plus the classes whose test killed one
alone) become the config's test-case-filter, and test projects with none of them are dropped. Only a speed hint: whatever this
narrower pass does not kill (a test outside the list, a stale list) is re-tested alone against both full test projects by
stryker-isolate.py, so no mutant is decided by the list. No usable list: the config is left as it is (the whole oracle)."""
import json, os, re, sys

CLASS = re.compile(r"^[A-Za-z_][A-Za-z0-9_.+]*$")

def narrow(conf, classes):
    """conf with test-case-filter and test-projects cut down to classes, or None (no usable class: keep the whole oracle)."""
    c = conf["stryker-config"]
    projs = c["test-projects"]
    proj = lambda p: os.path.basename(p)[: -len(".csproj")]
    keep = sorted({k for k in classes if CLASS.match(k) and any(k.startswith(proj(p) + ".") for p in projs)})
    if not keep:
        return None
    new = dict(c, **{"test-projects": [p for p in projs if any(k.startswith(proj(p) + ".") for k in keep)],
                     "test-case-filter": f"({c['test-case-filter']})&({'|'.join('FullyQualifiedName~' + k + '.' for k in keep)})"})
    return {**conf, "stryker-config": new}

_c = {"stryker-config": {"test-projects": ["A.Tests.csproj", "../B.Tests/B.Tests.csproj"], "test-case-filter": "Category!=Huge"}}
_n = narrow(_c, ["A.Tests.X", "A.Tests.Y`1", "C.Tests.Z"])
assert _n["stryker-config"] == {"test-projects": ["A.Tests.csproj"], "test-case-filter": "(Category!=Huge)&(FullyQualifiedName~A.Tests.X.)"}, _n
assert narrow(_c, []) is None and narrow(_c, ["Other.X"]) is None

if __name__ == "__main__":
    cfg, base = sys.argv[1], sys.argv[2]
    conf = json.load(open(cfg))
    n = narrow(conf, json.load(open(base)).get("classes") or []) if os.path.exists(base) else None
    if n is None:
        print("no recorded covering classes: Stryker runs the whole oracle")
    else:
        json.dump(n, open(cfg, "w"), indent=1)
        k = n["stryker-config"]["test-case-filter"].count("FullyQualifiedName~")
        print(f"Stryker runs the {k} test class(es) that ran this shard's mutants last time; anything they do not kill is re-run against the full oracle")
