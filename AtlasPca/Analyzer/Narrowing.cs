using System.Text;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Least privilege from observed behaviour. <c>SuggestNarrowing</c> proposes a narrower replacement for a grant from what its
/// holder really did, plus the unused-permission findings ranked by blast radius and reversibility. It is a review artefact, never
/// applied: it only narrows (the proposal is the original predicate AND extra conditions, then PROVEN subsumed by the original; an
/// inexact proof withholds it), only ledger-sourced observations count, a denied attempt never loosens a grant (it becomes an access
/// request for a human), and an optional decay appends an <c>expires</c> caveat.</summary>
public static class Narrowing
{
    public const string AccessRequestSigDomain = "atlas-pca/access-request/v1\0";

    internal static int RevWeight(string r) => CaveatAnalysis.ReversibilityOrder.ToList().IndexOf(r) + 1;

    /// <summary>resolveAction(catalog, verb).spec: an uncatalogued verb is irreversible with the maximum blast radius.</summary>
    internal static (string Reversibility, double Blast) SpecOf(Catalog catalog, string verb)
    {
        var s = catalog.Get(verb);
        return s != null ? (s.Reversibility, s.BlastRadius) : ("irreversible", 1);
    }

    static string CommonPrefix(List<string> rs)
    {
        var p = rs.Count > 0 ? rs[0] : "";
        foreach (var r in rs)
        {
            int i = 0;
            while (i < p.Length && i < r.Length && p[i] == r[i]) i++;
            p = p[..i];
        }
        var cut = p.LastIndexOf('/');
        return cut >= 0 ? p[..(cut + 1)] : "";
    }

    static double OptNum(object? o, string k, double dflt)
    {
        var v = Jx.Opt(o, k);
        return v == null || Jx.IsUndef(v) ? dflt : Jx.ToNumber(v);
    }

    static object? ParamOf(object? a, string name)
    {
        var p = Jx.Prop(a, "params");
        if (p == null || Jx.IsUndef(p)) return Jx.Undef;
        return Jx.Prop(p, name);
    }

    static object ParamsOrEmpty(object? a)
    {
        var p = Jx.Prop(a, "params");
        return p == null || Jx.IsUndef(p) ? new D() : p;
    }

    static D CtxOf(object? a)
    {
        var act = new D();
        Jx.Set(act, "verb", Jx.Prop(a, "verb"));
        Jx.Set(act, "resource", Jx.Prop(a, "resource"));
        act["params"] = ParamsOrEmpty(a);
        return new D { ["action"] = act };
    }

    static bool Matches(object? p, object? a) => Predicates.PredicateMatches(p, CtxOf(a));

    static double UpperBoundOf(object? where, string path)
    {
        double ub = double.PositiveInfinity;
        if (where is L l)
            foreach (var c in l)
                if (c is D d && d.TryGetValue("field", out var f) && f is string fs && fs == path
                    && d.GetValueOrDefault("op") is string op && (op == "lte" || op == "lt") && Jx.IsNum(d.GetValueOrDefault("value")))
                    ub = Math.Min(ub, IntentJs.NumOf(d["value"])!.Value);
        return ub;
    }

    static string Str(object? o) => o as string ?? JsX.Str(o);

    static L Build(L baseP, List<object?> trusted, bool narrowResources, double margin, double minSamples, double enumLimit)
    {
        var @out = new L();
        foreach (var p in baseP)
        {
            var hits = trusted.Where(a => Matches(p, a)).ToList();
            if (hits.Count == 0) continue;
            var verbs = hits.Select(h => Str(Jx.Prop(h, "verb"))).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();
            var resources = hits.Select(h => Str(Jx.Prop(h, "resource"))).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();
            var next = new D { ["verb"] = verbs.Count == 1 ? (object)verbs[0] : verbs.Cast<object?>().ToList() };
            var pRes = Jx.Prop(p, "resource");
            if (narrowResources)
            {
                if (resources.Count == 1) next["resource"] = resources[0];
                else
                {
                    var pre = CommonPrefix(resources);
                    if (pre.Length > 1) next["resource"] = pre + "*";
                    else if (!Jx.IsUndef(pRes)) next["resource"] = pRes;
                }
            }
            else if (!Jx.IsUndef(pRes)) next["resource"] = pRes;
            var pw = Jx.Prop(p, "where");
            var where = new L();
            if (pw is L pl) where.AddRange(pl);
            var nameSet = new Jx.OSet();
            foreach (var h in hits)
            {
                var hp = Jx.Prop(h, "params");
                if (hp == null || Jx.IsUndef(hp)) continue;
                foreach (var k in JsX.Keys(hp)) nameSet.Add(k);
            }
            foreach (var name in nameSet.ToList().OrderBy(x => x, StringComparer.Ordinal))
            {
                var path = "action.params." + name;
                var vals = hits.Select(h => ParamOf(h, name)).ToList();
                if (vals.Count < minSamples || vals.Any(Jx.IsUndef)) continue;
                if (vals.All(v => Jx.Fin(v) != null))
                {
                    var nums = vals.Select(v => Jx.Fin(v)!.Value).ToList();
                    var v2 = nums.Max() * (1 + margin);
                    var ceil = nums.All(d => d == Math.Floor(d)) ? Math.Ceiling(v2) : v2;
                    if (ceil < UpperBoundOf(pw, path)) where.Add(new D { ["field"] = path, ["op"] = "lte", ["value"] = Jx.N(ceil) });
                }
                else if (vals.All(v => v is string))
                {
                    var set = vals.Select(v => (string)v!).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();
                    if (set.Count <= enumLimit) where.Add(new D { ["field"] = path, ["op"] = "in", ["value"] = set.Cast<object?>().ToList() });
                }
            }
            if (where.Count > 0) next["where"] = where;
            @out.Add(next);
        }
        return @out;
    }

    sealed class Finding
    {
        public double Rank; public double Pred; public D Obj = new();
    }

    static Finding MakeFinding(string kind, int i, string? verb, string detail, (string Reversibility, double Blast) s, bool withVerb)
    {
        var o = new D { ["kind"] = kind, ["predicate"] = Jx.N(i) };
        if (withVerb) o["verb"] = verb;
        o["detail"] = detail;
        o["blastRadius"] = Jx.N(s.Blast);
        o["reversibility"] = s.Reversibility;
        var rank = s.Blast * RevWeight(s.Reversibility);
        o["rank"] = Jx.N(rank);
        return new Finding { Rank = rank, Pred = i, Obj = o };
    }

    sealed class Group { public D R = new(); public int N; }

    /// <summary>Propose a narrower grant from what the holder did, and list what was never used. Observed items are
    /// {verb, resource, params?, source: "ledger" | "agent", outcome?: "allowed" | "denied", entry?}. Options: margin (default 0.1), minSamples (5),
    /// enumLimit (8), taskBinding, decay {nowSec, expiresInSecs}. A null catalog is the built-in connector catalog.</summary>
    public static D SuggestNarrowing(object? policy, object? observed, object? o = null, Catalog? catalog = null)
    {
        var margin = OptNum(o, "margin", 0.1);
        var minSamples = OptNum(o, "minSamples", 5);
        var enumLimit = OptNum(o, "enumLimit", 8);
        var cat = catalog ?? Catalog.Default;
        var model = Enumerate.ToModel(policy);
        var digest = Residual.PolicyDigestOf(model);

        var obs = observed as L ?? throw JsX.TypeError("observed is not iterable");
        var trusted = new List<object?>();
        var refused = new List<object?>();
        int rejected = 0;
        foreach (var x in obs)
        {
            var ledger = Jx.Prop(x, "source") is string src && src == "ledger";
            var denied = Jx.Prop(x, "outcome") is string oc && oc == "denied";
            if (!ledger) rejected++;
            else if (denied) refused.Add(x);
            else trusted.Add(x);
        }
        var findings = new List<Finding>();
        var pr = Jx.Opt(policy, "predicates");
        var baseP = pr is L bl ? bl : new L();

        for (int i = 0; i < baseP.Count; i++)
        {
            var p = baseP[i];
            var hit = trusted.Any(a => Matches(p, a));
            var pv = Jx.Prop(p, "verb");
            var verbs = pv is string ? new L { pv } : pv is L vl ? new L(vl) : new L();
            if (!hit)
            {
                var v = verbs.Count > 0 && verbs[0] != null ? Str(verbs[0]) : "*";
                var s = SpecOf(cat, v == "*" ? "unknown.any" : v);
                var joined = string.Join(", ", verbs.Select(x => x == null ? "" : JsX.Str(x)));
                findings.Add(MakeFinding("unused-predicate", i, v, $"no observed action used predicate {i} ({(joined.Length > 0 ? joined : "*")})", s, true));
                continue;
            }
            foreach (var v in verbs)
            {
                if (v is string vs0 && vs0 == "*") continue;
                if (!trusted.Any(a => JsX.StrictEq(Jx.Prop(a, "verb"), v) && Matches(p, a)))
                {
                    var s = SpecOf(cat, Str(v));
                    findings.Add(MakeFinding("unused-verb", i, Str(v), $"verb {Str(v)} is granted by predicate {i} but never used", s, true));
                }
            }
            if (Jx.Prop(p, "where") is L pwl)
                foreach (var c in pwl)
                {
                    if (c is D cd && cd.GetValueOrDefault("field") is string f && cd.GetValueOrDefault("op") is string op && (op == "lte" || op == "lt")
                        && Jx.IsNum(cd.GetValueOrDefault("value")) && f.StartsWith("action.params.", StringComparison.Ordinal))
                    {
                        var name = f["action.params.".Length..];
                        var vals = trusted.Where(a => Matches(p, a)).Select(a => ParamOf(a, name)).Where(Jx.IsNum).Select(v => IntentJs.NumOf(v)!.Value).ToList();
                        var mx = vals.Count > 0 ? vals.Max() : double.NegativeInfinity;
                        var cv = IntentJs.NumOf(cd["value"])!.Value;
                        if (vals.Count >= minSamples && mx < cv / 2)
                        {
                            var v0 = verbs.Count > 0 ? verbs[0] : Jx.Undef;
                            var s = SpecOf(cat, Jx.Truthy(v0) ? Str(v0) : "unknown.any");
                            findings.Add(MakeFinding("unreached-cap", i, Jx.Truthy(v0) ? Str(v0) : null, $"{name} <= {Jx.NumStr(cv)} but the largest observed value is {Jx.NumStr(mx)}", s, Jx.Truthy(v0)));
                        }
                    }
                }
        }
        var sorted = findings.OrderByDescending(f => f.Rank).ThenBy(f => f.Pred).Select(f => (object?)f.Obj).ToList();

        var groups = new List<(string Key, Group G)>();
        foreach (var a in refused)
        {
            var k = Str(Jx.Prop(a, "verb")) + "\u0000" + Str(Jx.Prop(a, "resource"));
            var idx = groups.FindIndex(g => g.Key == k);
            if (idx >= 0) { groups[idx].G.N++; continue; }
            var r = new D { ["v"] = Jx.N(1), ["kind"] = "pca-access-request" };
            Jx.Set(r, "verb", Jx.Prop(a, "verb")); Jx.Set(r, "resource", Jx.Prop(a, "resource"));
            r["example_params"] = JsX.Spread(ParamsOrEmpty(a));
            r["denied_count"] = Jx.N(1);
            r["policy_digest"] = digest;
            if (Jx.Truthy(Jx.Opt(o, "taskBinding"))) r["task_binding"] = Jx.Opt(o, "taskBinding");
            groups.Add((k, new Group { R = r, N = 1 }));
        }
        var reqs = groups.Select(g => g.G).OrderByDescending(g => g.N).ThenBy(g => Str(g.R.GetValueOrDefault("verb")), StringComparer.Ordinal).ToList();
        foreach (var g in reqs) g.R["denied_count"] = Jx.N(g.N);

        var res = new D
        {
            ["used"] = Jx.N(trusted.Count), ["rejected"] = Jx.N(rejected), ["denied"] = Jx.N(refused.Count), ["coversObserved"] = false,
            ["findings"] = sorted, ["accessRequests"] = reqs.Select(g => (object?)g.R).ToList(),
        };
        if (Jx.Truthy(Jx.Opt(o, "taskBinding"))) res["taskBinding"] = Jx.Opt(o, "taskBinding");

        var caveats = new L(model.Caveats);
        var decay = Jx.Opt(o, "decay");
        if (Jx.Truthy(decay)) caveats.Add(new D { ["type"] = "expires", ["at"] = Jx.N(Jx.ToNumber(Jx.Prop(decay, "nowSec")) + Jx.ToNumber(Jx.Prop(decay, "expiresInSecs"))) });
        foreach (var narrowResources in new[] { true, false })
        {
            var predicates = Build(baseP, trusted, narrowResources, margin, minSamples, enumLimit);
            var proposal = new D { ["predicates"] = predicates, ["caveats"] = caveats, ["vetoes"] = model.Vetoes, ["tighten"] = model.Tighten };
            if (predicates.Count == 0)
            {
                res["reason"] = "no ledger observation matches any predicate";
                return res;
            }
            var proof = AnalyzerCore.Subsumes(policy, proposal);
            if (!(proof.GetValueOrDefault("subsumes") is true) || proof.GetValueOrDefault("approximate") is true)
            {
                res["reason"] = proof.TryGetValue("reason", out var why) && why != null ? why : "the proposal could not be proven narrower than the original";
                continue;
            }
            res.Remove("reason");
            res["proposal"] = proposal;
            res["coversObserved"] = trusted.All(a =>
            {
                var act = new D();
                Jx.Set(act, "verb", Jx.Prop(a, "verb")); Jx.Set(act, "resource", Jx.Prop(a, "resource"));
                act["params"] = ParamsOrEmpty(a);
                return AnalyzerCore.AdmitsConcrete(proposal, act);
            });
            res["diff"] = Exposure.DiffPolicies(policy, proposal);
            return res;
        }
        return res;
    }

    // ---- access requests ----

    static byte[] RequestMessage(object? r)
    {
        var pre = Encoding.UTF8.GetBytes(AccessRequestSigDomain);
        var d = Pca.Sha(Encoding.UTF8.GetBytes(Pca.HashCanonical(r)));
        return Pca.Cat(pre, d);
    }

    /// <summary>The agent's (or its holder's) signed ask: {request, signer, sig}. A request for a human to read; nothing here turns it into authority.</summary>
    public static D SignAccessRequest(object? request, byte[] secretSeed, string signerPublic)
    {
        using var key = EdKey.FromSeed(secretSeed);
        return new D { ["request"] = request, ["signer"] = signerPublic, ["sig"] = Pca.B64u(key.Sign(RequestMessage(request))) };
    }

    /// <summary>Is the signed request well formed and signed by the signer (a null <paramref name="expectedSigner"/> is any)? Never throws.</summary>
    public static bool VerifyAccessRequest(object? s, string? expectedSigner = null)
    {
        try
        {
            if (s is not D sd || !sd.TryGetValue("request", out var req) || req is not D rd) return false;
            if (!(rd.GetValueOrDefault("kind") is string kind && kind == "pca-access-request")) return false;
            if (!(IntentJs.NumOf(rd.GetValueOrDefault("v")) is double v && v == 1)) return false;
            var signer = sd.GetValueOrDefault("signer");
            if (expectedSigner != null && !(signer is string sg0 && sg0 == expectedSigner)) return false;
            if (sd.GetValueOrDefault("sig") is not string sig) return false;
            var pk = Pca.B64uDecode(signer, 32);
            var sb = Pca.B64uDecode(sig, 64);
            if (pk == null || sb == null) return false;
            return Pca.VerifyEd25519Strict(pk, RequestMessage(req), sb);
        }
        catch (Exception)
        {
            return false;
        }
    }
}
