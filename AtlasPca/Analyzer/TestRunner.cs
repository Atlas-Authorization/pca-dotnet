using System.Text;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Policy-as-code test runner. A policy test document lists actions with the decision the author expects (and optionally the clause
/// expected to decide). It names the policy it was written for by digest and may be signed, so a recompile that drifts must still reproduce
/// every confirmed example or the run fails. <see cref="GenerateBoundaryTests"/> writes the examples a reviewer would otherwise have to think
/// of: one minimal allow per permit clause, one trigger per prohibition, and for every numeric threshold the points just below, at and just
/// above it. Expectations in a generated document are the policy's CURRENT behaviour, to be read and confirmed by a person.</summary>
public static class TestRunner
{
    public const string PolicyTestsKind = "pca-policy-tests";
    public const string PolicyTestsSigDomain = "atlas-pca/policy-tests/v1\0";

    /// <summary>{v: 1, kind, policy_digest, cases}: the document for <paramref name="policy"/> over <paramref name="cases"/> ({name, action, expect, decidedBy?}).</summary>
    public static D PolicyTestsDoc(object? policy, object? cases) => new()
    {
        ["v"] = Jx.N(1), ["kind"] = PolicyTestsKind, ["policy_digest"] = Residual.PolicyDigestOf(Enumerate.ToModel(policy)), ["cases"] = cases,
    };

    static L CasesOf(object? doc) => Jx.Prop(doc, "cases") as L ?? throw JsX.TypeError("doc.cases is not iterable");

    /// <summary>Run a document against a policy: {total, passed, failures, digestMatch, ok}. With requireDigest a changed policy fails even if every case passes.</summary>
    public static D RunPolicyTests(object? policy, object? doc, object? opts = null)
    {
        var model = Enumerate.ToModel(policy);
        var cases = CasesOf(doc);
        var failures = new L();
        foreach (var c in cases)
        {
            var w = Coverage.WitnessOf(model, Jx.Prop(c, "action"));
            var decidedBy = ((D)w["winner"]!)["id"];
            var cb = Jx.Prop(c, "decidedBy");
            if (!JsX.StrictEq(w["decision"], Jx.Prop(c, "expect")) || (!Jx.IsUndef(cb) && !JsX.StrictEq(cb, decidedBy)))
            {
                var f = new D();
                Jx.Set(f, "name", Jx.Prop(c, "name"));
                Jx.Set(f, "expected", Jx.Prop(c, "expect"));
                f["got"] = w["decision"];
                f["decidedBy"] = decidedBy;
                if (!Jx.IsUndef(cb)) f["expectedDecidedBy"] = cb;
                failures.Add(f);
            }
        }
        var digestMatch = JsX.StrictEq(Jx.Prop(doc, "policy_digest"), Residual.PolicyDigestOf(model));
        var require = Jx.Opt(opts, "requireDigest") is true;
        return new D
        {
            ["total"] = Jx.N(cases.Count), ["passed"] = Jx.N(cases.Count - failures.Count), ["failures"] = failures, ["digestMatch"] = digestMatch,
            ["ok"] = failures.Count == 0 && (!require || digestMatch),
        };
    }

    static byte[] Message(object? doc)
    {
        var pre = Encoding.UTF8.GetBytes(PolicyTestsSigDomain);
        return Pca.Cat(pre, Pca.Sha(Encoding.UTF8.GetBytes(Pca.HashCanonical(doc))));
    }

    /// <summary>The principal signs the confirmed examples: {doc, signer, sig}.</summary>
    public static D SignPolicyTests(object? doc, byte[] secretSeed, string signerPublic)
    {
        using var key = EdKey.FromSeed(secretSeed);
        return new D { ["doc"] = doc, ["signer"] = signerPublic, ["sig"] = Pca.B64u(key.Sign(Message(doc))) };
    }

    /// <summary>Is the signed document signed by <paramref name="expectedSigner"/>? Never throws.</summary>
    public static bool VerifyPolicyTests(object? s, string? expectedSigner)
    {
        try
        {
            if (s is not D sd) return false;
            var signer = sd.GetValueOrDefault("signer");
            if (!(signer is string sg && expectedSigner != null && sg == expectedSigner)) return false;
            if (!(sd.GetValueOrDefault("doc") is D doc && doc.GetValueOrDefault("kind") is string kind && kind == PolicyTestsKind)) return false;
            if (sd.GetValueOrDefault("sig") is not string sig) return false;
            var pk = Pca.B64uDecode(signer, 32);
            var sb = Pca.B64uDecode(sig, 64);
            if (pk == null || sb == null) return false;
            return Pca.VerifyEd25519Strict(pk, Message(doc), sb);
        }
        catch (Exception)
        {
            return false;
        }
    }

    static void Walk(object? c, Jx.OSet @out)
    {
        if (c is not D o) return;
        if (o.GetValueOrDefault("field") is string f && f.StartsWith("action.params.", StringComparison.Ordinal)) @out.Add(f);
        foreach (var k in new[] { "all_of", "any_of" })
            if (o.GetValueOrDefault(k) is L kids) foreach (var x in kids) Walk(x, @out);
        var neg = o.GetValueOrDefault("not");
        if (Jx.Truthy(neg)) Walk(neg, @out);
    }

    static List<string> ParamPaths(object? p)
    {
        var @out = new Jx.OSet();
        if (Jx.Opt(p, "where") is L w) foreach (var c in w) Walk(c, @out);
        return @out.ToList();
    }

    /// <summary>Boundary examples for every clause and numeric threshold of the policy; expectations are the current behaviour. Options: epsilon (default 1).</summary>
    public static D GenerateBoundaryTests(object? policy, object? o = null)
    {
        var epsV = Jx.Opt(o, "epsilon");
        var eps = epsV == null || Jx.IsUndef(epsV) ? 1 : Jx.ToNumber(epsV);
        var model = Enumerate.ToModel(policy);
        var cases = new L();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Add(string name, object? action)
        {
            if (!seen.Add(AtlasPca.Js.JsJson.Stringify(action))) return;
            var w = Coverage.WitnessOf(model, action);
            var c = new D { ["name"] = name, ["action"] = action, ["expect"] = w["decision"] };
            var id = ((D)w["winner"]!)["id"];
            if (id != null) c["decidedBy"] = id;
            cases.Add(c);
        }
        for (int i = 0; i < model.Predicates.Count; i++)
        {
            var p = model.Predicates[i];
            var r = AnalyzerCore.AlwaysDenies(new D { ["predicates"] = new L { p }, ["caveats"] = model.Caveats, ["vetoes"] = model.Vetoes, ["tighten"] = model.Tighten });
            var base0 = r.GetValueOrDefault("witness");
            base0 ??= AnalyzerCore.AlwaysDenies(new D { ["predicates"] = new L { p }, ["caveats"] = model.Caveats }).GetValueOrDefault("witness");
            if (base0 is not D bd) continue;
            var pid = Coverage.PermitId(i);
            Add($"{pid}: minimal admitted action", bd);
            foreach (var path in ParamPaths(p))
            {
                var name = path["action.params.".Length..];
                foreach (var t in Exposure.ThresholdsOf(Enumerate.ToModel(new D { ["predicates"] = new L { p } }), path))
                {
                    var tags = new[] { "below", "at", "above" };
                    var vs = new[] { t - eps, t, t + eps };
                    for (int k = 0; k < 3; k++)
                    {
                        var prm = JsX.Spread(bd.GetValueOrDefault("params"));
                        prm[name] = Jx.N(vs[k]);
                        var a = Jx.Copy(bd); a["params"] = prm;
                        Add($"{pid}: {name} {tags[k]} {Jx.NumStr(t)}", a);
                    }
                }
            }
            var other = Jx.Copy(bd);
            other["resource"] = (bd.TryGetValue("resource", out var rs) ? JsX.Str(rs) : "undefined") + "/__other__";
            Add($"{pid}: unmentioned resource", other);
        }
        // a trigger per prohibition: an action some permit would allow and this prohibition stops (so the prohibition is what is tested)
        var permitOnly = new PolicyModel
        {
            Predicates = model.Predicates, Caveats = model.Caveats, Vetoes = new L(), Tighten = new L(), Meets = model.Meets,
            CaveatSat = model.CaveatSat, CaveatReason = model.CaveatReason, RevCap = model.RevCap, Undecidable = model.Undecidable,
        };
        var pr = Enumerate.CollectProbes(new ProbeInputs { PredicateSets = new List<L> { Enumerate.ProbeSet(model) }, VaryReversibility = model.RevCap != null });
        foreach (var v in model.Vetoes)
        {
            var (hits, _) = Enumerate.Collect(pr, rep => Enumerate.Decide(permitOnly, rep) != "deny" && Enumerate.VetoApplies(v, Enumerate.ContextOfAction(Enumerate.RepToAction(rep))), Enumerate.DefaultMaxCombinations, 1);
            if (hits.Count > 0) Add($"{JsX.Str(Jx.Prop(v, "id"))}: trigger", Enumerate.RepToAction(hits[0]));
        }
        return PolicyTestsDoc(policy, cases);
    }

    /// <summary>The decision of every case under <paramref name="policy"/> (for a table in a PR comment).</summary>
    public static L DecideAll(object? policy, object? doc)
    {
        var model = Enumerate.ToModel(policy);
        var @out = new L();
        foreach (var c in CasesOf(doc)) @out.Add(Enumerate.DecideAction(model, Jx.Prop(c, "action")));
        return @out;
    }
}
