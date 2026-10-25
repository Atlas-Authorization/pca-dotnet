using System.IO.Compression;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Rule 16 (OracleFacts: facts, relational dimensions, offer sets) and rule 17 (ParamProvenance: provenance, label receipts,
/// flows, read purpose) differential test against the TS reference (oracle-facts.ts, offer-set.ts, label-receipts.ts,
/// param-provenance.ts). test-data/k042-oracleprov.json.gz is written by tools/pca-audit/java-mutate/k042-oracleprov-oracle.mjs.
/// Every case compares the FULL result: exact validator reason, refusal reason, world (with member order), single_source, outcome,
/// friction, labels, classes, env, read-purpose lists, activity verdict, ratio_ppm and the flow-rule choice.</summary>
public class OracleProvOracleTests
{
    /// <summary>Where this verifier's reason differs from the reference BY DESIGN: a null / non-object input is refused by an input check or
    /// caught as an internal error (the exception's type name), where TypeScript checks the input type first. Pinned exactly.</summary>
    static readonly Dictionary<string, string> Own = new()
    {
        ["world/k042-input-null"] = "facts: action must be an object",
        ["world/k042-input-array"] = "facts: evaluation error (fail closed): InvalidCastException",
        ["prov/k042-input-null"] = "provenance: policy misconfigured (fail closed): provenance policy needs a params map",
        ["prov/k042-input-array"] = "provenance: evaluation error (fail closed): InvalidCastException",
    };

    static readonly Dictionary<string, Func<object?, string?>> Validators = new()
    {
        ["validateFactWire"] = OracleFacts.ValidateFactWire,
        ["validateWorldPolicy"] = OracleFacts.ValidateWorldPolicy,
        ["validateOfferPolicy"] = OracleFacts.ValidateOfferPolicy,
        ["validateOfferSetWire"] = OracleFacts.ValidateOfferSetWire,
        ["validateLabelsWire"] = ParamProvenance.ValidateLabelsWire,
        ["validateFlowRules"] = ParamProvenance.ValidateFlowRules,
        ["validateProvenancePolicy"] = ParamProvenance.ValidateProvenancePolicy,
        ["validateProvWire"] = ParamProvenance.ValidateProvWire,
    };

    static L Cases()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "test-data", "k042-oracleprov.json.gz");
            if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "k042-oracleprov.json.gz");
            if (!File.Exists(f)) continue;
            using var gz = new GZipStream(File.OpenRead(f), CompressionMode.Decompress);
            using var sr = new StreamReader(gz, new UTF8Encoding(false));
            return (L)IntentJs.Get(IntentJs.Normalize(Pca.ParseJson(sr.ReadToEnd())), "cases")!;
        }
        throw new FileNotFoundException("test-data/k042-oracleprov.json.gz");
    }

    static string Q(string s) => Pca.Canonicalize(s);

    /// <summary>JSON text keeping member ORDER (a reordered world / labels map is a difference), numbers by value.</summary>
    static string Ser(object? v)
    {
        switch (v)
        {
            case null: return "null";
            case string s: return Q(s);
            case bool b: return b ? "true" : "false";
            case IDictionary<string, object?> m: return "{" + string.Join(",", m.Select(e => Q(e.Key) + ":" + Ser(e.Value))) + "}";
            case IEnumerable<object?> l: return "[" + string.Join(",", l.Select(Ser)) + "]";
        }
        var d = IntentJs.NumOf(v);
        if (d != null) return d == Math.Round(d.Value) && Math.Abs(d.Value) < 1e17 ? ((long)d.Value).ToString() : d.Value.ToString("R", System.Globalization.CultureInfo.InvariantCulture);
        if (v is long or int) return v.ToString()!;
        return "<" + v.GetType().Name + ":" + v + ">";
    }

    static string? ReasonWant(string name, object? ts) => Own.TryGetValue(name, out var r) ? r : ts as string;

    [Fact]
    public void Oracle()
    {
        var cs = Cases();
        Assert.True(cs.Count > 1900, "only " + cs.Count + " cases");
        var errs = new List<string>(); int pinned = 0;
        foreach (D c in cs)
        {
            var name = (string)c["name"]!; var kind = (string)c["kind"]!;
            string got, want;
            try
            {
                switch (kind)
                {
                    case "fn": got = Ser(Validators[(string)c["fn"]!](c["arg"])); want = Ser(c["want"]); break;
                    case "ratio": got = Ser(OracleFacts.RatioPpm(IntentJs.Lng(c["a"]), IntentJs.Lng(c["b"]))); want = Ser(c["want"]); break;
                    case "flowRule": got = Ser(ParamProvenance.FlowRuleFor((D)c["rules"]!, (string)c["cls"]!)); want = Ser(c["want"]); break;
                    case "flowAllowed": got = Ser(ParamProvenance.FlowAllowed((D)c["rules"]!, (string)c["cls"]!, (string)c["origin"]!, c["aud"] as string)); want = Ser(c["want"]); break;
                    case "active": got = Ser(OracleFacts.IntentWorldActive(c["committed"], c["policy"])); want = Ser(c["expect"]); break;
                    case "read":
                    {
                        var r = ParamProvenance.DecideReadPurpose(c["input"]);
                        got = Ser(new D { ["outcome"] = r.Outcome, ["minimise"] = r.Minimise, ["uncovered"] = r.Uncovered });
                        var e = (D)c["expect"]!;
                        want = Ser(new D { ["outcome"] = e["outcome"], ["minimise"] = e["minimise"], ["uncovered"] = e["uncovered"] });
                        break;
                    }
                    case "world":
                    {
                        var r = OracleFacts.DecideIntentWorld(c["input"]);
                        var e = (D)c["expect"]!;
                        got = r.Ok ? "ok " + Ser(r.World) + " " + Ser(r.SingleSource) + " " + Ser(r.Reason) : "fail " + Ser(r.Reason) + " " + Ser(r.World) + " " + Ser(r.SingleSource);
                        want = e["ok"] is true ? "ok " + Ser(e["world"]) + " " + Ser(e.GetValueOrDefault("single_source")) + " null" : "fail " + Ser(ReasonWant(name, e["reason"])) + " null null";
                        if (Own.ContainsKey(name)) pinned++;
                        break;
                    }
                    case "prov":
                    {
                        var r = ParamProvenance.Decide(c["input"]);
                        var e = (D)c["expect"]!;
                        got = string.Join(" | ", r.Outcome, Ser(r.Reason), Ser(r.Friction), Ser(r.Labels), Ser(r.Classes), Ser(r.Env));
                        want = string.Join(" | ", (string)e["outcome"]!, Ser(ReasonWant(name, e["reason"])), Ser(e["friction"]), Ser(e["labels"]), Ser(e["classes"]), Ser(e["env"]));
                        if (Own.ContainsKey(name)) pinned++;
                        break;
                    }
                    default: throw new InvalidOperationException("unknown kind " + kind);
                }
            }
            catch (Exception ex) { errs.Add(name + " threw " + ex.GetType().Name + " " + ex.Message); continue; }
            if (got != want) errs.Add(name + "\n    got  " + got + "\n    want " + want);
        }
        Assert.Equal(Own.Count, pinned);
        Assert.True(errs.Count == 0, errs.Count + " mismatches:\n" + string.Join("\n", errs.Take(60)));
    }
}
