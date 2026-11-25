using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the elicitation learner (posterior, metrics, questions, synthesis, elicitation loop) against the TypeScript reference
/// (test-data/ref-intent-learner.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentLearnerTests
{
    const string M = "ref-intent-learner";

    internal static L Ints(IEnumerable<int> xs) => xs.Select(x => (object?)N(x)).ToList();
    static Outcome Oc(D op) => OutcomeFromJson(new D { ["verb"] = op["verb"], ["values"] = op["values"] });

    internal static object? Q(IntentLearner.Question? q) => q == null ? null : new D
    {
        ["verb"] = q.Verb, ["cell"] = Ints(q.Cell), ["outcome"] = OutcomeToJson(q.Outcome), ["p"] = N(q.P), ["score"] = N(q.Score),
    };

    static object? NumN(double? d) => d is double x ? N(x) : null;

    internal static D Met(IntentLearner.LearnerMetrics r) => new()
    {
        ["residualRisk"] = N(r.ResidualRisk), ["burden"] = N(r.Burden), ["uncertainty"] = N(r.Uncertainty), ["entropyBits"] = N(r.EntropyBits),
        ["log2VersionSpace"] = NumN(r.Log2VersionSpace), ["disagreementMass"] = N(r.DisagreementMass), ["meanHarm"] = N(r.MeanHarm),
        ["questions"] = N(r.Questions), ["conflicts"] = N(r.Conflicts),
    };

    static IntentLearner.LearnerOptions Options(object? o)
    {
        var m = (D)o!;
        var opts = IntentLearner.LearnerOptions.FromJson(o);
        if ((m.GetValueOrDefault("nullMassFn") as string) == "byRev") opts.NullMassFn = vs => vs.Reversibility == "reversible" ? 0.1 : 0.3;
        if (m.GetValueOrDefault("priorMix") is D pm)
        {
            var kind = (string)pm["weight"]!;
            Func<VerbSpace, Func<int, bool>, double> wt = kind == "size"
                ? (vs, has) => { double k = 1; for (int c = 0; c < 64; c++) if (has(c)) k++; return k; }
                : kind == "neg" ? (vs, has) => -1 : (vs, has) => 0;
            opts.PriorMix = new IntentLearner.PriorMix(Dbl(pm["beta"]), wt);
        }
        return opts;
    }

    static object? Scenario(L a)
    {
        var omega = OmegaFromJson(a[0]);
        var opts = Options(a[1]);
        var l = new IntentLearner(omega, opts);
        var output = new L();
        foreach (var oo in (L)a[2]!)
        {
            var op = (D)oo!;
            switch ((string)op["op"]!)
            {
                case "observe":
                {
                    var src = op.GetValueOrDefault("source") as string ?? "elicitation";
                    var region = op.GetValueOrDefault("region") == null ? null : IntentRegion.Region.FromJson(op["region"]);
                    var ob = l.Observe(Oc(op), (int)Dbl(op["y"]), src, region);
                    output.Add(ob?.ToJson());
                    break;
                }
                case "probe":
                {
                    var oc = Oc(op);
                    output.Add(new L { N(l.Acceptance(oc)), l.AdmitsOutcome(oc), l.IsVetoed(oc) });
                    break;
                }
                case "next": output.Add(Q(l.NextQuestion())); break;
                case "metrics": output.Add(Met(l.Metrics())); break;
                case "cells":
                    output.Add(l.Cells().Select(c => (object?)new D
                    {
                        ["verb"] = c.Verb, ["cell"] = Ints(c.Cell), ["p"] = N(c.P), ["mass"] = N(c.Mass), ["harm"] = N(c.Harm), ["inGrant"] = c.InGrant, ["vetoed"] = c.Vetoed,
                    }).ToList());
                    break;
                case "unconfirmed":
                    output.Add(l.UnconfirmedGrantCells().Select(c => (object?)new D { ["verb"] = c.Verb, ["cell"] = Ints(c.Cell), ["weight"] = N(c.Weight) }).ToList());
                    break;
                case "synth":
                {
                    var s = l.Synthesize();
                    output.Add(new D { ["predicates"] = s.Predicates.Select(x => (object?)x).ToList(), ["caveats"] = s.Caveats.Select(x => (object?)x).ToList() });
                    break;
                }
                case "vetoed": output.Add(l.VetoedCells().Select(x => (object?)x).ToList()); break;
                case "observations": output.Add(l.Observations.Select(x => (object?)x.ToJson()).ToList()); break;
                case "replay": output.Add(Met(IntentLearner.Replay(omega, opts, l.Observations).Metrics())); break;
                case "elicit": output.Add(Elicit(l, omega, op)); break;
                default: throw new ArgumentException("bad op");
            }
        }
        return output;
    }

    static object? Elicit(IntentLearner l, Omega omega, D op)
    {
        var adm = IntentPolicyKit.MakeAdmitter(op["policy"]);
        int flip = op.GetValueOrDefault("flipEvery") == null ? 0 : (int)Dbl(op["flipEvery"]);
        int k = 0;
        Func<IntentLearner.Question, int> ans = q =>
        {
            var vs = omega.Verbs.Last(v => v.Verb == q.Verb);
            int y = adm.Admits(vs, q.Outcome) ? 1 : 0;
            k++;
            return flip != 0 && k % flip == 0 ? 1 - y : y;
        };
        var eo = new IntentLearner.ElicitOptions(Dbl(op["epsRisk"]), Dbl(op["epsBurden"]), (int)Dbl(op["maxQuestions"]), op.GetValueOrDefault("audit") is true);
        if (op.GetValueOrDefault("seed") != null)
            foreach (var s in (L)op["seed"]!)
            {
                var sm = (D)s!;
                eo.Seed.Add(((string)sm["verb"]!, ((L)sm["cell"]!).Select(x => (int)Dbl(x)).ToArray()));
            }
        var r = IntentLearner.Elicit(l, ans, eo);
        return new D
        {
            ["stop"] = r.Stop, ["questions"] = N(r.Questions), ["auditQuestions"] = N(r.AuditQuestions), ["seedQuestions"] = N(r.SeedQuestions),
            ["asked"] = r.Asked.Select(Q).ToList(), ["metrics"] = Met(l.Metrics()),
        };
    }

    [Fact] public void ScenarioFn() => Base.Check(M, "scenario", Scenario);

    [Fact]
    public void HypothesisCellSetsFn() => Base.Check(M, "hypothesisCellSets", a =>
    {
        var vs = VerbSpaceFromJson(a[0]);
        var hc = a[1] == null ? null : IntentLearner.HypothesisClassSpec.FromJson(a[1]);
        int? mh = null;
        if (a.Count > 2 && a[2] != null) mh = (int)Dbl(((D)a[2]!)["maxHypotheses"]);
        var r = IntentLearner.HypothesisCellSets(vs, hc, mh, null);
        if (a.Count > 2 || a[1] == null) return N(r.Sets.Count);
        return new D
        {
            ["sets"] = r.Sets.Select(s => (object?)s.Select(b => (object?)N(b)).ToList()).ToList(),
            ["complexity"] = r.Complexity.Select(x => (object?)N(x)).ToList(),
        };
    });

    [Fact] public void HypothesisClassNameFn() => Base.Check(M, "hypothesisClassName", a => IntentLearner.HypothesisClassName(IntentLearner.HypothesisClassSpec.FromJson(a[0])));

    [Fact]
    public void BoxesToPredicatesFn() => Base.Check(M, "boxesToPredicates", a =>
        IntentLearner.BoxesToPredicates(VerbSpaceFromJson(a[0]), ((L)a[1]!).Select(x => (byte)Dbl(x)).ToArray()).Select(x => (object?)x).ToList());

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "scenario", "hypothesisCellSets", "hypothesisClassName", "boxesToPredicates" }); Assert.Equal(443, Base.Total(M)); }
}
