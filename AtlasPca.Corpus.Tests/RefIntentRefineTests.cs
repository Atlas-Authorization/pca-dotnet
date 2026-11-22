using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of cut refinement, partial answers and adaptive elicitation against the TypeScript reference
/// (test-data/ref-intent-refine.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentRefineTests
{
    const string M = "ref-intent-refine";

    static L Observations(IntentLearner l) => l.Observations.Select(o => (object?)o.ToJson()).ToList();

    static L Cells(IntentLearner l) => l.Cells().Select(c => (object?)new D { ["verb"] = c.Verb, ["cell"] = RefIntentLearnerTests.Ints(c.Cell), ["p"] = N(c.P) }).ToList();

    static D Synth(IntentLearner l)
    {
        var s = l.Synthesize();
        return new D { ["predicates"] = s.Predicates.Select(x => (object?)x).ToList(), ["caveats"] = s.Caveats.Select(x => (object?)x).ToList() };
    }

    [Fact]
    public void RefineOmegaFn() => Base.Check(M, "refineOmega", a => IntentOmega.OmegaToJson(IntentRefine.RefineOmega(OmegaFromJson(a[0]), IntentRefine.Refinement.FromJson(a[1]))));

    [Fact]
    public void RegionsOfFn() => Base.Check(M, "regionsOf", a =>
    {
        var l = RefIntentRampTests.Make(a[0], a[1], a[2]);
        var om = a[3] is true ? new Omega(new List<VerbSpace>(), new List<string>()) : l.Omega;
        return l.Observations.Select(o => (object?)IntentRefine.RegionOfObservation(om, o).ToJson()).ToList();
    });

    [Fact]
    public void RefineScenarioFn() => Base.Check(M, "refineScenario", a =>
    {
        var l = RefIntentRampTests.Make(a[0], a[1], a[2]);
        var nl = IntentRefine.RefineLearner(l, IntentRefine.Refinement.FromJson(a[3]), null);
        return new D { ["omega"] = IntentOmega.OmegaToJson(nl.Omega), ["observations"] = Observations(nl), ["metrics"] = RefIntentLearnerTests.Met(nl.Metrics()), ["cells"] = Cells(nl) };
    });

    [Fact]
    public void PartialScenarioFn() => Base.Check(M, "partialScenario", a =>
    {
        var l = RefIntentRampTests.Make(a[0], a[1], a[2]);
        var q = (D)a[3]!;
        var verb = (string)q["verb"]!;
        var vs = l.Omega.Verbs.LastOrDefault(v => v.Verb == verb);
        var cell = ((L)q["cell"]!).Select(x => (int)Dbl(x)).ToArray();
        var oc = vs == null ? new Outcome(verb, new Dictionary<string, object?>()) : CellRep(vs, cell);
        var question = new IntentLearner.Question(verb, cell, oc, l.Acceptance(oc), 0);
        var r = IntentRefine.AnswerPartial(l, question, IntentRefine.PartialAnswer.FromJson(a[4]));
        var added = r.Added.Select(o => (object?)o.ToJson()).ToList();
        if (verb == "nope") return added;
        return new D
        {
            ["omega"] = IntentOmega.OmegaToJson(r.Learner.Omega), ["added"] = added, ["observations"] = Observations(r.Learner),
            ["metrics"] = RefIntentLearnerTests.Met(r.Learner.Metrics()), ["synth"] = Synth(r.Learner),
        };
    });

    [Fact]
    public void AdaptiveScenarioFn() => Base.Check(M, "adaptiveScenario", a =>
    {
        var l0 = IntentMapKit.CreateLearner(OmegaFromJson(a[0]), IntentMapKit.MapLearnerOptions.FromJson(a[1]));
        var adm = IntentPolicyKit.MakeAdmitter(a[2]);
        var ps = ((L)a[3]!).Select(IntentRefine.PartialAnswer.FromJson).ToList();
        int ev = (int)Dbl(a[4]);
        var oo = (D)a[5]!;
        int k0 = 0, k1 = 0;
        Func<IntentLearner.Question, IntentLearner, object> ans = (q, l) =>
        {
            k0++;
            if (k0 % ev == 0 && k1 < ps.Count && q.Verb == "stripe.refund") return ps[k1++];
            var vs = l.Omega.Verbs.Last(v => v.Verb == q.Verb);
            return adm.Admits(vs, q.Outcome) ? 1 : 0;
        };
        var eo = new IntentLearner.ElicitOptions(0.001, 0.01, oo.GetValueOrDefault("maxQuestions") == null ? 25 : (int)Dbl(oo["maxQuestions"]), oo.GetValueOrDefault("audit") is true);
        if (oo.GetValueOrDefault("seed") != null)
            foreach (var s in (L)oo["seed"]!)
            {
                var sm = (D)s!;
                eo.Seed.Add(((string)sm["verb"]!, ((L)sm["cell"]!).Select(x => (int)Dbl(x)).ToArray()));
            }
        int? maxRef = oo.GetValueOrDefault("maxRefinements") == null ? null : (int)Dbl(oo["maxRefinements"]);
        var r = IntentRefine.ElicitAdaptive(l0, ans, eo, maxRef);
        return new D
        {
            ["stop"] = r.Stop, ["questions"] = N(r.Questions), ["auditQuestions"] = N(r.AuditQuestions), ["seedQuestions"] = N(r.SeedQuestions), ["refinements"] = N(r.Refinements),
            ["asked"] = r.Asked.Select(RefIntentLearnerTests.Q).ToList(), ["omega"] = IntentOmega.OmegaToJson(r.Learner.Omega),
            ["metrics"] = RefIntentLearnerTests.Met(r.Learner.Metrics()), ["observations"] = Observations(r.Learner),
        };
    });

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "refineOmega", "regionsOf", "refineScenario", "partialScenario", "adaptiveScenario" }); Assert.Equal(179, Base.Total(M)); }
}
