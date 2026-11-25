using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of lazy just-in-time elicitation (visit decisions, cell coordinates, intent_required, wallet check, delta grants) against the
/// TypeScript reference (test-data/ref-intent-jit.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentJitTests
{
    const string M = "ref-intent-jit";
    const string A = "action.params.";

    static int[] Ints(object? o) => ((L)o!).Select(x => (int)Dbl(x)).ToArray();

    static Func<VerbSpace, Outcome, bool> Ceiling(string name) => name switch
    {
        "all" => (vs, o) => true,
        "none" => (vs, o) => false,
        "amountLe60" => (vs, o) => !(o.Values.GetValueOrDefault(A + "amount") is double d) || d <= 60,
        _ => (vs, o) => o.Verb != "gmail.send",
    };

    static VerbSpace? Verb(Omega om, string v) => om.Verbs.LastOrDefault(x => x.Verb == v);

    static SuiteKey Site(object? seed) => SuiteKey.Ed25519(EdKey.FromSeed(Pca.B64uDecode(seed)!));

    [Fact]
    public void VisitScenarioFn() => Base.Check(M, "visitScenario", a =>
        IntentJit.DecideVisit(RefIntentRampTests.Make(a[0], a[1], a[2]), OutcomeFromJson(a[3]), (D)a[4]!, ((L)a[5]!).Select(c => Ceiling((string)c!)).ToList(), a[6] is true));

    [Fact] public void CellCoordsFn() => Base.Check(M, "cellCoords", a => IntentJit.CellCoords(VerbSpaceFromJson(a[0]), Ints(a[1])));

    [Fact]
    public void CellFromCoordsFn() => Base.Check(M, "cellFromCoords", a =>
        IntentJit.CellFromCoords(VerbSpaceFromJson(a[0]), (D)a[1]!) is { } r ? r.Select(d => (object?)N(d)).ToList() : null);

    [Fact]
    public void DeltaScenarioFn() => Base.Check(M, "deltaScenario", a =>
    {
        var both = new L(); both.AddRange((L)a[2]!); both.AddRange((L)a[3]!);
        var prev = RefIntentRampTests.Make(a[0], a[1], a[2]);
        var next = RefIntentRampTests.Make(a[0], a[1], both);
        var d = IntentJit.DeltaCells(prev, next);
        var cells = new D();
        foreach (var e in d) cells[e.Key] = e.Value.Select(b => (object?)N(b)).ToList();
        return new D { ["cells"] = cells, ["predicates"] = IntentJit.DeltaPredicates(next.Omega, d).Select(x => (object?)x).ToList() };
    });

    [Fact]
    public void RequiredScenarioFn() => Base.Check(M, "requiredScenario", a =>
    {
        var om = OmegaFromJson(a[0]);
        var vs = Verb(om, (string)a[1]!)!;
        var cell = Ints(a[2]);
        var inp = (D)a[3]!;
        var site = Site(a[4]);
        var body = IntentJit.IntentRequiredBody(inp, vs, cell);
        return new D { ["signed"] = IntentJit.SignedIntentRequired(inp, vs, cell, "site-1", site), ["body"] = body };
    });

    [Fact]
    public void WalletScenarioFn() => Base.Check(M, "walletScenario", a =>
    {
        var om = OmegaFromJson(a[0]);
        var inp = (D)a[1]!;
        var mutation = (string)a[2]!;
        var siteKey = EdKey.FromSeed(Pca.B64uDecode(a[7])!);
        var signed = IntentJit.SignedIntentRequired(inp, Verb(om, "stripe.refund")!, new[] { 1, 0 }, "site-1", SuiteKey.Ed25519(siteKey));
        object? body = IntentJs.Normalize(signed);
        var b = (D)body!;
        switch (mutation)
        {
            case "coords": ((D)((D)b["cell"]!)["coords"]!)[A + "amount"] = new L { new Num("2"), new Num("2") }; break;
            case "verb": ((D)b["cell"]!)["verb"] = "gmail.send"; break;
            case "sig": { var sg = (D)b["sig"]!; var v = (string)sg["value"]!; sg["value"] = v.Substring(0, v.Length - 2) + "AA"; break; }
            case "kid": ((D)b["sig"]!)["kid"] = "other"; break;
            case "session": b["session"] = Pca.B64u(Pca.Sha(System.Text.Encoding.UTF8.GetBytes("other"))); break;
            case "action": b["action_digest"] = Pca.B64u(Pca.Sha(System.Text.Encoding.UTF8.GetBytes("other"))); break;
            case "null": body = null; break;
        }
        var key = new D { ["kid"] = "site-1", ["alg"] = "ed25519", ["pk"] = siteKey.Id };
        var keys = new L { key };
        double now = Dbl(a[3]);
        long clock = now != Math.Floor(now) ? long.MinValue : (long)now;
        return IntentJit.WalletCheckIntentRequired(body, keys, clock, (string)a[5]!, (string)a[6]!, om, OutcomeFromJson(a[4]), (D)inp["pcactn"]!);
    });

    [Fact]
    public void MintScenarioFn() => Base.Check(M, "mintScenario", a =>
    {
        var both = new L(); both.AddRange((L)a[2]!); both.AddRange((L)a[3]!);
        var prev = RefIntentRampTests.Make(a[0], a[1], a[2]);
        var next = RefIntentRampTests.Make(a[0], a[1], both);
        return IntentJit.MintDelta(prev, next, (D)a[4]!, Site(a[5]));
    });

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "visitScenario", "cellCoords", "cellFromCoords", "deltaScenario", "requiredScenario", "walletScenario", "mintScenario" }); Assert.Equal(219, Base.Total(M)); }
}
