using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the trust ramp, the drift detector and signed runtime observations against the TypeScript reference
/// (test-data/ref-intent-ramp.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentRampTests
{
    const string M = "ref-intent-ramp";

    internal static IntentLearner Make(object? omega, object? mapOpts, object? obs)
    {
        var l = IntentMapKit.CreateLearner(OmegaFromJson(omega), IntentMapKit.MapLearnerOptions.FromJson(mapOpts));
        foreach (var xo in (L)obs!)
        {
            var x = (D)xo!;
            l.Observe(OutcomeFromJson(x), (int)Dbl(x["y"]), (string)x["source"]!, x.GetValueOrDefault("region") == null ? null : IntentRegion.Region.FromJson(x["region"]));
        }
        return l;
    }

    static double? Dnum(D m, string k) => m.GetValueOrDefault(k) == null ? null : Dbl(m[k]);

    [Fact] public void SignObservationFn() => Base.Check(M, "signObservation", a => IntentObservation.SignIntentObservation((D)a[0]!, Pca.B64uDecode(a[1])!));

    [Fact]
    public void VerifyObservationFn() => Base.Check(M, "verifyObservation", a =>
    {
        var opts = (D)a[1]!;
        return IntentObservation.VerifyIntentObservation(a[0], opts.GetValueOrDefault("expectedSigner") as string, opts.GetValueOrDefault("pqPins") as D);
    });

    [Fact]
    public void RampScenarioFn() => Base.Check(M, "rampScenario", a =>
    {
        var d = (D)a[3]!;
        var ramp = new IntentTrustRamp(Make(a[0], a[1], a[2]), Dnum(d, "rho0"), Dnum(d, "rho1"), Dnum(d, "h"));
        var output = new L();
        // the reference hands out its live queue (ramp.pending is the array itself): every state printed shows the queue as it ends, a rebase starts a new array
        var live = new L();
        void Sync() { live.Clear(); live.AddRange(ramp.Pending()); }
        foreach (var oo in (L)a[4]!)
        {
            var op = (D)oo!;
            switch ((string)op["op"]!)
            {
                case "record": output.Add(ramp.Record(OutcomeFromJson(op["outcome"]), (string)op["signal"]!).ToJson()); Sync(); break;
                case "observe":
                {
                    var c = (D)op["ctx"]!;
                    var trusted = ((L)c["trustedSigners"]!).Select(t => (string)t!).ToList();
                    var ver = c.GetValueOrDefault("verify") as D ?? new D();
                    output.Add(ramp.RecordObservation(op["obs"], (string)c["mapDigest"]!, trusted, ver.GetValueOrDefault("expectedSigner") as string, ver.GetValueOrDefault("pqPins") as D));
                    Sync();
                    break;
                }
                case "rebase":
                    ramp.Rebase(Make(op["omega"], op["mapOpts"], op["observations"]));
                    live = new L();
                    output.Add(new D { ["frozen"] = ramp.Frozen, ["pending"] = N(ramp.Pending().Count) });
                    break;
                default:
                    output.Add(new D { ["frozen"] = ramp.Frozen, ["pending"] = live, ["drift"] = ramp.Drift.State.ToJson() });
                    break;
            }
        }
        var end = new D
        {
            ["log"] = ramp.Log.Select(r => (object?)r.ToJson()).ToList(),
            ["frozen"] = ramp.Frozen,
            ["pending"] = live,
            ["metrics"] = RefIntentLearnerTests.Met(ramp.Learner.Metrics()),
        };
        return new L { output, end };
    });

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "signObservation", "verifyObservation", "rampScenario" }); Assert.Equal(158, Base.Total(M)); }
}
