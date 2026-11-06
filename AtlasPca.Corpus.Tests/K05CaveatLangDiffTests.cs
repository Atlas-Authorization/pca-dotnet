using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of the caveat language v2 (test-data/k05-caveatlang.json.gz, TS reference packages/pca/src/caveat-lang.ts,
/// track K1, and server/require-pca.ts presentedK1).</summary>
public class K05CaveatLangDiffTests
{
    const string M = "caveatlang";

    // a clock that is not a safe integer is refused by the safe-integer check (the typed port takes a long)
    static long Clock(object? n) => IntentJs.NumOf(n) is double d && d == Math.Floor(d) && Math.Abs(d) <= Pca.MaxSafeInt ? (long)d : long.MaxValue;

    // JS semantics of the reference's pins.find(p => p.label === ...): a non-object pin has no members (never matches) and is dropped; a null
    // pin throws (kept, the cast refuses). A non-string member is no key / label: "" (an empty pk never verifies).
    static List<DischargePin>? Pins(object? o) => (o as L)?.OfType<D>().Select(m =>
    {
        return new DischargePin(m.GetValueOrDefault("label") as string ?? "", m.GetValueOrDefault("class") as string ?? "", m.GetValueOrDefault("pk") as string ?? "",
            m.GetValueOrDefault("pq_pk") as string, m.GetValueOrDefault("spiffe_id") as string);
    }).ToList();

    // a K1 input that is not an object is no K1 input (the reference reads none of its members)
    static K1Input? K1Of(object? o)
    {
        if (o is not D k) return null;
        var pins = k.ContainsKey("pins") ? Pins(k["pins"]) : null;
        var dis = k.GetValueOrDefault("discharges") as L;
        var hist = k.GetValueOrDefault("history") as L;
        var ad = k.GetValueOrDefault("action_digest") as string;
        var sp = k.GetValueOrDefault("spiffe_id") as string;
        var rev = (k.GetValueOrDefault("revoked_discharges") as L)?.Cast<string>().ToList();
        return k.ContainsKey("narrow")
            ? new K1Input { Pins = pins, Discharges = dis, History = hist, ActionDigest = ad, SpiffeId = sp, RevokedDischarges = rev, Narrow = k["narrow"] }
            : new K1Input { Pins = pins, Discharges = dis, History = hist, ActionDigest = ad, SpiffeId = sp, RevokedDischarges = rev };
    }

    static D Bound(BoundCaveat b) => new() { ["caveat"] = b.Caveat, ["hop"] = (long)b.Hop, ["cap_hash"] = b.CapHash };

    [Fact] public void SpiffeIdError() => K05.Check(M, "spiffeIdError", a => CaveatLang.SpiffeIdError(a[0]));
    [Fact] public void NeedsDischargeError() => K05.Check(M, "needsDischargeError", a => CaveatLang.NeedsDischargeError(a[0]));
    [Fact] public void DischargeShapeError() => K05.Check(M, "dischargeShapeError", a => CaveatLang.DischargeShapeError(a[0]));
    [Fact] public void NarrowShapeError() => K05.Check(M, "narrowShapeError", a => CaveatLang.NarrowShapeError(a[0]));
    [Fact] public void MaxUsesError() => K05.Check(M, "maxUsesError", a => CaveatLang.MaxUsesError(a[0]));
    [Fact] public void MaxUsesSlotKey() => K05.Check(M, "maxUsesSlotKey", a => CaveatLang.MaxUsesSlotKey((string)a[0]!, (string)a[1]!, (int)K05.Long(a[2])));
    [Fact] public void SpiffeBoundError() => K05.Check(M, "spiffeBoundError", a => CaveatLang.SpiffeBoundError(a[0]));
    [Fact] public void DeriveError() => K05.Check(M, "deriveError", a => CaveatLang.DeriveError(a[0]));

    [Fact]
    public void EvaluateDerive() => K05.Check(M, "evaluateDerive", skip: c => K05.Args(c).Count > 1 && K05.Args(c)[1] is D i && i.GetValueOrDefault("claims") is D cl
        && cl.Values.Any(v => v is not D) ? "typed port: a claim set that is not an object cannot be expressed in DeriveInput" : null, run: a =>
    {
        var i = (D)a[1]!;
        var claims = (i.GetValueOrDefault("claims") as D ?? new D()).ToDictionary(e => e.Key, e => (D)e.Value!);
        return CaveatLang.EvaluateDerive((D)a[0]!, new DeriveInput(Clock(i.GetValueOrDefault("now")), i.GetValueOrDefault("action") as D, i.GetValueOrDefault("history") as L, claims));
    });

    [Fact]
    public void VerifyDischarge() => K05.Check(M, "verifyDischarge", a =>
    {
        var b = (D)a[2]!;
        var r = CaveatLang.VerifyDischarge(a[0], a[1], new DischargeBinding((string)b["cap_hash"]!, Pins(b.GetValueOrDefault("pins")), Clock(b.GetValueOrDefault("now")),
            b.GetValueOrDefault("action_digest") as string, (b.GetValueOrDefault("revoked") as L)?.Cast<string>().ToList()));
        return r.Ok ? new D { ["ok"] = true, ["digest"] = r.Digest, ["claims"] = r.Claims } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact]
    public void VerifyNarrow() => K05.Check(M, "verifyNarrow", a =>
    {
        var b = (D)a[3]!;
        var r = CaveatLang.VerifyNarrow(a[0], a[1], a[2], new NarrowBinding(Clock(b.GetValueOrDefault("now")), b.GetValueOrDefault("action_digest") as string));
        return r.Ok ? new D { ["ok"] = true, ["caveats"] = r.Caveats } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact]
    public void BoundCaveats() => K05.Check(M, "boundCaveats", a =>
        CaveatLang.BoundCaveats(a[0], a.Count > 1 ? a[1] : null)?.Select(b => (object?)Bound(b)).ToList());

    [Fact]
    public void EvaluateK1() => K05.Check(M, "evaluateK1", a =>
    {
        var ctx = a[3] as D;
        var r = CaveatLang.EvaluateK1(a[0], a[1], K1Of(a[2]), new K1Context(Clock(ctx?.GetValueOrDefault("now")), ctx?.GetValueOrDefault("action") as D));
        return new D
        {
            ["ok"] = r.Ok, ["failed"] = r.Failed, ["reasons"] = r.Reasons, ["plain"] = r.Plain,
            ["bound"] = r.Bound.Select(b => (object?)Bound(b)).ToList(),
        };
    });

    [Fact]
    public void EvaluateCaveatsK1() => K05.Check(M, "evaluateCaveatsK1", a =>
    {
        var (allow, failed) = CaveatLang.EvaluateCaveatsK1(a[0], a[1], K1Of(a[2]), (D)a[3]!);
        return new D { ["allow"] = allow, ["failed"] = failed };
    });

    // {ok: true, value: {discharges?, narrow?}} or {ok: false}
    [Fact]
    public void PresentedK1() => K05.Check(M, "presentedK1", a =>
    {
        var h = ((D)a[0]!).Select(e => new KeyValuePair<string, string>(e.Key, (string)e.Value!)).ToList();
        var p = CaveatLang.PresentedK1Of(h);
        if (!p.Ok) return new D { ["ok"] = false };
        var v = new D();
        if (p.Discharges != null) v["discharges"] = p.Discharges;
        if (p.HasNarrow) v["narrow"] = p.Narrow;
        return new D { ["ok"] = true, ["value"] = v };
    });

    [Fact]
    public void EveryFn() => K05.Covers(M, new[]
    {
        "spiffeIdError", "needsDischargeError", "dischargeShapeError", "narrowShapeError", "maxUsesError", "maxUsesSlotKey", "spiffeBoundError",
        "deriveError", "evaluateDerive", "verifyDischarge", "verifyNarrow", "boundCaveats", "evaluateK1", "evaluateCaveatsK1", "presentedK1",
        // not ported: dischargeRequests builds the holder's requests to discharge issuers (client side); no verifier decision rests on it
        "dischargeRequests",
    });
}
