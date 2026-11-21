// The end-to-end check a resource server runs on an entity attestation token: the signature, then the freshness, the channel binding, the optional AMD silicon
// root and the RATS appraisal, one verdict; and the admission evidence a blueprint admission takes from it (bound to one instance key).
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.AttestEat;

public static class EatFresh
{
    static object? P(object? o, string k) => Jx.Prop(o, k);
    static bool Def(object? x) => !Jx.IsUndef(x);

    /// <summary>Copies the members of <paramref name="from"/> named <paramref name="keys"/> that are present (a missing member is not copied; JSON null is).</summary>
    static D Pick(object? from, params string[] keys)
    {
        var d = new D();
        foreach (var k in keys) { var v = P(from, k); if (Def(v)) d[k] = v; }
        return d;
    }

    /// <summary>The verdict of a resource server's check of an EAT: authentic (<paramref name="verifyKey"/>, <c>typ</c>, <c>issuer</c>, <c>algorithms</c>), fresh (<c>nonce</c>, <c>maxAgeMs</c>, <c>clockSkewMs</c>,
    /// <c>now</c>), channel-bound (<c>channelId</c> and/or <c>channelBinding</c>), optionally silicon-verified (<c>amd</c>: <c>rawReport</c>, <c>vcek</c>, <c>ask</c>, <c>ark</c>, <c>family</c> or
    /// <c>trustAnchorArkSpkiSha384</c>, <c>clockSkewMs?</c>, <c>allowDebug?</c>, <c>expectedMeasurement?</c>; a failure is <c>contraindicated</c>) and appraised against <c>policy</c>. The first failing gate
    /// stops the pipeline: <c>{ok, tier?, reasons, claims?}</c>. A missing <c>policy</c> throws, like the reference.</summary>
    public static D VerifyFreshAttestedEat(object? eat, EatKey verifyKey, object? opts, Func<double>? clock = null)
    {
        var reasons = new L();
        D claims;
        try { claims = EatToken.VerifyEat(eat, verifyKey, Pick(opts, "issuer", "algorithms", "typ", "requireTyp")); }
        catch (Exception e) { return new D { ["ok"] = false, ["reasons"] = new L { "EAT signature/claims invalid: " + e.Message } }; }
        reasons.Add("signature + typ/iss verified");

        var now = Jx.Fin(P(opts, "now")) is double nd ? nd : (clock?.Invoke() ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        var maxAge = P(opts, "maxAgeMs");
        var fo = new D();
        Jx.Set(fo, "expectedNonce", P(opts, "nonce"));
        fo["maxAgeMs"] = maxAge == null || Jx.IsUndef(maxAge) ? Jx.NumOut(PcaAttestEat.DefaultMaxAgeMs) : maxAge;
        fo["now"] = Jx.NumOut(now);
        Jx.Set(fo, "clockSkewMs", P(opts, "clockSkewMs"));
        var fresh = PcaAttestEat.VerifyFreshness(claims, fo);
        if (fresh["ok"] is not true) return new D { ["ok"] = false, ["reasons"] = Plus(reasons, fresh.GetValueOrDefault("reason") as string ?? "not fresh"), ["claims"] = claims };
        reasons.Add("fresh (nonce + iat within window)");

        var chan = PcaAttestEat.VerifyChannelBinding(claims, MapKeys(opts, ("channelId", "channelId"), ("channelBinding", "expectedCnf")));
        if (chan["ok"] is not true) return new D { ["ok"] = false, ["reasons"] = Plus(reasons, chan.GetValueOrDefault("reason") as string ?? "channel binding failed"), ["claims"] = claims };
        reasons.Add("channel-bound (cnf matches live channel)");

        // the optional AMD silicon root: a failure is an active bad signal (fail closed); success lifts the appraisal to the hardware-rooted tier
        D extras = new();
        var amd = P(opts, "amd");
        if (Def(amd))
        {
            var expected = P(amd, "expectedMeasurement");
            if (expected == null || Jx.IsUndef(expected)) expected = PcaAttestEat.LaunchMeasurement(claims);
            var ao = Pick(amd, "vcek", "ask", "ark");
            ao["nowMs"] = Jx.NumOut(now);
            foreach (var k in new[] { "family", "trustAnchorArkSpkiSha384", "clockSkewMs", "allowDebug" }) { var v = P(amd, k); if (Def(v)) ao[k] = v; }
            if (Def(expected)) ao["expectedMeasurement"] = expected;
            var hw = EatAmd.VerifyAmdAttestation(P(amd, "rawReport"), ao);
            if (!hw.Ok)
                return new D { ["ok"] = false, ["tier"] = "contraindicated", ["reasons"] = Plus(reasons, "AMD hardware root verification failed: " + (hw.Reason ?? "unknown")), ["claims"] = claims };
            reasons.Add($"AMD SEV-SNP hardware root verified ({hw.HardwareRoot})");
            extras = new D { ["hardwareVerified"] = true, ["hardwareRootLabel"] = hw.HardwareRoot };
        }

        var policy = P(opts, "policy");
        var rv = P(policy, "referenceValues");
        var en = P(policy, "endorsements");
        var app = PcaAttestEat.Appraise(claims, NullToUndefToNull(rv), NullToUndefToNull(en), extras);
        var all = new L(reasons);
        all.AddRange((L)app["reasons"]!);
        return new D { ["ok"] = app["trustworthy"], ["tier"] = app["tier"], ["reasons"] = all, ["claims"] = claims };
    }

    // an absent or null member is "none given" (the reference's ?? {})
    static object? NullToUndefToNull(object? x) => x == null || Jx.IsUndef(x) ? null : x;

    static L Plus(L reasons, string last) => new(reasons) { last };

    /// <summary>A copy of the present members of <paramref name="from"/>, under new names.</summary>
    static D MapKeys(object? from, params (string From, string To)[] map)
    {
        var d = new D();
        foreach (var (f, t) in map) { var v = P(from, f); if (Def(v)) d[t] = v; }
        return d;
    }

    static double TierRank(object? name) => name is string s ? s switch
    {
        "rejected" or "contraindicated" => 0,
        "warning" => 1,
        "affirming" => 2,
        "affirming-hw-rooted" => 3,
        _ => double.NaN,
    } : double.NaN;

    /// <summary>EAT EVIDENCE FOR BLUEPRINT ADMISSION: the token must verify as <see cref="VerifyFreshAttestedEat"/> does (<paramref name="o"/> carries its options, <c>nonce</c> and <c>policy</c> among them) AND
    /// its <c>cnf.jkt</c> must be the thumbprint of <c>instanceKey</c> (unpadded base64url Ed25519 public key), so evidence for one instance cannot admit another. <c>minTier</c> (default
    /// <c>affirming</c>) is the lowest acceptable appraisal. The identity is the measured one the verifier established. Anything unverifiable is <c>ok: false</c>.</summary>
    public static D EatAdmissionEvidence(object? eat, EatKey verifyKey, object? o, Func<double>? clock = null)
    {
        try
        {
            if (o is not D od) throw JsX.TypeError("Cannot destructure the admission options");
            var minTierO = P(o, "minTier");
            // An unknown tier has no rank: refuse it before verification instead of admitting any tier.
            if (!Jx.IsUndef(minTierO) && minTierO is not ("affirming" or "affirming-hw-rooted")) return new D { ["ok"] = false, ["bound"] = false, ["reason"] = "invalid minTier" };
            var rest = new D();
            foreach (var (k, val) in od) if (k != "instanceKey" && k != "minTier") rest[k] = val;
            rest["channelBinding"] = new D { ["jkt"] = PcaAttestEat.Ed25519Jkt(JsX.Str(P(o, "instanceKey"))) };
            var v = VerifyFreshAttestedEat(eat, verifyKey, rest, clock);
            if (v["ok"] is not true || !v.TryGetValue("tier", out var tier) || tier == null)
            {
                var rs = (L)v["reasons"]!;
                return new D { ["ok"] = false, ["bound"] = false, ["reason"] = rs.Count > 0 ? rs[^1] : "EAT rejected" };
            }
            if (!(TierRank(tier) >= TierRank(Jx.IsUndef(minTierO) ? "affirming" : minTierO)))
                return new D { ["ok"] = false, ["bound"] = true, ["reason"] = $"appraisal tier {tier} is below the minimum" };
            // the freshness gate checked cnf.jkt against the instance key, so a pass means bound
            var m = P(v["claims"], "measured");
            if (!Jx.Truthy(m)) return new D { ["ok"] = true, ["bound"] = true };
            var identity = new D();
            foreach (var k in new[] { "runtime_measurement", "model_id", "weights_digest", "operator" }) Jx.Set(identity, k, P(m, k));
            return new D { ["ok"] = true, ["bound"] = true, ["identity"] = identity };
        }
        catch (Exception e) { return new D { ["ok"] = false, ["bound"] = false, ["reason"] = e.Message.StartsWith("TypeError", StringComparison.Ordinal) ? "TypeError" : "Error" }; }
    }
}
