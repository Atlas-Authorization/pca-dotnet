using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the FULL verdict of the reference resource-server verifier (test-data/ref-verify-verdict.json.gz, 1022 cases) through the public
/// <see cref="Pca.VerifyPcactn(object?, VerifyPcactnOptions)"/>: allow, r, requiredThreshold, the checks (names and statuses), the reasons (exact texts, exact order),
/// the budget and the assurance report. Counted deviations, each asserted with its number and reason: (1) option shapes the typed API cannot express (a string
/// where a clock, an audience, a context, a budget or a list belongs, ...): 14 cases, the reference answers them with a JavaScript type error; (2) four inputs
/// where the reference's verdict text is a JavaScript engine message: the verdict must still deny; (3) the two cases that carry <c>allowUnboundPq</c>, the
/// legacy insecure opt-out no native verifier offers: they must be refused.</summary>
public class RefVerifyVerdictTests
{
    const string M = "ref-verify-verdict";
    const int Total = 1022, Inexpressible = 14, EngineText = 4, UnboundPq = 2;

    sealed class Hostile : Exception;

    static bool IsNum(object? x) => x is Num;
    static double Dbl(object? x) => IntentJs.NumOf(x)!.Value;

    static PcaCore.Hook HookOf(object? h)
    {
        if (h is not D m) throw new Hostile();
        if (m.TryGetValue("throws", out var msg)) return _ => throw new InvalidOperationException((string)msg!);
        if (m.TryGetValue("raw", out var raw))
        {
            if (raw == null) return _ => null!; // the hook answers null: the reference reads a property of null
            return raw is D rd ? HookOf(rd) : _ => PcaCore.HookResult.None;
        }
        bool enforced = m.GetValueOrDefault("enforced") is true, ok = m.GetValueOrDefault("ok") is true;
        string? reason = m.GetValueOrDefault("reason") as string;
        double? t = null;
        if (m.TryGetValue("t", out var tv)) { if (!IsNum(tv)) throw new Hostile(); t = Dbl(tv); }
        return _ => enforced ? new PcaCore.HookResult(true, ok, reason, t) : PcaCore.HookResult.None;
    }

    static List<string> Strs(object? x) => x is L l && l.All(e => e is string) ? l.Cast<string>().ToList() : throw new Hostile();

    static VerifyPcactnOptions Map(D o)
    {
        if (o.GetValueOrDefault("grant") is not D grant) throw new Hostile();
        var v = new VerifyPcactnOptions(grant);
        if (o.TryGetValue("now", out var now)) v.Now = IsNum(now) && Base.IsJsonInt(now) ? Base.Long(now) : throw new Hostile();
        if (o.TryGetValue("audience", out var aud))
        {
            if (aud is string a) v.WithAudience(a); else if (aud == null) v.AudienceAny(); else throw new Hostile();
        }
        v.InsecureSkipPlanRootCheck = o.GetValueOrDefault("insecureSkipPlanRootCheck") is true;
        v.Assurance = o.GetValueOrDefault("assurance") is true;
        if (o.GetValueOrDefault("require") is { } rq) v.Require = Strs(rq);
        if (o.GetValueOrDefault("allowedSuites") is { } su) v.AllowedSuites = Strs(su);
        if (o.GetValueOrDefault("allowUnsupported") is { } au) v.AllowUnsupported = Strs(au);
        if (o.GetValueOrDefault("requireRiskInputs") is { } rr) v.RequireRiskInputs = Strs(rr);
        if (o.GetValueOrDefault("pqPins") is D pp) v.PqPins = pp.ToDictionary(e => e.Key, e => (string)e.Value!);
        if (o.GetValueOrDefault("requireAssurance") is D ra) v.RequireAssurance = AssuranceRequirement.FromJson(ra);
        if (o.GetValueOrDefault("intent") is D ip)
            v.IntentPolicy = new IntentPolicy(ip.GetValueOrDefault("require") is true, ip.TryGetValue("min_fidelity_ppm", out var mf) ? Dbl(mf) : null, ip.TryGetValue("max_residual_risk_ppm", out var mr) ? Dbl(mr) : null); // the reference reads the snake-case thresholds: a camel-case member is not a threshold
        if (o.GetValueOrDefault("operation") is D op)
            v.Operation = new Operation(op.GetValueOrDefault("verb") as string ?? null!, op.GetValueOrDefault("resource") as string ?? null!, op.GetValueOrDefault("params"));
        if (o.GetValueOrDefault("hooks") is D hs)
        {
            var hk = new PcaCore.Hooks();
            foreach (var (name, h) in hs)
                switch (name)
                {
                    case "attestation": hk.Attestation = HookOf(h); break;
                    case "threshold": hk.Threshold = HookOf(h); break;
                    case "revocation": hk.Revocation = HookOf(h); break;
                    case "zk": hk.Zk = HookOf(h); break;
                    // `replay` is no hook of the reference's verifier: ignored
                }
            v.Hooks = hk;
        }
        if (o.GetValueOrDefault("enforce") is D en)
        {
            var e = new PcaCore.Enforce();
            if (en.GetValueOrDefault("freshness") is D fr)
                e.Freshness = new PcaCore.FreshnessGate(Dbl(fr["maxAgeMs"])) { EpochMs = fr.TryGetValue("epochMs", out var em) ? Dbl(em) : null, ClockSkewMs = fr.TryGetValue("clockSkewMs", out var cs) ? Dbl(cs) : null, Now = fr.TryGetValue("now", out var fn) ? Base.Long(fn) : null };
            if (en.GetValueOrDefault("attestation") is D at)
            {
                var hook = HookOf(at.GetValueOrDefault("verifier"));
                e.Attestation = new PcaCore.AttestationGate(hook) { Required = !at.ContainsKey("required") || at["required"] is true };
            }
            v.Enforce = e;
        }
        if (o.TryGetValue("context", out var cx) && cx != null)
        {
            if (cx is not D c) throw new Hostile();
            var x = new VerifyContext();
            if (c.TryGetValue("plan", out var pl)) x.Plan = pl is L pll ? pll : throw new Hostile();
            if (c.TryGetValue("planAuthorized", out var pa)) x.PlanAuthorized = pa as bool?;
            if (c.TryGetValue("params", out var pr)) x.Params = pr as D ?? throw new Hostile();
            if (c.GetValueOrDefault("subject") is D sj) x.Subject = sj;
            if (c.GetValueOrDefault("env") is D ev) x.Env = ev;
            x.ReversibilityClass = c.GetValueOrDefault("reversibilityClass") as string;
            if (c.TryGetValue("risk", out var rk))
                x.Risk = rk is D rd ? rd.Where(e => IsNum(e.Value)).ToDictionary(e => e.Key, e => Dbl(e.Value)) : throw new Hostile();
            if (c.TryGetValue("budget", out var bu))
            {
                if (bu is not D b || !IsNum(b.GetValueOrDefault("B")) || !IsNum(b.GetValueOrDefault("tau")) || (b.TryGetValue("asOf", out var ao) && !IsNum(ao))) throw new Hostile();
                x.Budget = new TrustBudget(Dbl(b["B"]), Dbl(b["tau"]), b.ContainsKey("asOf") ? Dbl(b["asOf"]) : null);
            }
            if (c.GetValueOrDefault("recentActionTimes") is L rat) x.RecentActionTimes = rat.Select(Dbl).ToList();
            if (c.GetValueOrDefault("revocationEpoch") is D re)
                x.RevocationEpoch = new VerifyRevocationEpoch((D)re["epoch"]!, (string)re["guardianPublic"]!, re.TryGetValue("lastAcceptedEpoch", out var la) ? Dbl(la) : null, re.TryGetValue("maxAgeMs", out var ma) ? Dbl(ma) : null);
            if (c.GetValueOrDefault("beacon") is D bc)
                x.Beacon = new BeaconPresented(bc["beacon"], Strs(bc["issuers"]), (string)bc["instance"]!, bc.TryGetValue("lastAcceptedSeq", out var ls) ? Base.Long(ls) : null);
            v.Context = x;
        }
        return v;
    }

    static bool Close(double a, double b) => a == b || Math.Abs(a - b) <= 1e-12 * Math.Max(1, Math.Abs(b));

    static string? Diff(D want, D have)
    {
        if (!Equals(want["allow"], have["allow"])) return $"allow want {want["allow"]} have {have["allow"]}";
        if (!Close((double)have["r"]!, Dbl(want["r"]))) return $"r want {Base.Show(want["r"])} have {have["r"]}";
        var wt = (D)want["requiredThreshold"]!; var ht = (D)have["requiredThreshold"]!;
        if (Dbl(wt["t"]) != Convert.ToDouble(ht["t"]) || !Equals(wt["proof"], ht["proof"]) || !Equals(wt["optimisticAllowed"], ht["optimisticAllowed"])) return $"requiredThreshold want {Base.Show(wt)} have {Base.Show(Base.Json(ht))}";
        if (Base.Show(want["checks"]) != Base.Show(Base.Json(have["checks"]))) return $"checks want {Base.Show(want["checks"])} have {Base.Show(Base.Json(have["checks"]))}";
        if (Base.Show(want["reasons"]) != Base.Show(Base.Json(have["reasons"]))) return $"reasons want {Base.Show(want["reasons"])} have {Base.Show(Base.Json(have["reasons"]))}";
        if (want.ContainsKey("budget") != have.ContainsKey("budget")) return $"budget want {Base.Show(want.GetValueOrDefault("budget"))} have {Base.Show(Base.Json(have.GetValueOrDefault("budget")))}";
        if (want.ContainsKey("budget"))
        {
            var wb = (D)want["budget"]!; var hb = (D)have["budget"]!;
            if (!Close((double)hb["B"]!, Dbl(wb["B"])) || !Close((double)hb["tau"]!, Dbl(wb["tau"])) || wb.ContainsKey("asOf") != hb.ContainsKey("asOf") || (wb.ContainsKey("asOf") && !Close((double)hb["asOf"]!, Dbl(wb["asOf"]))))
                return $"budget want {Base.Show(wb)} have {Base.Show(Base.Json(hb))}";
        }
        if (want.ContainsKey("assurance") != have.ContainsKey("assurance") || (want.ContainsKey("assurance") && Base.Show(want["assurance"]) != Base.Show(Base.Json(have["assurance"]))))
            return $"assurance want {Base.Show(want.GetValueOrDefault("assurance"))} have {Base.Show(Base.Json(have.GetValueOrDefault("assurance")))}";
        return null;
    }

    static bool EngineMessage(D want) => want["reasons"] is L { Count: > 0 } r && r[0] is string s && (s.Contains("Cannot read properties") || s.Contains("is not a function"));

    [Fact]
    public void Replay()
    {
        Base.Covers(M, new[] { "verifyVerdict" });
        Assert.Equal(Total, Base.Total(M));
        var bad = new List<string>();
        int exact = 0, inexpressible = 0, engine = 0, unbound = 0, n = 0;
        var previousClock = AtlasPca.ReplayClock.Ms;
        AtlasPca.ReplayClock.Ms = () => (long)Base.ClockMs(M); // the cases that give no now read the corpus's frozen clock
        try
        {
        foreach (var c in Base.Of(M, "verifyVerdict"))
        {
            n++;
            var name = (string)c["name"]!;
            var a = Base.Args(c);
            var o = (D)a[1]!;
            var want = (D)c["out"]!;
            VerifyPcactnOptions opts;
            try { opts = Map(o); }
            catch (Hostile) { inexpressible++; continue; }
            D have;
            try { have = Pca.VerifyPcactn(a[0], opts); }
            catch (Exception e) { bad.Add($"{name}: threw {e.GetType().Name}: {e.Message}"); continue; }
            if (o.ContainsKey("allowUnboundPq"))
            {
                // the legacy insecure opt-out is not offered: the verdict must deny whatever the reference accepted through it
                unbound++;
                // a signer with no PQ key never reaches the opt-out, so its verdict is the reference's exactly; any other verdict must be a denial
                if (Diff(want, have) is not null && have["allow"] is not false) bad.Add($"{name}: allowUnboundPq case allowed with a verdict that differs from the reference");
                continue;
            }
            if (EngineMessage(want))
            {
                engine++;
                if (have["allow"] is not false) bad.Add($"{name}: engine-message case allowed");
                continue;
            }
            exact++;
            if (Diff(want, have) is { } why) bad.Add($"{name}\n   {why}");
        }
        }
        finally { AtlasPca.ReplayClock.Ms = previousClock; }
        Assert.True(bad.Count == 0, $"{bad.Count} of {n} divergent:\n" + string.Join("\n", bad.Take(30)));
        Assert.Equal(Total, n);
        Assert.Equal(Inexpressible, inexpressible);
        Assert.Equal(EngineText, engine);
        Assert.Equal(UnboundPq, unbound);
        Assert.Equal(Total - Inexpressible - EngineText - UnboundPq, exact);
    }
}
