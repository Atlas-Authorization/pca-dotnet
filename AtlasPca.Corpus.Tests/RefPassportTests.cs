using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the agent passport (test-data/ref-passport.json.gz, 516 cases): fingerprint, issuing, the binding match with its reasons, the registry, the trust score, the evidence binding, signing under three
/// suites, verification with every reason and detail (revocation and hardware callbacks built from the corpus specs) and the assurance label. A reference throw requires a refusal. The reference's legacy unbound-PQ
/// opt-out (allowUnboundPq) does not exist here: the case the reference accepts only through it is asserted REFUSED, by count. Every fn has a handler and the totals are asserted.</summary>
public class RefPassportTests
{
    const string M = "ref-passport";
    static int Unbound;

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static object? Registry(L a)
    {
        var r = PassportOps.BuildRegistry(Nums(a[0]));
        var outp = new L();
        foreach (var opo in (L)a[1]!)
        {
            var op = (L)opo!;
            switch ((string)op[0]!)
            {
                case "get": outp.Add(r.Get((string)op[1]!)); break;
                case "has": outp.Add(r.Has((string)op[1]!)); break;
                case "all": outp.Add(r.All().Cast<object?>().ToList()); break;
                default: throw new InvalidOperationException("unknown registry op");
            }
        }
        return outp;
    }

    static object? Sign(L a)
    {
        var o = (D)Nums(a[1])!;
        string? alg = null;
        SuiteSecretKeys? keys = null;
        if (o.GetValueOrDefault("suite") is D su)
        {
            alg = su.GetValueOrDefault("alg") as string;
            if (su.GetValueOrDefault("pqSeed") is { } seed) keys = new SuiteSecretKeys { MlDsa = PqSuites.MlDsa65Keygen(Base.Bytes(seed)) };
        }
        return PassportOps.SignPassport((D)Nums(a[0])!, Base.Bytes(o["issuerSecret"]), o.GetValueOrDefault("subject"), o.GetValueOrDefault("iat"), o.GetValueOrDefault("nbf"), o.GetValueOrDefault("exp"),
            o.GetValueOrDefault("evidence") as D, alg, keys);
    }

    static object? Verify(L a)
    {
        var o = (D)Nums(a[1])!;
        var opts = o.Where(e => e.Key is not ("revocation" or "hardware" or "allowUnboundPq")).ToDictionary(e => e.Key, e => e.Value);
        switch (o.GetValueOrDefault("revocation"))
        {
            case D r when r.TryGetValue("revokedIds", out var ids):
                opts["revocation"] = (Func<D, object?>)(p => ((L)ids!).Contains(p["id"]));
                break;
            case D r:
                opts["revocation"] = (Func<D, object?>)(_ => r.GetValueOrDefault("revoked"));
                break;
            case "throws":
                opts["revocation"] = (Func<D, object?>)(_ => throw new InvalidOperationException("revocation down"));
                break;
        }
        if (o.GetValueOrDefault("hardware") is D hw)
            opts["attestationVerifier"] = new HardwareAttestationFn(_ => hw.TryGetValue("throws", out var m) ? throw new InvalidOperationException((string)m!) : hw.GetValueOrDefault("result"));
        var v = PassportOps.VerifyPassport(a[0], opts);
        if (o.GetValueOrDefault("allowUnboundPq") is true && v["ok"] is not true && v["reason"] is "bad_signature") { Unbound++; return new D { ["unboundRefused"] = true }; }
        return v;
    }

    sealed class Labeled;

    static object? Assurance(L a)
    {
        var verdict = (D)a[0]!;
        object? verifier = null;
        if (a.Count > 1 && a[1] is D l) verifier = AssuranceLabels.Set(new Labeled(), new AssuranceLabel((string)l["level"]!, l.GetValueOrDefault("vendor") as string));
        else if (a.Count > 1 && a[1] == null) verifier = new Labeled();
        return PassportOps.PassportAssurance(verdict, verifier);
    }

    static bool Same(D c, object? have)
    {
        if (c["fn"] is "verifyPassport" && have is D h && h.GetValueOrDefault("unboundRefused") is true) return c["out"] is D w && w.GetValueOrDefault("ok") is true;
        return Base.Show(c["out"]) == Base.Show(have);
    }

    static void Fn(string fn, Func<L, object?> run, int min) => Base.Check(M, fn, a => Base.Json(run(a)), Same, null, min);

    [Fact] public void Constants() => Fn("constants", _ => PassportOps.Constants(), 1);
    [Fact] public void PassportFingerprint() => Fn("passportFingerprint", a => PassportOps.PassportFingerprint(Nums(a[0])), 13);
    [Fact] public void IssuePassport() => Fn("issuePassport", a => PassportOps.IssuePassport(Nums(a[0])), 12);
    [Fact] public void MatchesBinding() => Fn("matchesBinding", a => PassportOps.MatchesBinding(Nums(a[0]), Nums(a[1])), 267);
    [Fact] public void RegistryOps() => Fn("registry", Registry, 4);
    [Fact] public void TrustScore() => Fn("trustScore", a => PassportOps.TrustScore(Nums(a[0]), a.Count > 1 ? Nums(a[1]) : null), 67);
    [Fact] public void PassportEvidenceBinding() => Fn("passportEvidenceBinding", a => PassportOps.PassportEvidenceBinding(a[0], a[1], a[2]), 5);
    [Fact] public void SignPassport() => Fn("signPassport", Sign, 30);
    [Fact] public void PassportAssurance() => Fn("passportAssurance", Assurance, 8);

    [Fact]
    public void VerifyPassport()
    {
        Unbound = 0;
        Fn("verifyPassport", Verify, 109);
        Assert.Equal(1, Unbound);
    }

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "constants", "passportFingerprint", "issuePassport", "matchesBinding", "registry", "trustScore", "passportEvidenceBinding", "signPassport", "verifyPassport", "passportAssurance" });
        Assert.Equal(516, Base.Total(M));
        var counts = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int>
        {
            ["matchesBinding"] = 267, ["verifyPassport"] = 109, ["trustScore"] = 67, ["signPassport"] = 30, ["passportFingerprint"] = 13, ["issuePassport"] = 12, ["passportAssurance"] = 8,
            ["passportEvidenceBinding"] = 5, ["registry"] = 4, ["constants"] = 1,
        }, counts);
    }
}
