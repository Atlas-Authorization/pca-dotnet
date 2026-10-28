using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// Replays packages/pca/conformance/passport-vectors.json (signed agent passport): every signature suite this verifier implements
// (a suite it does not implement must answer unsupported_suite), the hardware branch through a stub verifier that answers what
// the vector says, and (passport_hardware_vectors) hardware-rooted passports verified by the REAL vendor verifiers built from the
// vendor configuration, through the default-verifier seam.
public class PassportVectorTests
{
    static readonly HashSet<string> Supported = new(Pq.SupportedSuites());

    /// <summary>Verifies every row; returns how many exercised a supported signature suite.</summary>
    internal static int ReplayRows(List<object?> rows, Dictionary<string, object?> docs)
    {
        int seenSuites = 0;
        foreach (var x in rows)
        {
            var v = D(x);
            var name = (string)v["name"]!;
            object? signed = v.TryGetValue("signed_ref", out var rf) && rf is string r ? docs[r] : v.GetValueOrDefault("signed");
            docs[name] = signed;
            var revoked = L(v["revoked"]).Cast<string>().ToHashSet();
            var o = new PassportOptions
            {
                TrustedIssuers = L(v["trustedIssuers"]).Cast<string>().ToList(), NowMs = N(v["now"]),
                Revoked = (id, _, _) => revoked.Contains(id),
            };
            if (v.TryGetValue("clockSkewMs", out var cs)) o.ClockSkewMs = N(cs);
            if (v.TryGetValue("maxEvidenceAgeMs", out var ma)) o.MaxEvidenceAgeMs = N(ma);
            if (v.GetValueOrDefault("subject") is string sub) o.Subject = sub;
            if (v.GetValueOrDefault("pqPins") is JD pins) o.PqPins = pins.ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
            PassportBinding? gotBinding = null;
            if (v.GetValueOrDefault("hardware") is JD h)
                o.Attest = (_, b) =>
                {
                    gotBinding = b;
                    if (h.GetValueOrDefault("throws") is true) throw new InvalidOperationException("verifier down");
                    return new PassportAttestation(h.GetValueOrDefault("ok") is true, h.GetValueOrDefault("bound") is true, h.GetValueOrDefault("measured") as JD);
                };
            if (v.GetValueOrDefault("hardware_verifier") is JD hv)
            {
                var ver = AttestationVerifiers.FromConfig((string)hv["vendor"]!, hv.GetValueOrDefault("config") as JD);
                var ev = hv.GetValueOrDefault("evidence") as JD;
                o.DefaultHardware = new DefaultHardware(ver, _ => ev);
            }
            var got = Passports.Verify(signed, o).Reason ?? "";
            var e = D(v["expect"]);
            var want = e["ok"] is true ? "" : (string)e["reason"]!;
            if (signed is JD sm && sm.GetValueOrDefault("alg") is string alg)
            {
                if (!Supported.Contains(alg)) want = "unsupported_suite"; else seenSuites++;
            }
            Assert.True(got == want, $"{name}: got '{got}' want '{want}'");
            if (v.GetValueOrDefault("expectBinding") is JD eb)
                Assert.True(gotBinding != null && gotBinding.HolderPub == (string)eb["holderPub"]! && gotBinding.GrantRef == (string)eb["grantRef"]!
                    && gotBinding.Epoch == N(eb["epoch"]) && gotBinding.Nonce == (string)eb["nonce"]!, $"{name}: the verifier was handed {gotBinding}");
        }
        return seenSuites;
    }

    static List<object?> Table(string name)
    {
        var doc = Load("passport-vectors.json");
        Assert.True(doc.ContainsKey(name), $"passport-vectors.json has no {name} table: regenerate it with the TypeScript reference (tsx scripts/gen-conformance-passport.ts in packages/pca)");
        return L(doc[name]);
    }

    [Fact]
    public void SignedPassportVectors()
    {
        var rows = Table("passport_vectors");
        Assert.True(rows.Count >= 74, $"only {rows.Count} vectors");
        Assert.True(ReplayRows(rows, new Dictionary<string, object?>()) >= 3, "fewer than 3 vectors exercised a supported post-quantum suite");
    }

    [Fact]
    public void PassportHardwareVectors()
    {
        var rows = Table("passport_hardware_vectors");
        Assert.True(rows.Count >= 40, $"only {rows.Count} passport_hardware_vectors");
        ReplayRows(rows, new Dictionary<string, object?>());
    }

    // ---- exact outcomes on the shared codes, without the vector file

    static JD Hw(bool ok, bool bound, JD? measured) => new() { ["ok"] = ok, ["bound"] = bound, ["measured"] = measured };

    [Fact]
    public void MalformedAndStructuralRefusals()
    {
        var o = new PassportOptions { TrustedIssuers = new[] { "k" }, NowMs = 1000, Revoked = (_, _, _) => false };
        foreach (var junk in new object?[] { null, "x", new List<object?>(), new JD(), new JD { ["typ"] = "atlas-pca/passport" }, new JD { ["typ"] = "atlas-pca/passport", ["passport"] = null } })
            Assert.Equal("malformed", Passports.Verify(junk, o).Reason);
        var s = new JD { ["typ"] = "atlas-pca/passport", ["passport"] = new JD(), ["ver"] = new Num("2") };
        Assert.Equal("unsupported_version", Passports.Verify(s, o).Reason);
        s["ver"] = new Num("1"); s["alg"] = "rot13";
        Assert.Equal("unsupported_suite", Passports.Verify(s, o).Reason);
        Assert.Equal("unsupported_suite", Passports.Verify(new JD(s) { ["alg"] = new Num("1") }, o).Reason);
        s.Remove("alg");
        Assert.Equal("malformed", Passports.Verify(s, o).Reason);
    }

    [Fact]
    public void ARevocationSourceIsRequiredAndAThrowDenies()
    {
        var rows = Table("passport_vectors");
        var v = rows.Cast<JD>().First(r => D(r["expect"])["ok"] is true && !r.ContainsKey("signed_ref") && !r.ContainsKey("hardware") && D(r["signed"]!).GetValueOrDefault("alg") == null);
        PassportOptions Opt(Func<string, string, string, bool>? rev) => new()
        {
            TrustedIssuers = L(v["trustedIssuers"]).Cast<string>().ToList(), NowMs = N(v["now"]), Revoked = rev,
            Subject = v.GetValueOrDefault("subject") as string,
        };
        Assert.Null(Passports.Verify(v["signed"], Opt((_, _, _) => false)).Reason);
        Assert.Equal("revocation_unavailable", Passports.Verify(v["signed"], Opt(null)).Reason);
        Assert.Equal("revocation_unavailable", Passports.Verify(v["signed"], Opt((_, _, _) => throw new InvalidOperationException())).Reason);
        Assert.Equal("revoked", Passports.Verify(v["signed"], Opt((_, _, _) => true)).Reason);
        Assert.Equal("unknown_issuer", Passports.Verify(v["signed"], new PassportOptions { TrustedIssuers = Array.Empty<string>(), NowMs = N(v["now"]), Revoked = (_, _, _) => false }).Reason);
    }
}
