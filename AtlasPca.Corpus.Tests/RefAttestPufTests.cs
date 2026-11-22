using System.Security.Cryptography;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the PUF attestation root (test-data/ref-attest-puf.json.gz, 278 cases): the fuzzy extractor, the simulated PUF, the TPM EK provider over an injected command runner, enrollment, the device
/// attestor, the enrollment registry and the verifier. A PUF response is one 0/1 value per byte. The simulated PUF seed is a 32-byte base64url string. Every fn has a handler and the totals are asserted.</summary>
public class RefAttestPufTests
{
    const string M = "ref-attest-puf";

    static byte[] B(object? o) => o is string s ? Pca.B64uDecode(s)! : Base.Bytes(o);

    static IPufProvider Puf(object? spec)
    {
        var s = (D)spec!;
        var flips = s.GetValueOrDefault("flip") is L fl ? fl.Select(x => (int)Math.Clamp(IntentJs.NumOf(x)!.Value, int.MinValue, int.MaxValue)).ToList() : null;
        return new SimulatedPuf((string)s["id"]!, B(s["seed"]), (int)Base.Long(s["length"]), flips);
    }

    static Func<int, byte[]> Rand(object? r)
    {
        var l = (L)r!;
        int i = 0;
        return n => { var b = B(l[i++ == 0 ? 0 : 1]); return b[..Math.Min(n, b.Length)]; };
    }

    static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

    static object? Enroll(L a)
    {
        var (key, helper) = AttestPuf.FuzzyEnroll(B(a[0]), ((D)a[1]!).GetValueOrDefault("rep"), ((D)a[1]!).GetValueOrDefault("messageBits"), Rand(a[2]));
        return new D { ["keySha256"] = Sha(key), ["helper"] = helper };
    }

    static object? Tpm(L a)
    {
        var c = (D)a[0]!;
        var calls = new L();
        var rs = c["run"];
        TpmCommandResult? Runner(string cmd, IReadOnlyList<string> args)
        {
            calls.Add(new L { cmd, args.Cast<object?>().ToList() });
            if (rs is "undefined") return null;
            var d = (D)rs!;
            if (d.TryGetValue("$throws", out var m)) throw new InvalidOperationException((string)m!);
            return new TpmCommandResult(d["status"] == null ? null : (int)Base.Long(d["status"]), Base.IsBytes(d.GetValueOrDefault("stdout")) ? Base.Bytes(d["stdout"]) : null, d.GetValueOrDefault("stderr") as string, d.GetValueOrDefault("error") as string);
        }
        D o;
        try
        {
            var p = new TpmEkPufProvider((D)c["opts"]!, Runner);
            o = new D { ["ok"] = true, ["value"] = (string)c["op"]! == "readEkPublic" ? p.ReadEkPublic() : p.Response(c.TryGetValue("challenge", out var ch) ? B(ch) : B(Challenge())) };
        }
        catch (Exception e) { o = new D { ["ok"] = false, ["error"] = e.Message }; }
        o["calls"] = calls;
        return o;
    }

    // the corpus' default challenge is rb('challenge') = sha256("attest-puf-oracle-randomness/challenge")
    static D Challenge() => new() { ["$bytes"] = Pca.B64u(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("attest-puf-oracle-randomness/challenge"))) };

    static object? Registry(L a)
    {
        var sc = (D)a[0]!;
        var r = new PufEnrollmentRegistry(sc["enrollments"]);
        var res = new L();
        foreach (var op in (L)sc["ops"]!)
        {
            var o = (D)op!;
            var k = o.Keys.First();
            switch (k)
            {
                case "register": r.Register(o[k]); res.Add(null); break;
                case "lookup": res.Add(r.Lookup((string)o[k]!)); break;
                case "revoke": r.Revoke((string)o[k]!); res.Add(null); break;
                default: res.Add(r.IsRevoked((string)o[k]!)); break;
            }
        }
        return res;
    }

    static D Cfg(D sc, bool withResolver = true)
    {
        var cfgIn = (D)sc["config"]!;
        var pIn = (D)cfgIn["policy"]!;
        var policy = new D { ["measurements"] = pIn["measurements"] };
        if (pIn.TryGetValue("weightsMeasurements", out var w)) policy["weightsMeasurements"] = w;
        if (pIn.GetValueOrDefault("identity") is "custom")
            policy["deriveIdentity"] = (Func<D, D, D>)((st, enr) => new D { ["model_id"] = "m-custom", ["weights_digest"] = st.GetValueOrDefault("weights_digest") ?? "", ["weights_measured"] = true, ["runtime_measurement"] = st["measurement"], ["operator"] = enr["providerId"] });
        var byId = new Dictionary<string, object?>();
        foreach (var e in (sc.GetValueOrDefault("enrollments") as L) ?? new L()) byId[(string)((D)e!)["providerId"]!] = e;
        var cfg = new D { ["policy"] = policy };
        if (cfgIn.ContainsKey("requirePq")) cfg["requirePq"] = cfgIn["requirePq"];
        if (cfgIn.GetValueOrDefault("noResolveEnrollment") is not true) cfg["resolveEnrollment"] = (Func<string, object?, object?, object?>)((id, _, _) => byId.GetValueOrDefault(id));
        if (cfgIn.GetValueOrDefault("noEvidenceSeam") is not true) cfg["resolveEvidence"] = (Func<object?, object?, object?>)((_, _) => sc["evidence"]);
        if (sc.GetValueOrDefault("revoked") is L rv) cfg["isRevoked"] = (Func<string, bool>)(id => rv.Contains(id));
        return cfg;
    }

    static object? VerifyPuf(L a)
    {
        var sc = (D)a[0]!;
        var input = (D)sc["input"]!;
        var v = AttestPuf.CreatePufVerifier(Cfg(sc));
        return v.Verify(new D { ["document"] = new D(), ["ctx"] = new D(), ["nowMs"] = input["nowMs"], ["expected"] = input.GetValueOrDefault("expected") });
    }

    static object? BuildVerifier(L a)
    {
        var cfg = (D)a[0]!;
        var live = new D();
        if (cfg.TryGetValue("policy", out var p)) live["policy"] = p;
        if (cfg.GetValueOrDefault("noResolveEnrollment") is not true) live["resolveEnrollment"] = (Func<string, object?, object?, object?>)((_, _, _) => null);
        AttestPuf.CreatePufVerifier(live);
        return new D { ["built"] = true };
    }

    // a reference result {ok: true, value} wraps the value of a run(); the other forms are compared as they are
    static object? Unwrap(object? want) => want is D d && d.Count == 2 && d.GetValueOrDefault("ok") is true && d.TryGetValue("value", out var v) ? v : want;

    static void Fn(string fn, Func<L, object?> run, int min) =>
        Base.Check(M, fn, a => Base.Json(run(a)), (c, have) => Base.Show(Unwrap(c["out"])) == Base.Show(have), null, min);

    [Fact] public void Constants() => Fn("constants", _ => AttestPuf.Constants(), 1);
    [Fact] public void RepetitionCorrectionBound() => Fn("repetitionCorrectionBound", a => (long)AttestPuf.RepetitionCorrectionBound(IntentJs.NumOf(a[0])!.Value), 12);
    [Fact] public void SimulatedPufResponse() => Fn("simulatedPufResponse", a => Puf(a[0]).Response(B(a[1])), 30);
    [Fact] public void FuzzyEnroll() => Fn("fuzzyEnroll", Enroll, 23);
    [Fact] public void FuzzyReproduce() => Fn("fuzzyReproduce", a => new D { ["keySha256"] = Sha(AttestPuf.FuzzyReproduce(B(a[0]), a[1])) }, 80);
    [Fact] public void TpmEk() => Base.Check(M, "tpmEk", a => Base.Json(Tpm(a)), null, null, 30);
    [Fact] public void EnrollPuf() => Fn("enrollPuf", a => AttestPuf.EnrollPuf(Puf(a[0]), B(a[1]), (D)a[2]!, Rand(a[3])), 13);
    [Fact] public void PufAttest() => Fn("pufAttest", a => AttestPuf.CreatePufAttestor(Puf(a[0]), (D)a[1]!).Attest((D)a[2]!), 22);
    [Fact] public void RegistryOps() => Fn("registry", Registry, 10);
    [Fact] public void VerifyPufStatements() => Fn("verifyPuf", VerifyPuf, 52);
    [Fact] public void BuildVerifierCases() => Fn("buildVerifier", BuildVerifier, 5);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "constants", "repetitionCorrectionBound", "simulatedPufResponse", "fuzzyEnroll", "fuzzyReproduce", "tpmEk", "enrollPuf", "pufAttest", "registry", "verifyPuf", "buildVerifier" });
        Assert.Equal(278, Base.Total(M));
        var counts = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int>
        {
            ["constants"] = 1, ["repetitionCorrectionBound"] = 12, ["simulatedPufResponse"] = 30, ["fuzzyEnroll"] = 23, ["fuzzyReproduce"] = 80, ["tpmEk"] = 30, ["enrollPuf"] = 13, ["pufAttest"] = 22,
            ["registry"] = 10, ["verifyPuf"] = 52, ["buildVerifier"] = 5,
        }, counts);
    }
}
