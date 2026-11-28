using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the software attestation layer (test-data/ref-attestation-soft.json.gz, 512 cases): the binding hash, the dev attestor and its documents, the registry, the nonce store and
/// entropy gate, the agent-binding match, VerifyAttestation and its hook, the multi-root verifier and evidence anchoring. Every fn has a handler and the per-fn totals are asserted. A reference
/// reason with "(fail closed):" carries the reference's own exception text after the colon: only the text up to it is compared. The legacy unbound-PQ opt-out does not exist here: the 2
/// verifyAttestation cases the reference accepts only through it are asserted refused, by count.</summary>
public class RefAttestationSoftTests
{
    const string M = "ref-attestation-soft";
    const string Mark = "(fail closed):";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static IHardwareAttestation? Hw(object? h)
    {
        if (h is not D d) return null;
        return new HardwareAttestationFn(_ => d.ContainsKey("throws") ? throw new InvalidOperationException((string)d["throws"]!) : d.GetValueOrDefault("result"));
    }

    static (string? Alg, SuiteSecretKeys? Keys) Suite(object? s)
    {
        if (s is not D d) return (null, null);
        var alg = (string)d["alg"]!;
        return alg == "ed25519" || !d.ContainsKey("pqSeed") ? (alg, null) : (alg, new SuiteSecretKeys { MlDsa = PqSuites.MlDsa65Keygen(Base.Bytes(d["pqSeed"])) });
    }

    static DevAttestor Attestor(object? secret, object? su)
    {
        var (alg, keys) = Suite(su);
        return AttestationSoft.CreateDevAttestor(Base.Bytes(secret), alg, keys);
    }

    static object? NonceStore(L a)
    {
        var opts = a[1] as D;
        object? t = IntentJs.OfLong(0);
        var store = new MemoryNonceStore(a[0], opts?.GetValueOrDefault("retentionMs"), () => t);
        var res = new L();
        foreach (var op in (L)a[2]!)
        {
            var o = (L)op!;
            if ((string)o[0]! == "clock") { t = o[1]; res.Add(null); }
            else res.Add(store.Consume(o[1]));
        }
        return res;
    }

    sealed class ConstStore(bool answer) : IAttestationNonceStore { public bool Consume(object? nonce) => answer; }

    static object? RegistryOp(L a)
    {
        var r = AttestationSoft.AttestationRegistry(a[0]);
        return ((L)a[1]!).Select(q => (object?)r(new D { ["pcactn"] = new D { ["attestation"] = new D { ["quote_digest"] = q } } })).ToList();
    }

    static object? Verify(L a)
    {
        var i = (D)Nums(a[0])!;
        var r = i.Where(e => e.Key is not ("hardware" or "document" or "allowUnboundPq")).ToDictionary(e => e.Key, e => e.Value);
        r["document"] = i.GetValueOrDefault("document");
        r["hardwareVerifier"] = Hw(i.GetValueOrDefault("hardware"));
        return AttestationSoft.VerifyAttestation(r);
    }

    static object? Quote(object? c) =>
        c is D cd && cd.GetValueOrDefault("pcactn") is D pc && pc.GetValueOrDefault("attestation") is D at ? at.GetValueOrDefault("quote_digest") : null;

    static object? Hook(L a)
    {
        var op = (D)Nums(a[0])!;
        var now = op["now"];
        var o = op.Where(e => e.Key is not ("store" or "storeConsume" or "hardware" or "docs" or "binding" or "now" or "allowUnboundPq")).ToDictionary(e => e.Key, e => e.Value);
        o["now"] = (Func<object?>)(() => now);
        o["hardwareVerifier"] = Hw(op.GetValueOrDefault("hardware"));
        var resolver = AttestationSoft.AttestationRegistry(op.GetValueOrDefault("docs") ?? new L());
        o["resolveDocument"] = (Func<object?, object?>)(c => resolver(c));
        if (op.GetValueOrDefault("store") is D s)
            o["nonceStore"] = new MemoryNonceStore(s.GetValueOrDefault("max"), s.GetValueOrDefault("retentionMs"), () => now);
        if (op.ContainsKey("storeConsume")) o["nonceStore"] = new ConstStore(op["storeConsume"] is true);
        var b = op.GetValueOrDefault("binding");
        if (b is "throws") o["expectedBinding"] = (Func<object?, object?>)(_ => throw new InvalidOperationException("boom"));
        else if (b is D bd)
            o["expectedBinding"] = (Func<object?, object?>)(c => Quote(c) is string qs && ((D)bd["byNonce"]!).TryGetValue(qs, out var e) ? e : null);
        var hook = AttestationSoft.CreateAttestationVerifier(o);
        return ((L)a[1]!).Select(c => (object?)hook(c)).ToList();
    }

    static object? MultiRoot(L a)
    {
        var pol = (D)Nums(a[0])!;
        var roots = new L();
        foreach (var r in (L)pol["roots"]!)
        {
            var rd = (D)r!;
            var e = new D { ["id"] = rd["id"], ["verifier"] = Hw(rd.GetValueOrDefault("hw")) };
            if (rd.ContainsKey("required")) e["required"] = rd["required"];
            if (rd.ContainsKey("suite")) e["suite"] = rd["suite"];
            roots.Add(e);
        }
        var v = AttestationSoft.CreateMultiRootVerifier(new D { ["threshold"] = pol["threshold"], ["roots"] = roots });
        return a[1] == null ? new D { ["built"] = true } : v.Verify((D)Nums(a[1])!);
    }

    static object? Anchor(L a)
    {
        var op = (D)a[1]!;
        var ledger = op.GetValueOrDefault("ledger") is "ok" ? new TransparencyLedger(op.GetValueOrDefault("principal") as string ?? "") : null;
        long preload = op.GetValueOrDefault("preload") is { } p ? Base.Long(p) : 0;
        if (ledger != null) for (long i = 0; i < preload; i++) ledger.AppendCommitment("c" + i);
        byte[]? secret = op.GetValueOrDefault("guardianSeed") is { } gs ? Base.Bytes(gs) : null;
        Func<object?>? now = op.TryGetValue("now", out var n) ? () => n : null;
        return AttestationSoft.AnchorAttestationEvidence(Nums(a[0]), ledger, secret, null, op.GetValueOrDefault("instanceId") as string, now, op.GetValueOrDefault("required") is true);
    }

    static bool Same(object? got, object? want)
    {
        if (want is string w && w.Contains(Mark)) return got is string g && g.StartsWith(w[..(w.IndexOf(Mark, StringComparison.Ordinal) + Mark.Length)], StringComparison.Ordinal);
        if (want is D wd && got is D gd) return wd.Count == gd.Count && wd.All(e => gd.TryGetValue(e.Key, out var x) && Same(x, e.Value));
        if (want is L wl && got is L gl) return wl.Count == gl.Count && wl.Zip(gl).All(p => Same(p.Second, p.First));
        return Base.Show(want) == Base.Show(got);
    }

    static bool Unbound(D c) => Base.Args(c) is { Count: > 0 } a && a[0] is D i && i.ContainsKey("allowUnboundPq") && c["out"] is D o && o.GetValueOrDefault("ok") is true;

    static void Fn(string fn, Func<L, object?> run, int min, Func<D, string?>? skip = null) =>
        Base.Check(M, fn, a => Base.Json(run(a)), (c, have) => Same(have, c["out"]), skip, min);

    [Fact] public void Constants() => Fn("constants", _ => AttestationSoft.Constants(), 1);
    [Fact] public void AttestationBinding() => Fn("attestationBinding", a => AttestationSoft.AttestationBinding(Nums(a[0])), 27);
    [Fact] public void AttestationBindingB64u() => Fn("attestationBindingB64u", a => AttestationSoft.AttestationBindingB64u(Nums(a[0])), 27);
    [Fact] public void Attest() => Fn("attest", a => Attestor(a[0], a[1]).Attest((D)Nums(a[2])!), 18);
    [Fact] public void AttestorPublicKey() => Fn("attestorPublicKey", a => Attestor(a[0], a[1]).PublicKey, 3);
    [Fact] public void AttestationDigest() => Fn("attestationDigest", a => AttestationSoft.AttestationDigest(Nums(a[0])), 6);
    [Fact] public void Registry() => Fn("registry", RegistryOp, 6);
    [Fact] public void NonceStoreReplay() => Fn("nonceStore", NonceStore, 23);
    [Fact] public void NonceEntropyOk() => Fn("nonceEntropyOk", a => AttestationSoft.NonceEntropyOk(Nums(a[0]), a.Count > 1 ? Nums(a[1]) : null), 32);
    [Fact] public void RequiresAttestation() => Fn("requiresAttestation", a => AttestationSoft.RequiresAttestation(Nums(a[0])), 29);
    [Fact] public void NonceBinds() => Fn("nonceBinds", a => AttestationSoft.NonceBinds(Nums(a[0]), Nums(a[1])), 8);
    [Fact] public void MatchAgentBinding() => Fn("matchAgentBinding", a => AttestationSoft.MatchAgentBinding(Nums(a[0]), Nums(a[1])), 170);
    [Fact] public void AttestationHook() => Fn("attestationHook", Hook, 23);
    [Fact] public void MultiRootVerifier() => Fn("multiRoot", MultiRoot, 27);
    [Fact] public void AttestationEvidenceDigest() => Fn("attestationEvidenceDigest", a => AttestationSoft.AttestationEvidenceDigest(Nums(a[0])), 11);
    [Fact] public void AnchorEvidence() => Fn("anchorEvidence", Anchor, 10);

    [Fact]
    public void VerifyAttestation()
    {
        Fn("verifyAttestation", Verify, 89, c => Unbound(c) ? "the unbound-PQ opt-out is not ported" : null);
        // the two cases the reference accepts only through allowUnboundPq: refused here (the PQ key is not pinned)
        var unbound = Base.Of(M, "verifyAttestation").Where(Unbound).ToList();
        Assert.Equal(2, unbound.Count);
        foreach (var c in unbound) Assert.Equal(false, ((D)Verify(Base.Args(c))!)["ok"]);
    }

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "attestationBinding", "attestationBindingB64u", "attest", "attestorPublicKey", "attestationDigest", "registry", "nonceStore", "nonceEntropyOk", "requiresAttestation",
            "nonceBinds", "matchAgentBinding", "verifyAttestation", "attestationHook", "multiRoot", "attestationEvidenceDigest", "anchorEvidence",
        });
        Assert.Equal(512, Base.Total(M));
        var counts = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int>
        {
            ["matchAgentBinding"] = 170, ["verifyAttestation"] = 91, ["nonceEntropyOk"] = 32, ["requiresAttestation"] = 29, ["attestationBinding"] = 27, ["attestationBindingB64u"] = 27,
            ["multiRoot"] = 27, ["nonceStore"] = 23, ["attestationHook"] = 23, ["attest"] = 18, ["attestationEvidenceDigest"] = 11, ["anchorEvidence"] = 10, ["nonceBinds"] = 8,
            ["attestationDigest"] = 6, ["registry"] = 6, ["attestorPublicKey"] = 3, ["constants"] = 1,
        }, counts);
        Assert.Equal(69, Base.Cases(M).Count(c => c["out"] is D o && o.ContainsKey("$throws")));
    }
}
