using AtlasPca.Js;
using AtlasPca.Revoke;
using AtlasPca.Rotate;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of key rotation and subtree revocation (test-data/ref-rotate.json.gz, TypeScript reference pca-rotate).
/// Keys cross the oracle as base64url Ed25519 seeds. A record or entry whose revokedAt is within two minutes of the wall clock prints "&lt;now&gt;" on both sides.</summary>
public class RefRotateTests
{
    const string M = "ref-rotate";

    static EdKey? Key(object? seed) => seed is string s ? EdKey.FromSeed(Pca.B64uDecode(s)!) : null;

    /// <summary>The frozen clock the corpus generator ran under (its header's clockMs).</summary>
    static readonly double Clock = Base.ClockMs(M);

    // the wall clock, or the corpus generator's frozen clock
    static bool IsNow(double ms) => Math.Abs(ms - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) < 120_000 || Math.Abs(ms - Clock) < 120_000;

    static object? Norm(object? v)
    {
        switch (v)
        {
            case L l: return l.Select(Norm).ToList();
            case D d:
                var o = new D();
                foreach (var (k, x) in d)
                    o[k] = k == "revokedAt" && x is Num n && IsNow(IntentJs.NumOf(n)!.Value) ? "<now>" : Norm(x);
                return o;
            default: return v;
        }
    }

    // JSON.parse(JSON.stringify(x)): -0 becomes 0, numbers print as JavaScript prints them
    static object? Roundtrip(object? v) => Norm(Pca.ParseJson(JsJson.Stringify(v)));

    static D Out(RotationResult r) => new() { ["chain"] = r.Chain, ["revocation"] = r.Revocation };

    static string? Reason(D op) => op.GetValueOrDefault("reason") as string;

    /// <summary>An explicit JSON null is not an omitted option: the reference refuses it (the API reads a missing one as the clock).</summary>
    static object? NowArg(D op) => op.TryGetValue("now", out var n) ? n ?? new object() : null;

    [Fact]
    public void RotateAgentKey() => Base.Check(M, "rotateAgentKey", a =>
    {
        var op = (D)a[1]!;
        var old = Key(op.GetValueOrDefault("oldSeed"));
        var nw = Key(op.GetValueOrDefault("newSeed"));
        return Roundtrip(Out(RotateApi.RotateAgentKey(a[0], old, nw, Reason(op), NowArg(op))));
    });

    [Fact]
    public void RotatePrincipalKey() => Base.Check(M, "rotatePrincipalKey", a =>
    {
        var args = (D)a[0]!;
        var old = Key(args.GetValueOrDefault("oldSeed"));
        var nw = Key(args.GetValueOrDefault("newSeed"));
        var secrets = args.GetValueOrDefault("holderSeeds") is L hs ? hs.Select(Key).ToList() : null;
        return Roundtrip(Out(RotateApi.RotatePrincipalKey(args.GetValueOrDefault("chain"), args.GetValueOrDefault("oldRoot"), old, nw, secrets, Reason(args), NowArg(args))));
    });

    [Fact]
    public void RevokeAndReissueSubtree() => Base.Check(M, "revokeAndReissueSubtree", a =>
    {
        var op = (D)a[2]!;
        return Roundtrip(Out(RotateApi.RevokeAndReissueSubtree(a[0], a[1], Key(op.GetValueOrDefault("newSeed")), Key(op.GetValueOrDefault("ancestorSeed")), Reason(op), NowArg(op))));
    });

    [Fact]
    public void CompromisedKeyFlow() => Base.Check(M, "compromisedKeyFlow", a =>
    {
        var op = (D)a[2]!;
        var r = RotateApi.CompromisedKeyFlow(a[0], a[1], Key(op.GetValueOrDefault("newSeed")), Key(op.GetValueOrDefault("ancestorSeed")), Reason(op), NowArg(op));
        return Roundtrip(new D { ["revocations"] = r.Revocations.Select(x => (object?)x).ToList(), ["reissued"] = r.Reissued });
    });

    /// <summary>A registry behind a sink that throws from its failAt-th revoke call and, with failUnrevoke, from every unrevoke.</summary>
    sealed class Sink(RevocationRegistry reg, long failAt, bool failUnrevoke) : IRevocationSink
    {
        long _calls;
        public async Task Revoke(D input)
        {
            _calls++;
            if (failAt == _calls) throw new InvalidOperationException("sink down");
            await reg.Revoke(input);
        }
        public Task<bool> Unrevoke(D key) => failUnrevoke ? throw new InvalidOperationException("unrevoke down") : reg.Unrevoke(key);
        public Task<D?> Lookup(string kind, string value) => reg.Lookup(kind, value);
    }

    static async Task<D> ApplyScenario(D spec)
    {
        var reg = new RevocationRegistry();
        foreach (var id in spec.GetValueOrDefault("pre") as L ?? new L())
            await reg.Revoke(new D { ["kind"] = "cap", ["value"] = id, ["reason"] = "pre", ["revokedAt"] = new Num(((long)Clock).ToString(System.Globalization.CultureInfo.InvariantCulture)) });
        var failAt = spec.GetValueOrDefault("failAt") is Num n ? (long)IntentJs.NumOf(n)!.Value : -1;
        var sink = new Sink(reg, failAt, spec.GetValueOrDefault("failUnrevoke") is true);
        object? result;
        try { result = (await RotateApi.ApplyRotation(sink, spec.GetValueOrDefault("records"), spec.GetValueOrDefault("reissued"))).Select(s => (object?)s).ToList(); }
        catch (Exception) { result = new D { ["$err"] = true }; }
        return new D { ["result"] = result, ["list"] = Roundtrip(await reg.List()) };
    }

    [Fact] public void ApplyRotationScenario() => Base.Check(M, "applyRotationScenario", a => ApplyScenario((D)a[0]!).GetAwaiter().GetResult());

    [Fact]
    public void EveryFn() { Base.Covers(M, new[] { "rotateAgentKey", "rotatePrincipalKey", "revokeAndReissueSubtree", "compromisedKeyFlow", "applyRotationScenario" }); Assert.Equal(1239, Base.Total(M)); }
}
