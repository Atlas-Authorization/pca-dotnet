using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class ChainCompactTests
{
    static SuiteKey K(byte b) => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat(b, 32).ToArray()));
    static readonly SuiteKey P = K(1), H = K(2), S = K(3);
    static JD Note(int v) => new() { ["type"] = "note", ["v"] = new Num(v.ToString()) };

    static (JD root, JD child, JL chain) Make()
    {
        var root = Issue.MintRoot(P, H.Id!, null, new JL { Note(1) });
        var child = Issue.Delegate(root, S.Id!, new JL { Note(2) }, H);
        return (root, child, new JL { root, child });
    }

    static string Show(List<BoundCaveat> l) => string.Join(";", l.Select(b => Pca.Canonicalize(b.Caveat) + "@" + b.Hop + ":" + b.CapHash));

    [Fact]
    public void CompactChainAndShape()
    {
        var (root, child, chain) = Make();
        var c = ChainCompact.CompactChain(chain);
        Assert.Equal(ChainCompact.HopsRoot(chain), c["hops_root"]);
        Assert.Same(child, c["leaf"]);
        Assert.Null(ChainCompact.CompactChainShapeError(c));
        Assert.Contains("depth", ChainCompact.CompactChainShapeError(new JD(c) { ["depth"] = new Num("0") }));
        Assert.Contains("43", ChainCompact.CompactChainShapeError(new JD(c) { ["hops_root"] = "x" }));
        Assert.Contains("unknown member", ChainCompact.CompactChainShapeError(new JD(c) { ["z"] = new Num("1") }));
        Assert.Equal("not an object", ChainCompact.CompactChainShapeError(null));
        Assert.Throws<ArgumentException>(() => ChainCompact.CompactChain(new JL()));
        Assert.NotEqual(ChainCompact.HopsRoot(chain), ChainCompact.HopsRoot(new JL { root }));
        Assert.NotEqual(ChainCompact.HopsRoot(chain), ChainCompact.HopsRoot(new JL { child, root }));
    }

    [Fact]
    public void MemoResolvesAndTheCaveatLanguageDecidesIdentically()
    {
        var (root, child, chain) = Make();
        var memo = new ChainMemo();
        var c = memo.RememberVerified(chain, P.Id!, 1000);
        Assert.Equal(1, memo.Size);
        var r = memo.Resolve(c, 2000);
        Assert.True(r.Ok);
        var v = r.View!;
        Assert.Equal(2, v.N); Assert.Same(child, v.Leaf); Assert.Equal(Pca.CapHash(child), v.Hash(1)); Assert.Equal(2, v.Count(1)); Assert.Equal(1, v.Count(0));
        Assert.Equal(Show(CaveatLang.BoundCaveats(root, chain)!), Show(CaveatLang.BoundCaveats(root, v)!));
        Assert.Equal(Pca.Canonicalize(new JL(CaveatLang.DischargeRequests(root, chain, null).Cast<object?>())), Pca.Canonicalize(new JL(CaveatLang.DischargeRequests(root, v, null).Cast<object?>())));
        var bad = chain.Select(h => (object?)new JD((JD)h!)).ToList();
        ((JD)bad[1]!)["sig"] = ((JD)bad[0]!)["sig"];
        Assert.Throws<ArgumentException>(() => new ChainMemo().RememberVerified(bad, P.Id!, 1000));
        Assert.Throws<ArgumentException>(() => new ChainMemo().RememberVerified(chain, S.Id!, 1000));
    }

    [Fact]
    public void ResolveRefusals()
    {
        var (root, _, chain) = Make();
        var memo = new ChainMemo(ttlMs: 100);
        var c = memo.RememberVerified(chain, P.Id!, 1000);
        Assert.Contains("not in this verifier memo", new ChainMemo().Resolve(c, 1000).Reason);
        Assert.Contains("depth differs", memo.Resolve(new JD(c) { ["depth"] = new Num("1") }, 1000).Reason);
        Assert.Contains("not the memoized last hop", memo.Resolve(new JD(c) { ["leaf"] = root }, 1000).Reason);
        Assert.Contains("malformed compact chain", memo.Resolve(new JD(), 1000).Reason);
        Assert.Contains("expired", memo.Resolve(c, 1101).Reason);
        Assert.Equal(0, memo.Size);
        Assert.False(memo.Forget("x"));
    }

    [Fact]
    public void FullMemoNeverEvictsALiveEntry()
    {
        var (root, _, chain) = Make();
        var memo = new ChainMemo(maxEntries: 1);
        memo.RememberVerified(chain, P.Id!, 1000);
        memo.RememberVerified(chain, P.Id!, 1001);
        Assert.Throws<InvalidOperationException>(() => memo.RememberVerified(new JL { root }, P.Id!, 1002));
        memo.Prune(10_000_000);
        Assert.Equal(0, memo.Size);
    }

    [Fact]
    public void CheapChainCheckAndHolderPqKey()
    {
        var (root, child, chain) = Make();
        Assert.Equal((true, 0, (string?)null), Pca.VerifyChainCheap(chain, P.Id));
        Assert.Equal("empty chain", Pca.VerifyChainCheap(new JL()).Reason);
        Assert.Contains("expected principal", Pca.VerifyChainCheap(chain, S.Id).Reason);
        Assert.Contains("not allowed", Pca.VerifyChainCheap(chain, null, new[] { "ml-dsa-65" }).Reason);
        Assert.Contains("broken parent link", Pca.VerifyChainCheap(new JL { root, root }).Reason);
        var t = chain.Select(h => (object?)new JD((JD)h!)).ToList();
        ((JD)t[1]!)["caveats"] = new JL { Note(1), Note(2), new JD { ["type"] = "x" } };
        Assert.Contains("body digest mismatch", Pca.VerifyChainCheap(t).Reason);
        var f = chain.Select(h => (object?)new JD((JD)h!)).ToList();
        ((JD)f[1]!)["sig"] = ((JD)f[0]!)["sig"];
        Assert.Contains("bad signature", Pca.VerifyChainCheap(f).Reason);
        Assert.Contains("malformed capability", Pca.VerifyChainCheap(new JL { new JD { ["a"] = new Num("1") } }).Reason);
        Assert.Contains("unknown signature alg", Pca.VerifyChainCheap(new JL { new JD(root) { ["alg"] = "rsa" } }).Reason);

        Assert.Null(Pca.HolderPqKey(null, "h", "k", null));
        Assert.Null(Pca.HolderPqKey("ed25519", "h", "k", null));
        var pk = Pca.B64u(Enumerable.Repeat((byte)'a', 1952).ToArray());
        Assert.Null(Pca.HolderPqKey("ml-dsa-65", "h", pk, null));
        Assert.Null(Pca.HolderPqKey("ml-dsa-65", "h", pk, "wrong"));
        Assert.Equal(pk, Pca.HolderPqKey("ml-dsa-65", "h", pk, Pca.HolderPqCommitment(pk)));
    }
}

public class PcactnCheapClaimsTests
{
    static JD P(string aud, long iat, long exp) => new() { ["aud"] = aud, ["iat"] = new Num(iat.ToString()), ["exp"] = new Num(exp.ToString()) };

    [Fact]
    public void RefusesWhatTheFullVerifierWould()
    {
        Assert.Null(Pca.PcactnCheapClaims(P("a", 1000, 2000), "a", 1500));
        Assert.Equal("audience", Pca.PcactnCheapClaims(P("b", 1000, 2000), "a", 1500)!.Check);
        Assert.Equal("audience", Pca.PcactnCheapClaims(new JD(), "a", 1500)!.Check);
        Assert.Contains("safe-integer", Pca.PcactnCheapClaims(new JD { ["aud"] = "a", ["iat"] = "x", ["exp"] = new Num("1") }, "a", 1)!.Reason);
        Assert.Contains("greater than iat", Pca.PcactnCheapClaims(P("a", 2000, 2000), "a", 1500)!.Reason);
        Assert.Contains("lifetime exceeds", Pca.PcactnCheapClaims(P("a", 0, 3_600_001), "a", 1)!.Reason);
        Assert.Contains("future", Pca.PcactnCheapClaims(P("a", 100_000, 200_000), "a", 1)!.Reason);
        Assert.Contains("expired", Pca.PcactnCheapClaims(P("a", 1000, 2000), "a", 3000)!.Reason);
    }
}
