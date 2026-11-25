using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the compact chain form (hop leaves, hops root, shape check, the view of a chain and the verifier memo driven through a scripted sequence)
/// against the reference corpus.</summary>
public class RefCoreChainCompactTests
{
    const string M = "ref-core-chain-compact";

    static D ViewOut(ChainView v) => new()
    {
        ["n"] = v.N, ["leaf"] = v.Leaf,
        ["hashes"] = Enumerable.Range(0, v.N).Select(i => (object?)v.Hash(i)).ToList(),
        ["counts"] = Enumerable.Range(0, v.N).Select(i => (object?)v.Count(i)).ToList(),
    };

    /// <summary>The clock the reference takes only when it is a safe integer.</summary>
    static long? Clock(object? n) => Base.IsJsonInt(n) && IntentJs.IsSafeInteger(n) ? Base.Long(n) : null;

    static L MemoSeqRun(D? opts, L steps)
    {
        var m = new ChainMemo(opts != null && opts.ContainsKey("maxEntries") ? (int)Base.Long(opts["maxEntries"]) : ChainCompact.MemoDefaultMaxEntries,
            opts != null && opts.ContainsKey("ttlMs") ? Base.Long(opts["ttlMs"]) : ChainCompact.MemoMaxTtlMs);
        var o = new L();
        foreach (var so in steps)
        {
            var s = (L)so!;
            switch ((string)s[0]!)
            {
                case "remember":
                    try
                    {
                        var now = Clock(s[3]) ?? throw new ArgumentException("the clock is not a safe integer");
                        o.Add(new D { ["ok"] = true, ["compact"] = m.RememberVerified((L)s[1]!, (string)s[2]!, now) });
                    }
                    catch (Exception) { o.Add(new D { ["ok"] = false }); }
                    break;
                case "resolve":
                    var at = Clock(s[2]);
                    if (at == null) { o.Add(new D { ["ok"] = false, ["reason"] = "the verifier clock is not a safe integer (fail closed)" }); break; }
                    var r = m.Resolve(s[1], at.Value);
                    o.Add(r.Ok ? new D { ["ok"] = true, ["view"] = ViewOut(r.View!) } : new D { ["ok"] = false, ["reason"] = r.Reason });
                    break;
                case "prune":
                    m.Prune(Base.Long(s[1]));
                    o.Add(null);
                    break;
                case "forget":
                    o.Add(m.Forget((string)s[1]!));
                    break;
                default:
                    o.Add(m.Size);
                    break;
            }
        }
        return o;
    }

    [Fact] public void HopLeaf() => Base.Check(M, "hopLeaf", a => ChainCompact.HopLeaf(a[0]));
    [Fact] public void HopsRoot() => Base.Check(M, "hopsRoot", a => ChainCompact.HopsRoot((L)a[0]!));
    [Fact] public void CompactChain() => Base.Check(M, "compactChain", a => ChainCompact.CompactChain((L)a[0]!));
    [Fact] public void CompactChainShapeError() => Base.Check(M, "compactChainShapeError", a => ChainCompact.CompactChainShapeError(a[0]));
    [Fact] public void ViewOfChain() => Base.Check(M, "viewOfChain", a => ViewOut(ChainCompact.ViewOfChain(a[0], a[1])));
    [Fact] public void MemoSeq() => Base.Check(M, "memoSeq", a => MemoSeqRun(a[0] as D, (L)a[1]!));

    [Fact] public void Covers() { Base.Covers(M, new[] { "hopLeaf", "hopsRoot", "compactChain", "compactChainShapeError", "viewOfChain", "memoSeq" }); Assert.Equal(69, Base.Total(M)); }
}
