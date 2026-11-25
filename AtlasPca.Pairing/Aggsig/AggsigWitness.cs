using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Aggsig;

/// <summary>
/// BLS aggregation of transparency-ledger witness cosignatures: a quorum cosigns the same tree-head statement
/// {size, root, prev_root, guardian_epoch}; the quorum collapses into one 96-byte aggregate verified by one FastAggregateVerify.
/// </summary>
public static class AggsigWitness
{
    const string SthWitnessBlsDomain = "atlas-pca/sth-witness-bls/v1\0";

    static byte[] WitnessMessage(D h)
    {
        var b = new D
        {
            ["size"] = h.GetValueOrDefault("size"),
            ["root"] = h.GetValueOrDefault("root"),
            ["prev_root"] = h.GetValueOrDefault("prev_root"),
            ["guardian_epoch"] = h.GetValueOrDefault("guardian_epoch") ?? new Num("0"),
        };
        return AtlasPca.Pca.Cat(AggsigCore.Utf8(SthWitnessBlsDomain), Encoding.UTF8.GetBytes(AtlasPca.Pca.Canonicalize(b)));
    }

    /// <summary>A trusted witness cosigns the tree-head statement with its BLS secret key: {key, sig, suite}.</summary>
    public static D CosignTreeHead(D statement, byte[] witnessSecret) => new()
    {
        ["key"] = AtlasPca.Pca.B64u(AggsigCore.PublicKeyOf(witnessSecret)),
        ["sig"] = AtlasPca.Pca.B64u(AggsigCore.Sign(witnessSecret, WitnessMessage(statement))),
        ["suite"] = AggsigChain.BlsSuite,
    };

    /// <summary>Verify ONE cosignature against the exact statement. Never throws.</summary>
    public static bool VerifyWitnessCosignature(D statement, D? cosig)
    {
        try
        {
            if (cosig == null || cosig.GetValueOrDefault("suite") is not string su || su != AggsigChain.BlsSuite) return false;
            var key = AtlasPca.Pca.B64uDecode(cosig.GetValueOrDefault("key"));
            var msg = WitnessMessage(statement);
            var sig = AtlasPca.Pca.B64uDecode(cosig.GetValueOrDefault("sig"));
            if (key == null || sig == null) return false;
            return AggsigCore.Verify(key, msg, sig);
        }
        catch (Exception e) when (e is InvalidOperationException or ArgumentException or InvalidCastException) { return false; }
    }

    /// <summary>Collapse a quorum of cosignatures into one aggregate. Throws on an empty set or a sig that is not valid b64u.</summary>
    public static byte[] AggregateWitnessCosignatures(IReadOnlyList<D>? cosigs)
    {
        if (cosigs == null || cosigs.Count == 0) throw new ArgumentException("aggregateWitnessCosignatures: empty set");
        var sigs = new List<byte[]>();
        foreach (var c in cosigs) sigs.Add(AtlasPca.Pca.B64uDecode(c.GetValueOrDefault("sig")) ?? throw new ArgumentException("not canonical base64url"));
        return Aggsig.Aggregate(sigs);
    }

    /// <summary>One FastAggregateVerify over the statement for exactly the registered witness keys supplied; a repeated witness is refused. Never throws.</summary>
    public static bool VerifyAggregatedWitnessCosignatures(D statement, IReadOnlyList<RegisteredKey?>? witnessKeys, byte[]? aggSig)
    {
        try
        {
            if (witnessKeys == null || witnessKeys.Count == 0) return false;
            var seen = new HashSet<string>();
            foreach (var k in witnessKeys)
            {
                if (k == null) return false;
                if (!seen.Add(Aggsig.Hex(k.Bytes()))) return false;
            }
            return Aggsig.FastAggregateVerify(witnessKeys, WitnessMessage(statement), aggSig);
        }
        catch (Exception e) when (e is InvalidOperationException or ArgumentException or InvalidCastException) { return false; }
    }
}
