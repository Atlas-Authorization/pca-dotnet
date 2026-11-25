using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Aggsig;

/// <summary>
/// A BLS-suite attenuable capability chain: the same structure as the core chain (hash-linked, holder-to-issuer continuity,
/// append-only caveats) but each hop is signed with the BLS12-381 PoP scheme, so an M-hop chain's signatures collapse into one
/// 96-byte aggregate checked with one pairing-product AggregateVerify. Capabilities are JSON maps (issuer, holder, caveats,
/// parent?, id, body_digest, sig, suite).
/// </summary>
public static class AggsigChain
{
    const string CapBlsDomain = "atlas-pca/cap-bls/v1\0";
    public const string BlsSuite = "bls12-381-pop";
    public const int MaxChainDepth = 16;

    static D BodyOf(D c) => new()
    {
        ["issuer"] = c.GetValueOrDefault("issuer"),
        ["holder"] = c.GetValueOrDefault("holder"),
        ["caveats"] = c.GetValueOrDefault("caveats"),
        ["parent"] = c.GetValueOrDefault("parent"),
    };

    static byte[] SigMessage(string bodyDigest)
    {
        var d = AtlasPca.Pca.B64uDecode(bodyDigest) ?? throw new ArgumentException("not canonical base64url");
        return AtlasPca.Pca.Cat(AggsigCore.Utf8(CapBlsDomain), d);
    }

    /// <summary>Identity of a capability: the hash of everything EXCEPT sig, so a free sig string cannot mint distinct identities for one hop.</summary>
    public static string CapHash(D c)
    {
        var rest = new D(c);
        rest.Remove("sig");
        return AtlasPca.Pca.HashCanonical(rest);
    }

    static L CloneCaveats(L cs) => (L)AtlasPca.Pca.ParseStrict(AtlasPca.Pca.Canonicalize(cs))!;

    static D Seal(string issuer, string holder, L caveats, string? parent, byte[] signerSecret)
    {
        var body = new D { ["issuer"] = issuer, ["holder"] = holder, ["caveats"] = caveats, ["parent"] = parent };
        var digest = AtlasPca.Pca.HashCanonical(body);
        var sig = AtlasPca.Pca.B64u(AggsigCore.Sign(signerSecret, SigMessage(digest)));
        var cap = new D
        {
            ["id"] = digest,
            ["issuer"] = issuer,
            ["holder"] = holder,
            ["caveats"] = caveats,
            ["body_digest"] = digest,
            ["sig"] = sig,
            ["suite"] = BlsSuite,
        };
        if (parent != null) cap["parent"] = parent;
        return cap;
    }

    /// <summary>b64u BLS G1 public key for a secret scalar: the identity a chain is rooted at / delegated to.</summary>
    public static string BlsPublicKey(byte[] secretKey) => AtlasPca.Pca.B64u(AggsigCore.PublicKeyOf(secretKey));

    /// <summary>Mint a root capability, signed by the principal.</summary>
    public static D MintBlsRoot(byte[] principalSecret, string principalPublic, string holder, L caveats) =>
        Seal(principalPublic, holder, CloneCaveats(caveats), null, principalSecret);

    /// <summary>Child with the SAME holder; caveats = parent caveats then added. Signed by the parent's holder.</summary>
    public static D BlsAttenuate(D parent, L added, byte[] signerSecret) =>
        BlsDelegate(parent, (string)parent["holder"]!, added, signerSecret);

    /// <summary>Like BlsAttenuate, but rebinds the holder to a new sub-agent key.</summary>
    public static D BlsDelegate(D parent, string toHolder, L added, byte[] signerSecret)
    {
        var cav = new L(CloneCaveats((L)parent["caveats"]!));
        cav.AddRange(CloneCaveats(added));
        return Seal((string)parent["holder"]!, toHolder, cav, CapHash(parent), signerSecret);
    }

    static bool WellTyped(object? o)
    {
        if (o is not D x) return false;
        if (!(x.GetValueOrDefault("id") is string && x.GetValueOrDefault("issuer") is string && x.GetValueOrDefault("holder") is string
              && x.GetValueOrDefault("body_digest") is string && x.GetValueOrDefault("sig") is string
              && x.GetValueOrDefault("suite") is string su && su == BlsSuite)) return false;
        if (x.ContainsKey("parent") && x["parent"] is not string) return false;
        if (x.GetValueOrDefault("caveats") is not L cavs) return false;
        foreach (var cv in cavs)
            if (cv is not D m || m.GetValueOrDefault("type") is not string) return false;
        return true;
    }

    /// <summary>Collapse every per-hop signature into one 96-byte aggregate. Throws on an empty chain or a sig that is not valid b64u.</summary>
    public static byte[] AggregateChainSignatures(L? chain)
    {
        if (chain == null || chain.Count == 0) throw new ArgumentException("aggregateChainSignatures: empty chain");
        var sigs = new List<byte[]>();
        foreach (var c in chain)
            sigs.Add(AtlasPca.Pca.B64uDecode(((D)c!)["sig"]) ?? throw new ArgumentException("not canonical base64url"));
        return Aggsig.Aggregate(sigs);
    }

    static D Ok() => new() { ["ok"] = true };

    static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    /// <summary>
    /// Verify an entire BLS capability chain against one aggregate signature: depth bound, well-typedness, root has no parent,
    /// optional expected root principal, parent hash-links, holder-to-issuer continuity, append-only caveat prefixes, then one
    /// distinct-message AggregateVerify. Every hop issuer must be in the registry.
    /// </summary>
    public static D VerifyAggregatedChain(L? chain, byte[]? aggSig, KeyRegistry? registry, string? expectedRootPrincipal)
    {
        if (registry == null) return Fail("a KeyRegistry of proof-of-possession-verified keys is required");
        if (chain == null || chain.Count == 0) return Fail("empty chain");
        if (chain.Count > MaxChainDepth) return Fail("chain too long (max " + MaxChainDepth + " hops)");
        for (int i = 0; i < chain.Count; i++) if (!WellTyped(chain[i])) return Fail("hop " + i + ": malformed capability");

        var pks = new List<RegisteredKey?>();
        var msgs = new List<byte[]>();
        var root = (D)chain[0]!;
        if (root.ContainsKey("parent")) return Fail("hop 0: root must not have a parent");
        if (expectedRootPrincipal != null && expectedRootPrincipal != (string)root["issuer"]!) return Fail("hop 0: root issuer is not the expected principal");

        for (int i = 0; i < chain.Count; i++)
        {
            var c = (D)chain[i]!;
            string digest;
            try { digest = AtlasPca.Pca.HashCanonical(BodyOf(c)); }
            catch (Exception e) when (e is InvalidOperationException or ArgumentException) { return Fail("hop " + i + ": malformed body"); }
            if (digest != (string)c["body_digest"]! || (string)c["id"]! != (string)c["body_digest"]!) return Fail("hop " + i + ": body digest mismatch");

            var issuerRaw = AtlasPca.Pca.B64uDecode(c["issuer"]);
            if (issuerRaw == null) return Fail("hop " + i + ": malformed issuer key");
            var pk = registry.Get(issuerRaw);
            if (pk == null) return Fail("hop " + i + ": issuer key has no verified proof of possession (not in the registry)");

            if (i > 0)
            {
                var parent = (D)chain[i - 1]!;
                if (CapHash(parent) != (c.GetValueOrDefault("parent") as string)) return Fail("hop " + i + ": broken parent link");
                if ((string)c["issuer"]! != (string)parent["holder"]!) return Fail("hop " + i + ": issuer is not the parent's bound holder");
                var cc = (L)c["caveats"]!;
                var pc = (L)parent["caveats"]!;
                if (cc.Count < pc.Count) return Fail("hop " + i + ": drops parent caveat(s)");
                for (int j = 0; j < pc.Count; j++)
                    if (AtlasPca.Pca.HashCanonical(cc[j]) != AtlasPca.Pca.HashCanonical(pc[j])) return Fail("hop " + i + ": caveat " + j + " altered or reordered");
            }
            pks.Add(pk);
            msgs.Add(SigMessage((string)c["body_digest"]!));
        }

        try
        {
            var raws = new List<byte[]>();
            for (int i = 0; i < chain.Count; i++)
            {
                var s = (string)((D)chain[i]!)["sig"]!;
                var raw = AtlasPca.Pca.B64uDecode(s);
                if (raw == null) return Fail("malformed hop sig");
                raws.Add(raw);
            }
            var sum = Aggsig.Aggregate(raws);
            if (aggSig == null || !sum.AsSpan().SequenceEqual(aggSig)) return Fail("hop sig fields do not sum to the aggregate signature");
        }
        catch (ArgumentException) { return Fail("malformed hop sig"); }

        if (!Aggsig.AggregateVerify(pks, msgs, aggSig)) return Fail("aggregate signature does not verify over all hops");
        return Ok();
    }
}
