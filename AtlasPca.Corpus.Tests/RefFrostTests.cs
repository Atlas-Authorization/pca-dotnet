using AtlasPca;
using Xunit;
using static AtlasPca.Frost;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Core FROST (RFC 9591, Ed25519/SHA-512): replays the reference corpus (deterministic nonces, keys, messages) and the RFC 9591 E.1 vectors.</summary>
public class RefFrostTests
{
    const string M = "ref-core-frost-java";

    static D O(object? o) => o as D ?? throw new ArgumentException("expected object");
    static L Lst(object? o) => o as L ?? throw new ArgumentException("expected array");
    static byte[]? ByOrNull(object? o) => o == null ? null : Base.Bytes(o);
    static long Whole(object? o) => o is Num n && decimal.TryParse(n.Raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) && d == decimal.Truncate(d) ? (long)d : throw new ArgumentException("expected integer");
    static int Whole32(object? o) => checked((int)Whole(o));

    static FrostCommitment Commitment(object? o) { var m = O(o); return new(Whole(m["identifier"]), Base.Bytes(m["hiding"]), Base.Bytes(m["binding"])); }
    static List<FrostCommitment>? Commitments(object? o) => o == null ? null : Lst(o).Select(Commitment).ToList();
    static List<VerificationShare>? VShares(object? o) => o == null ? null : Lst(o).Select(v => { var m = O(v); return new VerificationShare(Whole(m["identifier"]), Base.Bytes(m["publicKey"])); }).ToList();
    static FrostSignatureShare SigShare(object? o) { var m = O(o); return new(Whole(m["identifier"]), Base.Bytes(m["sigShare"])); }

    static D CommitmentOut(FrostCommitment c) => new() { ["identifier"] = c.Identifier, ["hiding"] = c.Hiding, ["binding"] = c.Binding };

    static D KeygenOut(FrostKeygenResult kg) => new()
    {
        ["groupPublicKey"] = kg.GroupPublicKey,
        ["participantShares"] = kg.ParticipantShares.Select(s => (object?)new D { ["identifier"] = s.Identifier, ["share"] = s.Share, ["publicKey"] = s.PublicKey }).ToList(),
        ["groupCommitment"] = kg.GroupCommitment.Cast<object?>().ToList(),
    };

    static FrostKeygenResult Keygen(D a)
    {
        var o = new FrostKeygenOpts { Secret = ByOrNull(a.GetValueOrDefault("secret")) };
        if (a.GetValueOrDefault("coefficients") != null) o.Coefficients = Lst(a["coefficients"]).Select(c => Base.Bytes(c)).ToList();
        if (a.GetValueOrDefault("identifiers") != null) o.Identifiers = Lst(a["identifiers"]).Select(Whole).ToArray();
        return TrustedDealerKeygen(Whole32(a["t"]), Whole32(a["n"]), o);
    }

    static FrostSignOpts SignOpts(object? o)
    {
        var s = new FrostSignOpts();
        if (o == null) return s;
        var m = O(o);
        if (m.GetValueOrDefault("threshold") != null) s.Threshold = Whole32(m["threshold"]);
        s.VerificationShare = ByOrNull(m.GetValueOrDefault("verificationShare"));
        s.VerificationShares = VShares(m.GetValueOrDefault("verificationShares"));
        return s;
    }

    /// <summary>The reference function names bound to the native calls (the argument list as the corpus gives it, byte strings as {"$bytes"}).</summary>
    internal static readonly Dictionary<string, Func<L, object?>> Fns = new()
    {
        ["scalar"] = a => ScalarToBytes(BytesToScalar(Base.Bytes(a[0]))),
        ["isCanonicalScalar"] = a => a[0] != null && IsCanonicalScalar(Base.Bytes(a[0])),
        ["hash"] = a =>
        {
            var m = Base.Bytes(a[1]);
            return (string)a[0]! switch
            {
                "H1" => ScalarToBytes(H1(m)), "H2" => ScalarToBytes(H2(m)), "H3" => ScalarToBytes(H3(m)), "H4" => H4(m), "H5" => H5(m),
                _ => throw new ArgumentException("unknown hash"),
            };
        },
        ["decodeSafePoint"] = a => DecodeSafePoint(ByOrNull(a[0])).ToBytes(),
        ["keygen"] = a => KeygenOut(Keygen(O(a[0]))),
        ["verifyingShare"] = a => VerifyingShare(Base.Bytes(a[0])),
        ["commit"] = a =>
        {
            var c = Commit(new FrostParticipantShare(Whole(a[0]), Base.Bytes(a[1]), new byte[32]), Base.Bytes(a[2]), Base.Bytes(a[3]));
            return new D { ["hidingNonce"] = c.HidingNonce, ["bindingNonce"] = c.BindingNonce, ["commitment"] = CommitmentOut(c.Commitment) };
        },
        ["flow"] = a =>
        {
            var input = O(a[0]);
            var kg = Keygen(input);
            var byId = kg.ParticipantShares.ToDictionary(s => s.Identifier);
            var quorum = Lst(input["signers"]).Select(id => byId.TryGetValue(Whole(id), out var p) ? p : throw new ArgumentException("unknown signer")).ToList();
            var rnd = Lst(input["randomness"]);
            var commits = new List<FrostCommitResult>();
            var vss = new List<VerificationShare>();
            for (var i = 0; i < quorum.Count; i++)
            {
                var r = O(rnd[i]);
                commits.Add(Commit(quorum[i], Base.Bytes(r["hr"]), Base.Bytes(r["br"])));
                vss.Add(new VerificationShare(quorum[i].Identifier, quorum[i].PublicKey));
            }
            var cs = commits.Select(c => c.Commitment).ToList();
            int? thr = input.GetValueOrDefault("threshold") == null ? null : Whole32(input["threshold"]);
            var msg = Base.Bytes(input["message"]);
            var shares = new List<FrostSignatureShare>();
            for (var i = 0; i < quorum.Count; i++)
                shares.Add(Sign(quorum[i].Identifier, quorum[i].Share, kg.GroupPublicKey, commits[i].Nonces(), msg, cs, new FrostSignOpts { Threshold = thr, VerificationShare = quorum[i].PublicKey, VerificationShares = vss }));
            var agg = Aggregate(msg, cs, shares, kg.GroupPublicKey, thr, vss);
            var o = KeygenOut(kg);
            o["commitments"] = cs.Select(c => (object?)CommitmentOut(c)).ToList();
            o["sigShares"] = shares.Select(s => (object?)new D { ["identifier"] = s.Identifier, ["sigShare"] = s.SigShare }).ToList();
            o["aggregate"] = agg;
            return o;
        },
        ["sign"] = a =>
        {
            FrostNonces? nonces = null;
            if (a[3] != null)
            {
                var n = O(a[3]);
                var h = ByOrNull(n.GetValueOrDefault("hiding")); var b = ByOrNull(n.GetValueOrDefault("binding"));
                if (h == null || b == null) throw new ArgumentException("malformed nonces");
                nonces = new FrostNonces(h, b);
            }
            var s = Sign(Whole(a[0]), Base.Bytes(a[1]), Base.Bytes(a[2]), nonces, Base.Bytes(a[4]), Commitments(a[5])!, SignOpts(a[6]));
            return new D { ["identifier"] = s.Identifier, ["sigShare"] = s.SigShare };
        },
        ["aggregate"] = a =>
        {
            var o = O(a[4]);
            int? thr = o.GetValueOrDefault("threshold") == null ? null : Whole32(o["threshold"]);
            return Aggregate(Base.Bytes(a[0]), Commitments(a[1])!, a[2] == null ? null : Lst(a[2]).Select(SigShare).ToList(), ByOrNull(a[3])!, thr, VShares(o.GetValueOrDefault("verificationShares")));
        },
        ["verifySigShare"] = a =>
        {
            try
            {
                var p = O(a[0]);
                return VerifySigShare(Whole(p["identifier"]), Base.Bytes(p["publicKey"]), Commitment(p["commitment"]), SigShare(p["sigShare"]),
                    Commitments(p["signingCommitments"])!, Base.Bytes(p["groupPublicKey"]), Base.Bytes(p["message"]));
            }
            catch (Exception) { return false; }
        },
        ["cosign"] = a =>
        {
            var group = Base.Bytes(a[0]); var msg = Base.Bytes(a[2]);
            List<FrostParticipantShare>? quorum = a[1] == null ? null : Lst(a[1]).Select(q => { var m = O(q); return new FrostParticipantShare(Whole(m["identifier"]), Base.Bytes(m["share"]), Base.Bytes(m["publicKey"])); }).ToList();
            var o = O(a[3]);
            var sig = Cosign(group, quorum, msg, o.GetValueOrDefault("threshold") == null ? null : Whole32(o["threshold"]));
            return Pca.VerifyEd25519Strict(group, msg, sig);
        },
    };

    [Fact] public void GenCorpusIsPresent() => Base.RequireGenCorpus(M);
    // the replays reuse fixed nonces, which the one-shot registry would refuse the second time: one replay at a time, each from a clean registry
    static readonly object Replay = new();
    static RefFrostTests()
    {
        foreach (var fn in new[] { "flow", "sign" })
        {
            var inner = Fns[fn];
            Fns[fn] = a => { lock (Replay) { AtlasPca.Frost.ForgetSpentForReplay(); return inner(a); } };
        }
    }

    [Fact] public void Scalar() => Base.Check(M, "scalar", Fns["scalar"]);
    [Fact] public void IsCanonical() => Base.Check(M, "isCanonicalScalar", Fns["isCanonicalScalar"]);
    [Fact] public void Hash() => Base.Check(M, "hash", Fns["hash"]);
    [Fact] public void DecodeSafe() => Base.Check(M, "decodeSafePoint", Fns["decodeSafePoint"]);
    [Fact] public void KeygenCases() => Base.Check(M, "keygen", Fns["keygen"]);
    [Fact] public void Verifying() => Base.Check(M, "verifyingShare", Fns["verifyingShare"]);
    [Fact] public void CommitCases() => Base.Check(M, "commit", Fns["commit"]);
    [Fact] public void Flow() => Base.Check(M, "flow", Fns["flow"]);
    [Fact] public void SignCases() => Base.Check(M, "sign", Fns["sign"]);
    [Fact] public void AggregateCases() => Base.Check(M, "aggregate", Fns["aggregate"]);
    [Fact] public void VerifySigShareCases() => Base.Check(M, "verifySigShare", Fns["verifySigShare"]);
    [Fact] public void CosignCases() => Base.Check(M, "cosign", Fns["cosign"]);
    [Fact] public void EveryFn() { Base.Covers(M, Fns.Keys); Assert.Equal(170, Base.Total(M)); }

    // ---- RFC 9591 appendix E.1 ----
    static byte[] Hex(string h) => Convert.FromHexString(h);
    const string GroupPk = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
    const string Aggregate64 = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b";

    [Fact]
    public void Rfc9591Ed25519Vector()
    {
        var kg = TrustedDealerKeygen(2, 3, new FrostKeygenOpts
        {
            Secret = Hex("7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304"),
            Coefficients = [Hex("178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204")],
            Identifiers = [1, 2, 3],
        });
        Assert.Equal(GroupPk, Convert.ToHexString(kg.GroupPublicKey).ToLowerInvariant());
        var p1 = kg.ParticipantShares[0]; var p3 = kg.ParticipantShares[2];
        Assert.Equal("929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509", Convert.ToHexString(p1.Share).ToLowerInvariant());
        var c1 = Commit(p1, Hex("0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec"), Hex("69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501"));
        var c3 = Commit(p3, Hex("86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f"), Hex("13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775"));
        Assert.Equal("b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3", Convert.ToHexString(c1.Commitment.Hiding).ToLowerInvariant());
        var cs = new List<FrostCommitment> { c1.Commitment, c3.Commitment };
        var msg = Hex("74657374");
        var s1 = Sign(1, p1.Share, kg.GroupPublicKey, c1.Nonces(), msg, cs);
        var s3 = Sign(3, p3.Share, kg.GroupPublicKey, c3.Nonces(), msg, cs);
        Assert.Equal("001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603", Convert.ToHexString(s1.SigShare).ToLowerInvariant());
        Assert.Equal("bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007", Convert.ToHexString(s3.SigShare).ToLowerInvariant());
        var vss = new List<VerificationShare> { new(1, p1.PublicKey), new(3, p3.PublicKey) };
        var sig = Aggregate(msg, cs, [s1, s3], kg.GroupPublicKey, null, vss);
        Assert.Equal(Aggregate64, Convert.ToHexString(sig).ToLowerInvariant());
        // one-shot: the nonces were consumed
        Assert.Throws<ArgumentException>(() => Sign(1, p1.Share, kg.GroupPublicKey, c1.Nonces(), msg, cs));
    }
}
