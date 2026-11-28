using AtlasPca.Evidence;
using AtlasPca.Scitt;
using Xunit;
using ScittApi = AtlasPca.Scitt.Scitt;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The evidence-bundle reference and its SCITT signed statement, over the walkthrough bundle of the committed corpus.</summary>
public class EvidenceReplayKillScittTests
{
    const string WalkthroughDigest = "U_o1IW6hTmfQR2IepB617OuoPYUOWbcP-0ssmH7nyDs";

    static D Bundle() => (D)((L)Base.Deep(Base.Args(EvidenceReplayKillTests.Load("ref-evidence-bundle-py").Cases[0]))!)[0]!;

    static SignStatementOpts Opts(string? subject = null, string? contentType = null) =>
        new("EdDSA", CoseKey.Ed25519Private(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()), "issuer.example", subject, contentType);

    static (CoseSign1 Statement, CborMap Claims) Decode(byte[] st)
    {
        var s = ScittApi.DecodeCoseSign1(st);
        return (s, (CborMap)s.ProtectedMap.Get(ScittApi.HdrCwtClaims)!);
    }

    [Fact]
    public void ReferenceNamesTheDigestAndCopiesTheSubject()
    {
        var b = Bundle();
        var r = EvidenceScitt.EvidenceRef(b);
        Assert.Equal(new[] { "kind", "digest", "subject" }, r.Keys.ToArray());
        Assert.Equal("pca-intent-evidence-ref", r["kind"]);
        Assert.Equal(WalkthroughDigest, r["digest"]);
        var orig = (D)b["subject"]!;
        var copy = (D)r["subject"]!;
        Assert.NotSame(orig, copy);
        Assert.Equal(orig.Keys.OrderBy(k => k, StringComparer.Ordinal), copy.Keys.OrderBy(k => k, StringComparer.Ordinal));
        foreach (var kv in orig) Assert.Equal(kv.Value, copy[kv.Key]);
        copy["extra"] = "x";
        Assert.False(orig.ContainsKey("extra"));
    }

    [Fact]
    public void StatementDefaultsItsSubjectToThePcActnDigestAndAlwaysUsesTheEvidenceContentType()
    {
        var b = Bundle();
        var r = EvidenceScitt.EvidenceRef(b);
        var (s, claims) = Decode(EvidenceScitt.EvidenceSignedStatement(b, Opts(contentType: "text/plain")));
        Assert.Equal("application/pca-intent-evidence+json", s.ProtectedMap.Get(ScittApi.HdrContentType));
        Assert.Equal(((D)r["subject"]!)["pcactn_digest"], claims.Get(ScittApi.CwtSub));
        Assert.Equal("issuer.example", claims.Get(ScittApi.CwtIss));
        Assert.Equal(Pca.Canon(r), s.Payload);
    }

    [Fact]
    public void AnExplicitSubjectWinsAndAnEmptyOneStaysEmpty()
    {
        var b = Bundle();
        var (_, named) = Decode(EvidenceScitt.EvidenceSignedStatement(b, Opts("custom-subject")));
        Assert.Equal("custom-subject", named.Get(ScittApi.CwtSub));
        var (_, empty) = Decode(EvidenceScitt.EvidenceSignedStatement(b, Opts("")));
        Assert.Equal("", empty.Get(ScittApi.CwtSub));
    }

    [Fact]
    public void AnchorLeafIsTheEvidenceKindCommit()
    {
        Assert.Equal(EvidenceVerify.AnchorCommit("evidence", WalkthroughDigest), EvidenceScitt.EvidenceAnchorCommit(WalkthroughDigest));
        Assert.NotEqual(EvidenceVerify.AnchorCommit("statement", WalkthroughDigest), EvidenceScitt.EvidenceAnchorCommit(WalkthroughDigest));
        Assert.Equal("application/pca-intent-evidence+json", EvidenceScitt.EvidenceContentType);
    }
}
