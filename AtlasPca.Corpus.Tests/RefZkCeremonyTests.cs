using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the ceremony and provenance functions of the zk reference corpus (test-data/ref-zk.json.gz): the verifying-key id, provenance
/// records and their check, the transcript digest, the transcript check (explicit mutations and a structural sweep) and the ceremony classification. The
/// other functions of that corpus are replayed by <see cref="RefZkTests"/>, which also checks that every function is handled.</summary>
public class RefZkCeremonyTests
{
    const string M = "ref-zk";

    [Fact] public void VkId() => Base.Check(M, "vkId", a => ZkCeremony.VkId(a[0]), min: 10);
    [Fact] public void CircuitProvenance() => Base.Check(M, "circuitProvenance", a => ZkCeremony.CircuitProvenance((D)a[0]!), min: 13);
    [Fact] public void CheckCircuitProvenance() => Base.Check(M, "checkCircuitProvenance", a => ZkCeremony.CheckCircuitProvenance(a[0], (D)a[1]!), min: 19);
    [Fact] public void TranscriptSha256() => Base.Check(M, "transcriptSha256", a => ZkCeremony.TranscriptSha256(a[0]), min: 3);
    [Fact] public void CheckTranscript() => Base.Check(M, "checkTranscript", a => ZkCeremony.CheckTranscript(a[0], a.Count > 1 ? a[1] as D : null), min: 257);
    [Fact] public void CeremonyOf() => Base.Check(M, "ceremonyOf", a => ZkCeremony.CeremonyOf(a[0], a.Count > 1 ? a[1] : null), min: 19);

    [Fact]
    public void TheCeremonyCasesAreAllReplayed()
    {
        var mine = new[] { "vkId", "circuitProvenance", "checkCircuitProvenance", "transcriptSha256", "checkTranscript", "ceremonyOf" };
        Assert.Equal(321, Base.Cases(M).Count(c => mine.Contains((string)c["fn"]!)));
        Assert.Equal(1429, Base.Cases(M).Count);
    }

    [Fact]
    public void TheTypedProvenanceBuilderAndCallerErrors()
    {
        var vkey = new D { ["curve"] = "bn128" };
        var h = new string('a', 64);
        var prov = ZkCeremony.CircuitProvenance("c1", h, h, vkey);
        Assert.Equal(ZkCeremony.VkId(vkey), prov["vkId"]);
        Assert.Null(ZkCeremony.CheckCircuitProvenance(prov, new D { ["circuit"] = "c1", ["sourceSha256"] = h, ["vkey"] = vkey }));
        Assert.Equal("verifying key is not the recorded one", ZkCeremony.CheckCircuitProvenance(prov, new D { ["circuit"] = "c1", ["sourceSha256"] = h, ["vkey"] = new D() }));
        // an incomplete pinned build is read as the reference reads it: a record never equals a circuit id or source hash the build lacks (a member both
        // lack is equal), and the missing key throws only when the comparison gets that far
        Assert.Equal("record is for another circuit", ZkCeremony.CheckCircuitProvenance(prov, new D { ["sourceSha256"] = h, ["vkey"] = vkey }));
        Assert.Equal("circuit sources differ from the pinned version", ZkCeremony.CheckCircuitProvenance(prov, new D { ["circuit"] = "c1", ["vkey"] = vkey }));
        Assert.Equal("record is for another circuit", ZkCeremony.CheckCircuitProvenance(prov, new D { ["circuit"] = null, ["sourceSha256"] = h, ["vkey"] = vkey }));
        var bare = new D { ["r1csSha256"] = h, ["vkId"] = ZkCeremony.VkId(vkey) };
        Assert.Null(ZkCeremony.CheckCircuitProvenance(bare, new D { ["vkey"] = vkey }));
        Assert.Equal("record is for another circuit", ZkCeremony.CheckCircuitProvenance(bare, new D { ["circuit"] = null, ["vkey"] = vkey }));
        Assert.Throws<ArgumentException>(() => ZkCeremony.CheckCircuitProvenance(prov, new D { ["circuit"] = "c1", ["sourceSha256"] = h }));
        Assert.Equal("record is for another circuit", ZkCeremony.CheckCircuitProvenance(prov, new D { ["sourceSha256"] = h }));
        Assert.Equal("not a provenance record", ZkCeremony.CheckCircuitProvenance("x", null!));
        Assert.Throws<ArgumentNullException>(() => ZkCeremony.CheckCircuitProvenance(prov, null!));
        Assert.Throws<ArgumentException>(() => ZkCeremony.CircuitProvenance(new D { ["circuit"] = "c1", ["sourceSha256"] = h, ["r1csSha256"] = h }));
        Assert.Equal("single-party", ZkCeremony.CeremonyOf(vkey));
    }

    [Fact]
    public void AMinimumThatIsNotANumberIsReadAsTheReferenceReadsIt()
    {
        var two = (D)Base.Args(Base.Of(M, "checkTranscript").Single(c => (string)c["name"]! == "checkTranscript/valid"))[0]!;
        Assert.Null(ZkCeremony.CheckTranscript(two));
        // text that is a number counts as that number
        Assert.Null(ZkCeremony.CheckTranscript(two, new D { ["minContributions"] = "2" }));
        Assert.Equal("fewer than 3 contributions", ZkCeremony.CheckTranscript(two, new D { ["minContributions"] = "3" }));
        Assert.Equal("fewer than 3 contributions", ZkCeremony.CheckTranscript(two, new D { ["minContributions"] = new L { new Num("3") } }));
        Assert.Null(ZkCeremony.CheckTranscript(two, new D { ["minContributions"] = true }));
        Assert.Null(ZkCeremony.CheckTranscript(two, new D { ["minContributions"] = null }));
        // a value that is no number leaves nothing to compare the count with: the minimum is not checked at all, not even the floor of two
        Assert.Null(ZkCeremony.CheckTranscript(two, new D { ["minContributions"] = "x" }));
        Assert.Null(ZkCeremony.CheckTranscript(two, new D { ["minContributions"] = new D() }));
        var one = (D)Base.Deep(two)!;
        var cs = (L)one["contributions"]!;
        cs.RemoveAt(1);
        ((D)one["beacon"]!)["prevZkeySha256"] = ((D)cs[0]!)["zkeySha256"];
        Assert.Equal("fewer than 2 contributions", ZkCeremony.CheckTranscript(one));
        Assert.Null(ZkCeremony.CheckTranscript(one, new D { ["minContributions"] = "x" }));
    }
}
