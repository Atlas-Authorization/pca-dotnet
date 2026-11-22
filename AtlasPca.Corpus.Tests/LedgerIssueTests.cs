using System.Security.Cryptography;
using System.Text;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The issuing side of the transparency ledger: a differential replay of the salted commit, the opening check and the commit-sequence root (with the v2 goal
/// parser, the profile revocation scope and exposure window and the budget-allocation caveat of the same corpus) against the reference, and the signing half checked
/// through the verifiers: every head, cosignature and proof the issuer makes is accepted, and each altered one is refused.</summary>
public class LedgerIssueTests
{
    const string M = "ref-core-kotlin-gaps";

    static double Dbl(object? o) => IntentJs.NumOf(o) ?? throw new ArgumentException("not a number");

    static EdKey Key(string label) => EdKey.FromSeed(SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label)));

    static D Act(string id) => new() { ["id"] = id, ["action"] = new D { ["verb"] = "github.read", ["resource"] = "repo/" + id } };

    [Fact] public void EntryCommit() => Base.Check(M, "entryCommit", a => Ledger.EntryCommit((string)a[0]!, a[1]), min: 16);
    [Fact] public void VerifyOpening() => Base.Check(M, "verifyOpening", a => Ledger.VerifyOpening(a[0], a[1]), min: 56);
    [Fact] public void LedgerRootOf() => Base.Check(M, "ledgerRootOf", a => Ledger.LedgerRootOf(((L)a[0]!).Cast<string>()), min: 15);

    [Fact]
    public void ParseIntentGoalV2() => Base.Check(M, "parseIntentGoalV2", a =>
        IntentSession.ParseIntentGoalV2(a[0]) is { } g ? new D { ["session"] = g.Session, ["mapDigest"] = g.MapDigest } : null, min: 12);

    [Fact] public void ProfileRevocationScope() => Base.Check(M, "profileRevocationScope", a => IntentRevocation.ProfileRevocationScope((string)a[0]!), min: 4);

    [Fact]
    public void RevocationExposureEnd() => Base.Check(M, "revocationExposureEnd", a =>
        a[2] == null ? IntentRevocation.RevocationExposureEnd(Dbl(a[0]), Dbl(a[1])) : IntentRevocation.RevocationExposureEnd(Dbl(a[0]), Dbl(a[1]), Dbl(a[2])), min: 5);

    [Fact] public void BudgetAllocCaveat() => Base.Check(M, "budgetAllocCaveat", a => PcaHelpers.BudgetAllocCaveat(Dbl(a[0])), min: 4);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "entryCommit", "verifyOpening", "ledgerRootOf", "parseIntentGoalV2", "profileRevocationScope", "revocationExposureEnd", "budgetAllocCaveat" });
        Assert.Equal(112, Base.Cases(M).Count);
    }

    [Fact]
    public void TheLogProvesInclusionAndConsistencyOfWhatItAppended()
    {
        var log = new TransparencyLedger("alice");
        Assert.Equal(Ledger.EmptyTreeRoot, (string)log.Head()["root"]!);
        var roots = new List<string> { Ledger.EmptyTreeRoot };
        for (int i = 0; i < 9; i++)
        {
            var (index, commit) = log.Append(Act("a" + i), "salt" + i);
            Assert.Equal(i, index);
            Assert.Equal(Ledger.EntryCommit("salt" + i, Act("a" + i)), commit);
            roots.Add((string)log.Head()["root"]!);
        }
        Assert.Equal(9, log.Size);
        Assert.Equal(Ledger.LedgerRootOf(log.Commits()), roots[9]);
        for (int n = 0; n <= 9; n++) Assert.Equal(roots[n], log.RootAt(n));
        Assert.Throws<ArgumentException>(() => log.RootAt(10));
        Assert.Throws<ArgumentException>(() => log.RootAt(-1));
        for (int i = 0; i < 9; i++)
        {
            var proof = log.InclusionProof(i);
            Assert.True(log.VerifyInclusion(roots[9], proof, log.Commits()[i]));
            Assert.False(log.VerifyInclusion(roots[9], proof, log.Commits()[(i + 1) % 9]));
            Assert.False(log.VerifyInclusion(roots[8], proof, log.Commits()[i]));
        }
        Assert.Throws<ArgumentException>(() => log.InclusionProof(9));
        for (int old = 0; old <= 9; old++)
            for (int cur = old; cur <= 9; cur++)
            {
                var proof = log.ConsistencyProof(old, cur);
                Assert.True(log.VerifyConsistency(roots[old], roots[cur], proof));
                if (old > 0 && old < cur) Assert.False(log.VerifyConsistency(roots[old - 1], roots[cur], proof));
            }
        Assert.Equal(Base.Show(log.ConsistencyProof(4, 9)), Base.Show(log.ConsistencyProof(4)));
        Assert.Throws<ArgumentException>(() => log.ConsistencyProof(5, 4));
        Assert.Throws<ArgumentException>(() => log.ConsistencyProof(0, 10));
    }

    [Fact]
    public void ARandomSaltIsSixteenBytesAndFresh()
    {
        var log = new TransparencyLedger();
        Assert.Equal("", log.Principal);
        log.Append(Act("a"));
        log.Append(Act("a"));
        var s0 = (string)((D)log.Entry(0)["opening"]!)["salt"]!;
        var s1 = (string)((D)log.Entry(1)["opening"]!)["salt"]!;
        Assert.NotNull(Pca.B64uDecode(s0, 16));
        Assert.NotEqual(s0, s1);
        Assert.NotEqual(log.Commits()[0], log.Commits()[1]);
        Assert.Empty(log.AuditOpenings());
    }

    [Fact]
    public void ShreddingKeepsTheTreeAndAuditFindsATamperedOpening()
    {
        var log = new TransparencyLedger("alice");
        var pc = Act("a0");
        log.Append(pc, "s0");
        log.Append(Act("a1"), "s1");
        var (ci, commit) = log.AppendCommitment("opaque");
        Assert.Equal(2, ci);
        Assert.Equal("opaque", commit);
        Assert.Throws<ArgumentException>(() => log.AppendCommitment(""));
        Assert.False(log.Entry(2).ContainsKey("opening"));
        Assert.Throws<ArgumentException>(() => log.Entry(3));
        Assert.Throws<ArgumentException>(() => log.Entry(-1));
        Assert.Empty(log.AuditOpenings());
        var root = (string)log.Head()["root"]!;
        Assert.True(Ledger.VerifyOpening(log.Commits()[0], log.Entry(0)["opening"]));
        pc["id"] = "tampered";
        Assert.Equal(new List<int> { 0 }, log.AuditOpenings());
        Assert.True(log.Shred(0));
        Assert.False(log.Shred(0));
        Assert.False(log.Shred(2));
        Assert.Throws<ArgumentException>(() => log.Shred(3));
        Assert.Throws<ArgumentException>(() => log.Shred(-1));
        Assert.False(log.Entry(0).ContainsKey("opening"));
        Assert.Empty(log.AuditOpenings());
        Assert.Equal(root, (string)log.Head()["root"]!);

        var back = TransparencyLedger.FromEntries(new[] { log.Entry(0), log.Entry(1), log.Entry(2) }, "alice");
        Assert.Equal(3, back.Size);
        Assert.Equal("alice", back.Principal);
        Assert.Equal(root, (string)back.Head()["root"]!);
        Assert.True(back.Entry(1).ContainsKey("opening"));
        Assert.Empty(back.AuditOpenings());
        var forged = TransparencyLedger.FromEntries(new[] { new D { ["commit"] = log.Commits()[1], ["opening"] = new D { ["salt"] = "other", ["pcactn"] = Act("a1") } } });
        Assert.Equal(new List<int> { 0 }, forged.AuditOpenings());
        Assert.Throws<ArgumentException>(() => TransparencyLedger.FromEntries(new[] { new D { ["opening"] = new D() } }));
    }

    [Fact]
    public void TheWitnessedHeadVerifiesUnderTheGuardianOnly()
    {
        using var g = Key("ledger/guardian");
        using var other = Key("ledger/other");
        var log = new TransparencyLedger("alice");
        log.Append(Act("a0"), "s0");
        var wh = log.WitnessHead(g);
        Assert.Equal(g.Id, wh["witness"]);
        Assert.Equal("alice", wh["principal"]);
        Assert.False(wh.ContainsKey("alg"));
        Assert.True(Ledger.VerifyWitnessedHead(wh, g.Id));
        Assert.False(Ledger.VerifyWitnessedHead(wh, other.Id));
        Assert.False(Ledger.VerifyWitnessedHead(new D(wh) { ["root"] = Ledger.EmptyTreeRoot }, g.Id));
        Assert.False(Ledger.VerifyWitnessedHead(new D(wh) { ["principal"] = "bob" }, g.Id));

        var fork = new TransparencyLedger("alice");
        fork.Append(Act("b0"), "s0");
        Assert.True(Ledger.DetectEquivocation(wh, fork.WitnessHead(g), g.Id));
        Assert.False(Ledger.DetectEquivocation(wh, log.WitnessHead(g), g.Id));
        Assert.False(Ledger.DetectEquivocation(wh, fork.WitnessHead(other), g.Id));
    }

    static D Head(TransparencyLedger log, string prevRoot, double t) => new()
    {
        ["instance_id"] = "inst", ["principal"] = log.Principal, ["size"] = log.Head()["size"], ["root"] = log.Head()["root"], ["prev_root"] = prevRoot, ["timestamp"] = IntentJs.Normalize(t),
    };

    [Fact]
    public void SignedTreeHeadsChainAndCosign()
    {
        using var g = Key("ledger/guardian");
        using var w1 = Key("ledger/w1");
        using var w2 = Key("ledger/w2");
        using var stranger = Key("ledger/stranger");
        var log = new TransparencyLedger("alice");
        log.Append(Act("a0"), "s0");
        var h1 = Ledger.SignTreeHead(g, Head(log, "", 1000));
        log.Append(Act("a1"), "s1");
        var h2 = Ledger.SignTreeHead(g, Head(log, (string)h1["root"]!, 2000));
        Assert.Equal(g.Id, h1["guardian"]);
        Assert.False(h1.ContainsKey("alg"));
        Assert.True(Ledger.VerifyTreeHead(h1, g.Id, null));
        Assert.False(Ledger.VerifyTreeHead(h1, stranger.Id, null));
        foreach (var k in new[] { "instance_id", "principal", "root", "prev_root" })
            Assert.False(Ledger.VerifyTreeHead(new D(h1) { [k] = "x" }, g.Id, null));
        Assert.False(Ledger.VerifyTreeHead(new D(h1) { ["size"] = IntentJs.OfLong(2) }, g.Id, null));
        Assert.False(Ledger.VerifyTreeHead(new D(h1) { ["timestamp"] = IntentJs.OfLong(1001) }, g.Id, null));
        Assert.True(Ledger.VerifyHeadConsistency(h1, h2, log.ConsistencyProof(1, 2), g.Id, null));
        var chain = new L { new D { ["sth"] = h1 }, new D { ["sth"] = h2, ["proof"] = log.ConsistencyProof(1, 2) } };
        Assert.True(Ledger.VerifyCheckpointChain(chain, g.Id, null).Ok);
        foreach (var k in new[] { "instance_id", "principal", "size", "root", "prev_root", "timestamp" })
        {
            var missing = Head(log, "", 1);
            missing.Remove(k);
            Assert.Throws<ArgumentException>(() => Ledger.SignTreeHead(g, missing));
        }

        var policy = new D { ["witnessKeys"] = new L { w1.Id, w2.Id }, ["threshold"] = IntentJs.OfLong(2) };
        var c1 = Ledger.CosignTreeHead(h2, w1);
        var c2 = Ledger.CosignTreeHead(h2, w2);
        Assert.Equal(w1.Id, c1["key"]);
        Assert.Equal(new[] { "key", "sig" }, c1.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.True(Ledger.VerifyWitnessCosignature(h2, c1, w1.Id));
        Assert.False(Ledger.VerifyWitnessCosignature(h2, c1, w2.Id));
        Assert.False(Ledger.VerifyWitnessCosignature(h1, c1, w1.Id));
        Assert.True(Ledger.VerifyTreeHead(new D(h2) { ["witnesses"] = new L { c1, c2 } }, g.Id, policy));
        Assert.False(Ledger.VerifyTreeHead(new D(h2) { ["witnesses"] = new L { c1, c1 } }, g.Id, policy));
        Assert.False(Ledger.VerifyTreeHead(new D(h2) { ["witnesses"] = new L { c1, Ledger.CosignTreeHead(h2, stranger) } }, g.Id, policy));
        // a cosignature is bound to the guardian epoch: absent and null are 0, any other epoch is another statement
        Assert.True(Ledger.VerifyWitnessCosignature(new D(h2) { ["guardian_epoch"] = IntentJs.OfLong(0) }, c1, w1.Id));
        Assert.True(Ledger.VerifyWitnessCosignature(h2, Ledger.CosignTreeHead(new D(h2) { ["guardian_epoch"] = null }, w1), w1.Id));
        Assert.False(Ledger.VerifyWitnessCosignature(new D(h2) { ["guardian_epoch"] = IntentJs.OfLong(1) }, c1, w1.Id));
        Assert.True(Ledger.VerifyWitnessCosignature(new D(h2) { ["guardian_epoch"] = IntentJs.OfLong(1) }, Ledger.CosignTreeHead(new D(h2) { ["guardian_epoch"] = IntentJs.OfLong(1) }, w1), w1.Id));
        var noRoot = new D(h2);
        noRoot.Remove("root");
        Assert.Throws<ArgumentException>(() => Ledger.CosignTreeHead(noRoot, w1));

        // the same size signed over two histories is a split view; the same head twice, another size or another signer is not
        var fork = new TransparencyLedger("alice");
        fork.Append(Act("a0"), "s0");
        fork.Append(Act("zz"), "s1");
        var f2 = Ledger.SignTreeHead(g, Head(fork, (string)h1["root"]!, 2000));
        Assert.True(Ledger.DetectTreeHeadEquivocation(h2, f2, g.Id));
        Assert.False(Ledger.DetectTreeHeadEquivocation(h2, h2, g.Id));
        Assert.False(Ledger.DetectTreeHeadEquivocation(h1, f2, g.Id));
        Assert.False(Ledger.DetectTreeHeadEquivocation(h2, Ledger.SignTreeHead(stranger, Head(fork, (string)h1["root"]!, 2000)), g.Id));
        var otherInstance = Head(fork, (string)h1["root"]!, 2000);
        otherInstance["instance_id"] = "inst2";
        Assert.False(Ledger.DetectTreeHeadEquivocation(h2, Ledger.SignTreeHead(g, otherInstance), g.Id));
        var otherPrincipal = Head(fork, (string)h1["root"]!, 2000);
        otherPrincipal["principal"] = "bob";
        Assert.False(Ledger.DetectTreeHeadEquivocation(h2, Ledger.SignTreeHead(g, otherPrincipal), g.Id));
        Assert.False(Ledger.DetectTreeHeadEquivocation(null, f2, g.Id));
        Assert.False(Ledger.DetectTreeHeadEquivocation(h2, "x", g.Id));
    }

    [Fact]
    public void ASuiteWhoseEd25519KeyIsNotTheSignerIsRefused()
    {
        using var g = Key("ledger/guardian");
        using var other = Key("ledger/other");
        var log = new TransparencyLedger("alice");
        Assert.Throws<ArgumentException>(() => log.WitnessHead(g, SuiteKey.Ed25519(other)));
        Assert.True(Ledger.VerifyWitnessedHead(log.WitnessHead(g, SuiteKey.Ed25519(g)), g.Id));
    }
}
