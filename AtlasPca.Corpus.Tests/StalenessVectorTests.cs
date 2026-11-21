using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Revocation staleness (T9): replays staleness-vectors.json (constants, max_age, effective_reversibility, age, epoch, gate, membership, gate_ids) with the
// reference reasons compared exactly (rows marked ok_only compare `ok` only). A missing vector file FAILS (Conf.Load throws).
public class StalenessVectorTests
{
    static D Doc() => Load("staleness-vectors.json");

    static List<D> Rows(string table, int expected)
    {
        var doc = Doc();
        Assert.True(doc.ContainsKey(table), $"{table}: missing table");
        var rows = L(doc[table]).Cast<D>().ToList();
        Assert.True(rows.Count == expected, $"{table}: {rows.Count} rows, this runner pins {expected}");
        return rows;
    }

    /// <summary>A vector number; the string "NaN" stands for NaN.</summary>
    static double Ms(object? v) => v is string s && s == "NaN" ? double.NaN : IntentJs.NumOf(v) ?? double.NaN;
    static double? OptMs(object? v) => IntentJs.NumOf(v);

    static void Expect(string label, RevocationCheck got, D v)
    {
        var exp = D(v["result"]);
        Assert.True(got.Ok == (bool)exp["ok"]!, $"{label}: ok={got.Ok} ({got.Reason}) want {exp["ok"]}");
        if (v.ContainsKey("ok_only") || got.Ok) return;
        Assert.True(got.Reason == (string)exp["reason"]!, $"{label}: reason '{got.Reason}' want '{exp["reason"]}'");
    }

    [Fact]
    public void Constants()
    {
        var c = D(Doc()["constants"]);
        Assert.Equal(N(c["refresh_ms"]), RevocationFreshness.EpochRefreshMs);
        Assert.Equal(N(c["validity_ms"]), RevocationFreshness.EpochValidityMs);
        Assert.Equal(N(c["irreversible_max_age_ms"]), RevocationFreshness.IrreversibleMaxAgeMs);
        Assert.Equal(N(c["skew_ms"]), RevocationFreshness.SkewMs);
    }

    [Fact]
    public void MaxAgeVectors()
    {
        foreach (var v in Rows("max_age", 15))
        {
            var p = RevocationStalenessPolicy.FromJson(v["policy"]);
            Assert.True(RevocationFreshness.MaxAgeMs(p, (string)v["class"]!) == Ms(v["max_age_ms"]), $"{Pca.Canonicalize(v["policy"])}/{v["class"]}");
        }
    }

    [Fact]
    public void EffectiveReversibilityVectors()
    {
        foreach (var v in Rows("effective_reversibility", 14))
            Assert.True(RevocationFreshness.EffectiveReversibility(v["server_class"], v["signed_class"]) == (string)v["effective"]!, $"{v["server_class"]}/{v["signed_class"]}");
    }

    [Fact]
    public void AgeVectors()
    {
        int i = 0;
        foreach (var v in Rows("age", 13))
        {
            double? issued = v["issued_at"] is string ? null : OptMs(v["issued_at"]); // null, "NaN" and "x" are all an unknown age
            var what = v.GetValueOrDefault("what") as string ?? "revocation state";
            Expect($"age#{i++}", RevocationFreshness.CheckAge(issued, Ms(v["now"]), Ms(v["max_age_ms"]), what), v);
        }
    }

    [Fact]
    public void EpochVectors()
    {
        foreach (var v in Rows("epoch", 25))
        {
            var o = new EpochCheckOptions { GuardianPublic = (string)v["guardian_public"]!, Now = Ms(v["now"]), GrantRef = v.GetValueOrDefault("grant_ref") as string };
            if (v.TryGetValue("last_accepted_epoch", out var last)) o.LastAcceptedEpoch = OptMs(last);
            if (v.TryGetValue("pcactn_epoch", out var pe)) o.PcactnEpoch = OptMs(pe);
            if (v.TryGetValue("max_age_ms", out var ma)) o.MaxAgeMs = Ms(ma);
            Expect("epoch/" + v["name"], RevocationFreshness.CheckEpoch(v["epoch"], o), v);
        }
    }

    [Fact]
    public void GateVectors()
    {
        var doc = Doc();
        var guardian = (string)doc["guardian_public"]!;
        foreach (var v in Rows("gate", 28))
        {
            var policy = RevocationStalenessPolicy.FromJson(v.GetValueOrDefault("policy")) with { AllowUnsignedRootForIrreversible = v.GetValueOrDefault("allow_unsigned_root_for_irreversible") is true };
            var g = new RevocationGateInput
            {
                Policy = policy, GuardianPublic = guardian, GrantRef = "g1", Now = Ms(v["now"]), PcactnEpoch = 0,
                ServerClass = v.GetValueOrDefault("server_class"), SignedClass = v.GetValueOrDefault("signed_class"),
            };
            switch ((string)v["mode"]!)
            {
                case "epoch": g.EpochSource = true; g.Epoch = v["epoch"]; g.Root = v.GetValueOrDefault("bare_root") as string; break;
                case "root": g.Root = (string)doc["revocation_root"]!; g.RootIssuedAt = OptMs(v.GetValueOrDefault("root_issued_at")); break;
                case "none": g.EpochSource = true; break;
                default: throw new InvalidOperationException("mode " + v["mode"]);
            }
            Expect("gate/" + v["name"], RevocationFreshness.Gate(g), v);
        }
    }

    [Fact]
    public void MembershipVectors()
    {
        var doc = Doc();
        var set = D(doc["revocation_set"]);
        var rows = Rows("membership", 27);
        foreach (var v in rows)
        {
            var got = Mesh.NonMembership((string)v["root"]!, D(v["proof"]), (string)v["id"]!);
            Assert.True(got == (bool)v["ok"]!, $"membership/{v["name"]}: {got}");
        }
        Assert.Contains(rows, v => (string)v["set"]! == "main" && (string)v["root"]! == (string)set["root"]!);
        Assert.Contains(rows, v => (string)v["set"]! == "empty" && (string)v["root"]! == (string)set["empty_root"]!);
        Assert.Contains(rows, v => (string)v["set"]! == "one" && (string)v["root"]! == (string)D(set["single"])["root"]!);
    }

    [Fact]
    public void GateIdsVectors()
    {
        var doc = Doc();
        var guardian = (string)doc["guardian_public"]!;
        var set = D(doc["revocation_set"]);
        var seed = Enumerable.Repeat((byte)11, 32).ToArray();
        foreach (var v in Rows("gate_ids", 10))
        {
            var ep = RevocationFreshness.SignEpoch(seed, new RevocationEpochBody("i", "g1", 0, N(set["size"]), (string)set["root"]!, N(v["epoch_issued_at"]), N(v["epoch_issued_at"]) + 600_000));
            Assert.True((string)ep["guardian"]! == guardian, $"{v["name"]}: the test key must be the vectors' guardian");
            var proofs = D(v["proofs"]);
            var g = new RevocationGateInput
            {
                Policy = new RevocationStalenessPolicy(MaxRevocationAgeMs: RevocationFreshness.EpochValidityMs), GuardianPublic = guardian, GrantRef = "g1",
                Now = Ms(v["now"]), PcactnEpoch = 0, SignedClass = "costly", EpochSource = true, Epoch = ep,
                Ids = L(v["ids"]).Cast<string>().ToList(), ProofFor = id => proofs.TryGetValue(id, out var pr) ? D(pr) : null,
            };
            Expect("gate_ids/" + v["name"], RevocationFreshness.Gate(g), v);
        }
    }

    [Fact]
    public void InvalidPolicyIsRefusedAndTheGateStaysClosed()
    {
        var bad = new Dictionary<string, RevocationStalenessPolicy>
        {
            ["zero"] = new(MaxRevocationAgeMs: 0), ["negative"] = new(Staleness: new StalenessWindows(Irreversible: -1)),
            ["nan"] = new(Staleness: new StalenessWindows(Costly: double.NaN)), ["infinite"] = new(MaxRevocationAgeMs: double.PositiveInfinity),
            ["not-number"] = RevocationStalenessPolicy.FromJson(new D { ["maxRevocationAgeMs"] = "300000" }),
        };
        foreach (var (name, p) in bad)
        {
            Assert.NotNull(p.Error());
            Assert.Throws<ArgumentException>(() => p.Validate());
            var r = RevocationFreshness.Gate(new RevocationGateInput { Policy = p, Now = 1, Root = "r", RootIssuedAt = 1, SignedClass = "reversible" });
            Assert.False(r.Ok, $"{name}: the gate opened under an invalid policy");
        }
        Assert.False(new RevocationStalenessPolicy().IsOn);
    }

    [Fact]
    public void SignedEpochSuitesUnderPins()
    {
        var seed = Enumerable.Repeat((byte)11, 32).ToArray();
        var ep = RevocationFreshness.SignEpoch(seed, new RevocationEpochBody("i", "g1", 0, 0, "r", 1000, 2000));
        var o = new EpochCheckOptions { GuardianPublic = (string)ep["guardian"]!, Now = 1500 };
        Assert.True(RevocationFreshness.CheckEpoch(ep, o).Ok);
        D With(string k, object? val) { var m = new D(ep) { [k] = val }; return m; }
        var tampered = RevocationFreshness.CheckEpoch(With("root", "other"), o);
        Assert.Equal("revocation epoch signature invalid", tampered.Reason);
        // a post-quantum suite with no pin, or with a pin that is not the epoch's key, is refused; an unregistered suite is not signed by the guardian
        Assert.False(RevocationFreshness.CheckEpoch(With("alg", "ml-dsa-65"), o).Ok);
        o.Pins = new Dictionary<string, string> { [o.GuardianPublic] = "AAAA" };
        Assert.False(RevocationFreshness.CheckEpoch(With("alg", "ml-dsa-65"), o).Ok);
        o.Pins = null;
        Assert.Equal("revocation epoch not signed by the pinned guardian", RevocationFreshness.CheckEpoch(With("alg", "no-such-suite"), o).Reason);
        Assert.Throws<ArgumentException>(() => RevocationFreshness.SignEpoch(new byte[] { 1 }, new RevocationEpochBody("", "", 0, 0, "", 0, 0)));
    }
}
