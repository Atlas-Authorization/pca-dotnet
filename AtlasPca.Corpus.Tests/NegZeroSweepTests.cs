using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

// The strict profile refuses -0 wherever a wire integer is validated (mirrors the TS -0 sweep); 0 itself still passes.
public class NegZeroSweepTests
{
    static Num N(string raw) => new(raw);

    [Fact]
    public void LedgerConsistencyRefusesNegZeroSizes()
    {
        var e = Ledger.EmptyTreeRoot;
        Assert.True(Ledger.VerifyLedgerConsistency(e, e, new D { ["oldSize"] = N("0"), ["newSize"] = N("0"), ["path"] = new List<object?>() }));
        Assert.False(Ledger.VerifyLedgerConsistency(e, e, new D { ["oldSize"] = N("-0"), ["newSize"] = N("0"), ["path"] = new List<object?>() }));
        Assert.False(Ledger.VerifyLedgerConsistency(e, e, new D { ["oldSize"] = N("0"), ["newSize"] = N("-0"), ["path"] = new List<object?>() }));
    }

    [Fact]
    public void RevocationEpochRefusesNegZero()
    {
        foreach (var k in new[] { "epoch", "set_size", "issued_at", "not_after" })
        {
            var ep = new D { ["guardian"] = "g", ["instance_id"] = "i", ["grant_ref"] = "r", ["epoch"] = N("0"), ["set_size"] = N("0"), ["root"] = "x",
                ["issued_at"] = N("0"), ["not_after"] = N("0"), ["sig"] = "s" };
            var o = new EpochCheckOptions { GuardianPublic = "g", Now = 0 };
            Assert.NotEqual("malformed revocation epoch", RevocationFreshness.CheckEpoch(ep, o).Reason);
            ep[k] = N("-0");
            Assert.Equal("malformed revocation epoch", RevocationFreshness.CheckEpoch(ep, o).Reason);
        }
    }

    [Fact]
    public void SettlementGuardianEpochRefusesNegZero()
    {
        var r = new D { ["claimId"] = "c", ["action"] = "open", ["amount"] = N("5"), ["from"] = "a", ["to"] = "b", ["at"] = N("1"),
            ["evidenceDigest"] = "", ["sig"] = "s", ["guardian_epoch"] = N("0") }; // open: evidenceDigest must be empty
        Assert.NotEqual("shape", Optimistic.SettlementWireCheck(r, "g"));
        r["guardian_epoch"] = N("-0");
        Assert.Equal("shape", Optimistic.SettlementWireCheck(r, "g"));
    }

    [Fact]
    public void PolicyTemplateIntegerSlotsRefuseNegZero()
    {
        var def = (D)((D)Conf.Load("policy-link-vectors.json")["template"]!)["def"]!;
        var slots = new D { ["acct"] = "a42", ["cap"] = N("-0"), ["region"] = "eu", ["verbs"] = new List<object?> { "mail.send" } };
        Assert.Equal("slot 'cap' must be a safe integer", PolicyAuthoring.InstantiateTemplate(def, slots).Reason);
        ((D)((D)def["slots"]!)["cap"]!)["min"] = N("-0");
        Assert.Equal("slot 'cap'.min must be a safe integer", PolicyAuthoring.TemplateDefError(def));
    }
}
