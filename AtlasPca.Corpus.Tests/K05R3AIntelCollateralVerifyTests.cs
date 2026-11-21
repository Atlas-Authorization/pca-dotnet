using AtlasPca;
using Xunit;
using K = AtlasPca.Corpus.Tests.K05R3AIntelKit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Kill tests for AttestIntelCollateral.Verify end to end over a synthetic Intel PKI, quote and signed collateral (K05R3AIntelKit). Every
/// message is the reference's (attest-intel-collateral.ts verifyIntelTdxCollateral / evaluateTcb / evaluateQe / checkFresh).</summary>
public class K05R3AIntelCollateralVerifyTests
{
    static CollateralResult Run(K.Rig r, CollateralPolicy? pol = null, string? pin = null) =>
        AttestIntelCollateral.Verify(r.QuoteBytes(), r.Collateral(), K.Now, pol, pin ?? K.RootPin, false);

    static string Refused(K.Rig r, CollateralPolicy? pol = null)
    {
        var x = Run(r, pol);
        Assert.False(x.Ok);
        return x.Reason;
    }

    static string[] Adv(params string[] a) => a;

    // ---- the fail-closed catches (reachable only through the test seam: everything inside is revalidated before)

    static string RefusedUnderFault(string site)
    {
        AttestIntelCollateral.FaultHook = s => { if (s == site) throw new AttestError("boom"); };
        try { return Refused(new K.Rig()); }
        finally { AttestIntelCollateral.FaultHook = null; }
    }

    [Fact]
    public void AFaultWhileCheckingAnIssuerChainFailsClosed() =>
        Assert.Equal("TCB info: collateral verification error (fail closed): boom", RefusedUnderFault("chain"));

    [Fact]
    public void AFaultWhileEvaluatingTheCollateralFailsClosed() =>
        Assert.Equal("collateral verification error (fail closed): boom", RefusedUnderFault("verify"));

    // ---- the honest baseline

    [Fact]
    public void AnHonestRigVerifies()
    {
        var r = Run(new K.Rig());
        Assert.True(r.Ok, r.Reason);
        Assert.Equal("", r.Reason);
        Assert.Equal("UpToDate", r.Status);
        Assert.Empty(r.AdvisoryIds);
    }

    // ---- completeness and the quote

    [Fact]
    public void AnUnsetCollateralFieldIsIncomplete()
    {
        var rig = new K.Rig();
        var f = rig.Collateral();
        var q = rig.QuoteBytes();
        var variants = new[]
        {
            new IntelCollateral { TcbInfoChain = f.TcbInfoChain, QeIdentityJson = f.QeIdentityJson, QeIdentityChain = f.QeIdentityChain, PckCrl = f.PckCrl, RootCrl = f.RootCrl },
            new IntelCollateral { TcbInfoJson = f.TcbInfoJson, QeIdentityJson = f.QeIdentityJson, QeIdentityChain = f.QeIdentityChain, PckCrl = f.PckCrl, RootCrl = f.RootCrl },
            new IntelCollateral { TcbInfoJson = f.TcbInfoJson, TcbInfoChain = f.TcbInfoChain, QeIdentityChain = f.QeIdentityChain, PckCrl = f.PckCrl, RootCrl = f.RootCrl },
            new IntelCollateral { TcbInfoJson = f.TcbInfoJson, TcbInfoChain = f.TcbInfoChain, QeIdentityJson = f.QeIdentityJson, PckCrl = f.PckCrl, RootCrl = f.RootCrl },
        };
        foreach (var v in variants)
            Assert.Equal("collateral incomplete (fail closed)", AttestIntelCollateral.Verify(q, v, K.Now, null, K.RootPin, false).Reason);
        Assert.Equal("collateral incomplete (fail closed)", AttestIntelCollateral.Verify(q, null, K.Now, null, K.RootPin, false).Reason);
    }

    [Fact]
    public void AnInvalidQuoteIsNamedWithItsReason()
    {
        var x = AttestIntelCollateral.Verify(new byte[1], new K.Rig().Collateral(), K.Now, null, K.RootPin, false);
        Assert.False(x.Ok);
        Assert.Equal("quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length", x.Reason);
    }

    [Fact]
    public void ASingleSelfIssuedQuoteCertificateHasNoLeaf()
    {
        // a lone self-signed P-256 certificate carrying the SGX extension passes the quote check (it is its own root) but issues itself
        var solo = K.MakeCert("CN=solo", K.PckKey, "CN=solo", K.PckKey, 7, false, K.From, K.To, K.SgxExt(Enumerable.Repeat((byte)5, 16).ToArray(), 11));
        var rig = new K.Rig { QuoteChain = K.Pem(solo) };
        var x = Run(rig, null, K.PinOf(solo));
        Assert.False(x.Ok);
        Assert.Equal("PCK leaf not found", x.Reason);
    }

    // ---- the signer chains

    [Fact]
    public void AnExpiredSigningChainIsAValidityFailure()
    {
        Assert.Equal("TCB info: issuer chain certificate outside its validity period", Refused(new K.Rig { TcbChain = K.ExpiredSignChain }));
        Assert.Equal("QE identity: issuer chain certificate outside its validity period", Refused(new K.Rig { QeChain = K.ExpiredSignChain }));
    }

    [Fact]
    public void ASigningChainUnderAnotherRootIsInvalid()
    {
        const string why = "issuer chain invalid: Intel SGX Root CA does not match the pinned trust anchor";
        Assert.Equal("TCB info: " + why, Refused(new K.Rig { TcbChain = K.StrangerChain }));
        Assert.Equal("QE identity: " + why, Refused(new K.Rig { QeChain = K.StrangerChain }));
    }

    // ---- freshness

    [Fact]
    public void AMissingOrUnparsableDateIsNamed()
    {
        var a = new K.Rig(); a.Tcb.Remove("nextUpdate");
        Assert.Equal("TCB info: issueDate/nextUpdate missing", Refused(a));
        var b = new K.Rig(); b.Tcb.Remove("issueDate");
        Assert.Equal("TCB info: issueDate/nextUpdate missing", Refused(b));
        var c = new K.Rig(); c.Tcb["issueDate"] = "not a date";
        Assert.Equal("TCB info: issueDate/nextUpdate missing", Refused(c));
        var d = new K.Rig(); d.Qe.Remove("nextUpdate");
        Assert.Equal("QE identity: issueDate/nextUpdate missing", Refused(d));
        var e = new K.Rig(); e.Qe.Remove("issueDate");
        Assert.Equal("QE identity: issueDate/nextUpdate missing", Refused(e));
    }

    [Fact]
    public void ADocumentIsFreshFromIssueDateThroughNextUpdateInclusive()
    {
        var edge = new K.Rig();
        edge.Tcb["issueDate"] = "2030-01-01T00:00:00Z"; edge.Tcb["nextUpdate"] = "2030-01-01T00:00:00Z";
        edge.Qe["issueDate"] = "2030-01-01T00:00:00Z"; edge.Qe["nextUpdate"] = "2030-01-01T00:00:00Z";
        var ok = Run(edge);
        Assert.True(ok.Ok, ok.Reason);

        var early = new K.Rig(); early.Tcb["issueDate"] = "2030-01-01T00:00:01Z";
        Assert.Equal("TCB info: issueDate is in the future", Refused(early));
        var late = new K.Rig(); late.Tcb["nextUpdate"] = "2029-12-31T23:59:59Z";
        Assert.Equal("TCB info: stale (nextUpdate passed)", Refused(late));
        var qeEarly = new K.Rig(); qeEarly.Qe["issueDate"] = "2030-01-01T00:00:01Z";
        Assert.Equal("QE identity: issueDate is in the future", Refused(qeEarly));
        var qeLate = new K.Rig(); qeLate.Qe["nextUpdate"] = "2029-12-31T23:59:59Z";
        Assert.Equal("QE identity: stale (nextUpdate passed)", Refused(qeLate));
    }

    // ---- tcbEvaluationDataNumber

    [Fact]
    public void AnEvaluationNumberOfZeroIsPresent()
    {
        var a = new K.Rig(); a.Tcb["tcbEvaluationDataNumber"] = 0;
        var ra = Run(a);
        Assert.True(ra.Ok, ra.Reason);
        var b = new K.Rig(); b.Qe["tcbEvaluationDataNumber"] = 0;
        var rb = Run(b);
        Assert.True(rb.Ok, rb.Reason);
    }

    [Fact]
    public void AMissingEvaluationNumberIsNamed()
    {
        var a = new K.Rig(); a.Tcb.Remove("tcbEvaluationDataNumber");
        Assert.Equal("tcbEvaluationDataNumber missing", Refused(a));
        var b = new K.Rig(); b.Qe.Remove("tcbEvaluationDataNumber");
        Assert.Equal("tcbEvaluationDataNumber missing", Refused(b));
    }

    [Fact]
    public void ThePolicyMinimumBindsBothDocuments()
    {
        var pol = new CollateralPolicy { HasMinEval = true, MinEval = 5 };
        const string below = "tcbEvaluationDataNumber below policy minimum";
        K.Rig R(int info, int qe) { var r = new K.Rig(); r.Tcb["tcbEvaluationDataNumber"] = info; r.Qe["tcbEvaluationDataNumber"] = qe; return r; }
        Assert.Equal(below, Refused(R(4, 6), pol));
        Assert.Equal(below, Refused(R(6, 4), pol));
        var atMin = Run(R(5, 5), pol);
        Assert.True(atMin.Ok, atMin.Reason);
        var above = Run(R(6, 6), pol);
        Assert.True(above.Ok, above.Reason);
    }

    // ---- the TDX module identity

    static K.Rig ModuleRig(params JD[] identities)
    {
        var r = new K.Rig();
        r.TeeTcb[0] = 2; r.TeeTcb[1] = 1;
        r.Tcb["tdxModuleIdentities"] = new JL(identities.Cast<object?>());
        return r;
    }

    [Fact]
    public void AModuleIdentityIsMatchedAndItsAdvisoriesCollected()
    {
        // the identity covers components 0 and 1 of the TD report SVN: the levels' first two TDX components are not compared
        var r = ModuleRig(K.Ident("TDX_01", adv: Adv("INTEL-SA-M")));
        r.Tcb["tcbLevels"] = new JL { K.Level("UpToDate", tdx: K.TdxComps(9, 9)) };
        var x = Run(r);
        Assert.True(x.Ok, x.Reason);
        Assert.Equal(new[] { "INTEL-SA-M" }, x.AdvisoryIds.ToArray());
    }

    [Fact]
    public void TheFirstIdentityWithTheIdWins()
    {
        var r = ModuleRig(K.Ident("TDX_01"), K.Ident("TDX_01", mrsigner: 0x44));
        var x = Run(r);
        Assert.True(x.Ok, x.Reason);
    }

    [Fact]
    public void WithoutAModuleIdentityEveryTdxComponentIsCompared()
    {
        var r = new K.Rig();
        r.Tcb["tcbLevels"] = new JL { K.Level("UpToDate", tdx: K.TdxComps(1, 0)) };
        Assert.Equal("TCB evaluation: platform TCB is below every level in the TCB info", Refused(r));
        var r2 = new K.Rig();
        r2.Tcb["tcbLevels"] = new JL { K.Level("UpToDate", tdx: K.TdxComps(0, 1)) };
        Assert.Equal("TCB evaluation: platform TCB is below every level in the TCB info", Refused(r2));
    }

    [Fact]
    public void AMalformedModuleFieldIsNamedWhicheverIsBad()
    {
        const string want = "TCB evaluation: TDX module identity fields malformed";
        var nonHex = new string('z', 96);
        var a = new K.Rig(); ((JD)a.Tcb["tdxModule"]!)["mrsigner"] = nonHex;
        Assert.Equal(want, Refused(a));
        var b = new K.Rig(); ((JD)b.Tcb["tdxModule"]!)["attributes"] = new string('z', 16);
        Assert.Equal(want, Refused(b));
        var c = new K.Rig(); ((JD)c.Tcb["tdxModule"]!)["attributesMask"] = "ff";
        Assert.Equal(want, Refused(c));
        var d = new K.Rig(); ((JD)d.Tcb["tdxModule"]!).Remove("mrsigner");
        Assert.Equal(want, Refused(d));
    }

    // ---- the TCB levels

    static K.Rig LevelRig(JD level)
    {
        var r = new K.Rig();
        r.Tcb["tcbLevels"] = new JL { level };
        return r;
    }

    [Fact]
    public void AMalformedLevelIsNamed()
    {
        Assert.Equal("TCB evaluation: malformed TCB level", Refused(LevelRig(new JD { ["tcbStatus"] = "UpToDate" })));
        var s = new K.Rig(); s.Tcb["tcbLevels"] = new JL { "x" };
        Assert.Equal("TCB evaluation: malformed TCB level", Refused(s));
    }

    [Fact]
    public void AMalformedLevelComponentIsNamedWhicheverIsBad()
    {
        const string want = "TCB evaluation: malformed TCB level components";
        var a = K.Level("UpToDate"); ((JD)a["tcb"]!)["sgxtcbcomponents"] = new JL();
        Assert.Equal(want, Refused(LevelRig(a)));
        var b = K.Level("UpToDate"); ((JD)b["tcb"]!)["tdxtcbcomponents"] = new JL();
        Assert.Equal(want, Refused(LevelRig(b)));
        var c = K.Level("UpToDate"); ((JD)c["tcb"]!).Remove("pcesvn");
        Assert.Equal(want, Refused(LevelRig(c)));
    }

    // ---- the advisories

    [Fact]
    public void AdvisoriesFromBothDocumentsAreMergedOnceAndSorted()
    {
        var r = new K.Rig();
        r.Tcb["tcbLevels"] = new JL { K.Level("UpToDate", adv: Adv("INTEL-SA-B", "INTEL-SA-C")) };
        r.Qe["tcbLevels"] = new JL { K.QeLevel(3, Adv("INTEL-SA-A", "INTEL-SA-C")) };
        var x = Run(r);
        Assert.True(x.Ok, x.Reason);
        Assert.Equal(new[] { "INTEL-SA-A", "INTEL-SA-B", "INTEL-SA-C" }, x.AdvisoryIds.ToArray());
    }

    // ---- the quoting enclave

    [Fact]
    public void TheQeProductAndSvnAreTwoLittleEndianBytes()
    {
        var r = new K.Rig { QeProd = 258, QeSvn = 257 };
        r.Qe["isvprodid"] = 258;
        r.Qe["tcbLevels"] = new JL { K.QeLevel(257) };
        var x = Run(r);
        Assert.True(x.Ok, x.Reason);
    }
}
