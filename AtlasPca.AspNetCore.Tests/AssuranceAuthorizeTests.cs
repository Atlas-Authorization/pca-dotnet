using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// Assurance labels through Authorize (T8, B7): the `assurance` check is raised by AuthorizeInput.RequireAssurance, fails BEFORE the
// replay counter is claimed, and every result carries the per-check report (the capability chain is reported as `cap_chain`).
public class AssuranceAuthorizeTests
{
    static readonly JD Fix = (JD)Pca.ParseJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly string Aud = (string)Fix["audience"]!;
    static readonly long Now = long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture);
    static readonly JD Case = ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static readonly JD Grant = (JD)Case["grant"]!;
    static readonly JD Step = (JD)((JL)Case["steps"]!)[0]!;
    static readonly JD Pcactn = (JD)Step["pcactn"]!;
    static readonly Operation Op = new((string)((JD)Step["operation"]!)["verb"]!, (string)((JD)Step["operation"]!)["resource"]!, ((JD)Step["operation"]!)["params"]);

    static AuthorizeInput Input(IStateStore store, AssuranceRequirement? req = null) => new AuthorizeInput
    {
        Operation = Op, Audience = Aud, ResolveGrant = r => r == (string)Grant["id"]! ? Grant : null, StateStore = store, IsRevoked = (_, _) => false,
        Now = Now, Plan = "single-step", RequireAssurance = req,
    }.WithProv();

    static string Key => Pca.StateKey((string)Grant["id"]!, (string)((JD)((JL)Pcactn["cap_chain"]!).Last()!)["holder"]!);

    [Fact]
    public void AnEd25519ProofDoesNotMeetAPostQuantumRequirementAndTheCounterIsNotSpent()
    {
        var store = new MemoryStateStore();
        var r = Pca.Authorize(Pcactn, Input(store, new AssuranceRequirement(Signature: "pq")));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["assurance"]);
        Assert.Equal("assurance: post-quantum signatures required but leaf_signature is ed25519", r.Reason);
        var leaf = r.Assurance.Get("leaf_signature")!;
        Assert.Equal(("ed25519", "ed25519"), (leaf.Level, leaf.Suites!.Single()));
        // the refusal wrote no replay state: the same proof still passes without the requirement
        Assert.Null(store.Last(Key));
        var ok = Pca.Authorize(Pcactn, Input(store));
        Assert.True(ok.Allow, ok.Reason);
        var chain = ok.Assurance.Get("cap_chain")!;
        Assert.Equal(("pass", "ed25519"), (chain.Outcome, chain.Level));
        Assert.False(ok.Checks.ContainsKey("assurance"));
    }

    [Fact]
    public void AnEmptyRequirementAllowsAndAMissingAttestationIsNeverSilentlyMet()
    {
        Assert.True(Pca.Authorize(Pcactn, Input(new MemoryStateStore(), new AssuranceRequirement())).Allow);
        var hw = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), new AssuranceRequirement(Attestation: "hardware")));
        Assert.False(hw.Allow);
        Assert.Equal("assurance: hardware attestation required but there is no attestation evidence", hw.Reason);
    }
}
