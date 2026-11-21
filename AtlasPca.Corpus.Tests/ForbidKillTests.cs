using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Exact outcomes of the forbid-wins decision, its certificate table rule (Consistent) and the certificate check, around every branch.
public class ForbidKillTests
{
    const string Unsafe = "re:(a+)+"; // outside the safe regex subset: undecidable, so a permit does not match and a veto still applies

    static JD Clause(string id, string kind, string verb = "pay", string? signer = null, string? resource = null)
    {
        var w = new JD { ["verb"] = verb };
        if (resource != null) w["resource"] = resource;
        var c = new JD { ["id"] = id, ["kind"] = kind, ["when"] = w };
        if (signer != null) c["signer"] = signer;
        return c;
    }

    static JL Cl(params JD[] c) => c.Select(x => (object?)x).ToList();
    static JD Ctx(string verb = "pay", string resource = "/r") => new() { ["action"] = new JD { ["verb"] = verb, ["resource"] = resource } };

    static JD R(string? id, string kind, string value, string? signer = null)
    {
        var r = new JD { ["kind"] = kind, ["value"] = value };
        if (id != null) r["id"] = id;
        if (signer != null) r["signer"] = signer;
        return r;
    }

    static JD Cert(string decision, string wkind, string? wid, string[] shadowed, params JD[] rows) => new()
    {
        ["v"] = 1L, ["kind"] = "forbid-wins", ["policy"] = "p", ["action"] = "a", ["decision"] = decision,
        ["winner"] = new JD { ["kind"] = wkind, ["id"] = wid }, ["shadowed"] = shadowed.Select(s => (object?)s).ToList(), ["clauses"] = rows.Select(r => (object?)r).ToList(),
    };

    static string Vals(ClauseDecision d) => string.Join(",", d.Values.Select(v => v.Id + "=" + v.Kind + ":" + v.Value));

    // ---- the certificate table rule ----

    [Fact]
    public void EachOutcomeIsEntailedByItsRows()
    {
        Assert.True(Forbid.Consistent(Cert("deny", "forbid", "f", new[] { "p", "e" }, R("p", "permit", "true"), R("f", "forbid", "unknown"), R("e", "escalate", "true"))));
        Assert.True(Forbid.Consistent(Cert("deny", "none", null, new[] { "e" }, R("p", "permit", "false"), R("f", "forbid", "false"), R("e", "escalate", "true"))));
        Assert.True(Forbid.Consistent(Cert("escalate", "escalate", "e1", new[] { "p1", "e2" }, R("p1", "permit", "true"), R("e1", "escalate", "unknown"), R("e2", "escalate", "true"))));
        Assert.True(Forbid.Consistent(Cert("allow", "permit", "p1", new[] { "p2" }, R("p1", "permit", "true"), R("p2", "permit", "unknown"))));
        Assert.True(Forbid.Consistent(Cert("allow", "permit", "p1", Array.Empty<string>(), R("p1", "permit", "true"), R("f", "forbid", "false"), R("e", "escalate", "false"))));
    }

    [Fact]
    public void AWrongDecisionWinnerOrShadowedListIsRefused()
    {
        var rows = new[] { R("p1", "permit", "true"), R("e1", "escalate", "true") };
        Assert.True(Forbid.Consistent(Cert("escalate", "escalate", "e1", new[] { "p1" }, rows)));
        Assert.False(Forbid.Consistent(Cert("allow", "escalate", "e1", new[] { "p1" }, rows)));
        Assert.False(Forbid.Consistent(Cert("escalate", "permit", "e1", new[] { "p1" }, rows)));
        Assert.False(Forbid.Consistent(Cert("escalate", "escalate", "p1", new[] { "p1" }, rows)));
        Assert.False(Forbid.Consistent(Cert("escalate", "escalate", "e1", Array.Empty<string>(), rows)));
        Assert.False(Forbid.Consistent(Cert("deny", "forbid", "e1", new[] { "p1" }, rows)));
    }

    [Fact]
    public void TheMalformedCertificateIsTheOneWithNoTable()
    {
        Assert.True(Forbid.Consistent(Cert("deny", "malformed", null, Array.Empty<string>())));
        Assert.False(Forbid.Consistent(Cert("deny", "malformed", null, Array.Empty<string>(), R("x", "forbid", "true")))); // rows
        Assert.False(Forbid.Consistent(Cert("allow", "malformed", null, Array.Empty<string>()))); // decision
        Assert.False(Forbid.Consistent(Cert("deny", "malformed", "x", Array.Empty<string>()))); // winner id
        Assert.False(Forbid.Consistent(Cert("deny", "malformed", null, new[] { "x" }))); // shadowed
    }

    [Fact]
    public void ARowOfAnUnknownKindOrValueRefusesTheTable()
    {
        JD Bad(object? kind, object? value) => Cert("deny", "none", null, Array.Empty<string>(), new JD { ["id"] = "x", ["kind"] = kind, ["value"] = value });
        Assert.False(Forbid.Consistent(Bad("bogus", "true")));
        Assert.False(Forbid.Consistent(Bad(5L, "true")));
        Assert.False(Forbid.Consistent(Bad("forbid", "maybe")));
        Assert.False(Forbid.Consistent(Bad("forbid", true)));
        Assert.False(Forbid.Consistent(Bad("forbid", "")));
        Assert.True(Forbid.Consistent(Cert("deny", "none", null, Array.Empty<string>(), R("x", "permit", "false"))));
        Assert.True(Forbid.Consistent(Cert("deny", "none", null, Array.Empty<string>(), R("x", "forbid", "false"))));
        Assert.True(Forbid.Consistent(Cert("deny", "none", null, new[] { "x" }, R("x", "escalate", "unknown"))));
        Assert.True(Forbid.Consistent(Cert("deny", "forbid", "x", Array.Empty<string>(), R("x", "forbid", "true"))));
    }

    [Fact]
    public void ARowThatIsNoObjectIsRefusedNotTrusted()
    {
        var c = Cert("deny", "none", null, Array.Empty<string>());
        c["clauses"] = new JL { "x" };
        Assert.False(Forbid.Consistent(c));
        c["clauses"] = new JL { new JD { ["id"] = "x", ["kind"] = "permit", ["value"] = "true" }, 5L };
        Assert.False(Forbid.Consistent(c));
    }

    [Fact]
    public void ThePrecedenceNamesTheWinnerAmongForbidsAndTheIdBreaksTies()
    {
        var rows = new[] { R("a", "forbid", "true", "user"), R("z", "forbid", "true", "org") };
        var withOrg = new ClauseOptions(Precedence: new[] { "org", "user" });
        Assert.True(Forbid.Consistent(Cert("deny", "forbid", "z", new[] { "a" }, rows), withOrg));
        Assert.False(Forbid.Consistent(Cert("deny", "forbid", "z", new[] { "a" }, rows)));
        Assert.True(Forbid.Consistent(Cert("deny", "forbid", "a", new[] { "z" }, rows)));
        Assert.False(Forbid.Consistent(Cert("deny", "forbid", "a", new[] { "z" }, rows), withOrg));
        // equal rank: the id in ordinal order, ascending
        Assert.True(Forbid.Consistent(Cert("deny", "forbid", "a", new[] { "b", "c" }, R("c", "forbid", "true"), R("b", "forbid", "true"), R("a", "forbid", "true"))));
        Assert.False(Forbid.Consistent(Cert("deny", "forbid", "c", new[] { "b", "a" }, R("c", "forbid", "true"), R("b", "forbid", "true"), R("a", "forbid", "true"))));
        // a row with no id sorts as the empty string, before any id
        Assert.True(Forbid.Consistent(Cert("deny", "forbid", null, new[] { "!" }, R("!", "forbid", "true"), R(null, "forbid", "true"))));
        Assert.False(Forbid.Consistent(Cert("deny", "forbid", "!", Array.Empty<string>(), R("!", "forbid", "true"), R(null, "forbid", "true"))));
    }

    // ---- the decision ----

    [Fact]
    public void AnUnlistedOrUnsignedForbidRanksLastAndAListedOneByItsPosition()
    {
        var cl = Cl(Clause("a", "forbid"), Clause("b", "forbid", signer: "zzz"), Clause("c", "forbid", signer: "user"), Clause("d", "forbid", signer: "org"));
        var d = Forbid.Decide(cl, Ctx(), new ClauseOptions(Precedence: new[] { "org", "user" }));
        Assert.Equal(("deny", "forbid", "d"), (d.Decision, d.WinnerKind, d.WinnerId));
        Assert.Equal(new[] { "c", "a", "b" }, d.Shadowed);
        // without precedence everything ranks alike: the ids alone order the forbids
        var plain = Forbid.Decide(cl, Ctx());
        Assert.Equal("a", plain.WinnerId);
        Assert.Equal(new[] { "b", "c", "d" }, plain.Shadowed);
        // a listed signer beats an unlisted one whatever the ids say
        var mixed = Forbid.Decide(Cl(Clause("a", "forbid", signer: "zzz"), Clause("z", "forbid", signer: "org")), Ctx(), new ClauseOptions(Precedence: new[] { "org" }));
        Assert.Equal("z", mixed.WinnerId);
        // an unsigned clause is no entry of the list, even a null one
        var nullEntry = Forbid.Decide(Cl(Clause("a", "forbid"), Clause("b", "forbid", signer: "org")), Ctx(), new ClauseOptions(Precedence: new string[] { null!, "org" }));
        Assert.Equal("b", nullEntry.WinnerId);
        // an unsigned clause ranks after every listed signer
        var third = Forbid.Decide(Cl(Clause("z", "forbid"), Clause("y", "forbid", signer: "c")), Ctx(), new ClauseOptions(Precedence: new[] { "a", "b", "c" }));
        Assert.Equal("y", third.WinnerId);
    }

    [Fact]
    public void ForbidsOfEqualRankAreOrderedByIdAscending()
    {
        var d = Forbid.Decide(Cl(Clause("b", "forbid"), Clause("a", "forbid"), Clause("c", "forbid"), Clause("p", "permit")), Ctx());
        Assert.Equal(("deny", "forbid", "a"), (d.Decision, d.WinnerKind, d.WinnerId));
        Assert.Equal(new[] { "b", "c", "p" }, d.Shadowed);
        Assert.Equal("b=forbid:true,a=forbid:true,c=forbid:true,p=permit:true", Vals(d));
    }

    [Fact]
    public void PermitSignersDropOnlyPermitsOfOtherOrNoSigners()
    {
        var cl = Cl(Clause("p-ok", "permit", signer: "alice"), Clause("p-bad", "permit", signer: "mallory"), Clause("p-anon", "permit"), Clause("f-m", "forbid", signer: "mallory"), Clause("e-m", "escalate", signer: "mallory"));
        var d = Forbid.Decide(cl, Ctx(), new ClauseOptions(PermitSigners: new[] { "alice" }));
        Assert.Equal("p-ok=permit:true,p-bad=permit:false,p-anon=permit:false,f-m=forbid:true,e-m=escalate:true", Vals(d));
        Assert.Equal(("deny", "forbid", "f-m"), (d.Decision, d.WinnerKind, d.WinnerId));
        Assert.Equal(new[] { "p-ok", "e-m" }, d.Shadowed);
        // the same clauses without the list: every permit counts
        Assert.Equal("p-ok=permit:true,p-bad=permit:true,p-anon=permit:true,f-m=forbid:true,e-m=escalate:true", Vals(Forbid.Decide(cl, Ctx())));
        // when no permit survives, it is a default deny
        var none = Forbid.Decide(Cl(Clause("p-bad", "permit", signer: "mallory")), Ctx(), new ClauseOptions(PermitSigners: new[] { "alice" }));
        Assert.Equal(("deny", "none", (string?)null), (none.Decision, none.WinnerKind, none.WinnerId));
        // an empty list admits no permit at all
        Assert.Equal("none", Forbid.Decide(Cl(Clause("p", "permit", signer: "alice")), Ctx(), new ClauseOptions(PermitSigners: Array.Empty<string>())).WinnerKind);
    }

    [Fact]
    public void AnActionWithoutAStringVerbAndResourceIsMalformed()
    {
        var cl = Cl(Clause("p", "permit"));
        foreach (var ctx in new JD?[]
        {
            null, new JD(), new JD { ["action"] = 5L },
            new JD { ["action"] = new JD { ["verb"] = "pay" } },
            new JD { ["action"] = new JD { ["resource"] = "/r" } },
            new JD { ["action"] = new JD { ["verb"] = 5L, ["resource"] = "/r" } },
            new JD { ["action"] = new JD { ["verb"] = "pay", ["resource"] = 5L } },
        })
        {
            var d = Forbid.Decide(cl, ctx);
            Assert.Equal(("deny", "malformed", (string?)null), (d.Decision, d.WinnerKind, d.WinnerId));
            Assert.Empty(d.Shadowed);
            Assert.Empty(d.Values);
        }
        Assert.Equal("allow", Forbid.Decide(cl, Ctx()).Decision);
    }

    [Fact]
    public void EachKindValuesAreTrueFalseOrUnknownByItsOwnPolarity()
    {
        // a veto that cleanly matches is true, one that cleanly misses is false
        var a = Forbid.Decide(Cl(Clause("p", "permit"), Clause("miss", "forbid", "refund")), Ctx());
        Assert.Equal("allow", a.Decision);
        Assert.Equal("p=permit:true,miss=forbid:false", Vals(a));
        // a permit that cannot be decided is not matched
        var b = Forbid.Decide(Cl(Clause("p", "permit", resource: Unsafe)), Ctx());
        Assert.Equal(("deny", "none"), (b.Decision, b.WinnerKind));
        Assert.Equal("p=permit:false", Vals(b));
        // a forbid or an escalate that cannot be decided still applies, as unknown
        var c = Forbid.Decide(Cl(Clause("u", "forbid", resource: Unsafe)), Ctx());
        Assert.Equal(("deny", "forbid", "u"), (c.Decision, c.WinnerKind, c.WinnerId));
        Assert.Equal("u=forbid:unknown", Vals(c));
        var d = Forbid.Decide(Cl(Clause("p", "permit"), Clause("e", "escalate", resource: Unsafe)), Ctx());
        Assert.Equal(("escalate", "escalate", "e"), (d.Decision, d.WinnerKind, d.WinnerId));
        Assert.Equal("p=permit:true,e=escalate:unknown", Vals(d));
        // a clean escalate match is true and shadows the permit
        var e = Forbid.Decide(Cl(Clause("p", "permit"), Clause("e", "escalate")), Ctx());
        Assert.Equal("p=permit:true,e=escalate:true", Vals(e));
        Assert.Equal(new[] { "p" }, e.Shadowed);
    }

    // ---- the certificate ----

    [Fact]
    public void ACertifiedDecisionChecksOutAndAnyTamperingDoesNot()
    {
        var cl = Cl(Clause("p", "permit"), Clause("e", "escalate", resource: Unsafe), Clause("z", "forbid", "refund", signer: "org"));
        var opts = new ClauseOptions(Precedence: new[] { "org" });
        var cert = Forbid.Certify(cl, Ctx(), opts);
        Assert.Equal("escalate", cert["decision"]);
        Assert.True(Forbid.Check(cert, cl, Ctx(), opts).Ok);
        Assert.Equal((false, "certificate does not match the recomputed decision"), Forbid.Check(cert, cl, Ctx("pay", "/other"), opts));
        Assert.Equal((false, "malformed clauses"), Forbid.Check(cert, "x", Ctx(), opts));
    }

    [Fact]
    public void ACertificateThatCannotBeRecomputedFailsClosed()
    {
        var cl = Cl(Clause("p", "permit"));
        var cert = Forbid.Certify(cl, Ctx());
        var unhashable = new JD { ["action"] = new JD { ["verb"] = "pay", ["resource"] = "/r", ["params"] = new JD { ["note"] = "\ud800" } } }; // a lone surrogate has no canonical form
        Assert.Equal((false, "certificate check error (fail closed)"), Forbid.Check(cert, cl, unhashable));
    }
}
