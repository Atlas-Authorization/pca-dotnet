using System.Text;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.ContractsKillSupport;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Exact-output kills for <see cref="Contracts"/>: clause and contract validation (every boundary and message), the per-clause verdicts, the contract monitor
/// (check / advance / check-and-advance) with the full result shape and next state, and signing / verification.</summary>
public class ContractsKillTests2
{
    const string NeverX = "'kind':'never','p':{'verb':'x'}";
    const string Missed = "bounded-liveness deadline missed (no q within 3 actions of p)";
    const string Prec = "precedence violated (prerequisite p not yet admitted before q)";

    static List<string> One(string s) => new() { s };
    static List<string> VCl(string json, HashSet<string>? seen = null, int depth = 1) => Contracts.ValidateClause(J(json), seen ?? new HashSet<string>(), depth);
    static List<string> VC(string json) => Contracts.Validate(J(json));

    static JD Act(string verb) => M("{'action':{'verb':'" + verb + "','resource':'/r'}}");
    static JD C(string clauses, string extra = "") => M("{'version':1,'principal':'p','clauses':" + clauses + extra + "}");
    static JD St(string latched = "{}", string? deadlines = null, long now = 1000) =>
        M("{'now':" + now + ",'seq':0,'parent':null,'ledger':{},'latched':" + latched + (deadlines == null ? "" : ",'deadlines':" + deadlines) + "}");

    static string R(InvariantEval e) => $"{e.Id}|{e.Kind}|{e.Result}|{e.Reason}";
    static string Rows(ContractResult r) => string.Join(";", r.Evaluated.Select(R));
    static AdvanceContractResult Adv(JD contract, JD state, string verb, double? now = null, long? seq = null, string? digest = null) => Contracts.Advance(state, Act(verb), contract, seq, digest, now);
    static JD Latched(AdvanceContractResult r) => (JD)r.Next["latched"]!;
    static JD? Deadlines(AdvanceContractResult r) => r.Next.GetValueOrDefault("deadlines") as JD;

    static string Neverx(int n, string prefix) => "[" + string.Join(",", Enumerable.Range(0, n).Select(i => "{'id':'" + prefix + i + "','kind':'never','p':{'verb':'x'}}")) + "]";
    static string Invariants(int n) => "[" + string.Join(",", Enumerable.Range(0, n).Select(i => "{'id':'i" + i + "','kind':'never','when':{'verb':'x'}}")) + "]";

    sealed class NullText { public override string? ToString() => null; }

    // ---- validateClause ---------------------------------------------------------------------------------------------------

    [Fact]
    public void ClauseDepthShapeAndId()
    {
        Assert.Equal(One("clause nesting too deep"), VCl("{'id':'a'," + NeverX + "}", depth: 17));
        Assert.Empty(VCl("{'id':'a'," + NeverX + "}", depth: 16));
        Assert.Equal(One("clause not an object"), Contracts.ValidateClause("x", new HashSet<string>(), 1));
        Assert.Equal(One("clause not an object"), Contracts.ValidateClause(null, new HashSet<string>(), 1));
        Assert.Equal(One("<no id>: missing clause id"), VCl("{'kind':'never','p':{'verb':'x'}}"));
        Assert.Equal(One("<no id>: missing clause id"), VCl("{'id':''," + NeverX + "}"));
        Assert.Equal(One("<no id>: missing clause id"), VCl("{'id':5," + NeverX + "}"));
        var id128 = new string('a', 128); var id129 = new string('a', 129);
        Assert.Empty(VCl("{'id':'" + id128 + "'," + NeverX + "}"));
        Assert.Equal(One(id129 + ": id too long"), VCl("{'id':'" + id129 + "'," + NeverX + "}"));
        foreach (var bad in new[] { "__proto__", "constructor", "prototype" })
            Assert.Equal(One(bad + ": forbidden id"), VCl("{'id':'" + bad + "'," + NeverX + "}"));
        var seen = new HashSet<string>();
        Assert.Empty(VCl("{'id':'a'," + NeverX + "}", seen));
        Assert.Contains("a", seen);
        Assert.Equal(One("a: duplicate id"), VCl("{'id':'a'," + NeverX + "}", seen));
        Assert.Single(seen);
    }

    [Fact]
    public void AlwaysAndNeverCheckOnlyP()
    {
        foreach (var kind in new[] { "always", "never" })
        {
            Assert.Empty(VCl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'}}"));
            Assert.Equal(One("a: p: not an object"), VCl("{'id':'a','kind':'" + kind + "','p':5}"));
            Assert.Equal(One("a: p: not an object"), VCl("{'id':'a','kind':'" + kind + "'}"));
            Assert.Equal(One("a: p: bad verb"), VCl("{'id':'a','kind':'" + kind + "','p':{}}"));
            Assert.Empty(VCl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'},'q':5}"));
        }
    }

    [Fact]
    public void PairedClauseKindsCheckPThenQ()
    {
        foreach (var kind in new[] { "precedes", "requires_prior" })
        {
            Assert.Empty(VCl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'},'q':{'verb':'y'}}"));
            Assert.Equal(One("a: p: not an object"), VCl("{'id':'a','kind':'" + kind + "','p':5,'q':{'verb':'y'}}"));
            Assert.Equal(One("a: q: not an object"), VCl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'},'q':5}"));
            Assert.Equal(One("a: q: bad verb"), VCl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'},'q':{}}"));
            Assert.Equal(One("a: p: not an object"), VCl("{'id':'a','kind':'" + kind + "','p':5,'q':6}"));
            Assert.Empty(VCl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'},'q':{'verb':'y'},'within':0}"));
        }
    }

    [Fact]
    public void RespondsWithinBounds()
    {
        var pre = "{'id':'a','kind':'responds_within','p':{'verb':'x'},'q':{'verb':'y'}";
        var msg = "a: within must be an integer in [1, MAX_DEADLINE]";
        Assert.Empty(VCl(pre + ",'within':1}"));
        Assert.Empty(VCl(pre + ",'within':2}"));
        Assert.Empty(VCl(pre + ",'within':1000000}"));
        Assert.Equal(One(msg), VCl(pre + ",'within':1000001}"));
        Assert.Equal(One(msg), VCl(pre + ",'within':0}"));
        Assert.Equal(One(msg), VCl(pre + ",'within':-1}"));
        Assert.Equal(One(msg), VCl(pre + ",'within':2.5}"));
        Assert.Equal(One(msg), VCl(pre + ",'within':'3'}"));
        Assert.Equal(One(msg), VCl(pre + "}"));
        Assert.Equal(One("a: p: not an object"), VCl("{'id':'a','kind':'responds_within','p':1,'q':{'verb':'y'},'within':3}"));
        Assert.Equal(One("a: q: not an object"), VCl("{'id':'a','kind':'responds_within','p':{'verb':'x'},'q':1,'within':3}"));
        Assert.Equal(One("a: p: not an object"), VCl("{'id':'a','kind':'responds_within','p':1,'q':2,'within':3}"));
    }

    [Fact]
    public void AndClausesAndUnknownKinds()
    {
        var msg = "a: and.clauses must be a non-empty array";
        Assert.Equal(One(msg), VCl("{'id':'a','kind':'and'}"));
        Assert.Equal(One(msg), VCl("{'id':'a','kind':'and','clauses':[]}"));
        Assert.Equal(One(msg), VCl("{'id':'a','kind':'and','clauses':'x'}"));
        Assert.Empty(VCl("{'id':'a','kind':'and','clauses':[{'id':'b'," + NeverX + "}]}"));
        Assert.Equal(new List<string> { "b: p: not an object", "b: duplicate id", "<no id>: missing clause id" },
            VCl("{'id':'a','kind':'and','clauses':[{'id':'b','kind':'never','p':1},{'id':'b'," + NeverX + "},{'kind':'never'}]}"));
        Assert.Equal(One("a: duplicate id"), VCl("{'id':'a','kind':'and','clauses':[{'id':'a'," + NeverX + "}]}"));
        Assert.Equal(One("clause nesting too deep"), VCl("{'id':'a','kind':'and','clauses':[{'id':'b'," + NeverX + "}]}", depth: 16));
    }

    [Fact]
    public void AnUnknownKindIsPrintedLikeTheReferenceStringifiesIt()
    {
        Assert.Equal(One("a: unknown clause kind bogus"), VCl("{'id':'a','kind':'bogus'}"));
        Assert.Equal(One("a: unknown clause kind undefined"), VCl("{'id':'a'}"));
        Assert.Equal(One("a: unknown clause kind null"), VCl("{'id':'a','kind':null}"));
        Assert.Equal(One("a: unknown clause kind true"), VCl("{'id':'a','kind':true}"));
        Assert.Equal(One("a: unknown clause kind false"), VCl("{'id':'a','kind':false}"));
        Assert.Equal(One("a: unknown clause kind 5"), VCl("{'id':'a','kind':5}"));
        Assert.Equal(One("a: unknown clause kind 1.5"), VCl("{'id':'a','kind':1.5}"));
        Assert.Equal(One("a: unknown clause kind [object Object]"), VCl("{'id':'a','kind':{}}"));
        Assert.Equal(One("a: unknown clause kind "), VCl("{'id':'a','kind':[]}"));
        Assert.Equal(One("a: unknown clause kind 1,,x"), VCl("{'id':'a','kind':[1,null,'x']}"));
        Assert.Equal(One("a: unknown clause kind "), VCl("{'id':'a','kind':''}"));
    }

    // ---- validate / count ------------------------------------------------------------------------------------------------

    [Fact]
    public void VersionAndPrincipal()
    {
        Assert.Equal(new List<string> { "unsupported version undefined", "principal missing" }, VC("{}"));
        Assert.Equal(One("unsupported version 2"), VC("{'version':2,'principal':'p'}"));
        Assert.Equal(One("unsupported version 1"), VC("{'version':'1','principal':'p'}"));
        Assert.Equal(One("unsupported version null"), VC("{'version':null,'principal':'p'}"));
        Assert.Equal(One("unsupported version true"), VC("{'version':true,'principal':'p'}"));
        Assert.Equal(One("unsupported version false"), VC("{'version':false,'principal':'p'}"));
        Assert.Equal(One("unsupported version 1.5"), VC("{'version':1.5,'principal':'p'}"));
        Assert.Equal(One("unsupported version [object Object]"), VC("{'version':{},'principal':'p'}"));
        Assert.Equal(One("unsupported version "), VC("{'version':[],'principal':'p'}"));
        Assert.Equal(One("unsupported version 1,2"), VC("{'version':[1,2],'principal':'p'}"));
        Assert.Equal(One("unsupported version some text"), Contracts.Validate(new JD { ["version"] = new StringBuilder("some text"), ["principal"] = "p" }));
        Assert.Equal(One("unsupported version "), Contracts.Validate(new JD { ["version"] = new NullText(), ["principal"] = "p" }));
        Assert.Equal(One("principal missing"), VC("{'version':1,'principal':''}"));
        Assert.Equal(One("principal missing"), VC("{'version':1,'principal':5}"));
        Assert.Equal(One("principal missing"), VC("{'version':1}"));
        Assert.Empty(VC("{'version':1,'principal':'p'}"));
        Assert.Equal(One("contract not an object"), Contracts.Validate(null));
        Assert.Equal(One("contract not an object"), Contracts.Validate("x"));
    }

    [Fact]
    public void InvariantsArrayRules()
    {
        Assert.Equal(One("invariants not an array"), VC("{'version':1,'principal':'p','invariants':'x','clauses':5}"));
        Assert.Equal(One("invariants not an array"), VC("{'version':1,'principal':'p','invariants':{}}"));
        Assert.Empty(VC("{'version':1,'principal':'p','invariants':" + Invariants(256) + "}"));
        Assert.Equal(One("too many invariants"), VC("{'version':1,'principal':'p','invariants':" + Invariants(257) + "}"));
        Assert.Equal(One("invariant not an object"), VC("{'version':1,'principal':'p','invariants':['x']}"));
        Assert.Equal(One("<no id>: missing id"), VC("{'version':1,'principal':'p','invariants':[{'id':5,'kind':'never','when':{'verb':'x'}}]}"));
        Assert.Equal(One("i0: duplicate id"), VC("{'version':1,'principal':'p','invariants':[{'id':'i0','kind':'never','when':{'verb':'x'}},{'id':'i0','kind':'never','when':{'verb':'y'}}]}"));
        Assert.Equal(new List<string> { "i0: when: not an object", "i0: duplicate id" },
            VC("{'version':1,'principal':'p','invariants':[{'id':'i0','kind':'never','when':1},{'id':'i0','kind':'never','when':{'verb':'x'}}]}"));
        Assert.Equal(One("i0: duplicate id"), VC("{'version':1,'principal':'p','invariants':" + Invariants(1) + ",'clauses':[{'id':'i0'," + NeverX + "}]}"));
    }

    [Fact]
    public void ClausesArrayRulesAndTheCountBound()
    {
        Assert.Equal(One("clauses not an array"), VC("{'version':1,'principal':'p','clauses':'x'}"));
        Assert.Equal(One("clauses not an array"), VC("{'version':1,'principal':'p','clauses':{}}"));
        Assert.Empty(VC("{'version':1,'principal':'p','clauses':" + Neverx(256, "c") + "}"));
        Assert.Equal(One("too many clauses"), VC("{'version':1,'principal':'p','clauses':" + Neverx(257, "c") + "}"));
        Assert.Equal(One("clause not an object"), VC("{'version':1,'principal':'p','clauses':['x']}"));
        // a clause that is not an "and" is counted once, whatever else it carries
        var many = string.Join(",", Enumerable.Range(0, 300).Select(i => "{'id':'z" + i + "','kind':'never','p':{'verb':'x'}}"));
        Assert.Empty(VC("{'version':1,'principal':'p','clauses':[{'id':'a','kind':'never','p':{'verb':'x'},'clauses':[" + many + "]}]}"));
        // an "and" counts itself and every sub clause: 254 + 1 + 1 = 256 fits, 255 + 1 + 1 does not
        var sub = "{'id':'s','kind':'never','p':{'verb':'x'}}";
        string WithAnd(int n) => "[" + string.Join(",", Enumerable.Range(0, n).Select(i => "{'id':'c" + i + "','kind':'never','p':{'verb':'x'}}").Append("{'id':'a','kind':'and','clauses':[" + sub + "]}")) + "]";
        Assert.Empty(VC("{'version':1,'principal':'p','clauses':" + WithAnd(254) + "}"));
        Assert.Equal(One("too many clauses"), VC("{'version':1,'principal':'p','clauses':" + WithAnd(255) + "}"));
        var subs = string.Join(",", Enumerable.Range(0, 256).Select(i => "{'id':'s" + i + "','kind':'never','p':{'verb':'x'}}"));
        Assert.Equal(One("too many clauses"), VC("{'version':1,'principal':'p','clauses':[{'id':'a','kind':'and','clauses':[" + subs + "]}]}"));
        Assert.Equal(One("a: and.clauses must be a non-empty array"), VC("{'version':1,'principal':'p','clauses':[{'id':'a','kind':'and','clauses':'x'}]}"));
    }

    static string NestedAnds(int levels)
    {
        var open = new StringBuilder(); var close = new StringBuilder();
        for (int i = 1; i <= levels; i++) { open.Append("{'id':'a" + i + "','kind':'and','clauses':["); close.Append("]}"); }
        return open + "{'id':'leaf'," + NeverX + "}" + close;
    }

    [Fact]
    public void NestingDepthIsBoundedAtBothTheCountAndTheValidation()
    {
        var pre = "{'version':1,'principal':'p','clauses':[";
        Assert.Empty(VC(pre + NestedAnds(15) + "]}"));
        Assert.Equal(One("clause nesting too deep"), VC(pre + NestedAnds(16) + "]}"));
        Assert.Equal(new List<string> { "too many clauses", "clause nesting too deep" }, VC(pre + NestedAnds(17) + "]}"));
        Assert.Equal(new List<string> { "too many clauses", "clause nesting too deep" }, VC(pre + NestedAnds(40) + "]}"));
    }

    // ---- sign / verify ----------------------------------------------------------------------------------------------------

    static JD ContractFor(string principal) => M("{'version':1,'principal':'" + principal + "','clauses':[{'id':'a','kind':'never','p':{'verb':'x'}}]}");

    [Fact]
    public void SigningBindsTheBodyAndLeavesTheInputAlone()
    {
        var key = Key(7);
        var c = ContractFor(key.Id);
        var signed = Contracts.Sign(c, key);
        Assert.False(c.ContainsKey("id"));
        Assert.False(c.ContainsKey("sig"));
        Assert.NotSame(c, signed);
        Assert.Equal(new[] { "clauses", "id", "principal", "sig", "version" }, signed.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());
        Assert.Equal(Contracts.ContractId(c), signed["id"]);
        Assert.Equal(signed["id"], Contracts.ContractId(signed));
        Assert.Equal((true, (string?)null), Contracts.Verify(signed, key.Id));
        Assert.Equal((true, (string?)null), Contracts.Verify(signed));
        // a stale id / sig on the input is stripped, not signed over
        var stale = new JD(ContractFor(key.Id)) { ["id"] = "zz", ["sig"] = "yy" };
        var again = Contracts.Sign(stale, key);
        Assert.Equal(signed["id"], again["id"]);
        Assert.Equal(signed["sig"], again["sig"]);
        Assert.Equal("zz", stale["id"]);
        Assert.Equal("yy", stale["sig"]);
    }

    [Fact]
    public void SigningRefusesAnInvalidContractNamingEveryProblem()
    {
        var key = Key(7);
        Assert.Equal("signContract: unsupported version 2; principal missing", Assert.Throws<ArgumentException>(() => Contracts.Sign(M("{'version':2,'clauses':[]}"), key)).Message);
        Assert.Equal("signContract: clauses not an array", Assert.Throws<ArgumentException>(() => Contracts.Sign(M("{'version':1,'principal':'p','clauses':5}"), key)).Message);
    }

    [Fact]
    public void VerifyReasons()
    {
        var key = Key(7);
        var signed = Contracts.Sign(ContractFor(key.Id), key);
        Assert.Equal((false, (string?)"principal mismatch"), Contracts.Verify(signed, "someone-else"));
        Assert.Equal((false, (string?)"unsupported version 2"), Contracts.Verify(M("{'version':2,'principal':'p'}")));
        var changed = new JD(signed) { ["clauses"] = J("[{'id':'a','kind':'never','p':{'verb':'y'}}]") };
        Assert.Equal((false, (string?)"id does not match content"), Contracts.Verify(changed, key.Id));
        var noId = new JD(signed); noId.Remove("id");
        Assert.Equal((false, (string?)"id does not match content"), Contracts.Verify(noId, key.Id));
        Assert.Equal((false, (string?)"id does not match content"), Contracts.Verify(new JD(signed) { ["id"] = J("5") }, key.Id));
        var other = Contracts.Sign(ContractFor(key.Id), Key(8));
        Assert.Equal((false, (string?)"bad signature"), Contracts.Verify(new JD(signed) { ["sig"] = other["sig"] }, key.Id));
        var noSig = new JD(signed); noSig.Remove("sig");
        Assert.Equal((false, (string?)"bad signature"), Contracts.Verify(noSig, key.Id));
        Assert.Equal((false, (string?)"bad signature"), Contracts.Verify(new JD(signed) { ["sig"] = J("5") }, key.Id));
        Assert.Equal((false, (string?)"id does not match content"), Contracts.Verify(new JD(signed) { ["principal"] = Key(8).Id }));
        // a body that cannot be canonicalised is a refusal, never an exception
        var bad = M("{'version':1,'principal':'p','id':'x'}");
        bad["extra"] = new object();
        Assert.Equal((false, (string?)"verification error (fail closed)"), Contracts.Verify(bad));
    }

    [Fact]
    public void TheEmbeddedConstitutionAndTheLiftedConstitution()
    {
        Assert.Equal("{\"invariants\":[{\"id\":\"i\"}],\"principal\":\"p\",\"version\":1}", Pca.Canonicalize(Contracts.EmbeddedConstitution(M("{'principal':'p','invariants':[{'id':'i'}],'clauses':[]}"))));
        Assert.Equal("{\"invariants\":[],\"principal\":\"p\",\"version\":1}", Pca.Canonicalize(Contracts.EmbeddedConstitution(M("{'principal':'p'}"))));
        Assert.Equal("{\"invariants\":[],\"principal\":\"p\",\"version\":1}", Pca.Canonicalize(Contracts.EmbeddedConstitution(M("{'principal':'p','invariants':'x'}"))));
        Assert.Equal("{\"invariants\":[],\"principal\":null,\"version\":1}", Pca.Canonicalize(Contracts.EmbeddedConstitution(M("{'invariants':5}"))));
        Assert.Equal("{\"clauses\":[],\"invariants\":[],\"principal\":\"p\",\"version\":1}", Pca.Canonicalize(Contracts.FromConstitution(M("{'version':1,'principal':'p','invariants':[]}"))));
    }

    // ---- per-clause verdicts (through check) ------------------------------------------------------------------------------

    [Fact]
    public void AlwaysClause()
    {
        var c = C("[{'id':'c1','kind':'always','p':{'verb':'read'}}]");
        var ok = Contracts.Check(Act("read"), c, St());
        Assert.True(ok.Ok);
        Assert.Equal("c1|always|pass|", Rows(ok));
        var r = "always-invariant violated (action does not satisfy p)";
        var bad = Contracts.Check(Act("write"), c, St());
        Assert.False(bad.Ok);
        Assert.Equal(new[] { "c1" }, bad.Violated);
        Assert.Equal(new[] { "c1: " + r }, bad.Reasons);
        Assert.Equal("c1|always|violated|" + r, Rows(bad));
        var custom = Contracts.Check(Act("write"), C("[{'id':'c1','kind':'always','p':{'verb':'read'},'description':'custom'}]"), St());
        Assert.Equal(new[] { "c1: custom" }, custom.Reasons);
        Assert.Equal("c1|always|violated|custom", Rows(custom));
    }

    [Fact]
    public void NeverClause()
    {
        var c = C("[{'id':'n1','kind':'never','p':{'verb':'delete'}}]");
        Assert.Equal("n1|never|pass|", Rows(Contracts.Check(Act("read"), c, St())));
        var r = "never-invariant violated (forbidden action)";
        var bad = Contracts.Check(Act("delete"), c, St());
        Assert.False(bad.Ok);
        Assert.Equal(new[] { "n1: " + r }, bad.Reasons);
        Assert.Equal("n1|never|violated|" + r, Rows(bad));
        var custom = Contracts.Check(Act("delete"), C("[{'id':'n1','kind':'never','p':{'verb':'delete'},'description':'no deletes'}]"), St());
        Assert.Equal(new[] { "n1: no deletes" }, custom.Reasons);
    }

    [Fact]
    public void PrecedesAndRequiresPriorNeedTheirPrerequisiteLatched()
    {
        foreach (var kind in new[] { "precedes", "requires_prior" })
        {
            var c = C("[{'id':'o','kind':'" + kind + "','p':{'verb':'review'},'q':{'verb':'deploy'}}]");
            var viol = Contracts.Check(Act("deploy"), c, St());
            Assert.False(viol.Ok);
            Assert.Equal(new[] { "o: " + Prec }, viol.Reasons);
            Assert.Equal("o|" + kind + "|violated|" + Prec, Rows(viol));
            Assert.Equal("o|" + kind + "|pass|", Rows(Contracts.Check(Act("review"), c, St())));
            Assert.Equal("o|" + kind + "|pass|", Rows(Contracts.Check(Act("read"), c, St())));
            Assert.Equal("o|" + kind + "|pass|", Rows(Contracts.Check(Act("deploy"), c, St("{'o':1}"))));
            Assert.Equal("o|" + kind + "|violated|" + Prec, Rows(Contracts.Check(Act("deploy"), c, St("{'zz':1}"))));
            var custom = C("[{'id':'o','kind':'" + kind + "','p':{'verb':'review'},'q':{'verb':'deploy'},'description':'review first'}]");
            Assert.Equal("o|" + kind + "|violated|review first", Rows(Contracts.Check(Act("deploy"), custom, St())));
            // one verb is both the prerequisite and the guarded action: violated until latched
            var same = C("[{'id':'o','kind':'" + kind + "','p':{'verb':'x'},'q':{'verb':'x'}}]");
            Assert.Equal("o|" + kind + "|violated|" + Prec, Rows(Contracts.Check(Act("x"), same, St())));
            Assert.Equal("o|" + kind + "|pass|", Rows(Contracts.Check(Act("x"), same, St("{'o':5}"))));
        }
    }

    [Fact]
    public void RespondsWithinChecksTheOpenDeadline()
    {
        var c = C("[{'id':'r','kind':'responds_within','p':{'verb':'alarm'},'q':{'verb':'ack'},'within':3}]");
        Assert.Equal("r|responds_within|pass|", Rows(Contracts.Check(Act("alarm"), c, St())));
        Assert.Equal("r|responds_within|pass|", Rows(Contracts.Check(Act("read"), c, St())));
        Assert.Equal("r|responds_within|pass|", Rows(Contracts.Check(Act("read"), c, St(deadlines: "{'r':2}"))));
        Assert.Equal("r|responds_within|pass|", Rows(Contracts.Check(Act("read"), c, St(deadlines: "{'other':1}"))));
        var d1 = St(deadlines: "{'r':1}");
        foreach (var verb in new[] { "read", "alarm" })
        {
            var miss = Contracts.Check(Act(verb), c, d1);
            Assert.False(miss.Ok);
            Assert.Equal(new[] { "r" }, miss.Violated);
            Assert.Equal(new[] { "r: " + Missed }, miss.Reasons);
            Assert.Equal("r|responds_within|violated|" + Missed, Rows(miss));
        }
        Assert.Equal("r|responds_within|pass|", Rows(Contracts.Check(Act("ack"), c, d1)));
        var late = C("[{'id':'r','kind':'responds_within','p':{'verb':'alarm'},'q':{'verb':'ack'},'within':3,'description':'late'}]");
        Assert.Equal("r|responds_within|violated|late", Rows(Contracts.Check(Act("read"), late, d1)));
        var two = C("[{'id':'r','kind':'responds_within','p':{'verb':'alarm'},'q':{'verb':'ack'},'within':2.0}]");
        Assert.Equal("r|responds_within|violated|bounded-liveness deadline missed (no q within 2 actions of p)", Rows(Contracts.Check(Act("read"), two, d1)));
    }

    [Fact]
    public void AnAndClauseReportsEverySubClauseInOrder()
    {
        var c = C("[{'id':'both','kind':'and','clauses':[{'id':'s1','kind':'never','p':{'verb':'read'}},{'id':'s2','kind':'precedes','p':{'verb':'review'},'q':{'verb':'deploy'}},{'id':'s3','kind':'always','p':{'verb':'deploy'}}]}]");
        var r = Contracts.Check(Act("deploy"), c, St());
        Assert.False(r.Ok);
        Assert.Equal("s1|never|pass|;s2|precedes|violated|" + Prec + ";s3|always|pass|", Rows(r));
        Assert.Equal(new[] { "s2" }, r.Violated);
        var both = Contracts.Check(Act("read"), c, St());
        Assert.Equal(new[] { "s1", "s3" }, both.Violated);
        Assert.Equal(3, both.Evaluated.Count);
    }

    // ---- fail-closed paths (injected faults) -------------------------------------------------------------------------------

    [Fact]
    public void AClauseThatFailsWhileBeingEvaluatedViolates()
    {
        // "p" is read once on insertion, once by the validation and a third time by the evaluation, which throws
        var clause = new JD(new ContractsKillProbeComparer("p", 3)) { ["id"] = "n1", ["kind"] = "never", ["p"] = M("{'verb':'x'}") };
        var contract = new JD { ["version"] = 1L, ["principal"] = "p", ["clauses"] = new JL { clause } };
        var r = Contracts.Check(Act("x"), contract, St());
        Assert.False(r.Ok);
        Assert.Equal(new[] { "n1" }, r.Violated);
        Assert.Equal(new[] { "n1: clause evaluation error (fail closed)" }, r.Reasons);
        Assert.Equal("n1|never|violated|clause evaluation error (fail closed)", Rows(r));
    }

    [Fact]
    public void AClauseWhoseSetupFailsIsReportedAsAClauseFault()
    {
        // the description is read before the evaluation proper; the monitor reports a clause-level fault for that clause
        var clause = new JD(new ContractsKillProbeComparer("description", 1)) { ["id"] = "n1", ["kind"] = "never", ["p"] = M("{'verb':'x'}") };
        var contract = new JD { ["version"] = 1L, ["principal"] = "p", ["clauses"] = new JL { clause } };
        var r = Contracts.Check(Act("read"), contract, St());
        Assert.False(r.Ok);
        Assert.Equal(new[] { "n1" }, r.Violated);
        Assert.Equal(new[] { "n1: clause evaluation error (fail closed)" }, r.Reasons);
        Assert.Equal("n1|clause|violated|clause evaluation error (fail closed)", Rows(r));
    }

    [Fact]
    public void AMonitorFaultIsAStructuralViolation()
    {
        var action = new JD(new ContractsKillProbeComparer("action", 2)) { ["action"] = M("{'verb':'x','resource':'/r'}") };
        var r = Contracts.Check(action, C("[{'id':'n1','kind':'never','p':{'verb':'delete'}}]"), St());
        Assert.False(r.Ok);
        Assert.Equal(new[] { "<monitor>" }, r.Violated);
        Assert.Equal(new[] { "<monitor>: monitor error (fail closed)" }, r.Reasons);
        Assert.Equal("<monitor>|structural|violated|monitor error (fail closed)", Rows(r));
    }

    [Fact]
    public void AnAdvanceThatFailsPartWayRefusesAndKeepsTheInputState()
    {
        var state = new JD(new ContractsKillProbeComparer("now", 2))
        {
            ["now"] = 1000L, ["seq"] = 0L, ["parent"] = null, ["ledger"] = new JD(), ["latched"] = new JD(),
        };
        var r = Contracts.Advance(state, Act("read"), C("[{'id':'n1','kind':'never','p':{'verb':'delete'}}]"));
        Assert.False(r.Ok);
        Assert.Equal("state", r.DecidedBy);
        Assert.Equal(new[] { "<state>" }, r.Violated);
        Assert.Equal(new[] { "<state>: malformed monitor state", "<state>: advance error (fail closed)" }, r.Reasons);
        Assert.Same(state, r.Next);
    }

    // ---- structural verdicts ----------------------------------------------------------------------------------------------

    [Fact]
    public void StructuralFailuresNameTheirPart()
    {
        var c = C("[{'id':'n1','kind':'never','p':{'verb':'delete'}}]");
        var badContract = Contracts.Check(Act("read"), M("{'version':2}"), St());
        Assert.Equal("<contract>|structural|violated|unsupported version 2", Rows(badContract));
        Assert.Equal(new[] { "<contract>: unsupported version 2" }, badContract.Reasons);
        var badAction = Contracts.Check(M("{'action':{'verb':'x'}}"), c, St());
        Assert.Equal("<action>|structural|violated|malformed action", Rows(badAction));
        Assert.Equal("<action>|structural|violated|malformed action", Rows(Contracts.Check(null, c, St())));
        Assert.Equal("<action>|structural|violated|malformed action", Rows(Contracts.Check(M("{'action':5}"), c, St())));
        Assert.Equal("<action>|structural|violated|malformed action", Rows(Contracts.Check(M("{'action':{'verb':'x','resource':5}}"), c, St())));
        var badState = Contracts.Check(Act("read"), c, M("{'now':1000,'seq':-1,'parent':null,'ledger':{},'latched':{}}"));
        Assert.Equal("<state>|structural|violated|malformed monitor state: seq", Rows(badState));
    }

    [Fact]
    public void AnEmbeddedConstitutionIsEvaluatedBeforeTheClauses()
    {
        var c = C("[{'id':'n1','kind':'never','p':{'verb':'x'}}]", ",'invariants':[{'id':'i1','kind':'never','when':{'verb':'x'}}]");
        var r = Contracts.Check(Act("x"), c, St());
        Assert.Equal(new[] { "i1", "n1" }, r.Violated);
        Assert.Equal(new[] { "i1", "n1" }, r.Evaluated.Select(e => e.Id).ToArray());
        Assert.Equal(new[] { "never", "never" }, r.Evaluated.Select(e => e.Kind).ToArray());
        // a violated row that carries no reason is reported as plain "violated"
        var blank = C("[]", ",'invariants':[{'id':'i1','kind':'never','when':{'verb':'x'},'description':''}]");
        var b = Contracts.Check(Act("x"), blank, St());
        Assert.False(b.Ok);
        Assert.Equal(new[] { "i1" }, b.Violated);
        Assert.Equal(new[] { "i1: violated" }, b.Reasons);
    }

    // ---- advance ----------------------------------------------------------------------------------------------------------

    static readonly string Order = "[{'id':'o','kind':'precedes','p':{'verb':'review'},'q':{'verb':'deploy'}}]";
    static readonly string Resp = "[{'id':'r','kind':'responds_within','p':{'verb':'alarm'},'q':{'verb':'ack'},'within':3}]";

    [Fact]
    public void AnAdmittedActionAdvancesTheChainAndLatchesThePrerequisite()
    {
        var c = C(Order);
        var s0 = St();
        var r = Adv(c, s0, "review");
        Assert.True(r.Ok);
        Assert.Equal("none", r.DecidedBy);
        Assert.Empty(r.Violated);
        Assert.Empty(r.Reasons);
        Assert.Equal("o|precedes|pass|", string.Join(";", r.Evaluated.Select(R)));
        Assert.Equal(1d, Nv(r.Next["seq"]));
        var latched = Latched(r);
        Assert.Equal(new[] { "o" }, latched.Keys.ToArray());
        Assert.IsType<long>(latched["o"]);
        Assert.Equal(1000L, latched["o"]);
        Assert.False(r.Next.ContainsKey("deadlines"));
        Assert.Equal(0d, Nv(s0["seq"]));
        // the guarded action is now admitted and the latch is kept, not re-stamped
        var r2 = Adv(c, r.Next, "deploy", 5000);
        Assert.True(r2.Ok);
        Assert.Equal(1000L, Latched(r2)["o"]);
        Assert.Equal(2d, Nv(r2.Next["seq"]));
    }

    [Fact]
    public void ALatchTimeIsAnIntegerWhenWholeAndKeepsItsFractionOtherwise()
    {
        var c = C(Order);
        var frac = Adv(c, St(), "review", 1000.5);
        Assert.True(frac.Ok);
        Assert.IsType<double>(Latched(frac)["o"]);
        Assert.Equal(1000.5, Latched(frac)["o"]);
        // at 9e15 the number stays a double, below it a whole number is stored as an integer
        var big = Adv(c, St(), "review", 9e15);
        Assert.True(big.Ok);
        Assert.IsType<double>(Latched(big)["o"]);
        var below = Adv(c, St(), "review", 9e15 - 1);
        Assert.True(below.Ok);
        Assert.IsType<long>(Latched(below)["o"]);
        Assert.Equal(9_000_000_000_000_000L - 1, Latched(below)["o"]);
    }

    [Fact]
    public void ResponseDeadlinesOpenCountDownAndMiss()
    {
        var c = C(Resp);
        var r1 = Adv(c, St(), "alarm");
        Assert.True(r1.Ok);
        Assert.IsType<long>(Deadlines(r1)!["r"]);
        Assert.Equal(3L, Deadlines(r1)!["r"]);
        var r2 = Adv(c, r1.Next, "read");
        Assert.Equal(2L, Deadlines(r2)!["r"]);
        var r3 = Adv(c, r2.Next, "read");
        Assert.Equal(1L, Deadlines(r3)!["r"]);
        var r4 = Adv(c, r3.Next, "read");
        Assert.False(r4.Ok);
        Assert.Equal("contract", r4.DecidedBy);
        Assert.Equal(new[] { "r" }, r4.Violated);
        Assert.Equal(new[] { "r: " + Missed }, r4.Reasons);
        Assert.Same(r3.Next, r4.Next);
        Assert.False(Adv(c, r3.Next, "alarm").Ok);
        // a response in time discharges the obligation and drops the counter
        var ack = Adv(c, r3.Next, "ack");
        Assert.True(ack.Ok);
        Assert.False(ack.Next.ContainsKey("deadlines"));
    }

    [Fact]
    public void ANewAlarmKeepsTheNearerDeadline()
    {
        var c = C(Resp);
        Assert.Equal(1L, Deadlines(Adv(c, St(deadlines: "{'r':2}"), "alarm"))!["r"]);
        Assert.Equal(3L, Deadlines(Adv(c, St(deadlines: "{'r':5}"), "alarm"))!["r"]);
        Assert.Equal(2L, Deadlines(Adv(c, St(deadlines: "{'r':3}"), "alarm"))!["r"]);
        var both = C("[{'id':'r','kind':'responds_within','p':{'verb':'x'},'q':{'verb':'x'},'within':3}]");
        Assert.Equal(3L, Deadlines(Adv(both, St(deadlines: "{'r':2}"), "x"))!["r"]);
    }

    [Fact]
    public void DeadlinesOfOtherKeysAreCarriedForward()
    {
        var c = C("[{'id':'n','kind':'never','p':{'verb':'delete'}}]");
        var r = Adv(c, St(deadlines: "{'zz':4}"), "read");
        Assert.True(r.Ok);
        Assert.Equal(new[] { "zz" }, Deadlines(r)!.Keys.ToArray());
        Assert.Equal(4d, Nv(Deadlines(r)!["zz"]));
        Assert.False(Adv(c, St(), "read").Next.ContainsKey("deadlines"));
    }

    [Fact]
    public void StaleHeadsAreRefusedAsStateWithTheClausesVerdictKept()
    {
        var c = C("[{'id':'n','kind':'never','p':{'verb':'delete'}}]");
        var s = St();
        var seq = Adv(c, s, "read", seq: 5);
        Assert.False(seq.Ok);
        Assert.Equal("state", seq.DecidedBy);
        Assert.Equal(new[] { "<state>" }, seq.Violated);
        Assert.Equal(new[] { "<state>: stale state head (seq)" }, seq.Reasons);
        Assert.Equal("n|never|pass|", string.Join(";", seq.Evaluated.Select(R)));
        Assert.Same(s, seq.Next);
        Assert.True(Adv(c, s, "read", seq: 0).Ok);
        // a clause violation and a stale head together: the clause first, the state last
        var both = Adv(c, s, "delete", seq: 5);
        Assert.Equal(new[] { "n", "<state>" }, both.Violated);
        Assert.Equal(new[] { "n: never-invariant violated (forbidden action)", "<state>: stale state head (seq)" }, both.Reasons);
        var dig = Adv(c, s, "read", digest: "bogus");
        Assert.False(dig.Ok);
        Assert.Equal(new[] { "<state>: stale state head (digest)" }, dig.Reasons);
        Assert.True(Adv(c, s, "read", digest: Prohibitions.StateDigest(s)).Ok);
        // a state that is already a structural failure is listed once
        var bad = M("{'now':1000,'seq':-1,'parent':null,'ledger':{},'latched':{}}");
        var stale = Adv(c, bad, "read", seq: 5);
        Assert.Equal(new[] { "<state>" }, stale.Violated);
        Assert.Equal(new[] { "<state>: malformed monitor state: seq", "<state>: stale state head (seq)" }, stale.Reasons);
        // an unhashable state has the placeholder digest, which is a head like any other
        var unhashable = Adv(c, bad, "read", digest: "<unhashable>");
        Assert.Equal(new[] { "<state>" }, unhashable.Violated);
        Assert.Equal(new[] { "<state>: malformed monitor state: seq" }, unhashable.Reasons);
        Assert.Equal("state", unhashable.DecidedBy);
    }

    [Fact]
    public void ABackwardsClockIsRefusedAsState()
    {
        var r = Adv(C(Order), St(), "review", 999);
        Assert.False(r.Ok);
        Assert.Equal("state", r.DecidedBy);
        Assert.Equal(new[] { "<state>" }, r.Violated);
        Assert.Equal(new[] { "<state>: advance failed: clock regression" }, r.Reasons);
    }

    [Fact]
    public void AResultingStateThatWouldBeInvalidIsRefused()
    {
        var keys = string.Join(",", Enumerable.Range(0, 1024).Select(i => "'l" + i + "':1"));
        var full = St("{" + keys + "}");
        Assert.Null(Prohibitions.StateProblem(full));
        var r = Adv(C(Order), full, "review");
        Assert.False(r.Ok);
        Assert.Equal("state", r.DecidedBy);
        Assert.Equal(new[] { "<state>" }, r.Violated);
        Assert.Equal(new[] { "<state>: resulting state invalid: malformed monitor state: too many keys" }, r.Reasons);
        Assert.Same(full, r.Next);
    }

    [Fact]
    public void WhoDecidedIsReadFromTheStructuralIds()
    {
        var c = C("[{'id':'n','kind':'never','p':{'verb':'delete'}}]");
        Assert.Equal("contract", Adv(c, St(), "delete").DecidedBy);
        Assert.Equal("state", Contracts.Advance(St(), M("{'action':{'verb':'x'}}"), c).DecidedBy);
        Assert.Equal("none", Adv(c, St(), "read").DecidedBy);
        // an id is structural only when it starts AND ends with an angle bracket
        string By(string id) => Adv(C("[{'id':'" + id + "','kind':'never','p':{'verb':'x'}}]"), St(), "x").DecidedBy;
        Assert.Equal("contract", By("<x"));
        Assert.Equal("contract", By("x>"));
        Assert.Equal("state", By("<x>"));
        // one structural id among the violated ones decides it, even next to an ordinary one
        var mixed = C("[{'id':'<x>','kind':'never','p':{'verb':'x'}},{'id':'b','kind':'never','p':{'verb':'x'}}]");
        var r = Adv(mixed, St(), "x");
        Assert.Equal(new[] { "<x>", "b" }, r.Violated);
        Assert.Equal("state", r.DecidedBy);
    }

    // ---- check and advance ------------------------------------------------------------------------------------------------

    [Fact]
    public void ANotPermittedActionIsDeniedByTheContractVerdictAndLeavesTheState()
    {
        var c = C(Order);
        var s = St();
        var (denied, allow) = Contracts.CheckAndAdvance(false, s, Act("review"), c);
        Assert.False(allow);
        Assert.False(denied.Ok);
        Assert.Equal("contract", denied.DecidedBy);
        Assert.Empty(denied.Violated);
        Assert.Equal(new[] { "<permission>: not permitted" }, denied.Reasons);
        Assert.Equal("o|precedes|pass|", string.Join(";", denied.Evaluated.Select(R)));
        Assert.Same(s, denied.Next);
        var (ok, allowed) = Contracts.CheckAndAdvance(true, s, Act("review"), c);
        Assert.True(allowed);
        Assert.True(ok.Ok);
        Assert.Equal(1d, Nv(ok.Next["seq"]));
        // a refused contract is not allowed whatever the permission says, and is not given the permission note
        var (refused, a2) = Contracts.CheckAndAdvance(true, s, Act("deploy"), c);
        Assert.False(a2);
        Assert.Equal(new[] { "o: " + Prec }, refused.Reasons);
    }
}
