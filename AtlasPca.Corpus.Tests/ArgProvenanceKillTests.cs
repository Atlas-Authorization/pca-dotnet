using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Mutation kills for provenance by default: token boundaries (non-ASCII included), the trusted-context shortcut and raise-only
// observations, the chain links (prev at 0, issued_at direction), the last-receipt binding (verb, resource, params), the pin lookup
// (mediator AND kid), the floor fallback of a non-sensitive action, and a hybrid post-quantum mediator key.
public class ArgProvenanceKillTests
{
    static readonly SuiteKey Key = SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)7, 32).ToArray()));
    static readonly string Session = Pca.B64u(new byte[32]);
    static readonly JD SendFacts = new() { ["effects"] = new JL { "send" }, ["traits"] = new JL { "pca.exfiltration" } };
    static readonly JD ReadFacts = new() { ["effects"] = new JL { "read" } };

    static ProvenanceRecorder Rec(SuiteKey? key = null, Func<long>? now = null) => new("m", "k1", key ?? Key, Session, now ?? (() => 1000));
    static JL Pins(params ProvMediatorPin[] p) => p.Select(x => (object?)x.ToJson()).ToList();
    static JD Send(string to) => new() { ["to"] = to, ["subject"] = "Q3 report", ["body"] = "Attached." };
    static JD Op(string verb, string resource, JD prms) => new() { ["verb"] = verb, ["resource"] = resource, ["params"] = prms };

    static ArgProvenanceDecision Decide(object? bundle, JD op, object? action = null, JL? pins = null, JL? observed = null, bool control = false) =>
        ArgProvenance.Decide(new ArgProvenanceInput
        {
            Bundle = bundle, Operation = op, Mediators = pins ?? Pins(Rec().Pin), Action = action, Observed = observed, PrincipalControl = control,
        });

    static JD PrincipalOnly(string to = "bob@acme.example", Func<long>? now = null)
    {
        var r = Rec(now: now);
        r.Principal("Email the Q3 report to bob@acme.example");
        return r.ForAction("email.send", "mail", Send(to));
    }

    static JD Receipt(JD bundle, int i) => (JD)((JL)bundle["receipts"]!)[i]!;

    [Fact]
    public void TokenBoundaries()
    {
        Assert.True(ArgProvenance.OccursAsToken("pay 120", "120"));
        Assert.False(ArgProvenance.OccursAsToken("é120", "120"));   // a non-ASCII code unit is a word character (fewer matches)
        Assert.False(ArgProvenance.OccursAsToken("120é", "120"));
        Assert.True(ArgProvenance.OccursAsToken("é 120 é", "120"));
        Assert.False(ArgProvenance.OccursAsToken("x120", "120"));
        Assert.False(ArgProvenance.OccursAsToken("120x", "120"));
        Assert.False(ArgProvenance.OccursAsToken("_120", "120"));
        Assert.True(ArgProvenance.OccursAsToken("a@x", "@x"));      // a needle that starts with a non-word character needs no boundary before
        Assert.True(ArgProvenance.OccursAsToken("x@ ", "x@"));
        Assert.True(ArgProvenance.OccursAsToken("x@y", "x@"));      // nor after when it ends with one
        Assert.True(ArgProvenance.OccursAsToken("120 x120", "120")); // the first occurrence
        Assert.True(ArgProvenance.OccursAsToken("x120 120", "120")); // a later occurrence
        Assert.False(ArgProvenance.OccursAsToken("éa", "a"));
        Assert.False(ArgProvenance.OccursAsToken("aé", "a"));
        Assert.True(ArgProvenance.OccursAsToken("é", "é"));
        Assert.False(ArgProvenance.OccursAsToken(null, "a"));
        Assert.False(ArgProvenance.OccursAsToken("a", null));
        Assert.False(ArgProvenance.OccursAsToken("a", ""));
        Assert.False(ArgProvenance.OccursAsToken("Bob", "bob"));
    }

    [Fact]
    public void TrustedContextShortcutAndObservedRaises()
    {
        // the principal's own context: a value the principal never typed is still trusted (the context is trusted)
        var b = PrincipalOnly("carol@acme.example");
        var d = Decide(b, Op("email.send", "mail", Send("carol@acme.example")), SendFacts);
        Assert.Equal(("pass", true, "trusted"), (d.Outcome, d.Verified, d.Control));
        Assert.All(d.Labels.Values, l => Assert.Equal("trusted", l));
        // a server observation raises the context: the choice and the untyped body escalate; the recipient and subject the principal
        // typed verbatim stay trusted
        var obs = new JL { new ProvObservation("web", "https://evil.example").ToJson() };
        var e = Decide(PrincipalOnly(), Op("email.send", "mail", Send("bob@acme.example")), SendFacts, observed: obs);
        Assert.Equal(("escalate", "untrusted_control_and_args", "web"), (e.Outcome, e.Code, e.Control));
        Assert.Equal(new[] { "web:https://evil.example" }, e.Path);
        Assert.Equal(("trusted", "trusted", "web"), (e.Labels["to"], e.Labels["subject"], e.Labels["body"]));
        Assert.Equal(new[] { "body" }, e.Tainted);
        // a tool observation is lower than web: joined, web wins; retrieval is a tool
        var both = new JL { new ProvObservation("retrieval", "kb").ToJson(), new ProvObservation("web", "w").ToJson() };
        Assert.Equal("web", Decide(PrincipalOnly(), Op("email.send", "mail", Send("bob@acme.example")), SendFacts, observed: both).Control);
        Assert.Equal("tool", Decide(PrincipalOnly(), Op("email.send", "mail", Send("bob@acme.example")), SendFacts, observed: new JL { both[0] }).Control);
        // a malformed observation is a deny
        Assert.Equal("malformed_config", Decide(PrincipalOnly(), Op("email.send", "mail", Send("bob@acme.example")), SendFacts, observed: new JL { new JD { ["origin"] = "principal", ["source"] = "x" } }).Code);
    }

    [Fact]
    public void ChainLinks()
    {
        var op = Op("email.send", "mail", Send("bob@acme.example"));
        var ok = PrincipalOnly();
        Assert.Equal("pass", Decide(ok, op, SendFacts).Outcome);
        // receipt 0 must have a null prev
        var b0 = PrincipalOnly();
        Receipt(b0, 0)["prev"] = Receipt(b0, 1)["content_digest"];
        Assert.Equal(("deny", "broken_chain"), (Decide(b0, op, SendFacts).Outcome, Decide(b0, op, SendFacts).Code));
        // receipt 1 must link to receipt 0
        var b1 = PrincipalOnly();
        Receipt(b1, 1)["prev"] = null;
        Assert.Equal("broken_chain", Decide(b1, op, SendFacts).Code);
        // issued_at never goes back (equal is fine: the clock above is constant)
        var b2 = PrincipalOnly();
        Receipt(b2, 1)["issued_at"] = 999L;
        var older = Decide(b2, op, SendFacts);
        Assert.Equal(("broken_chain", "receipt 1 is older than its predecessor"), (older.Code, older.Reason));
        long t = 1000;
        var later = PrincipalOnly(now: () => t++);
        Assert.Equal("pass", Decide(later, op, SendFacts).Outcome);
        // a later issued_at forged without re-signing is a bad signature, never a chain error
        var b3 = PrincipalOnly();
        Receipt(b3, 1)["issued_at"] = 5000L;
        Assert.Equal("bad_signature", Decide(b3, op, SendFacts).Code);
    }

    [Fact]
    public void LastReceiptBindsVerbResourceAndParams()
    {
        var b = PrincipalOnly();
        Assert.Equal("pass", Decide(b, Op("email.send", "mail", Send("bob@acme.example")), SendFacts).Outcome);
        Assert.Equal("unbound_action", Decide(b, Op("email.draft", "mail", Send("bob@acme.example")), SendFacts).Code);
        Assert.Equal("unbound_action", Decide(b, Op("email.send", "mail2", Send("bob@acme.example")), SendFacts).Code);
        Assert.Equal("unbound_action", Decide(b, Op("email.send", "mail", Send("eve@acme.example")), SendFacts).Code);
        Assert.Equal("unbound_action", Decide(b, Op("email.send", "mail", new JD(Send("bob@acme.example")) { ["cc"] = "x" }), SendFacts).Code);
    }

    [Fact]
    public void PinLookupNeedsMediatorAndKid()
    {
        var b = PrincipalOnly();
        var op = Op("email.send", "mail", Send("bob@acme.example"));
        var pin = Rec().Pin;
        Assert.True(Decide(b, op, SendFacts, Pins(pin)).Verified);
        foreach (var other in new[] { pin with { Kid = "k2" }, pin with { Mediator = "m2" } })
        {
            var d = Decide(b, op, SendFacts, Pins(other));
            Assert.Equal(("escalate", false, "agent"), (d.Outcome, d.Verified, d.Control));
            Assert.Equal(new[] { "unlabelled" }, d.Path);
        }
        // the matching pin is found among others; a matching pin with another key is a bad signature
        Assert.True(Decide(b, op, SendFacts, Pins(pin with { Kid = "k2" }, pin)).Verified);
        var wrongKey = pin with { Pk = EdKey.FromSeed(Enumerable.Repeat((byte)8, 32).ToArray()).Id };
        Assert.Equal("bad_signature", Decide(b, op, SendFacts, Pins(wrongKey)).Code);
    }

    [Fact]
    public void FloorFallbackOfANonSensitiveAction()
    {
        var r = Rec();
        r.Web("https://w.example", "read doc d2");
        var read = Op("docs.read", "docs", new JD { ["id"] = "d2" });
        var b = r.ForAction("docs.read", "docs", read["params"]);
        // read-only: the floor of an undeclared parameter is agent (nothing tainted), control does not matter
        var d = Decide(b, read, ReadFacts);
        Assert.Equal(("pass", false, "web"), (d.Outcome, d.Sensitive, d.Labels["id"]));
        Assert.Empty(d.Tainted);
        // the same call as an unknown action is sensitive: the floor is first_party
        var u = Decide(b, read);
        Assert.Equal(("escalate", true, "untrusted_control_and_args"), (u.Outcome, u.Sensitive, u.Code));
        Assert.Equal(new[] { "id" }, u.Tainted);
        // a declared floor wins over the fallback, per parameter
        var s = Rec();
        s.Principal("reply");
        s.Tool("t", "x");
        var b2 = s.ForAction("email.send", "mail", Send("bob@acme.example"));
        var f = Decide(b2, Op("email.send", "mail", Send("bob@acme.example")), new JD(SendFacts) { ["params"] = new JD { ["to"] = "tool" } }, control: true);
        Assert.Equal(("escalate", "untrusted_args"), (f.Outcome, f.Code));
        Assert.Equal(new[] { "body", "subject" }, f.Tainted);
    }

    [Fact]
    public void HybridPostQuantumMediatorReceipts()
    {
        var hybrid = SuiteKey.Create("hybrid-ed25519-ml-dsa-65", EdKey.FromSeed(Enumerable.Repeat((byte)5, 32).ToArray()), PqKey.Generate(Pq.Prim.MlDsa65));
        var r = Rec(hybrid);
        Assert.NotNull(r.Pin.PqPk);
        Assert.Equal(r.Pin.PqPk, r.Pin.ToJson()["pq_pk"]);
        var b = ArgProvenance.PrincipalDirect(r, "payments.send", "bank", new JD { ["iban"] = "DE89370400440532013000", ["amount"] = 120L });
        Assert.All(((JL)b["receipts"]!).Cast<JD>(), x => Assert.Equal("hybrid-ed25519-ml-dsa-65", x["alg"]));
        var op = Op("payments.send", "bank", new JD { ["iban"] = "DE89370400440532013000", ["amount"] = 120L });
        var facts = new JD { ["effects"] = new JL { "spend" }, ["traits"] = new JL { "pca.financial" } };
        var d = Decide(b, op, facts, Pins(r.Pin));
        Assert.Equal(("pass", true), (d.Outcome, d.Verified));
        // the same Ed25519 identity pinned with another ML-DSA key: the PQ half does not verify
        var otherPq = r.Pin with { PqPk = SuiteKey.Create("hybrid-ed25519-ml-dsa-65", EdKey.FromSeed(Enumerable.Repeat((byte)5, 32).ToArray()), PqKey.Generate(Pq.Prim.MlDsa65)).PqPk };
        Assert.Equal(("deny", "bad_signature"), (Decide(b, op, facts, Pins(otherPq)).Outcome, Decide(b, op, facts, Pins(otherPq)).Code));
    }
}
