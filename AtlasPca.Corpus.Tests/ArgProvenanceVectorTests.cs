using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Provenance by default, replaying packages/pca/conformance/arg-provenance-vectors.json (a missing file fails): token boundaries,
// leaves, read-only facts and every decision (full equality; a deny compares everything but its reason text, which must be non-empty).
// The recorder reproduces the vector bundles byte for byte under the generator's fixed key, session and clock.
public class ArgProvenanceVectorTests
{
    static readonly JD Doc = Load("arg-provenance-vectors.json");
    static JD Decision(string name) => L(Doc["decisions"]).Select(D).First(c => (string)c["name"]! == name);

    static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/arg-provenance/" + label));
    const long VectorNow = 1793188800000; // Date.UTC(2026, 9, 28, 12, 0, 0)
    internal static ProvenanceRecorder VectorRecorder() =>
        new("assistant-harness", "k1", SuiteKey.Ed25519(EdKey.FromSeed(Seed("key/harness"))), Pca.B64u(Seed("session/harness")), () => VectorNow);

    internal static ArgProvenanceDecision Run(JD input) => ArgProvenance.Decide(new ArgProvenanceInput
    {
        Bundle = input.GetValueOrDefault("bundle"), Operation = input.GetValueOrDefault("operation"), Mediators = input.GetValueOrDefault("mediators"),
        Action = input.GetValueOrDefault("action"), PrincipalPlan = input.GetValueOrDefault("principal_plan") is true,
        PrincipalControl = input.GetValueOrDefault("principal_control") is true, Observed = input.GetValueOrDefault("observed"),
    });

    [Fact]
    public void FormatAndThePin()
    {
        Assert.Equal("pca-arg-provenance-vectors/1", Doc["format"]);
        Assert.Equal(Pca.Canonicalize(Doc["pin"]), Pca.Canonicalize(VectorRecorder().Pin.ToJson()));
    }

    [Fact]
    public void Tokens()
    {
        Assert.True(L(Doc["tokens"]).Count >= 18);
        foreach (var t in L(Doc["tokens"]).Select(D))
            Assert.True(ArgProvenance.OccursAsToken((string)t["text"]!, (string)t["needle"]!) == (bool)t["expect"]!, $"token '{t["needle"]}' in '{t["text"]}'");
    }

    [Fact]
    public void Leaves()
    {
        Assert.True(L(Doc["leaves"]).Count >= 11);
        foreach (var l in L(Doc["leaves"]).Select(D))
        {
            var got = ArgProvenance.Leaves(l["value"]);
            if (l["expect"] == null) Assert.True(got == null, $"leaves {l["name"]}: expected null");
            else Assert.True(got != null && L(l["expect"]).Select(x => (string)x!).SequenceEqual(got), $"leaves {l["name"]}");
        }
    }

    [Fact]
    public void ReadOnly()
    {
        Assert.True(L(Doc["read_only"]).Count >= 7);
        foreach (var r in L(Doc["read_only"]).Select(D))
            Assert.True(ArgProvenance.IsReadOnlyAction(r["action"]) == (bool)r["expect"]!, $"read-only {r["name"]}");
    }

    [Fact]
    public void Decisions()
    {
        var cases = L(Doc["decisions"]).Select(D).ToList();
        Assert.True(cases.Count >= 38);
        var outcomes = new HashSet<string>();
        var codes = new HashSet<string>();
        foreach (var c in cases)
        {
            var e = D(c["expect"]);
            var got = Run(D(c["input"])).ToJson();
            outcomes.Add((string)got["outcome"]!);
            if (got.GetValueOrDefault("code") is string code) codes.Add(code);
            if ((string)e["outcome"]! == "deny")
            {
                Assert.True(got["reason"] is string { Length: > 0 }, $"decision {c["name"]}: a deny needs a reason");
                got.Remove("reason");
                e = new JD(e);
                e.Remove("reason");
            }
            Assert.True(Pca.Canonicalize(e) == Pca.Canonicalize(got), $"decision {c["name"]}: {Pca.Canonicalize(got)}");
        }
        Assert.True(outcomes.SetEquals(new[] { "pass", "escalate", "deny" }), string.Join(",", outcomes));
        foreach (var k in new[] { "untrusted_control", "untrusted_args", "untrusted_control_and_args", "malformed_bundle", "broken_chain", "bad_signature", "unbound_action", "content_mismatch", "malformed_action", "malformed_config" })
            Assert.Contains(k, codes);
    }

    // ---- the recorder, byte for byte

    [Fact]
    public void RecorderReproducesThePrincipalDirectBundle()
    {
        var b = ArgProvenance.PrincipalDirect(VectorRecorder(), "payments.send", "bank", new JD { ["iban"] = "DE89370400440532013000", ["amount"] = 120L });
        Assert.Equal(Pca.Canonicalize(D(Decision("principal-direct")["input"])["bundle"]), Pca.Canonicalize(b));
    }

    [Fact]
    public void RecorderReproducesThePrincipalOnlyBundleAndItRoundTrips()
    {
        var r = VectorRecorder();
        r.Principal("Email the Q3 report to bob@acme.example");
        var op = new JD { ["to"] = "bob@acme.example", ["subject"] = "Q3 report", ["body"] = "Attached." };
        var b = r.ForAction("email.send", "mail", op);
        var input = D(Decision("principal-only")["input"]);
        Assert.Equal(Pca.Canonicalize(input["bundle"]), Pca.Canonicalize(b));
        Assert.Equal(2, r.Receipts().Count);
        // through the header and back: the same decision as the vector's
        var (read, unreadable) = ArgProvenance.ReadBundle(ProvenanceRecorder.HeaderValue(b), null);
        Assert.False(unreadable);
        var replay = new JD(input) { ["bundle"] = read };
        Assert.Equal(Pca.Canonicalize(D(Decision("principal-only")["expect"])), Pca.Canonicalize(Run(replay).ToJson()));
        // and through the body member
        var (fromBody, _) = ArgProvenance.ReadBundle(null, Pca.Canonicalize(new JD { ["x"] = 1L, [ArgProvenance.BodyMember] = b }));
        Assert.Equal(Pca.Canonicalize(b), Pca.Canonicalize(fromBody));
    }
}
