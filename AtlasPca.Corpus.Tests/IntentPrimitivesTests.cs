using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Mutation kills for IntentPrimitives.cs: the primitive kinds, the verdict shapes (Result), the refusal reasons (Reason), the
/// required-suite rule and the README comparison (Mismatch): every compared member is corrupted in turn and the exact difference text is
/// asserted, and every member the comparison must NOT look at (under a deny / a failed conform / an inactive branch) is set to a wrong value.</summary>
public class IntentPrimitivesTests
{
    static string ConfDir()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var c = Path.Combine(d, "packages", "pca", "conformance");
            if (File.Exists(Path.Combine(c, "vectors.json"))) return c;
        }
        throw new InvalidOperationException("conformance dir not found");
    }

    static readonly Lazy<D> Prim = new(() =>
        (D)((D)Pca.ParseJson(File.ReadAllText(Path.Combine(ConfDir(), "vectors.json")))!)["primitives"]!);

    static IEnumerable<D> Entries(string kind) => ((L)Prim.Value[kind]!).Cast<D>();
    static object? InputOf(D e) => IntentJs.Get(e, "input_json") is string raw ? Pca.ParseJson(raw) : e["input"];
    static D Got(string kind, D e) => IntentPrimitives.Result(kind, InputOf(e))!;
    static D Copy(object? o) => (D)IntentJs.Normalize(o)!;

    /// <summary>First entry of the kind whose own verdict satisfies <paramref name="pred"/>; its input and its verdict as the expect.</summary>
    static (object? Input, D Got) Pick(string kind, Func<D, bool> pred)
    {
        foreach (var e in Entries(kind))
        {
            if (IntentJs.Get(e, "requires_suite") != null) continue;
            var input = InputOf(e);
            D g;
            try { g = IntentPrimitives.Result(kind, input)!; } catch { continue; }
            if (pred(g)) return (input, g);
        }
        throw new InvalidOperationException("no " + kind + " entry");
    }

    static string? Mm(string kind, object? input, D expect) => IntentPrimitives.Mismatch(kind, input, expect);
    static D With(D expect, string k, object? v) { var c = Copy(expect); c[k] = v; return c; }
    static string S(object? o) => o switch { true => "True", false => "False", null => "", _ => o.ToString()! };

    [Fact]
    public void KindsAreTheRunnerOrder() => Assert.Equal(new[] { "intent_schema", "intent_revocation", "intent_world", "intent_provenance", "intent_classifier",
        "intent_wb_active", "intent_map_commit", "intent_map", "intent_read_purpose" }, IntentPrimitives.Kinds);

    [Fact]
    public void UnknownKind()
    {
        Assert.Null(IntentPrimitives.Result("nope", new D()));
        Assert.Equal("unknown kind", Mm("nope", new D(), new D()));
        Assert.Null(IntentPrimitives.Reason("nope", new D()));
        Assert.Null(IntentPrimitives.Reason("intent_wb_active", new D()));
    }

    [Fact]
    public void EveryEntryMeetsItsOwnVerdictAndNothingElseIsCompared()
    {
        foreach (var kind in IntentPrimitives.Kinds)
            foreach (var e in Entries(kind))
            {
                if (IntentJs.Get(e, "requires_suite") != null) continue;
                var input = InputOf(e);
                Assert.Null(Mm(kind, input, Copy(e["expect"])));
                Assert.NotNull(IntentPrimitives.Result(kind, input));
            }
    }

    [Fact]
    public void ReasonOfEachRefusingKind()
    {
        foreach (var kind in new[] { "intent_schema", "intent_revocation", "intent_world", "intent_provenance", "intent_classifier", "intent_map" })
        {
            int refused = 0, passed = 0;
            foreach (var e in Entries(kind))
            {
                if (IntentJs.Get(e, "requires_suite") != null) continue;
                var r = IntentPrimitives.Reason(kind, InputOf(e));
                var g = Got(kind, e);
                bool ok = kind switch
                {
                    "intent_schema" => g["sig"] is true && ((D)g["conform"]!)["ok"] is true,
                    "intent_provenance" => (string)g["outcome"]! == "pass",
                    _ => g["ok"] is true,
                };
                if (ok) { Assert.Null(r); passed++; } else { Assert.NotNull(r); refused++; }
            }
            Assert.True(refused > 0 && passed > 0, kind);
        }
    }

    [Fact]
    public void Schema()
    {
        var (okIn, ok) = Pick("intent_schema", g => g["sig"] is true && ((D)g["conform"]!)["ok"] is true);
        Assert.Null(Mm("intent_schema", okIn, ok));
        Assert.Equal("sig=True", Mm("intent_schema", okIn, With(ok, "sig", false)));
        Assert.Equal("digest", Mm("intent_schema", okIn, With(ok, "digest", "zz")));
        Assert.Equal("conform.ok=True", Mm("intent_schema", okIn, With(ok, "conform", new D { ["ok"] = false })));
        // a passing conform has no code / path to compare
        Assert.Null(Mm("intent_schema", okIn, With(ok, "conform", new D { ["ok"] = true, ["code"] = "x", ["path"] = "y" })));

        var (badIn, bad) = Pick("intent_schema", g => g["sig"] is true && ((D)g["conform"]!)["ok"] is false && ((D)g["conform"]!).ContainsKey("path"));
        var bc = (D)bad["conform"]!;
        string code = (string)bc["code"]!, path = (string)bc["path"]!;
        Assert.Null(Mm("intent_schema", badIn, bad));
        Assert.Equal("conform.ok=False", Mm("intent_schema", badIn, With(bad, "conform", new D { ["ok"] = true })));
        var codeOff = Copy(bc); codeOff["code"] = "zz";
        Assert.Equal($"conform.code/path={code}/{path}", Mm("intent_schema", badIn, With(bad, "conform", codeOff)));
        var pathOff = Copy(bc); pathOff["path"] = "zz";
        Assert.Equal($"conform.code/path={code}/{path}", Mm("intent_schema", badIn, With(bad, "conform", pathOff)));

        // sig false: the digest is not compared (there is none)
        var sigOff = Pick("intent_schema", g => g["sig"] is false);
        Assert.Null(Mm("intent_schema", sigOff.Input, With(sigOff.Got, "digest", "zz")));
        Assert.Equal("sig=False", Mm("intent_schema", sigOff.Input, With(sigOff.Got, "sig", true)));
    }

    [Fact]
    public void World()
    {
        var (okIn, ok) = Pick("intent_world", g => g["ok"] is true && ((L)g["single_source"]!).Count >= 0 && ((D)g["world"]!).Count > 0);
        Assert.Null(Mm("intent_world", okIn, ok));
        Assert.Equal("ok=True", Mm("intent_world", okIn, With(ok, "ok", false)));
        Assert.Equal("world / single_source", Mm("intent_world", okIn, With(ok, "world", new D { ["x"] = new Num("1") })));
        Assert.Equal("world / single_source", Mm("intent_world", okIn, With(ok, "single_source", new L { "zz" })));
        var (badIn, bad) = Pick("intent_world", g => g["ok"] is false);
        Assert.Null(Mm("intent_world", badIn, bad));
        Assert.Null(Mm("intent_world", badIn, With(With(bad, "world", new D { ["x"] = new Num("1") }), "single_source", new L { "zz" })));
        Assert.Equal("ok=False", Mm("intent_world", badIn, With(bad, "ok", true)));
    }

    [Fact]
    public void Provenance()
    {
        var (denyIn, deny) = Pick("intent_provenance", g => (string)g["outcome"]! == "deny");
        Assert.Null(Mm("intent_provenance", denyIn, deny));
        Assert.Null(Mm("intent_provenance", denyIn, With(With(deny, "labels", new D { ["a"] = "b" }), "classes", new D { ["a"] = new L() })));
        Assert.Equal("outcome=deny", Mm("intent_provenance", denyIn, With(deny, "outcome", "pass")));

        var (qIn, q) = Pick("intent_provenance", g => (string)g["outcome"]! == "question");
        Assert.Null(Mm("intent_provenance", qIn, q));
        Assert.Equal("labels / classes", Mm("intent_provenance", qIn, With(q, "labels", new D { ["zz"] = "agent" })));
        Assert.Equal("labels / classes", Mm("intent_provenance", qIn, With(q, "classes", new D { ["zz"] = new L() })));
        Assert.Equal("friction=" + S(q["friction"]), Mm("intent_provenance", qIn, With(q, "friction", "zz")));
        Assert.Equal("outcome=question", Mm("intent_provenance", qIn, With(q, "outcome", "pass")));

        var (aIn, a) = Pick("intent_provenance", g => (string)g["outcome"]! == "pass");
        Assert.Null(Mm("intent_provenance", aIn, a));
        Assert.Null(Mm("intent_provenance", aIn, With(a, "friction", "zz"))); // friction is compared only for a question
        Assert.Equal("labels / classes", Mm("intent_provenance", aIn, With(a, "labels", new D { ["zz"] = "agent" })));
        Assert.Equal("labels / classes", Mm("intent_provenance", aIn, With(a, "classes", new D { ["zz"] = new L() })));
    }

    [Fact]
    public void Classifier()
    {
        var (okIn, ok) = Pick("intent_classifier", g => g["ok"] is true);
        Assert.Null(Mm("intent_classifier", okIn, ok));
        Assert.Equal("classes", Mm("intent_classifier", okIn, With(ok, "classes", new D { ["zz"] = "q" })));
        Assert.Equal("ok=True", Mm("intent_classifier", okIn, With(ok, "ok", false)));
        var (badIn, bad) = Pick("intent_classifier", g => g["ok"] is false);
        Assert.Null(Mm("intent_classifier", badIn, With(bad, "classes", new D { ["zz"] = "q" })));
        Assert.Equal("ok=False", Mm("intent_classifier", badIn, With(bad, "ok", true)));
    }

    [Fact]
    public void WbActive()
    {
        var (inp, g) = Pick("intent_wb_active", x => x["facts"] is true && x["provenance"] is true && x["classes"] is true);
        Assert.Null(Mm("intent_wb_active", inp, g));
        foreach (var k in new[] { "facts", "provenance", "classes" })
            Assert.Equal("active=True,True,True", Mm("intent_wb_active", inp, With(g, k, false)));
        var (inp2, g2) = Pick("intent_wb_active", x => x["facts"] is false && x["provenance"] is false && x["classes"] is false);
        foreach (var k in new[] { "facts", "provenance", "classes" })
            Assert.Equal("active=False,False,False", Mm("intent_wb_active", inp2, With(g2, k, true)));
    }

    [Fact]
    public void ReadPurpose()
    {
        var (inp, g) = Pick("intent_read_purpose", x => ((L)x["minimise"]!).Count > 0 && ((L)x["uncovered"]!).Count > 0);
        Assert.Null(Mm("intent_read_purpose", inp, g));
        var o = (string)g["outcome"]!;
        Assert.Equal("outcome=" + o, Mm("intent_read_purpose", inp, With(g, "outcome", "zz")));
        Assert.Equal("outcome=" + o, Mm("intent_read_purpose", inp, With(g, "minimise", new L())));
        Assert.Equal("outcome=" + o, Mm("intent_read_purpose", inp, With(g, "uncovered", new L())));
    }

    [Fact]
    public void MapCommit()
    {
        var (inp, g) = Pick("intent_map_commit", _ => true);
        Assert.Null(Mm("intent_map_commit", inp, g));
        Assert.Equal("map_commit=" + g["map_commit"], Mm("intent_map_commit", inp, With(g, "map_commit", "zz")));
    }

    [Fact]
    public void Map()
    {
        var (okIn, ok) = Pick("intent_map", g => g["ok"] is true);
        Assert.Null(Mm("intent_map", okIn, ok));
        Assert.Equal("cell / p_ppm", Mm("intent_map", okIn, With(ok, "cell", new L { new Num("99") })));
        Assert.Equal("cell / p_ppm", Mm("intent_map", okIn, With(ok, "p_ppm", new Num("-1"))));
        Assert.Equal("ok=True", Mm("intent_map", okIn, With(ok, "ok", false)));
        var (badIn, bad) = Pick("intent_map", g => g["ok"] is false);
        Assert.Null(Mm("intent_map", badIn, With(With(bad, "cell", new L { new Num("9") }), "p_ppm", new Num("9"))));
        Assert.Equal("ok=False", Mm("intent_map", badIn, With(bad, "ok", true)));
    }

    [Fact]
    public void RevocationUsesTheDefaultComparison()
    {
        var (okIn, ok) = Pick("intent_revocation", g => g["ok"] is true);
        Assert.Null(Mm("intent_revocation", okIn, ok));
        Assert.Equal("ok=True", Mm("intent_revocation", okIn, With(ok, "ok", false)));
        var (badIn, bad) = Pick("intent_revocation", g => g["ok"] is false);
        Assert.Equal("ok=False", Mm("intent_revocation", badIn, With(bad, "ok", true)));
    }

    [Fact]
    public void MissingRequiredSuiteRule()
    {
        Assert.Null(IntentPrimitives.MissingRequiredSuite(null));
        Assert.Null(IntentPrimitives.MissingRequiredSuite(5L));
        Assert.Null(IntentPrimitives.MissingRequiredSuite("ed25519"));
        Assert.Equal("fn-dsa-512", IntentPrimitives.MissingRequiredSuite("fn-dsa-512"));
        Assert.Null(IntentPrimitives.MissingRequiredSuite(new L { "ed25519", "ml-dsa-65" }));
        Assert.Equal("fn-dsa-512", IntentPrimitives.MissingRequiredSuite(new L { "ed25519", "fn-dsa-512", "fn-dsa-1024" }));
        Assert.Null(IntentPrimitives.MissingRequiredSuite(new L { 5L, null, "ed25519" }));
        // the first MISSING one, not the first one
        Assert.Equal("fn-dsa-1024", IntentPrimitives.MissingRequiredSuite(new L { "ed25519", "fn-dsa-1024" }));
    }

    [Fact]
    public void EntryComparison()
    {
        var (okIn, ok) = Pick("intent_schema", g => g["sig"] is true && ((D)g["conform"]!)["ok"] is true);
        // plain entry
        Assert.Null(IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = okIn, ["expect"] = ok }));
        Assert.Equal("sig=True", IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = okIn, ["expect"] = With(ok, "sig", false) }));
        // input_json wins over input
        var text = Pca.Canonicalize(okIn);
        Assert.Null(IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = new D(), ["input_json"] = text, ["expect"] = ok }));
        // reason_contains: the refusal reason must contain it; a passing primitive has no reason
        var (badIn, bad) = Pick("intent_schema", g => g["sig"] is true && ((D)g["conform"]!)["ok"] is false);
        var reason = IntentPrimitives.Reason("intent_schema", badIn)!;
        Assert.NotNull(reason);
        Assert.Null(IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = badIn, ["expect"] = With(bad, "reason_contains", reason[..3]) }));
        Assert.Equal($"reason '{reason}' does not contain ZZZ", IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = badIn, ["expect"] = With(bad, "reason_contains", "ZZZ") }));
        Assert.Equal("reason '' does not contain ZZZ", IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = okIn, ["expect"] = With(ok, "reason_contains", "ZZZ") }));
        // the verdict difference is reported first
        Assert.Equal("sig=True", IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = okIn, ["expect"] = With(With(ok, "sig", false), "reason_contains", "ZZZ") }));
        // required suite this SDK lacks: must fail with unsupported_suite, whatever else the expect says
        var plain = IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = okIn, ["expect"] = ok, ["requires_suite"] = "fn-dsa-512" });
        Assert.Equal("requires_suite fn-dsa-512: must fail with unsupported_suite ()", plain);
        var unsup = Copy(okIn);
        ((D)((D)unsup["schema"]!)["sig"]!)["alg"] = "fn-dsa-512";
        Assert.Contains("unsupported_suite", IntentPrimitives.Reason("intent_schema", unsup));
        Assert.Null(IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = unsup, ["expect"] = new D { ["sig"] = true }, ["requires_suite"] = "fn-dsa-512" }));
        Assert.Null(IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = unsup, ["expect"] = ok, ["requires_suite"] = new L { "ed25519", "fn-dsa-512" } }));
        // a refusal WITHOUT the token still fails the requirement and names the reason
        var other = Copy(okIn); other["schema"] = "x";
        Assert.Equal("requires_suite fn-dsa-512: must fail with unsupported_suite (schema is not an object)",
            IntentPrimitives.Mismatch("intent_schema", new D { ["input"] = other, ["expect"] = ok, ["requires_suite"] = "fn-dsa-512" }));
    }
}
