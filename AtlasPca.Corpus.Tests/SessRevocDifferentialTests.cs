using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential tests of IntentSession (rule 13: the intent_session wire member, the grant caveat, the signed session root) and
/// IntentRevocation (rule 13 step 7) against the TS reference: test-data/k042-sessrevoc-cases.json is written by
/// tools/pca-audit/java-mutate/k042-sessrevoc-oracle.mts. Every case compares the exact reason; a reason ending in
/// "(fail closed): " is compared up to that prefix (the text after it is the language's own internal-error text).</summary>
public class SessRevocDifferentialTests
{
    const string FailClosed = "(fail closed): ";

    static readonly Lazy<D> Data = new(() =>
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "test-data", "k042-sessrevoc-cases.json");
            if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "k042-sessrevoc-cases.json");
            if (File.Exists(f)) return (D)Pca.ParseJson(File.ReadAllText(f, new UTF8Encoding(false)))!;
        }
        throw new FileNotFoundException("test-data/k042-sessrevoc-cases.json");
    });

    static List<D> List(string kind) => ((L)Data.Value[kind]!).Cast<D>().ToList();
    static object? Json(object? text) => IntentJs.Normalize(Pca.ParseJson((string)text!));
    static double Dbl(object? n) => IntentJs.NumOf(n)!.Value;
    static void Same(string name, object? want, string? got)
    {
        if (want is string w && w.EndsWith(FailClosed, StringComparison.Ordinal)) { Assert.NotNull(got); Assert.True(got!.StartsWith(w, StringComparison.Ordinal), name + ": " + got); }
        else Assert.True((want as string) == got, $"{name}: want <{want}> got <{got}>");
    }

    [Fact]
    public void Wire()
    {
        var cs = List("wire"); Assert.True(cs.Count >= 60);
        foreach (var c in cs) Same("wire " + c["name"], c["reason"], IntentSession.ValidateWire(Json(c["v"])));
    }

    [Fact]
    public void Caveat()
    {
        var cs = List("caveat"); Assert.True(cs.Count >= 17);
        foreach (var c in cs) Same("caveat " + c["name"], c["reason"], IntentSession.CaveatError(Json(c["c"])));
    }

    [Fact]
    public void Root() => BigStack.Run(() =>
    {
        var cs = List("root"); Assert.True(cs.Count >= 150);
        foreach (var c in cs)
        {
            var n = (string)c["name"]!;
            var s = Json(c["s"]);
            Same("shape " + n, c["shape"], IntentSession.RootShapeError(s));
            var pins = c.ContainsKey("pq_pins") ? Json(c["pq_pins"]) : null;
            Same("verify " + n, c["verify"], IntentSession.VerifyRoot(s, pins));
        }
    });

    [Fact]
    public void Revocation()
    {
        var cs = List("rev"); Assert.True(cs.Count >= 100);
        foreach (var c in cs)
        {
            var ev = c["ev"] == null ? null : Json(c["ev"]);
            var ids = c["ids"] == null ? null : Json(c["ids"]);
            bool lastPresent = c["last"] != null;
            var last = lastPresent ? Json(c["last"]) : null;
            var got = IntentRevocation.CheckSessionRevocation(ev, c["session"] as string, Json(c["authority"]), ids as L, Dbl(c["now"]), Dbl(c["maxAge"]), c["scope"] as string, null, lastPresent, last);
            Same("rev " + c["name"], c["reason"], got);
        }
    }

    [Fact]
    public void Primitive()
    {
        var cs = List("prim"); Assert.True(cs.Count >= 27);
        foreach (var c in cs)
        {
            var input = Pca.ParseJson((string)c["text"]!); // raw spellings (1e3, 1.50): PrimitiveReason normalizes
            Same("prim " + c["name"], c["reason"], IntentRevocation.PrimitiveReason(input));
            Assert.Equal(c["reason"] == null, IntentRevocation.CheckPrimitive(input));
        }
    }
}
