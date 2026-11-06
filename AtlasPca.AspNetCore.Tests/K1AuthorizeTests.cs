using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using AtlasPca;
using Xunit;

namespace AtlasPca.AspNetCore.Tests;

// Caveat language v2 through Pca.Authorize: the K1 input is opt-in. With a K1 callback and a chain that carries no K1 caveat the
// outcome of every shared signed fixture is the outcome without it (the extra `k1_caveats` check only passes).
public class K1AuthorizeTests
{
    static readonly Dictionary<string, object?> Fix = (Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(Path.Combine(
        AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly string Aud = (string)Fix["audience"]!;
    static readonly long Now = long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture);

    static AuthorizeResult Run(Dictionary<string, object?> c, Dictionary<string, object?> s, bool k1)
    {
        var grant = (Dictionary<string, object?>)c["grant"]!;
        var o = (Dictionary<string, object?>)s["operation"]!;
        var input = new AuthorizeInput
        {
            Operation = new Operation((string)o["verb"]!, (string)o["resource"]!, o["params"]), Audience = Aud,
            ResolveGrant = r => r == (string)grant["id"]! ? grant : null, StateStore = new MemoryStateStore(),
            IsRevoked = (_, _) => (bool)s["revoked"]!, Now = Now, Plan = "single-step",
            K1 = k1 ? _ => new K1Input() : null,
        };
        return Pca.Authorize(s["pcactn"], input.WithProv());
    }

    [Fact]
    public void K1InputWithoutK1CaveatsChangesNothing()
    {
        int steps = 0;
        foreach (var c in ((List<object?>)Fix["cases"]!).Cast<Dictionary<string, object?>>())
            foreach (var s in ((List<object?>)c["steps"]!).Cast<Dictionary<string, object?>>())
            {
                var a = Run(c, s, false);
                var b = Run(c, s, true);
                Assert.True(a.Allow == b.Allow && a.Status == b.Status, $"{c["name"]}: {a.Allow}/{a.Status} vs {b.Allow}/{b.Status} with K1");
                var fa = a.Checks.Where(kv => kv.Value == "fail").Select(kv => kv.Key).OrderBy(k => k, StringComparer.Ordinal);
                var fb = b.Checks.Where(kv => kv.Value == "fail").Select(kv => kv.Key).OrderBy(k => k, StringComparer.Ordinal);
                Assert.Equal(fa, fb);
                if (b.Checks.TryGetValue("k1_caveats", out var st)) Assert.Equal("pass", st);
                steps++;
            }
        Assert.True(steps >= 35, $"only {steps} steps ran");
    }

    static Dictionary<string, object?> K1Vectors()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var f = Path.Combine(dir.FullName, "packages", "pca", "conformance", "caveat-lang-vectors.json");
            if (File.Exists(f)) return (Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(f))!;
            dir = dir.Parent;
        }
        throw new FileNotFoundException("caveat-lang-vectors.json not found");
    }

    static long Lng(object? n) => long.Parse(((Num)n!).Raw, CultureInfo.InvariantCulture);

    // consume_once_ttl against the durable store too (in-memory SQLite, shared cache, as the claim tests)
    [Fact]
    public void ConsumeOnceTtlVectorsOnSqlStore()
    {
        var table = (List<object?>)((Dictionary<string, object?>)K1Vectors()["primitives"]!)["consume_once_ttl"]!;
        Assert.True(table.Count >= 9);
        foreach (var x in table.Cast<Dictionary<string, object?>>())
        {
            using var keep = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=file:" + Guid.NewGuid().ToString("N") + "?mode=memory&cache=shared");
            keep.Open();
            var sql = new SqlStateStore(() => new Microsoft.Data.Sqlite.SqliteConnection(keep.ConnectionString));
            sql.EnsureSchema();
            var got = ((List<object?>)((Dictionary<string, object?>)x["input"]!)["steps"]!).Cast<Dictionary<string, object?>>().Select(m =>
            {
                try { return sql.ConsumeOnce((string)m["key"]!, Lng(m["retain_until"]), Lng(m["now"])) ? "true" : "false"; }
                catch (ArgumentException) { return "error"; }
            }).ToList();
            var want = ((List<object?>)((Dictionary<string, object?>)x["expect"]!)["results"]!).Cast<string>();
            Assert.True(want.SequenceEqual(got), $"{x["name"]}: [{string.Join(",", got)}]");
        }
    }

    [Fact]
    public void MiddlewareReadsDischargeHeaders()
    {
        var ctx = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        Assert.True(AtlasPca.AspNetCore.PcaMiddleware.PresentedFrom(ctx).Ok);
        Assert.Null(AtlasPca.AspNetCore.PcaMiddleware.PresentedFrom(ctx).Discharges);
        ctx.Request.Headers["pca-discharges"] = Pca.B64u(System.Text.Encoding.UTF8.GetBytes("[1]"));
        ctx.Request.Headers["PCA-Narrow"] = Pca.B64u(System.Text.Encoding.UTF8.GetBytes("{}"));
        var p = AtlasPca.AspNetCore.PcaMiddleware.PresentedFrom(ctx);
        Assert.True(p.Ok && p.Discharges!.Count == 1 && p.HasNarrow);
        ctx.Request.Headers["pca-discharges"] = "!!!!";
        Assert.False(AtlasPca.AspNetCore.PcaMiddleware.PresentedFrom(ctx).Ok);
    }
}
