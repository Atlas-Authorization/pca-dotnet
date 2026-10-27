using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The pca-goal vectors (packages/pca-conformance/vectors/goal): goal digest, decision + witness for every probe, and the fn vectors
// (canon, units, polarity, meet, pep, commit, claim). An independent port of the reference semantics (the Go / Rust / Python runners
// of packages/pca-conformance/runners/goal): every vector must reproduce the recorded outcome exactly; nothing is skipped.
public class GoalVectorTests
{
    // ---- canonical form (ints as their lexeme, strings escape quote, backslash, the short \b \t \n \f \r forms and other controls as \u00xx, keys in UTF-8 order)

    internal static string Canon(object? v)
    {
        switch (v)
        {
            case null: return "null";
            case bool b: return b ? "true" : "false";
            case Num n: return n.Raw;
            case BigInteger bi: return bi.ToString();
            case int i: return i.ToString();
            case long l: return l.ToString();
            case string s:
                {
                    var o = new StringBuilder("\"");
                    foreach (var ch in s)
                    {
                        if (ch == '"') o.Append("\\\"");
                        else if (ch == '\\') o.Append("\\\\");
                        else if (ch == '\b') o.Append("\\b");
                        else if (ch == '\t') o.Append("\\t");
                        else if (ch == '\n') o.Append("\\n");
                        else if (ch == '\f') o.Append("\\f");
                        else if (ch == '\r') o.Append("\\r");
                        else if (ch < 0x20) o.Append("\\u").Append(((int)ch).ToString("x4"));
                        else o.Append(ch);
                    }
                    return o.Append('"').ToString();
                }
            case L list: return "[" + string.Join(",", list.Select(Canon)) + "]";
            case IEnumerable<string> strs: return "[" + string.Join(",", strs.Select(Canon)) + "]";
            case D d: return "{" + string.Join(",", IntentJs.SortedUtf8(d.Keys).Select(k => Canon(k) + ":" + Canon(d[k]))) + "}";
        }
        throw new InvalidOperationException("canon: " + v.GetType());
    }

    static string B64(byte[] h) => Pca.B64u(h);
    static string HashCanon(object? v) => B64(SHA256.HashData(Encoding.UTF8.GetBytes(Canon(v))));
    static string GoalDigest(object? g) => HashCanon(new D { ["d"] = "atlas-pca/goal-ir/v1", ["goal"] = g });

    // ---- accessors (a missing member of a vector is a failure, as in the reference runners)

    static string S(object? o) => (string)o!;
    static L Li(object? o) => (L)o!;
    static D Ob(object? o) => (D)o!;
    static object? Get(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;
    static BigInteger Q(object? o) => o is Num n ? BigInteger.Parse(n.Raw) : throw new InvalidCastException("not an integer: " + o);
    static bool Eq(object? a, object? b) => Canon(a) == Canon(b);
    static int ByteCmp(string a, string b) => IntentJs.CompareUtf8(a, b);

    static int B2k(bool b) => b ? 2 : 0;

    // ---- Kleene truth 0/1/2 (false / unknown / true); decisions 0/1/2 (deny / escalate / allow)

    static int EqV(D x, D y)
    {
        if (S(x["k"]) == "q") return S(y["k"]) == "q" && Eq(Ob(x["q"])["u"], Ob(y["q"])["u"]) ? B2k(Q(Ob(x["q"])["n"]) == Q(Ob(y["q"])["n"])) : 1;
        if (S(x["k"]) == "s") return S(y["k"]) == "s" ? B2k(Eq(x["s"], y["s"])) : 1;
        return 1;
    }

    static int LtV(D x, D y) =>
        S(x["k"]) == "q" && S(y["k"]) == "q" && Eq(Ob(x["q"])["u"], Ob(y["q"])["u"]) ? B2k(Q(Ob(x["q"])["n"]) < Q(Ob(y["q"])["n"])) : 1;

    static int Cmp(string op, D? x, D? y)
    {
        if (x == null || y == null) return 1;
        switch (op)
        {
            case "eq": return EqV(x, y);
            case "ne": return 2 - EqV(x, y);
            case "lt": return LtV(x, y);
            case "gte": return 2 - LtV(x, y);
            case "gt": return LtV(y, x);
            case "lte": return 2 - LtV(y, x);
        }
        int t = 1;
        if (S(y["k"]) == "set")
        {
            t = 0;
            foreach (var it in Li(y["items"])) t = Math.Max(t, EqV(x, Ob(it)));
        }
        return op == "in" ? t : 2 - t;
    }

    static D? Term(D t, D act, D h)
    {
        switch (S(t["k"]))
        {
            case "param": return Ob(act["params"]).TryGetValue(S(t["path"]), out var p) ? p as D : null;
            case "lit": return Ob(t["v"]);
        }
        return Ob(h["aggs"]).TryGetValue(S(t["bid"]), out var q) && q != null ? new D { ["k"] = "q", ["q"] = q } : null;
    }

    static int Cond(D c, D act, D h) => S(c["k"]) switch
    {
        "true" => 2,
        "cmp" => Cmp(S(c["op"]), Term(Ob(c["l"]), act, h), Term(Ob(c["r"]), act, h)),
        "and" => Math.Min(Cond(Ob(c["a"]), act, h), Cond(Ob(c["b"]), act, h)),
        "or" => Math.Max(Cond(Ob(c["a"]), act, h), Cond(Ob(c["b"]), act, h)),
        _ => 2 - Cond(Ob(c["c"]), act, h),
    };

    // ---- resource selectors, verbs, bounds

    static L PartIds(D o, D p)
    {
        var k = S(p["k"]);
        if (k == "exact") return new L { p["id"] };
        if (k == "oneof") return Li(p["ids"]);
        foreach (var r in Li(o["rels"]).Cast<D>())
            if (Eq(r["rel"], p["rel"]) && Eq(r["anchor"], p["anchor"])) return Li(r["members"]);
        return new L();
    }

    /// <summary>Null means "any resource".</summary>
    static L? Resolve(D o, D s)
    {
        var k = S(s["k"]);
        if (k == "any") return null;
        if (k != "all_of") return PartIds(o, s);
        L? acc = null;
        foreach (var p in Enumerable.Reverse(Li(s["parts"])))
        {
            var ids = PartIds(o, Ob(p));
            var cur = acc;
            acc = cur == null ? ids : new L(ids.Where(i => cur.Any(c => Eq(c, i))));
        }
        return acc;
    }

    static bool ResOk(L? p, object? r) => p == null || p.Any(x => Eq(x, r));
    static L VerbsOfClass(D o, object? cls) => new(Li(o["verbs"]).Cast<D>().Where(v => Eq(v["cls"], cls)).Select(v => v["verb"]));

    static L ProhVerbs(D o, D p)
    {
        var t = Ob(p["target"]);
        return S(t["k"]) == "verb" ? new L { t["verb"] } : VerbsOfClass(o, t["cls"]);
    }

    sealed record Sel(L Gids, L Verbs);

    static Sel LSel(D o, D b)
    {
        var s = Ob(b["sel"]);
        return S(s["k"]) == "gids" ? new Sel(Li(s["gids"]), new L()) : new Sel(new L(), VerbsOfClass(o, s["cls"]));
    }

    static bool Applies(Sel s, object? gid, object? verb) => s.Gids.Any(x => Eq(x, gid)) || s.Verbs.Any(x => Eq(x, verb));

    static BigInteger FloorDiv(BigInteger a, BigInteger b)
    {
        var q = BigInteger.DivRem(a, b, out var r);
        return r != 0 && ((r < 0) != (b < 0)) ? q - 1 : q;
    }

    static bool InScope(D b, D a, D x)
    {
        var s = Ob(b["scope"]);
        switch (S(s["k"]))
        {
            case "session": return Eq(a["sess"], x["sess"]);
            case "principal": return Eq(a["prin"], x["prin"]);
            case "org": return Eq(a["org"], x["org"]);
        }
        var ag = Li(s["agents"]);
        return ag.Any(g => Eq(g, a["agent"])) && ag.Any(g => Eq(g, x["agent"]));
    }

    static bool InWindow(D w, D a, D x)
    {
        BigInteger at = Q(a["t"]), xt = Q(x["t"]), ms = Q(w["ms"]);
        switch (S(w["k"]))
        {
            case "sliding": return at - ms < xt && xt <= at;
            case "period": return ms > 0 && FloorDiv(at - Q(w["t0"]), ms) == FloorDiv(xt - Q(w["t0"]), ms);
        }
        return true;
    }

    /// <summary>Is the bound exceeded: 2 yes, 0 no, 1 unknown.</summary>
    static int Exceeded(D b, Sel s, D a, D h)
    {
        var items = new List<D>();
        foreach (var m in Li(h["adms"]).Cast<D>())
        {
            var x = Ob(m["act"]);
            if (Applies(s, m["gid"], x["verb"]) && InScope(b, a, x) && InWindow(Ob(b["window"]), a, x)) items.Add(x);
        }
        items.Add(a);
        var cap = Q(Ob(b["cap"])["n"]);
        var agg = S(b["agg"]);
        if (agg == "count") return B2k(items.Count > cap);
        if (agg == "distinct")
        {
            var vs = new HashSet<string>(StringComparer.Ordinal);
            foreach (var x in items)
            {
                if (!Ob(x["params"]).TryGetValue(S(b["key"]), out var kv)) return 1;
                vs.Add(Canon(kv));
            }
            return B2k(vs.Count > cap);
        }
        var ns = new List<BigInteger>();
        foreach (var x in items)
        {
            var v = Term(Ob(b["value"]), x, h);
            if (v == null || S(v["k"]) != "q" || !Eq(Ob(v["q"])["u"], Ob(b["cap"])["u"])) return 1;
            ns.Add(Q(Ob(v["q"])["n"]));
        }
        return B2k((agg == "sum" ? ns.Aggregate(BigInteger.Zero, (s2, y) => s2 + y) : ns.Max()) > cap);
    }

    static int BoundDec(D b, Sel s, D a, D h)
    {
        var e = Exceeded(b, s, a, h);
        return e == 2 ? (S(b["onExceed"]) == "deny" ? 0 : 1) : e == 1 ? 1 : 2;
    }

    /// <summary>Holes drop the grants they affect (all of them when global) and are then cleared.</summary>
    static D Strip(D g)
    {
        var holes = Li(g["holes"]).Cast<D>().ToList();
        return new D(g)
        {
            ["holes"] = new L(),
            ["grants"] = new L(Li(g["grants"]).Where(x => !holes.Any(h => h.GetValueOrDefault("global") is true || Li(h["affects"]).Any(af => Eq(af, Ob(x)["gid"]))))),
        };
    }

    static int GrantDec(D g, D o, D gr, D a, D h)
    {
        bool delegOk = Q(a["depth"]) == 0 || Li(Ob(g["deleg"])["mayTouch"]).Any(x => Eq(x, gr["gid"]));
        int m = Math.Min(Math.Min(B2k(Eq(a["verb"], gr["verb"]) && delegOk), B2k(ResOk(Resolve(o, Ob(gr["res"])), a["res"]))), Cond(Ob(gr["cond"]), a, h));
        foreach (var b in Li(g["bounds"]).Cast<D>())
        {
            var s = LSel(o, b);
            if (Applies(s, gr["gid"], a["verb"])) m = Math.Min(m, BoundDec(b, s, a, h));
        }
        return m;
    }

    static D Result(string d, D? witness) => new() { ["decision"] = d, ["witness"] = witness };

    static D Decide(D goal, D o, D a, D h)
    {
        var g = Strip(goal);
        var v = Ob(g["validity"]);
        BigInteger at = Q(a["t"]), depth = Q(a["depth"]);
        int d = 2;
        if (at < Q(v["notBefore"]) || at > Q(v["notAfter"])) d = 0;
        else if (Q(v["maxIdle"]) > 0 && Q(h["last"]) >= 0 && at - Q(h["last"]) > Q(v["maxIdle"])) d = 0;
        else if (depth < 0 || depth > Q(Ob(g["deleg"])["maxDepth"])) d = 0;
        foreach (var p in Li(g["prohibits"]).Cast<D>())
        {
            int m = Math.Min(Math.Min(B2k(ProhVerbs(o, p).Any(x => Eq(x, a["verb"]))), B2k(ResOk(Resolve(o, Ob(p["res"])), a["res"]))), Cond(Ob(p["cond"]), a, h));
            d = Math.Min(d, m == 2 ? 0 : m == 1 ? 1 : 2);
        }
        foreach (var c in Li(g["escalateOn"])) d = Math.Min(d, Cond(Ob(c), a, h) == 0 ? 2 : 1);
        var grants = Li(g["grants"]).Cast<D>().ToList();
        var per = grants.Select(gr => GrantDec(g, o, gr, a, h)).ToList();
        d = Math.Min(d, per.Count > 0 ? per.Max() : 0);
        if (d != 2) return Result(d == 1 ? "escalate" : "deny", null);
        var win = grants[per.IndexOf(2)];
        var bids = new L(Li(g["bounds"]).Cast<D>().Where(b => Applies(LSel(o, b), win["gid"], a["verb"])).Select(b => b["bid"]));
        return Result("allow", new D { ["gid"] = win["gid"], ["bids"] = bids });
    }

    // ---- lowering (the policy digest)

    static string NegOp(string op) => op switch { "eq" => "ne", "ne" => "eq", "lt" => "gte", "gte" => "lt", "gt" => "lte", "lte" => "gt", "in" => "nin", "nin" => "in", _ => throw new KeyNotFoundException(op) };

    static D Nnf(D c, bool pos) => S(c["k"]) switch
    {
        "true" => new D { ["k"] = pos ? "true" : "false" },
        "cmp" => new D { ["k"] = "atom", ["op"] = pos ? S(c["op"]) : NegOp(S(c["op"])), ["l"] = c["l"], ["r"] = c["r"] },
        "and" => new D { ["k"] = pos ? "and" : "or", ["a"] = Nnf(Ob(c["a"]), pos), ["b"] = Nnf(Ob(c["b"]), pos) },
        "or" => new D { ["k"] = pos ? "or" : "and", ["a"] = Nnf(Ob(c["a"]), pos), ["b"] = Nnf(Ob(c["b"]), pos) },
        _ => Nnf(Ob(c["c"]), !pos),
    };

    static D Pat(L? p) => p == null ? new D { ["k"] = "star" } : new D { ["k"] = "set", ["ids"] = p };

    static D Lower(D o, D goal)
    {
        var g = Strip(goal);
        var ceils = new L(Li(g["bounds"]).Cast<D>().Select(b =>
        {
            var s = LSel(o, b);
            return new D
            {
                ["bid"] = b["bid"], ["selGids"] = s.Gids, ["selVerbs"] = s.Verbs, ["agg"] = b["agg"], ["value"] = b["value"], ["key"] = b["key"],
                ["window"] = b["window"], ["scope"] = b["scope"], ["cap"] = b["cap"], ["onExceed"] = b["onExceed"],
            };
        }));
        var preds = new L(Li(g["grants"]).Cast<D>().Select(x => new D { ["gid"] = x["gid"], ["verb"] = x["verb"], ["res"] = Pat(Resolve(o, Ob(x["res"]))), ["cond"] = Nnf(Ob(x["cond"]), true) }));
        var prohs = new L(Li(g["prohibits"]).Cast<D>().Select(p => new D { ["pid"] = p["pid"], ["verbs"] = ProhVerbs(o, p), ["res"] = Pat(Resolve(o, Ob(p["res"]))), ["cond"] = Nnf(Ob(p["cond"]), true) }));
        return new D
        {
            ["preds"] = preds, ["prohs"] = prohs, ["ceils"] = ceils, ["escs"] = new L(Li(g["escalateOn"]).Select(c => (object?)Nnf(Ob(c), true))),
            ["validity"] = g["validity"], ["deleg"] = g["deleg"],
        };
    }

    // ---- the fn vectors

    static readonly string[] Rank = { "deny", "escalate", "allow" };
    static string Meet(string d, string s)
    {
        int si = Array.IndexOf(Rank, s);
        return si >= 0 && si < Array.IndexOf(Rank, d) ? s : d;
    }
    static readonly string[] Model = { "env.class.", "env.prov.", "env.judge.", "env.world." };

    static List<string> Polarity(L ws)
    {
        var o = new HashSet<string>(StringComparer.Ordinal);
        void Walk(D c)
        {
            var k = S(c["k"]);
            if (k is "and" or "or") { Walk(Ob(c["a"])); Walk(Ob(c["b"])); }
            else if (k == "not") Walk(Ob(c["c"]));
            else if (k == "cmp")
                foreach (var t in new[] { Ob(c["l"]), Ob(c["r"]) })
                    if (S(t["k"]) == "param" && Model.Any(m => S(t["path"]).StartsWith(m, StringComparison.Ordinal))) o.Add(S(t["path"]));
        }
        foreach (var w in ws) Walk(Ob(w));
        return IntentJs.SortedUtf8(o);
    }

    static List<string> Units(D schema, D terms) =>
        IntentJs.SortedUtf8(terms.Keys.Where(p => !schema.ContainsKey(p) || !Eq(schema[p], terms[p])));

    static bool Pep(string d, D ctx, object? ans)
    {
        if (d == "allow") return true;
        if (d == "deny") return false;
        return ans is D a && a.Count > 0 && a["valid"] is true && new[] { "policy_digest", "action_digest", "history_head" }.All(k => Eq(a[k], ctx[k]));
    }

    static string Commit(string g, string p, string s) => B64(SHA256.HashData(Encoding.UTF8.GetBytes($"pca-goal:v3:commit:{g}:{p}:{s}")));

    static object? RunFn(D v)
    {
        var i = v["input"]; var f = S(v["fn"]);
        switch (f)
        {
            case "canon": return new D { ["canon"] = Canon(i), ["digest"] = GoalDigest(i) };
            case "units": return Units(Ob(Ob(i)["schema"]), Ob(Ob(i)["terms"]));
            case "polarity": return Polarity(Li(i));
            case "meet": return Meet(S(Ob(i)["decision"]), S(Ob(i)["signal"]));
            case "pep": return Pep(S(Ob(i)["decision"]), Ob(Ob(i)["ctx"]), Ob(i)["answer"]);
            case "commit": return new D { ["commit"] = Commit(S(Ob(i)["goal_digest"]), S(Ob(i)["policy_digest"]), S(Ob(i)["salt"])), ["opens_other_goal"] = false };
            case "claim":
                {
                    var rp = Ob(i)["replayed_ppm"];
                    return rp != null && Q(rp) < Q(Ob(i)["min_ppm"]) ? Meet(S(Ob(i)["base"]), "escalate") : S(Ob(i)["base"]);
                }
        }
        throw new InvalidOperationException("unknown fn " + f);
    }

    static List<D> Vectors()
    {
        var dir = GoalDir();
        return Directory.GetFiles(dir, "*.json").Where(f => Path.GetFileName(f) != "index.json").OrderBy(f => f, StringComparer.Ordinal)
            .Select(f => Ob(Pca.ParseJson(File.ReadAllText(f, new UTF8Encoding(false))))).ToList();
    }

    [Fact]
    public void TheCorpusHasTheDocumentedShape()
    {
        var idx = Ob(Pca.ParseJson(File.ReadAllText(Path.Combine(GoalDir(), "index.json"))));
        Assert.Equal("pca-goal-vectors/2", idx["format"]);
        var vs = Vectors();
        var counts = Ob(idx["counts"]);
        Assert.Equal(N(counts["gen"]) + N(counts["ill"]) + N(counts["w"]) + N(counts["fn"]), vs.Count);
        Assert.Equal(Li(idx["cases"]).Count, vs.Count);
        Assert.Equal(N(counts["fn"]), vs.Count(v => S(v["kind"]) == "fn"));
    }

    [Fact]
    public void GoalDigestsAndDecisionsReproduceTheReference()
    {
        var bad = new List<string>(); int n = 0, probes = 0;
        foreach (var v in Vectors())
        {
            n++;
            var id = S(v["id"]);
            if (S(v["kind"]) == "fn")
            {
                if (Canon(RunFn(v)) != Canon(v["expect"])) bad.Add(id);
                continue;
            }
            if (GoalDigest(v["goal"]) != S(v["goal_digest"])) bad.Add(id + ":goal_digest");
            if (Ob(v["compile"])["ok"] is not true) continue;
            if (HashCanon(Lower(Ob(v["ontology"]), Ob(v["goal"]))) != S(v["policy_digest"])) bad.Add(id + ":policy_digest");
            var ps = Li(v["probes"]);
            for (int i = 0; i < ps.Count; i++)
            {
                probes++;
                var p = Ob(ps[i]);
                var got = Decide(Ob(v["goal"]), Ob(v["ontology"]), Ob(p["action"]), Ob(p["history"]));
                if (Canon(got) != Canon(p["expect"])) bad.Add($"{id}#{i}");
            }
        }
        Assert.True(n >= 240 && probes > 6000, $"{n} vectors, {probes} probes");
        Assert.True(bad.Count == 0, $"{bad.Count} disagreements of {n} vectors / {probes} probes: " + string.Join(", ", bad.Take(20)));
    }

    // ---- exact outcomes of the building blocks (hand-written, independent of the corpus)

    [Fact]
    public void MeetIsTheLowerDecisionAndNeverRaises()
    {
        Assert.Equal("deny", Meet("allow", "deny"));
        Assert.Equal("escalate", Meet("allow", "escalate"));
        Assert.Equal("allow", Meet("allow", "ok"));
        Assert.Equal("deny", Meet("deny", "escalate"));
    }

    [Fact]
    public void ThreeValuedConnectivesAreKleene()
    {
        D t = new() { ["k"] = "true" };
        D u = new() { ["k"] = "cmp", ["op"] = "lt", ["l"] = new D { ["k"] = "lit", ["v"] = new D { ["k"] = "s", ["s"] = "a" } }, ["r"] = new D { ["k"] = "lit", ["v"] = new D { ["k"] = "s", ["s"] = "b" } } };
        D Not(D c) => new() { ["k"] = "not", ["c"] = c };
        D Bin(string k, D x, D y) => new() { ["k"] = k, ["a"] = x, ["b"] = y };
        var f = Not(t); var none = new D();
        int C(D c) => Cond(c, none, none);
        Assert.Equal(2, C(t)); Assert.Equal(1, C(u)); Assert.Equal(0, C(f));
        Assert.Equal(0, C(Bin("and", Bin("and", t, u), f)));
        Assert.Equal(1, C(Bin("and", t, u)));
        Assert.Equal(2, C(Bin("or", Bin("or", f, u), t)));
        Assert.Equal(1, C(Bin("or", f, u)));
        Assert.Equal(1, C(Not(u)));
    }

    [Fact]
    public void FloorDivisionRoundsTowardNegativeInfinity()
    {
        Assert.Equal(new BigInteger(-1), FloorDiv(-1, 5));
        Assert.Equal(new BigInteger(-2), FloorDiv(-6, 5));
        Assert.Equal(new BigInteger(2), FloorDiv(10, 5));
        Assert.Equal(new BigInteger(0), FloorDiv(4, 5));
    }

    [Fact]
    public void CanonEscapesOnlyQuoteBackslashAndControls()
    {
        Assert.Equal("{\"a\":[1,\"x\\\"y\\\\z\\né\"],\"b\":null}", Canon(Pca.ParseJson("{\"b\":null,\"a\":[1,\"x\\\"y\\\\z\\né\"]}")));
    }
}
