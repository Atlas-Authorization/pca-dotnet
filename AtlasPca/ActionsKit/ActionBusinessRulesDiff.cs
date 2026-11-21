// The semantic diff of two rules blocks (widening needs a reviewer) and the reviewer's signature over a widened rules block.
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static partial class ActionBusinessRules
{
    static string SetRelR(IEnumerable<string> a, IEnumerable<string> b)
    {
        var A = new HashSet<string>(a); var B = new HashSet<string>(b);
        var aInB = A.IsSubsetOf(B); var bInA = B.IsSubsetOf(A);
        return aInB && bInA ? "eq" : bInA ? "narrow" : aInB ? "widen" : "inc";
    }

    static string NumRel(double a, double b) => a == b ? "eq" : b < a ? "narrow" : "widen";

    static readonly object Undef = JsX.Undef;
    static object? Gu(D x, string k) => x.TryGetValue(k, out var v) ? v : Undef;

    static string? Presence(object? a, object? b) => ReferenceEquals(a, Undef) && ReferenceEquals(b, Undef) ? "eq" : ReferenceEquals(a, Undef) ? "narrow" : ReferenceEquals(b, Undef) ? "widen" : null;

    static string Combine(IEnumerable<string> rs)
    {
        var l = rs.ToList();
        return l.Contains("inc") || (l.Contains("narrow") && l.Contains("widen")) ? "inc" : l.Contains("widen") ? "widen" : l.Contains("narrow") ? "narrow" : "eq";
    }

    static string Flip(string r) => r == "narrow" ? "widen" : r == "widen" ? "narrow" : r;

    static HashSet<int> MinutesOfWeek(D h)
    {
        var s = new HashSet<int>();
        int frm = Mins((string)h["from"]!), to = Mins((string)h["to"]!);
        foreach (var day in Ak.Strs(h["days"]))
        {
            var b = Array.IndexOf(RuleDays, day) * 1440;
            if (frm < to) for (int x = frm; x < to; x++) s.Add(b + x);
            else if (frm > to)
            {
                for (int x = frm; x < 1440; x++) s.Add(b + x);
                for (int x = 0; x < to; x++) s.Add((b + 1440) % 10080 + x);
            }
        }
        return s;
    }

    static string AsStr(object? v) => v is string s ? s : "";

    /// <summary>The semantic diff of two rules blocks of one action (either may be absent): {class, reasons}. Conservative: unordered is incomparable.</summary>
    public static D DiffBusinessRules(D d, object? prev, object? nxt)
    {
        var o = Truthy(prev) ? (D)prev! : new D();
        var n = Truthy(nxt) ? (D)nxt! : new D();
        var usesMoney = UsesMoney(o) || UsesMoney(n);
        var m = usesMoney ? MoneyOf(d) : null;
        var rels = new List<(string, string)>();

        string CcyMapRel(D a, D b)
        {
            var rs = new List<string> { SetRelR(a.Keys, b.Keys) };
            foreach (var (c, av) in a) if (b.TryGetValue(c, out var bv)) rs.Add(NumRel(MinorUnits(av, ExpOf(m!.Exp), c), MinorUnits(bv, ExpOf(m!.Exp), c)));
            return Combine(rs);
        }

        var p = Presence(Gu(o, "amount"), Gu(n, "amount"));
        rels.Add(("amount", p ?? CcyMapRel((D)((D)o["amount"]!)["max"]!, (D)((D)n["amount"]!)["max"]!)));
        p = Presence(Gu(o, "approval"), Gu(n, "approval"));
        if (p == null)
        {
            var a = (D)o["approval"]!; var b = (D)n["approval"]!;
            var rs = new List<string>();
            if (Truthy(Ak.G(a, "always")) && Truthy(Ak.G(b, "always"))) rs.Add("eq");
            else if (Truthy(Ak.G(a, "always"))) rs.Add("widen");
            else if (Truthy(Ak.G(b, "always"))) rs.Add("narrow");
            else rs.Add(CcyMapRel((D)a["above"]!, (D)b["above"]!));
            rs.Add(NumRel(-(Ak.G(a, "approvers") != null ? Num(a["approvers"]) : 1), -(Ak.G(b, "approvers") != null ? Num(b["approvers"]) : 1)));
            rs.Add(JsX.StrictEq(Gu(a, "group"), Gu(b, "group")) ? "eq" : "inc");
            p = Combine(rs);
        }
        rels.Add(("approval", p));

        string SKey(object? so) => $"{(Ak.G(so, "param") is string ps ? ps : "")}|{(Ak.G(so, "role") is string rl ? rl : "")}|{Ak.JsStr(Ak.G(so, "caller"))}";
        rels.Add(("scope", Flip(SetRelR(Ak.Lst(o, "scope").Select(SKey), Ak.Lst(n, "scope").Select(SKey)))));

        Dictionary<string, double> Best(object? rs)
        {
            var mp = new Dictionary<string, double>();
            if (rs is L l)
                foreach (var xo in l)
                {
                    var x = (D)xo!;
                    var k = $"{x["per"]}|{(Truthy(Ak.G(x, "by")) ? (string)x["by"]! : "principal")}";
                    mp[k] = Math.Min(mp.GetValueOrDefault(k, double.PositiveInfinity), Num(x["max"]));
                }
            return mp;
        }
        var A = Best(Ak.G(o, "rate")); var B = Best(Ak.G(n, "rate"));
        var rr = new List<string>();
        foreach (var k in A.Keys.Concat(B.Keys.Where(kk => !A.ContainsKey(kk))))
            rr.Add(!A.ContainsKey(k) ? "narrow" : !B.ContainsKey(k) ? "widen" : NumRel(A[k], B[k]));
        rels.Add(("rate", Combine(rr)));

        p = Presence(Gu(o, "hours"), Gu(n, "hours"));
        if (p == null)
        {
            var a = (D)o["hours"]!; var b = (D)n["hours"]!;
            if (!JsX.StrictEq(a["tz"], b["tz"])) p = "inc";
            else
            {
                var sa = MinutesOfWeek(a); var sb = MinutesOfWeek(b);
                var inner = sa.SetEquals(sb) ? "eq" : sb.IsSubsetOf(sa) ? "narrow" : sa.IsSubsetOf(sb) ? "widen" : "inc";
                p = Combine(new[] { inner, NumRel(Ak.S(a, "outside") == "deny" ? 0 : 1, Ak.S(b, "outside") == "deny" ? 0 : 1) });
            }
        }
        rels.Add(("hours", p));

        p = Presence(Gu(o, "recipients"), Gu(n, "recipients"));
        if (p == null)
        {
            var a = (D)o["recipients"]!; var b = (D)n["recipients"]!;
            if (!SameOpt(a, b, "param") || !SameOpt(a, b, "role")) p = "inc";
            else
            {
                var allowedA = Ak.Strs(Ak.G(a, "domains")).Select(x => "@" + x).Concat(Ak.Strs(Ak.G(a, "addresses"))).ToList();
                var allowedB = Ak.Strs(Ak.G(b, "domains")).Select(x => "@" + x).Concat(Ak.Strs(Ak.G(b, "addresses"))).ToList();
                bool Covered(string x, List<string> st) => st.Contains(x) || (!x.StartsWith("@", StringComparison.Ordinal) && st.Contains("@" + x.Split('@')[1]));
                var bInA = allowedB.All(x => Covered(x, allowedA)); var aInB = allowedA.All(x => Covered(x, allowedB));
                p = bInA && aInB ? "eq" : bInA ? "narrow" : aInB ? "widen" : "inc";
            }
        }
        rels.Add(("recipients", p));
        rels.Add(("required", Flip(SetRelR(Ak.Strs(Ak.G(o, "required")), Ak.Strs(Ak.G(n, "required"))))));

        var diffs = rels.Where(x => x.Item2 != "eq").ToList();
        var reasons = diffs.Select(x => $"rules.{x.Item1}: {(x.Item2 == "inc" ? "incomparable" : x.Item2)}").OrderBy(s => s, StringComparer.Ordinal).ToList();
        var cls = Combine(diffs.Select(x => x.Item2));
        return new D { ["class"] = cls == "eq" ? "equal" : cls == "inc" ? "incomparable" : cls, ["reasons"] = Ak.ToL(reasons) };
    }

    static bool SameOpt(D a, D b, string k) => !a.ContainsKey(k) || !b.ContainsKey(k) ? !a.ContainsKey(k) && !b.ContainsKey(k) : IntentJs.JsonEquals(a[k], b[k]);

    // ---- the reviewer's signature over a widened rules block
    public static byte[] RulesReviewMessage(D b) => IntentJs.Message(RulesReviewDomain + "\0", new D
    {
        ["verb"] = b["verb"], ["def_digest"] = b["def_digest"], ["rules_digest"] = b["rules_digest"], ["reviewer_kid"] = b["reviewer_kid"], ["ts"] = b["ts"],
    });

    public static D SignRulesReview(D b, byte[] secret)
    {
        var o = new D(b);
        o["sig"] = Pca.B64u(EdKey.FromSeed(secret).Sign(RulesReviewMessage(b)));
        return o;
    }

    /// <summary>Null iff <paramref name="r"/> is a valid review of exactly these rules on exactly this def (digests, pinned reviewer key, validity, signature). Never throws.</summary>
    public static string? RulesReviewError(object? r, D d, object? rules, object? pins)
    {
        try
        {
            if (pins == null) return "no reviewer keys are pinned";
            var pe = Actions.ReviewerPinsError(pins);
            if (pe != null) return "bad pins: " + pe;
            if (r is not D rd) return "no rules review";
            if (!JsX.StrictEq(Ak.G(rd, "verb"), d["verb"])) return "the rules review names another action";
            if (!JsX.StrictEq(Ak.G(rd, "def_digest"), Actions.DefDigest(d))) return "the rules review covers another version of the action";
            if (!JsX.StrictEq(Ak.G(rd, "rules_digest"), BusinessRulesDigest((string)d["verb"]!, (D)rules!))) return "the rules review covers other rules";
            var ts = Ak.G(rd, "ts");
            if (Ak.G(rd, "sig") is not string sig || Ak.G(rd, "reviewer_kid") is not string kid || !Isi(ts) || NegZero(ts)) return "malformed rules review";
            var key = ((L)((D)pins)["keys"]!).Select(k => (D)k!).FirstOrDefault(k => (string?)k["kid"] == kid);
            if (key == null) return $"no pinned key '{kid}'";
            if (!((L)key["roles"]!).Contains("reviewer")) return $"key '{key["kid"]}' does not hold the reviewer role";
            if ((Ak.G(key, "not_before") != null && Num(ts) < Num(key["not_before"])) || (Ak.G(key, "not_after") != null && Num(ts) > Num(key["not_after"]))) return "the review time is outside the key validity";
            var body = new D(rd); body.Remove("sig");
            return IntentJs.VerifyEd(key["pk"], RulesReviewMessage(body), sig) ? null : "the rules review signature is invalid";
        }
        catch (Exception e) { return "malformed rules review: " + e.Message; }
    }
}
