using System.Text.RegularExpressions;
using static AtlasPca.PolicyBridgeKit.PbJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyBridgeKit;

/// <summary>OPA/Rego to PCA predicate translator. Models only the "allow rule as a conjunction of input comparisons" idiom and fails closed on
/// everything else: a rule with a conjunct outside the subset is dropped whole (never widened). Each allow rule is an independent predicate.</summary>
public static class Rego
{
    static readonly Regex CommentRe = Find("#[^\\n]*");
    static readonly Regex PackageRe = Find(WbL + "package" + S + "+([A-Za-z_][A-Za-z0-9_.]*)");
    static readonly Regex DefaultRe = Find(WbL + "default" + S + "+allow" + S + "*(?::?=)" + S + "*(true|false)" + WbR);

    public static D RegoToPca(string moduleText)
    {
        var report = PolicyBridge.NewReport("rego");
        var predicates = new L();
        var src = CommentRe.Replace(moduleText, "");

        var pkg = PackageRe.Match(src);
        if (pkg.Success) PolicyBridge.ListOf(report, "translated").Add("package " + pkg.Groups[1].Value);

        var def = DefaultRe.Match(src);
        if (def.Success && def.Groups[1].Value == "true")
            PolicyBridge.ListOf(report, "skipped").Add("`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny");
        else if (!def.Success)
            PolicyBridge.ListOf(report, "skipped").Add("no `default allow = false` found; assuming default-deny");

        foreach (var body in ExtractAllowBodies(src, report)) TranslateRule(body, predicates, report);
        return PolicyBridge.Result(predicates, new L(), report);
    }

    static void TranslateRule(string body, L predicates, D report)
    {
        object? verb = "*";
        string? resource = null;
        var where = new L();

        foreach (var stmt in TrimmedNonEmpty(Regex.Split(body, "[\\n;]")))
        {
            var parsed = ParseStatement(stmt);
            if (parsed.Kind == Kind.Unmodeled)
            {
                PolicyBridge.ListOf(report, "skipped").Add("unmodeled statement \"" + Truncate(stmt) + "\" — rule dropped (fail closed)");
                return;
            }
            if (parsed.Kind == Kind.Verb)
            {
                if (verb is string vs && vs == "*") verb = parsed.Verb;
                else
                {
                    var have = AsList(verb); var next = AsList(parsed.Verb); var both = new L();
                    foreach (var v in have) if (next.Any(x => Equals(x, v))) both.Add(v);
                    if (both.Count == 0)
                    {
                        PolicyBridge.ListOf(report, "translated").Add("rule can never match (contradictory action selectors), nothing emitted");
                        return;
                    }
                    verb = both.Count == 1 ? both[0] : both;
                }
            }
            else if (parsed.Kind == Kind.Resource)
            {
                if (resource != null && resource != parsed.Resource)
                {
                    PolicyBridge.ListOf(report, "translated").Add("rule can never match (contradictory resource selectors), nothing emitted");
                    return;
                }
                resource = parsed.Resource;
            }
            else where.Add(parsed.Condition);
        }

        var predicate = new D { ["verb"] = verb };
        if (resource != null) predicate["resource"] = resource;
        if (where.Count > 0) predicate["where"] = where;
        predicates.Add(predicate);
        PolicyBridge.ListOf(report, "translated").Add("allow → verb " + JsonVerb(verb) + (resource != null && resource.Length > 0 ? " on " + resource : "") + " (" + where.Count + " condition(s))");
    }

    static L AsList(object? verb) => verb is L l ? l : new L { verb };

    enum Kind { Verb, Resource, Condition, Unmodeled }

    sealed class Parsed
    {
        public Kind Kind;
        public object? Verb;
        public string? Resource;
        public D? Condition;
        public static readonly Parsed Unmodeled = new() { Kind = Kind.Unmodeled };
        public static Parsed OfVerb(object? v) => new() { Kind = Kind.Verb, Verb = v };
        public static Parsed OfResource(string r) => new() { Kind = Kind.Resource, Resource = r };
        public static Parsed Cond(D c) => new() { Kind = Kind.Condition, Condition = c };
    }

    static readonly Regex NotRe = Full("not" + S + "+([\\s\\S]+)");
    static readonly Regex UnmodeledSyntaxRe = Find(":=|" + WbL + "some" + WbR + "|" + WbL + "every" + WbR + "|\\[" + Dot + "*\\|" + Dot + "*\\]");
    static readonly Regex IndexedRe = Find(WbL + "input\\.[A-Za-z0-9_.]*\\[");
    static readonly Regex ComparisonRe = Full("(?s)(input\\.[A-Za-z0-9_.]+)" + S + "*(==|!=|<=|>=|<|>|" + WbL + "in" + WbR + ")" + S + "*(.+)");
    static readonly Regex InputPathRe = Full("input\\.[A-Za-z0-9_.]+");

    static Parsed ParseStatement(string stmt)
    {
        var s = Trim(stmt);

        var nm = NotRe.Match(s);
        if (nm.Success)
        {
            var inner = ParseStatement(Trim(nm.Groups[1].Value));
            if (inner.Kind != Kind.Condition) return Parsed.Unmodeled;
            // `not input.p == lit` is unification and stays inside the negation (an absent path makes it undefined, so the not holds); every
            // other comparison resolves its arguments first, so an absent path leaves the statement undefined.
            var c = inner.Condition!;
            if (c.GetValueOrDefault("op") is string op && op == "eq" && c.GetValueOrDefault("field") is string)
            {
                var all = new L { Obj("field", c["field"], "op", "exists") };
                if (c.GetValueOrDefault("ref") is string) all.Add(Obj("field", c["ref"], "op", "exists"));
                all.Add(c);
                return Parsed.Cond(Obj("not", Obj("all_of", all)));
            }
            return Parsed.Cond(Obj("not", c));
        }

        var builtin = ParseBuiltin(s);
        if (builtin != null) return builtin;

        if (UnmodeledSyntaxRe.IsMatch(s)) return Parsed.Unmodeled;
        if (s.IndexOf('(') >= 0) return Parsed.Unmodeled;
        if (IndexedRe.IsMatch(s)) return Parsed.Unmodeled;

        var m = ComparisonRe.Match(s);
        if (!m.Success) return Parsed.Unmodeled;
        var path = m.Groups[1].Value;
        var opTok = m.Groups[2].Value;
        var rhsRaw = Trim(m.Groups[3].Value);
        var sub = path["input.".Length..];

        if (opTok == "in")
        {
            var set = ParseSetLiteral(rhsRaw);
            if (set == null) return Parsed.Unmodeled;
            if (sub == "action")
            {
                foreach (var v in set) if (v is not string) return Parsed.Unmodeled;
                return Parsed.OfVerb(new L(set));
            }
            return Parsed.Cond(Obj("field", "env." + sub, "op", "in", "value", set));
        }

        if ((opTok == "==" || opTok == "!=") && InputPathRe.IsMatch(rhsRaw))
            return Parsed.Cond(Obj("field", "env." + sub, "op", opTok == "!=" ? "ne" : "eq", "ref", "env." + rhsRaw["input.".Length..]));

        var lit = ToLiteral(rhsRaw);
        if (ReferenceEquals(lit, NoLiteral)) return Parsed.Unmodeled;

        if (opTok == "==")
        {
            if (sub == "action" && lit is string la) return Parsed.OfVerb(la);
            if (sub == "resource" && lit is string lr) return Parsed.OfResource(lr);
            return Parsed.Cond(Obj("field", "env." + sub, "op", "eq", "value", lit));
        }
        if (opTok == "!=") return Parsed.Cond(Obj("field", "env." + sub, "op", "ne", "value", lit));

        if (lit is not Num) return Parsed.Unmodeled;
        var cmp = opTok == "<" ? "lt" : opTok == "<=" ? "lte" : opTok == ">" ? "gt" : "gte";
        return Parsed.Cond(Obj("field", "env." + sub, "op", cmp, "value", lit));
    }

    static readonly Regex StartsWithRe = Full("startswith\\(" + S + "*(input\\.[A-Za-z0-9_.]+)" + S + "*," + S + "*\"([^\"]*)\"" + S + "*\\)");
    static readonly Regex GlobRe = Full("glob\\.match\\(" + S + "*\"([^\"]*)\"" + S + "*," + S + "*(\\[" + S + "*\\]|null)" + S + "*," + S + "*(input\\.[A-Za-z0-9_.]+)" + S + "*\\)");
    static readonly Regex GlobMetaRe = Find("[\\[\\]{}]");
    static readonly Regex WildcardRe = Find("[*?\\\\]");

    /// <summary>A pure, anchored matcher builtin as a condition; null = not a builtin we model (fall through), Unmodeled = recognised but outside the subset.</summary>
    static Parsed? ParseBuiltin(string s)
    {
        var sw = StartsWithRe.Match(s);
        if (sw.Success)
        {
            var sub = sw.Groups[1].Value["input.".Length..];
            return Parsed.Cond(Obj("field", "env." + sub, "op", "prefix", "value", sw.Groups[2].Value));
        }
        var gm = GlobRe.Match(s);
        if (gm.Success)
        {
            var pattern = gm.Groups[1].Value;
            if (GlobMetaRe.IsMatch(pattern)) return Parsed.Unmodeled;
            // An EMPTY delimiter list means OPA splits on ".", so a wildcard would be cut by a dot: only `null` makes `*` span all.
            if (gm.Groups[2].Value.StartsWith('[') && WildcardRe.IsMatch(pattern)) return Parsed.Unmodeled;
            var sub = gm.Groups[3].Value["input.".Length..];
            return Parsed.Cond(Obj("field", "env." + sub, "op", "like", "value", pattern));
        }
        return null;
    }

    /// <summary>Find each <c>allow</c> rule body <c>{ ... }</c>, brace-aware (set literals inside the body use braces).</summary>
    static readonly Regex AllowRe = Find(WbL + "allow" + WbR + S + "*(?:(?::?=" + S + "*true" + WbR + "|=" + S + "*true" + WbR + "|" + WbL + "if" + WbR + ")" + S + "*)?\\{");

    static List<string> ExtractAllowBodies(string src, D report)
    {
        var bodies = new List<string>();
        int pos = 0;
        while (pos <= src.Length)
        {
            var m = AllowRe.Match(src, pos);
            if (!m.Success) break;
            int open = src.IndexOf('{', m.Index);
            int close = MatchDelim(src, open, '{', '}');
            if (close < 0)
            {
                PolicyBridge.ListOf(report, "errors").Add("unterminated `allow { ... }` block");
                break;
            }
            bodies.Add(src.Substring(open + 1, close - open - 1));
            pos = close + 1;
        }
        return bodies;
    }

    // ---- literals ----

    static readonly object NoLiteral = new();
    static readonly Regex NumberRe = Full("-?[0-9]+(?:\\.[0-9]+)?");

    static object? ToLiteral(string expr)
    {
        var s = Trim(expr);
        if (s.Length >= 2 && s[0] == '"' && s[^1] == '"' && s.IndexOf('"', 1) == s.Length - 1) return s[1..^1];
        if (s == "true") return true;
        if (s == "false") return false;
        if (NumberRe.IsMatch(s)) return Number(s);
        return NoLiteral;
    }

    /// <summary>A Rego set <c>{"a","b"}</c> or array <c>["a","b"]</c> of scalar literals; null when it is neither or an item is not a scalar.</summary>
    static L? ParseSetLiteral(string expr)
    {
        var s = Trim(expr);
        bool isSet = s.StartsWith('{') && s.EndsWith('}');
        bool isArr = s.StartsWith('[') && s.EndsWith(']');
        if (!isSet && !isArr) return null;
        var values = new L();
        foreach (var it in TrimmedNonEmpty(SplitTopLevel(Slice(s, 1, -1), ",")))
        {
            var lit = ToLiteral(it);
            if (ReferenceEquals(lit, NoLiteral)) return null;
            values.Add(lit);
        }
        return values;
    }
}
