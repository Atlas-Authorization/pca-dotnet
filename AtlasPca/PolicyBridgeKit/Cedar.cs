using System.Text;
using System.Text.RegularExpressions;
using static AtlasPca.PolicyBridgeKit.PbJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyBridgeKit;

/// <summary>Cedar to PCA predicate translator: <c>permit</c> / <c>forbid (principal, action, resource) [when {..}] [unless {..}];</c> units become
/// permit predicates and deny predicates over the predicate DSL. Everything outside the documented subset is reported and fails closed (a dropped
/// <c>forbid</c> is an error).</summary>
public static class Cedar
{
    /// <summary>The reflexive adjacency map (child uid to parent uids) that <c>in</c> / member_of resolves against.</summary>
    const string EntityParents = "env.entity_parents";

    /// <summary>An error of the translation (the reference's thrown Error); its message lands in the report.</summary>
    sealed class CedarError(string message) : Exception(message);

    public static D CedarToPca(string policyText) => TranslateCedar(policyText, true);

    /// <summary><paramref name="errorGuards"/> = false omits the trailing "no attribute was missing" guard (structure only; not exact).</summary>
    public static D TranslateCedar(string policyText, bool errorGuards)
    {
        var report = PolicyBridge.NewReport("cedar");
        var predicates = new L(); var denies = new L();
        var cleaned = CommentRe.Replace(policyText, "");
        foreach (var stmt in TrimmedNonEmpty(SplitTopLevel(cleaned, ";")))
        {
            try { TranslateStatement(stmt, predicates, denies, report, errorGuards); }
            catch (CedarError e) { PolicyBridge.ListOf(report, "errors").Add("policy \"" + Truncate(stmt) + "\": " + e.Message); }
            catch (InsufficientExecutionStackException) { PolicyBridge.ListOf(report, "errors").Add("policy \"" + Truncate(stmt) + "\": Maximum call stack size exceeded"); }
        }
        return PolicyBridge.Result(predicates, denies, report);
    }

    static readonly Regex CommentRe = Find("//[^\\n]*");

    // ---- statement ----

    static readonly Regex AnnotRe = Start(S + "*(?:@[A-Za-z_][A-Za-z0-9_]*" + S + "*\\([^)]*\\)" + S + "*)+");
    static readonly Regex HeadRe = Start(S + "*(" + CI("permit") + "|" + CI("forbid") + ")" + S + "*\\(");

    static void TranslateStatement(string stmt, L permits, L denies, D report, bool errorGuards)
    {
        RuntimeHelpers_EnsureSufficientStack();
        var body = stmt;
        var annot = AnnotRe.Match(body);
        if (annot.Success) body = Slice(body, annot.Length);

        var head = HeadRe.Match(body);
        if (!head.Success)
        {
            PolicyBridge.ListOf(report, "skipped").Add("unrecognized statement: \"" + Truncate(stmt) + "\"");
            return;
        }
        var effect = head.Groups[1].Value.ToLowerInvariant() == "forbid" ? "forbid" : "permit";

        int openIdx = body.IndexOf('(', head.Index);
        int closeIdx = MatchDelim(body, openIdx, '(', ')');
        if (closeIdx < 0) throw new CedarError("unterminated scope parentheses");
        var scopeText = body.Substring(openIdx + 1, closeIdx - openIdx - 1);
        var rest = body[(closeIdx + 1)..];

        var scope = ParseScope(scopeText);

        var where = new L(scope.ScopeConditions);
        var guards = new L();

        foreach (var block in ParseConditionBlocks(rest))
        {
            var parsed = ParseExpr(block.Text);
            if (parsed == null)
            {
                PolicyBridge.ListOf(report, "skipped").Add("unmodeled " + block.Kind + "-condition \"" + Truncate(block.Text) + "\" — policy dropped (fail closed)");
                DropPolicy(effect, stmt, report);
                return;
            }
            where.Add(block.Kind == "when" ? parsed : Obj("not", parsed));
            var g = NoError(parsed);
            if (g != null) guards.Add(g);
        }

        int conditionCount = where.Count;
        if (errorGuards && guards.Count > 0) where.Add(guards.Count == 1 ? guards[0] : Obj("all_of", guards));

        var predicate = new D { ["verb"] = scope.Verb };
        if (scope.Resource != null) predicate["resource"] = scope.Resource;
        if (where.Count > 0) predicate["where"] = where;

        var on = scope.Resource != null && scope.Resource.Length > 0 ? " on " + scope.Resource : "";
        if (effect == "permit")
        {
            permits.Add(predicate);
            PolicyBridge.ListOf(report, "translated").Add("permit → verb " + JsonVerb(scope.Verb) + on + " (" + conditionCount + " condition(s))");
        }
        else
        {
            denies.Add(predicate);
            PolicyBridge.ListOf(report, "translated").Add("forbid → deny verb " + JsonVerb(scope.Verb) + on + " (" + conditionCount + " condition(s))");
        }
    }

    // the reference's recursion limit ("Maximum call stack size exceeded") is reported, never a crash
    static void RuntimeHelpers_EnsureSufficientStack() => System.Runtime.CompilerServices.RuntimeHelpers.EnsureSufficientExecutionStack();

    /// <summary>A dropped permit grants nothing; a dropped forbid is unsafe, so it is an error.</summary>
    static void DropPolicy(string effect, string stmt, D report)
    {
        if (effect == "forbid")
            PolicyBridge.ListOf(report, "errors").Add("forbid could not be fully modeled and was dropped — treat result as fail-closed: \"" + Truncate(stmt) + "\"");
    }

    // ---- scope ----

    sealed class Scope
    {
        public object? Verb = "*";
        public string? Resource;
        public readonly L ScopeConditions = new();
    }

    static readonly Regex ScopeClauseRe = Full("(principal|action|resource)" + WbR + S + "*(?:(==|in|is)" + S + "*)?([\\s\\S]*)");

    static Scope ParseScope(string scopeText)
    {
        var result = new Scope();
        foreach (var clause in TrimmedNonEmpty(SplitTopLevel(scopeText, ",")))
        {
            var m = ScopeClauseRe.Match(clause);
            if (!m.Success) throw new CedarError("unparseable scope clause \"" + Truncate(clause) + "\"");
            var variable = m.Groups[1].Value;
            var op = m.Groups[2].Success ? m.Groups[2].Value : null;
            var operand = Trim(m.Groups[3].Success ? m.Groups[3].Value : "");

            if (op == null) continue;

            if (variable == "action")
            {
                if (op == "==")
                {
                    var id = EntityId(operand);
                    if (id == null) throw new CedarError("action == expects an Action entity, got \"" + Truncate(operand) + "\"");
                    result.Verb = id;
                }
                else if (op == "in" && operand.StartsWith('['))
                {
                    var verbs = new L();
                    foreach (var it in TrimmedNonEmpty(SplitTopLevel(Slice(operand, 1, -1), ",")))
                    {
                        var id = EntityId(it);
                        if (id == null) throw new CedarError("action in [...] expects Action entities, got \"" + Truncate(it) + "\"");
                        verbs.Add(id);
                    }
                    result.Verb = verbs;
                }
                else throw new CedarError("unsupported action scope operator \"" + op + "\"");
            }
            else
            {
                var field = variable == "resource" ? "action.resource" : "subject.id";
                if (op == "==")
                {
                    var eid = EntityUid(operand);
                    if (variable == "resource")
                    {
                        if (eid == null) throw new CedarError("resource == expects an entity, got \"" + Truncate(operand) + "\"");
                        result.Resource = eid;
                    }
                    else
                    {
                        if (eid == null) throw new CedarError("principal == expects an entity, got \"" + Truncate(operand) + "\"");
                        result.ScopeConditions.Add(Obj("field", field, "op", "eq", "value", eid));
                    }
                }
                else if (op == "is")
                {
                    var type = TypeName(operand);
                    if (type == null) throw new CedarError(variable + " is expects a type, got \"" + Truncate(operand) + "\"");
                    result.ScopeConditions.Add(Obj("field", field, "op", "is_a", "value", type));
                }
                else
                {
                    var mem = MemberOfCondition(field, operand);
                    if (mem == null) throw new CedarError(variable + " in expects an entity (hierarchy), got \"" + Truncate(operand) + "\"");
                    result.ScopeConditions.Add(mem);
                }
            }
        }
        return result;
    }

    // ---- conditions ----

    sealed record Block(string Kind, string Text);

    static readonly Regex BlockRe = Find(WbL + "(when|unless)" + WbR + S + "*\\{");

    static List<Block> ParseConditionBlocks(string rest)
    {
        var blocks = new List<Block>();
        int pos = 0;
        while (pos <= rest.Length)
        {
            var m = BlockRe.Match(rest, pos);
            if (!m.Success) break;
            var kind = m.Groups[1].Value == "unless" ? "unless" : "when";
            int open = rest.IndexOf('{', m.Index);
            int close = MatchDelim(rest, open, '{', '}');
            if (close < 0) throw new CedarError("unterminated " + kind + " block");
            blocks.Add(new Block(kind, rest.Substring(open + 1, close - open - 1)));
            pos = close + 1;
        }
        return blocks;
    }

    /// <summary>A boolean expression: <c>||</c> (any_of) over <c>&amp;&amp;</c> (all_of) over parentheses over comparison atoms; null if outside the subset.</summary>
    static D? ParseExpr(string text)
    {
        RuntimeHelpers_EnsureSufficientStack();
        var t = Trim(text);
        if (t.Length == 0) return null;

        var ors = TrimmedNonEmpty(SplitTopLevel(t, "||"));
        if (ors.Count > 1)
        {
            var subs = new L();
            foreach (var s in ors) { var c = ParseExpr(s); if (c == null) return null; subs.Add(c); }
            return Obj("any_of", subs);
        }
        var ands = TrimmedNonEmpty(SplitTopLevel(t, "&&"));
        if (ands.Count > 1)
        {
            var subs = new L();
            foreach (var s in ands) { var c = ParseExpr(s); if (c == null) return null; subs.Add(c); }
            return Obj("all_of", subs);
        }
        if (t.StartsWith('(') && MatchDelim(t, 0, '(', ')') == t.Length - 1) return ParseExpr(Slice(t, 1, -1));
        return ParseAtom(t);
    }

    static readonly string[][] Cmp = { new[] { "==", "eq" }, new[] { "!=", "ne" }, new[] { "<=", "lte" }, new[] { ">=", "gte" }, new[] { "<", "lt" }, new[] { ">", "gt" } };
    static readonly Regex WordOpRe = Full("([\\s\\S]*?" + NS + ")" + S + "+(in|is|like|has)" + S + "+([\\s\\S]+)");

    static D? ParseAtom(string text)
    {
        var t = Trim(text);
        foreach (var c in Cmp)
        {
            int idx = IndexOfTopLevel(t, c[0]);
            if (idx >= 0)
            {
                var lhs = Trim(t[..idx]);
                var rhs = Trim(t[(idx + c[0].Length)..]);
                return BuildComparison(lhs, c[1], rhs);
            }
        }
        var wm = WordOpRe.Match(t);
        if (wm.Success) return BuildWordOp(Trim(wm.Groups[1].Value), wm.Groups[2].Value, Trim(wm.Groups[3].Value));
        return null;
    }

    static D? BuildComparison(string lhsRaw, string op, string rhsRaw)
    {
        var field = ToFieldPath(lhsRaw);
        if (field == null) return null;
        if (field == "action.verb")
        {
            if (op != "eq" && op != "ne") return null;
            var id = EntityId(rhsRaw);
            return id == null ? null : Obj("field", field, "op", op, "value", id);
        }
        if (IsPathExpr(rhsRaw))
        {
            var refPath = ToFieldPath(rhsRaw);
            if (refPath != null) return Obj("field", field, "op", op, "ref", refPath);
        }
        var lit = ToLiteral(rhsRaw);
        if (ReferenceEquals(lit, NoLiteral)) return null;
        return Obj("field", field, "op", op, "value", lit);
    }

    static readonly Regex HasAttrRe = Full("[A-Za-z_][A-Za-z0-9_]*");

    static D? BuildWordOp(string lhsRaw, string kind, string rhsRaw)
    {
        if (kind == "has")
        {
            if (!HasAttrRe.IsMatch(rhsRaw)) return null;
            var hf = ToFieldPath(lhsRaw + "." + rhsRaw);
            return hf == null ? null : Obj("field", hf, "op", "exists");
        }

        var field = ToFieldPath(lhsRaw);
        if (field == null) return null;

        if (field == "action.verb")
        {
            if (kind != "in") return null;
            var inner = rhsRaw.StartsWith('[') && rhsRaw.EndsWith(']') ? Slice(rhsRaw, 1, -1) : rhsRaw;
            var ids = new L();
            foreach (var x in TrimmedNonEmpty(SplitTopLevel(inner, ",")))
            {
                var id = EntityId(x);
                if (id == null) return null;
                ids.Add(id);
            }
            return ids.Count > 0 ? Obj("field", field, "op", "in", "value", ids) : null;
        }

        if (kind == "is")
        {
            var type = TypeName(rhsRaw);
            return type == null ? null : Obj("field", field, "op", "is_a", "value", type);
        }

        if (kind == "like")
        {
            if (rhsRaw.Length < 2 || !rhsRaw.StartsWith('"') || !rhsRaw.EndsWith('"')) return null;
            return Obj("field", field, "op", "like", "value", CedarLikeToGlob(rhsRaw[1..^1]));
        }

        // kind == "in"
        if (rhsRaw.StartsWith('['))
        {
            var inner = rhsRaw.EndsWith(']') ? Slice(rhsRaw, 1, -1) : Slice(rhsRaw, 1);
            var items = TrimmedNonEmpty(SplitTopLevel(inner, ","));
            bool allEntities = true;
            foreach (var it in items) if (EntityUid(it) == null) { allEntities = false; break; }
            if (allEntities && items.Count > 0)
            {
                var uids = new L();
                foreach (var it in items) uids.Add(EntityUid(it));
                return Obj("field", field, "op", "member_of", "value", uids, "collection", EntityParents);
            }
            var values = new L();
            foreach (var it in items)
            {
                var lit = ToLiteral(it);
                if (ReferenceEquals(lit, NoLiteral)) return null;
                values.Add(lit);
            }
            return Obj("field", field, "op", "in", "value", values);
        }
        return MemberOfCondition(field, rhsRaw);
    }

    /// <summary>A member_of condition for <c>&lt;field&gt; in &lt;entity|path&gt;</c> (an entity literal gives a value, a path gives a ref).</summary>
    static D? MemberOfCondition(string field, string operand)
    {
        var eid = EntityUid(operand);
        if (eid != null) return Obj("field", field, "op", "member_of", "value", eid, "collection", EntityParents);
        if (IsPathExpr(operand))
        {
            var r = ToFieldPath(operand);
            if (r != null) return Obj("field", field, "op", "member_of", "ref", r, "collection", EntityParents);
        }
        return null;
    }

    static readonly Regex PathStartRe = Start("(principal|resource|action|context)" + WbR);
    static bool IsPathExpr(string expr) => PathStartRe.IsMatch(expr);

    static readonly Regex PAttrRe = Full("principal\\.([A-Za-z_][A-Za-z0-9_.]*)");
    static readonly Regex RAttrRe = Full("resource\\.([A-Za-z_][A-Za-z0-9_.]*)");
    static readonly Regex CAttrRe = Full("context\\.([A-Za-z_][A-Za-z0-9_.]*)");

    /// <summary>Map a Cedar scope-variable expression to a PCA dotted field path; null if not a path.</summary>
    static string? ToFieldPath(string expr)
    {
        if (expr == "principal") return "subject.id";
        if (expr == "resource") return "action.resource";
        if (expr == "action") return "action.verb";
        if (expr == "context") return "env";
        var mp = PAttrRe.Match(expr);
        if (mp.Success) return "subject." + mp.Groups[1].Value;
        var mr = RAttrRe.Match(expr);
        if (mr.Success) return "env.resource." + mr.Groups[1].Value;
        var mc = CAttrRe.Match(expr);
        if (mc.Success) return "env." + mc.Groups[1].Value;
        return null;
    }

    // ---- literals / entities ----

    /// <summary>A Cedar type name (<c>User</c>, <c>Ns::User</c>), or null.</summary>
    internal static string? TypeName(string expr)
    {
        var s = Trim(expr);
        int i = 0, n = s.Length;
        while (true)
        {
            if (i >= n || !IsIdentStart(s[i])) return null;
            i++;
            while (i < n && IsIdentPart(s[i])) i++;
            if (i == n) return s;
            if (i + 1 < n && s[i] == ':' && s[i + 1] == ':') { i += 2; continue; }
            return null;
        }
    }

    /// <summary>Split <c>Prefix::"id"</c> into {prefix, id}, or null (prefix at least one character, no line terminator; id without a quote).</summary>
    static string[]? EntityParts(string expr)
    {
        var s = Trim(expr);
        int n = s.Length;
        if (n < 4 || s[n - 1] != '"') return null;
        int j = s.LastIndexOf('"', n - 2);
        if (j < 3 || s[j - 1] != ':' || s[j - 2] != ':') return null;
        var prefix = s[..(j - 2)];
        foreach (var c in prefix) if (c == '\n' || c == '\r' || c == '\u2028' || c == '\u2029') return null;
        return new[] { prefix, s.Substring(j + 1, n - 1 - (j + 1)) };
    }

    /// <summary>The quoted id of an entity reference <c>Ns::Type::"id"</c>, or null.</summary>
    internal static string? EntityId(string expr) => EntityParts(expr)?[1];

    /// <summary>An entity reference rendered as its UID with quotes dropped: <c>Type::"id"</c> becomes <c>Type::id</c>.</summary>
    internal static string? EntityUid(string expr) { var p = EntityParts(expr); return p == null ? null : p[0] + "::" + p[1]; }

    static readonly object NoLiteral = new();
    static readonly Regex NumberRe = Full("-?[0-9]+(?:\\.[0-9]+)?");

    static object? ToLiteral(string expr)
    {
        var s = Trim(expr);
        if (s.Length >= 2 && s[0] == '"' && s[^1] == '"' && s.IndexOf('"', 1) == s.Length - 1) return s[1..^1];
        if (s == "true") return true;
        if (s == "false") return false;
        if (NumberRe.IsMatch(s)) return Number(s);
        var eid = EntityUid(s);
        if (eid != null) return eid;
        return NoLiteral;
    }

    /// <summary>A Cedar <c>like</c> pattern (only <c>*</c> is a wildcard; <c>\*</c> is a literal star) as the PCA glob.</summary>
    internal static string CedarLikeToGlob(string inner)
    {
        var o = new StringBuilder();
        for (int i = 0; i < inner.Length; i++)
        {
            var ch = inner[i];
            if (ch == '\\')
            {
                if (i + 1 < inner.Length)
                {
                    var n = inner[i + 1];
                    if (n == '*') { o.Append("\\*"); i++; continue; }
                    o.Append(EscapeGlobLiteral(n));
                    i++;
                    continue;
                }
                o.Append("\\\\");
                continue;
            }
            if (ch == '*') { o.Append('*'); continue; }
            o.Append(EscapeGlobLiteral(ch));
        }
        return o.ToString();
    }

    static string EscapeGlobLiteral(char ch) => ch == '*' || ch == '?' || ch == '\\' ? "\\" + ch : ch.ToString();

    // ---- Cedar evaluation-error semantics ----

    static readonly HashSet<string> TotalFields = new() { "subject.id", "action.verb", "action.resource", "env" };

    /// <summary>Attribute reads that can raise a Cedar "attribute missing" error: principal.x, resource.x, context.x.</summary>
    static List<string> GuardedPaths(string? field)
    {
        if (field == null || TotalFields.Contains(field) || field.StartsWith("env.entity_parents", StringComparison.Ordinal)) return new List<string>();
        return field.StartsWith("subject.", StringComparison.Ordinal) || field.StartsWith("env.", StringComparison.Ordinal) ? new List<string> { field } : new List<string>();
    }

    static D Exists(string field) => Obj("field", field, "op", "exists");

    static D AllOf(List<D> xs) => xs.Count == 1 ? xs[0] : Obj("all_of", new L(xs));
    static D AnyOf(List<D> xs) => xs.Count == 1 ? xs[0] : Obj("any_of", new L(xs));

    /// <summary>"Evaluating this expression raises no Cedar error", as a condition (null = it cannot). Cedar evaluates <c>&amp;&amp;</c> and <c>||</c> left to
    /// right and does not look at the right side once the left has decided, so it only needs its attributes present when the left was true (&amp;&amp;) or false (||).</summary>
    internal static D? NoError(D c)
    {
        if (c.ContainsKey("not")) return NoError((D)c["not"]!);
        if (c.ContainsKey("all_of") || c.ContainsKey("any_of"))
        {
            bool isAnd = c.ContainsKey("all_of");
            var kids = (L)(isAnd ? c["all_of"] : c["any_of"])!;
            D? acc = null;
            for (int i = kids.Count - 1; i >= 0; i--)
            {
                var kid = (D)kids[i]!;
                var n = NoError(kid);
                D? cont = acc == null ? null : AnyOf(new List<D> { isAnd ? Obj("not", kid) : kid, acc });
                acc = n == null ? cont : cont == null ? n : AllOf(new List<D> { n, cont });
            }
            return acc;
        }
        var field = c.GetValueOrDefault("field") as string;
        var rf = c.GetValueOrDefault("ref") as string;
        if (c.GetValueOrDefault("op") is string op && op == "exists" && field != null)
        {
            int k = field.LastIndexOf('.');
            var bas = k >= 0 && k < field.Length - 1 ? field[..k] : field;
            int parts = 1;
            foreach (var ch in bas) if (ch == '.') parts++;
            bool deep = parts >= (bas.StartsWith("env.resource", StringComparison.Ordinal) ? 3 : 2);
            var baseNeeds = new List<D>();
            if (deep) foreach (var p in GuardedPaths(bas)) baseNeeds.Add(Exists(p));
            return baseNeeds.Count == 0 ? null : AllOf(baseNeeds);
        }
        var needs = new List<D>();
        foreach (var p in GuardedPaths(field)) needs.Add(Exists(p));
        foreach (var p in GuardedPaths(rf)) needs.Add(Exists(p));
        return needs.Count == 0 ? null : AllOf(needs);
    }
}
