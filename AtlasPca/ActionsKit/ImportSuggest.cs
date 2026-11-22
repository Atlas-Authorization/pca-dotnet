// The deterministic suggestion layer: a versioned rule set proposes traits, param roles and param tags for a draft def. Union only: a suggestion can ADD a
// trait, a role (to a param that has none) or a tag, never remove or replace anything, and it never marks a def confirmed. A suggested def is still
// pca.unreviewed for floor purposes until a pinned reviewer signs it. Defs, rule sets and suggestions are JSON trees.
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using static AtlasPca.ActionsKit.ImportCommon;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ImportSuggest
{
    public const string SuggestRulesKind = "pca-suggest-rules";
    public const string SuggestRulesDomain = "atlas-pca/suggest-rules/v1";

    static Regex Full(string p) => new("\\A(?:" + p + ")\\z", RegexOptions.CultureInvariant);
    static readonly Regex RuleIdRe = Full("SR-[0-9]{3,4}");
    static readonly Regex VersionRe = Full("[0-9]+\\.[0-9]+\\.[0-9]+");
    static readonly Regex TraitIdRe = Full("[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,63}");
    static readonly string[] MatchKeys = { "methods", "path_re", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_types", "param_formats", "roles", "effects" };
    static readonly string[] ParamTags = { "pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql" };
    static readonly string[] ParamTypes = { "string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref" };
    const int MaxRules = 1024;
    const int MaxList = 64;
    // a group that holds a quantifier or an alternation, followed by another quantifier: the shapes that backtrack exponentially
    static readonly Regex NestedQuantifier = new("\\([^)]*[+*][^)]*\\)[+*{]|\\([^)]*\\|[^)]*\\)[+*{]", RegexOptions.CultureInvariant);
    static readonly Regex Backref = new("\\\\[1-9]", RegexOptions.CultureInvariant);
    static readonly Regex Lookaround = new("\\(\\?[<=!]", RegexOptions.CultureInvariant);

    static bool IsStrList(object? v, int max)
    {
        if (v is not L l) return false;
        if (l.Count == 0 || l.Count > max) return false;
        foreach (var x in l) if (x is not string s || s.Length == 0 || s.Length > 64) return false;
        return true;
    }

    // ---- JavaScript regular expression to a .NET pattern (the bounded subset the rules use) ----

    const string JsSpaceClass = "\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF";
    const string WordClass = "a-zA-Z0-9_";
    const string WordBoundary = "(?:(?<=[a-zA-Z0-9_])(?![a-zA-Z0-9_])|(?<![a-zA-Z0-9_])(?=[a-zA-Z0-9_]))";
    const string NotWordBoundary = "(?:(?<=[a-zA-Z0-9_])(?=[a-zA-Z0-9_])|(?<![a-zA-Z0-9_])(?![a-zA-Z0-9_]))";

    static bool Hex(string s, int from, int n)
    {
        if (from + n > s.Length) return false;
        for (int i = from; i < from + n; i++) if (!char.IsAsciiHexDigit(s[i])) return false;
        return true;
    }

    /// <summary>The end of a {n}, {n,} or {n,m} quantifier starting at i, or -1.</summary>
    static int QuantEnd(string s, int i)
    {
        int j = i + 1, d = 0;
        while (j < s.Length && s[j] >= '0' && s[j] <= '9') { j++; d++; }
        if (d == 0) return -1;
        if (j < s.Length && s[j] == ',') { j++; while (j < s.Length && s[j] >= '0' && s[j] <= '9') j++; }
        return j < s.Length && s[j] == '}' ? j + 1 : -1;
    }

    /// <summary>Compile a JavaScript pattern (no flags); an ArgumentException where the engine would raise SyntaxError.</summary>
    internal static Regex JsRegex(string s)
    {
        var o = new StringBuilder();
        int n = s.Length, i = 0, depth = 0;
        bool inClass = false, canQuant = false;
        while (i < n)
        {
            char c = s[i];
            if (inClass)
            {
                if (c == ']') { o.Append(']'); inClass = false; canQuant = true; i++; continue; }
                if (c == '\\')
                {
                    if (i + 1 >= n) throw new ArgumentException("\\ at end of pattern");
                    char e = s[i + 1];
                    i += 2;
                    if (e == 's') o.Append(JsSpaceClass);
                    else if (e == 'S') o.Append("[^").Append(JsSpaceClass).Append(']');
                    else if (e == 'd') o.Append("0-9");
                    else if (e == 'w') o.Append(WordClass);
                    else if (e == 'D' || e == 'W') o.Append('\\').Append(e);
                    else if (e == 'b') o.Append("\\x08");
                    else if (e == 't' || e == 'n' || e == 'f' || e == 'r') o.Append('\\').Append(e);
                    else if (e == 'v') o.Append("\\u000B");
                    else if (e == '0') o.Append("\\x00");
                    else if (e == 'x' && Hex(s, i, 2)) { o.Append("\\x").Append(s, i, 2); i += 2; }
                    else if (e == 'u' && Hex(s, i, 4)) { o.Append("\\u").Append(s, i, 4); i += 4; }
                    else if (e < 128 && !char.IsAsciiLetterOrDigit(e)) o.Append('\\').Append(e);
                    else o.Append(e);
                    continue;
                }
                if (c == '[' || c == '&' || c == '^') o.Append('\\').Append(c); else o.Append(c);
                i++;
                continue;
            }
            switch (c)
            {
                case '\\':
                {
                    if (i + 1 >= n) throw new ArgumentException("\\ at end of pattern");
                    char e = s[i + 1];
                    i += 2;
                    canQuant = true;
                    if (e == 'b') { o.Append(WordBoundary); canQuant = false; }
                    else if (e == 'B') { o.Append(NotWordBoundary); canQuant = false; }
                    else if (e == 'd') o.Append("[0-9]");
                    else if (e == 'D') o.Append("[^0-9]");
                    else if (e == 'w') o.Append('[').Append(WordClass).Append(']');
                    else if (e == 'W') o.Append("[^").Append(WordClass).Append(']');
                    else if (e == 's') o.Append('[').Append(JsSpaceClass).Append(']');
                    else if (e == 'S') o.Append("[^").Append(JsSpaceClass).Append(']');
                    else if (e == 't' || e == 'n' || e == 'f' || e == 'r') o.Append('\\').Append(e);
                    else if (e == 'v') o.Append("\\u000B");
                    else if (e == '0') o.Append("\\x00");
                    else if (e >= '1' && e <= '9') o.Append('\\').Append(e);
                    else if (e == 'x' && Hex(s, i, 2)) { o.Append("\\x").Append(s, i, 2); i += 2; }
                    else if (e == 'u' && Hex(s, i, 4)) { o.Append("\\u").Append(s, i, 4); i += 4; }
                    else if (e == 'c' && i < n && char.IsAsciiLetter(s[i])) { o.Append("\\c").Append(s[i]); i++; }
                    else if (e == 'c') o.Append("\\\\c");
                    else if (e < 128 && !char.IsAsciiLetterOrDigit(e)) o.Append('\\').Append(e);
                    else o.Append(e);
                    break;
                }
                case '(':
                {
                    if (i + 1 < n && s[i + 1] == '?')
                    {
                        if (i + 2 < n && (s[i + 2] == ':' || s[i + 2] == '=' || s[i + 2] == '!')) { o.Append("(?").Append(s[i + 2]); i += 3; }
                        else throw new ArgumentException("invalid group");
                    }
                    else { o.Append('('); i++; }
                    depth++;
                    canQuant = false;
                    break;
                }
                case ')':
                    if (depth == 0) throw new ArgumentException("unmatched )");
                    depth--; o.Append(')'); canQuant = true; i++;
                    break;
                case '|': o.Append('|'); canQuant = false; i++; break;
                case '*':
                case '+':
                case '?':
                {
                    if (!canQuant) throw new ArgumentException("nothing to repeat");
                    o.Append(c); i++;
                    if (i < n && s[i] == '?') { o.Append('?'); i++; }
                    canQuant = false;
                    break;
                }
                case '{':
                {
                    int e = QuantEnd(s, i);
                    if (e < 0) { o.Append("\\{"); canQuant = true; i++; break; }
                    if (!canQuant) throw new ArgumentException("nothing to repeat");
                    o.Append(s, i, e - i); i = e;
                    if (i < n && s[i] == '?') { o.Append('?'); i++; }
                    canQuant = false;
                    break;
                }
                case '}': o.Append("\\}"); canQuant = true; i++; break;
                case ']': o.Append("\\]"); canQuant = true; i++; break;
                case '[':
                {
                    if (string.CompareOrdinal(s, i, "[]", 0, 2) == 0) { o.Append("(?!)"); i += 2; canQuant = true; break; }
                    if (string.CompareOrdinal(s, i, "[^]", 0, 3) == 0) { o.Append("[\\s\\S]"); i += 3; canQuant = true; break; }
                    inClass = true; i++;
                    if (i < n && s[i] == '^') { o.Append("[^"); i++; } else o.Append('[');
                    break;
                }
                case '.': o.Append("[^\\n\\r\\u2028\\u2029]"); canQuant = true; i++; break;
                case '^': o.Append('^'); canQuant = false; i++; break;
                case '$': o.Append("\\z"); canQuant = false; i++; break;
                default: o.Append(c); canQuant = true; i++; break;
            }
        }
        if (inClass || depth != 0) throw new ArgumentException("unterminated pattern");
        return new Regex(o.ToString(), RegexOptions.CultureInvariant); // RegexParseException is an ArgumentException
    }

    // ---- rule set validation, digest, signature ----

    /// <summary>String.prototype.toUpperCase for the characters whose uppercase is not one code unit.</summary>
    static string JsUpper(string s) => s.ToUpperInvariant().Replace("ß", "SS", StringComparison.Ordinal);

    /// <summary>Null if the rule set is well formed: closed members, unique ids, safe regular expressions, known trait/role/tag names.</summary>
    public static string? SuggestRulesError(object? r, ISet<string>? known)
    {
        if (r is not D o) return "rules must be an object";
        foreach (var k in ImportJx.Keys(o)) if (!new[] { "v", "kind", "version", "rules", "digest", "sig" }.Contains(k)) return "unknown member '" + k + "'";
        var one = ImportJx.Dbl(o.GetValueOrDefault("v"));
        if (one == null || one != 1.0 || o.GetValueOrDefault("kind") is not SuggestRulesKind) return "not a suggest-rules document (v 1)";
        if (o.GetValueOrDefault("version") is not string ver || !VersionRe.IsMatch(ver)) return "version must be semver";
        if (o.GetValueOrDefault("rules") is not L rl || rl.Count == 0 || rl.Count > MaxRules) return "rules must be 1.." + MaxRules + " entries";
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var x in rl)
        {
            if (x is not D rule) return "a rule must be an object";
            foreach (var k in ImportJx.Keys(rule)) if (!new[] { "id", "match", "adds", "note" }.Contains(k)) return "rule: unknown member '" + k + "'";
            if (rule.GetValueOrDefault("id") is not string w || !RuleIdRe.IsMatch(w) || ids.Contains(w)) return "rule ids must be unique SR-nnn";
            ids.Add(w);
            if (rule.GetValueOrDefault("note") is not string note || note.Length == 0 || note.Length > 200) return w + ": note must be 1..200 characters";
            if (rule.GetValueOrDefault("match") is not D m || m.Count == 0) return w + ": match must be a non-empty object";
            foreach (var k in ImportJx.Keys(m)) if (!MatchKeys.Contains(k)) return w + ": unknown match member '" + k + "'";
            foreach (var k in new[] { "methods", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_formats", "roles" })
                if (m.ContainsKey(k) && !IsStrList(m[k], MaxList)) return w + ": match." + k + " must be 1.." + MaxList + " short strings";
            if (m.ContainsKey("methods")) foreach (var s in (L)m["methods"]!) if ((string)s! != JsUpper((string)s!)) return w + ": methods are uppercase";
            if (m.ContainsKey("param_types"))
            {
                bool bad = !IsStrList(m["param_types"], MaxList);
                if (!bad) foreach (var t in (L)m["param_types"]!) if (!ParamTypes.Contains((string)t!)) { bad = true; break; }
                if (bad) return w + ": match.param_types is not a list of param types";
            }
            if (m.ContainsKey("effects") && !IsStrList(m["effects"], 12)) return w + ": match.effects must be a list of effects";
            if (m.ContainsKey("path_re"))
            {
                if (m["path_re"] is not string re || re.Length == 0 || re.Length > 128) return w + ": path_re must be 1..128 characters";
                if (NestedQuantifier.IsMatch(re) || Backref.IsMatch(re) || Lookaround.IsMatch(re))
                    return w + ": path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)";
                try { JsRegex(re); } catch (ArgumentException) { return w + ": path_re is not a regular expression"; }
            }
            bool hasParam = m.ContainsKey("param_names") || m.ContainsKey("param_names_all") || m.ContainsKey("param_formats") || m.ContainsKey("roles");
            if (m.ContainsKey("param_types") && !m.ContainsKey("param_names") && !m.ContainsKey("param_formats") && !m.ContainsKey("param_names_all")) return w + ": param_types needs param_names, param_names_all or param_formats";
            if (!IsStrList(rule.GetValueOrDefault("adds"), 16)) return w + ": adds must be 1..16 entries";
            foreach (var ao in (L)rule["adds"]!)
            {
                var a = (string)ao!;
                if (a.StartsWith("tag:", StringComparison.Ordinal))
                {
                    if (!ParamTags.Contains(a.Substring(4))) return w + ": unknown tag '" + a + "'";
                    if (!hasParam) return w + ": a tag needs a param matcher";
                }
                else if (Actions.IsRole(a))
                {
                    if (!hasParam) return w + ": a role needs a param matcher";
                }
                else if (TraitIdRe.IsMatch(a))
                {
                    if (known != null && !known.Contains(a)) return w + ": unknown trait '" + a + "'";
                }
                else return w + ": '" + a + "' is not a trait, role or tag:";
            }
        }
        return null;
    }

    /// <summary>b64u sha256 of the strict canonical rule set (without digest and sig).</summary>
    public static string RulesDigest(D r)
    {
        var body = new D();
        foreach (var k in new[] { "v", "kind", "version", "rules" }) if (r.ContainsKey(k)) body[k] = r[k];
        return Pca.HashCanonical(new D { ["d"] = SuggestRulesDomain, ["rules"] = body });
    }

    public static D SealRules(D r)
    {
        var o = new D(r) { ["digest"] = RulesDigest(r) };
        return o;
    }

    static byte[] RulesMessage(string digest) => IntentJs.Message(SuggestRulesDomain + "\0", new D { ["digest"] = digest });

    /// <summary>Sign a rule set as the rules publisher (a release step; the signature covers the digest). secret: the Ed25519 seed.</summary>
    public static D SignRules(D r, string kid, byte[] secret)
    {
        var bad = SuggestRulesError(r, null);
        if (bad != null) throw new ActionKitError("bad_rules", bad);
        var sealedRules = SealRules(r);
        sealedRules["sig"] = new D { ["alg"] = "ed25519", ["kid"] = kid, ["value"] = Pca.B64u(EdKey.FromSeed(secret).Sign(RulesMessage((string)sealedRules["digest"]!))) };
        return sealedRules;
    }

    /// <summary>Verify a signed rule set against pinned publisher keys ([{kid, pk}]): shape, digest, signature. Never throws.</summary>
    public static D VerifyRules(object? doc, IEnumerable<D> pins)
    {
        D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };
        try
        {
            var bad = SuggestRulesError(doc, null);
            if (bad != null) return Fail(bad);
            var d = (D)doc!;
            if (!JsX.StrictEq(RulesDigest(d), d.GetValueOrDefault("digest"))) return Fail("digest does not match the rules");
            if (!ImportJx.Truthy(d.GetValueOrDefault("sig"))) return Fail("the rule set is not signed");
            var sig = d["sig"];
            var kid = ImportJx.Get(sig, "kid");
            D? key = null;
            foreach (var p in pins) if (kid != null && JsX.StrictEq(kid, p.GetValueOrDefault("kid"))) { key = p; break; }
            if (key == null) return Fail("no pinned rules key '" + (ImportJx.Has(sig, "kid") ? ImportJx.JsStr(kid) : "undefined") + "'");
            var value = ImportJx.Get(sig, "value");
            bool ok = key.GetValueOrDefault("pk") is string && value is string && IntentJs.VerifyEd(key["pk"], RulesMessage((string)d["digest"]!), value);
            return ok ? new D { ["ok"] = true } : Fail("rules signature invalid");
        }
        catch (Exception e) { return Fail("rules verification error: " + e.Message); }
    }

    // ---- facts ----

    /// <summary>Light stemmer: plural, -ing, -ed and a trailing -e fold together (charges, charged, charging to charg).</summary>
    public static string Stem(string t)
    {
        var s = t;
        if (s.Length > 4 && s.EndsWith("ies", StringComparison.Ordinal)) s = s.Substring(0, s.Length - 3) + "y";
        else if ((s.EndsWith("sses", StringComparison.Ordinal) || s.EndsWith("xes", StringComparison.Ordinal) || s.EndsWith("zes", StringComparison.Ordinal) || s.EndsWith("ches", StringComparison.Ordinal) || s.EndsWith("shes", StringComparison.Ordinal)) && s.Length > 4) s = s.Substring(0, s.Length - 2);
        else if (s.Length > 3 && s.EndsWith("s", StringComparison.Ordinal) && !s.EndsWith("ss", StringComparison.Ordinal)) s = s.Substring(0, s.Length - 1);
        if (s.Length > 5 && s.EndsWith("ing", StringComparison.Ordinal)) s = s.Substring(0, s.Length - 3);
        else if (s.Length > 4 && s.EndsWith("ed", StringComparison.Ordinal)) s = s.Substring(0, s.Length - 2);
        if (s.Length > 3 && s.EndsWith("e", StringComparison.Ordinal)) s = s.Substring(0, s.Length - 1);
        return s;
    }

    const string Sep = "|";

    /// <summary>What the rules read of a def: methods, binding locations, stemmed name tokens (with and without path segments), params and effects.</summary>
    public sealed class Facts
    {
        public readonly List<string> Methods = new();
        public readonly List<string> Locs = new();
        public readonly List<string> Tokens = new();
        public readonly List<string> Strict = new();
        public readonly List<FParam> Params = new();
        public readonly List<string> Effects = new();

        public D ToJson()
        {
            var ps = new L();
            foreach (var p in Params)
            {
                var m = ImportJx.Obj(("name", p.Name), ("tokens", Ak.ToL(p.Tokens)), ("type", p.Type));
                if (p.Format != null) m["format"] = p.Format;
                if (p.Role != null) m["role"] = p.Role;
                ps.Add(m);
            }
            return ImportJx.Obj(("methods", Ak.ToL(Ak.SortUniq(Methods))), ("locs", Ak.ToL(Locs)), ("tokens", Ak.ToL(Tokens)), ("strict", Ak.ToL(Strict)), ("params", ps), ("effects", Ak.ToL(Ak.SortUniq(Effects))));
        }
    }

    public sealed class FParam
    {
        public readonly string Name; public readonly string? Type, Format, Role; public readonly List<string> Tokens;
        internal FParam(string name, List<string> tokens, string? type, string? format, string? role) { Name = name; Tokens = tokens; Type = type; Format = format; Role = role; }
    }

    static List<string> Stems(List<string> toks) => toks.Select(Stem).ToList();

    static string Up(object? s) => JsUpper(ImportJx.JsStr(s));

    static void AddOnce(List<string> l, string v) { if (!l.Contains(v)) l.Add(v); }

    public static Facts FactsOf(D d)
    {
        var b = d.GetValueOrDefault("bindings") ?? new D();
        var f = new Facts();
        var src = new List<List<string>>();
        var isPath = new List<bool>();
        var verbSegs = ImportJx.JsStr(d.GetValueOrDefault("verb")).Split('.');
        var vt = new List<string>();
        for (int i = 1; i < verbSegs.Length; i++) vt.AddRange(TokensOf(verbSegs[i]));
        src.Add(vt); isPath.Add(false);
        if (d.GetValueOrDefault("aliases") is L al) foreach (var a in al) { src.Add(TokensOf(a)); isPath.Add(false); }
        src.Add(TokensOf(d.GetValueOrDefault("title"))); isPath.Add(false);
        var oa = ImportJx.Get(b, "openapi");
        if (ImportJx.Truthy(oa))
        {
            src.Add(TokensOf(ImportJx.Get(oa, "operationId"))); isPath.Add(false);
            if (ImportJx.Truthy(ImportJx.Get(oa, "method"))) AddOnce(f.Methods, Up(ImportJx.Get(oa, "method")));
            if (ImportJx.Truthy(ImportJx.Get(oa, "path")))
            {
                var p = ImportJx.JsStr(ImportJx.Get(oa, "path"));
                f.Locs.Add(p);
                src.Add(PathTokens(p)); isPath.Add(true);
            }
        }
        var http = ImportJx.Get(b, "http");
        if (ImportJx.Truthy(http))
        {
            AddOnce(f.Methods, Up(ImportJx.Get(http, "method")));
            var p = ImportJx.JsStr(ImportJx.Get(http, "path"));
            f.Locs.Add(p);
            src.Add(PathTokens(p)); isPath.Add(true);
        }
        var mcp = ImportJx.Get(b, "mcp");
        if (ImportJx.Truthy(mcp)) { f.Locs.Add(ImportJx.JsStr(ImportJx.Get(mcp, "tool"))); src.Add(TokensOf(ImportJx.Get(mcp, "tool"))); isPath.Add(false); }
        var gql = ImportJx.Get(b, "graphql");
        if (ImportJx.Truthy(gql)) { AddOnce(f.Methods, Up(ImportJx.Get(gql, "op"))); f.Locs.Add(ImportJx.JsStr(ImportJx.Get(gql, "field"))); src.Add(TokensOf(ImportJx.Get(gql, "field"))); isPath.Add(false); }
        var grpc = ImportJx.Get(b, "grpc");
        if (ImportJx.Truthy(grpc))
        {
            f.Locs.Add(ImportJx.JsStr(ImportJx.Get(grpc, "service")) + "/" + ImportJx.JsStr(ImportJx.Get(grpc, "method")));
            src.Add(TokensOf(ImportJx.Get(grpc, "service"))); isPath.Add(false);
            src.Add(TokensOf(ImportJx.Get(grpc, "method"))); isPath.Add(false);
        }
        var asy = ImportJx.Get(b, "asyncapi");
        if (ImportJx.Truthy(asy)) { AddOnce(f.Methods, Up(ImportJx.Get(asy, "op"))); f.Locs.Add(ImportJx.JsStr(ImportJx.Get(asy, "channel"))); src.Add(TokensOf(ImportJx.Get(asy, "channel"))); isPath.Add(false); }
        for (int i = 0; i < src.Count; i++)
        {
            if (f.Tokens.Count > 0) f.Tokens.Add(Sep);
            f.Tokens.AddRange(Stems(src[i]));
            if (!isPath[i]) { if (f.Strict.Count > 0) f.Strict.Add(Sep); f.Strict.AddRange(Stems(src[i])); }
        }
        var parms = d.GetValueOrDefault("params") as D ?? new D();
        var pnames = parms.Keys.ToList();
        pnames.Sort(StringComparer.Ordinal);
        foreach (var name in pnames)
        {
            var p = parms[name];
            var fm = ImportJx.Get(p, "format"); var ro = ImportJx.Get(p, "role");
            f.Params.Add(new FParam(name, Stems(TokensOf(name)), ImportJx.Get(p, "type") as string, ImportJx.Truthy(fm) ? ImportJx.JsStr(fm) : null, ImportJx.Truthy(ro) ? ImportJx.JsStr(ro) : null));
        }
        var clipped = f.Locs.Select(l => l.Length > 512 ? l.Substring(0, 512) : l).ToList();
        f.Locs.Clear();
        f.Locs.AddRange(clipped);
        if (d.GetValueOrDefault("effects") is L el) foreach (var e in el) AddOnce(f.Effects, ImportJx.JsStr(e));
        return f;
    }

    static List<string> PathTokens(string p)
    {
        var o = new List<string>();
        foreach (var s in p.Split('/')) if (s.Length > 0 && s.IndexOf('{') < 0 && s.IndexOf('}') < 0) o.AddRange(TokensOf(s));
        return o;
    }

    /// <summary>True iff the stemmed pattern occurs as a contiguous run in hay.</summary>
    static bool HasSeq(List<string> hay, List<string> pat)
    {
        if (pat.Count == 0) return false;
        for (int i = 0; i + pat.Count <= hay.Count; i++)
        {
            bool ok = true;
            for (int j = 0; j < pat.Count; j++) if (hay[i + j] != pat[j]) { ok = false; break; }
            if (ok) return true;
        }
        return false;
    }

    static List<string> PatOf(string s) => Stems(TokensOf(s));

    public static D EmptySuggestion() => ImportJx.Obj(("traits", new L()), ("roles", new D()), ("tags", new D()), ("fired", new L()));

    static readonly HashSet<string> IntRoles = new() { "money.amount", "money.fee", "count.limit", "bytes.size" };

    static bool RoleFits(string role, string? type)
    {
        if (IntRoles.Contains(role)) return type == "integer";
        if (role.StartsWith("time.", StringComparison.Ordinal)) return type is "date" or "datetime" or "integer";
        return type == "string";
    }

    static List<string> Strs(object? o) => o is L l ? l.Select(ImportJx.JsStr).ToList() : new List<string>();

    /// <summary>Run the rules over a def. Only trait ids in registry (when given) can be suggested; anything else is dropped (the closed vocabulary).
    /// Pure and deterministic. Returns {traits, roles, tags, fired}.</summary>
    public static D SuggestWithRules(D d, D rules, Dictionary<string, D>? registry)
    {
        var f = FactsOf(d);
        var traits = new SortedSet<string>(StringComparer.Ordinal);
        var roles = new D();
        var tags = new Dictionary<string, SortedSet<string>>();
        var fired = new L();
        var stemsAll = f.Tokens;
        foreach (var ro in (L)rules["rules"]!)
        {
            var rule = (D)ro!;
            var m = (D)rule["match"]!;
            if (ImportJx.Truthy(m.GetValueOrDefault("methods")) && !Strs(m["methods"]).Any(x => f.Methods.Contains(x))) continue;
            if (ImportJx.Truthy(m.GetValueOrDefault("effects")) && !Strs(m["effects"]).Any(x => f.Effects.Contains(x))) continue;
            if (ImportJx.Truthy(m.GetValueOrDefault("name_tokens")) && !Strs(m["name_tokens"]).Any(p => HasSeq(stemsAll, PatOf(p)))) continue;
            if (ImportJx.Truthy(m.GetValueOrDefault("name_tokens_strict")) && !Strs(m["name_tokens_strict"]).Any(p => HasSeq(f.Strict, PatOf(p)))) continue;
            if (ImportJx.Truthy(m.GetValueOrDefault("path_re")))
            {
                var re = JsRegex(ImportJx.JsStr(m["path_re"]));
                if (!f.Locs.Any(l => re.IsMatch(l))) continue;
            }
            if (ImportJx.Truthy(m.GetValueOrDefault("roles")))
            {
                var rs = Strs(m["roles"]);
                if (!f.Params.Any(p => p.Role != null && rs.Contains(p.Role))) continue;
            }
            var matched = new List<FParam>();
            bool paramCond = m.ContainsKey("param_names") || m.ContainsKey("param_formats");
            var ptypes = ImportJx.Truthy(m.GetValueOrDefault("param_types")) ? Strs(m["param_types"]) : null;
            if (paramCond)
            {
                var pats = new List<List<string>>();
                if (ImportJx.Truthy(m.GetValueOrDefault("param_names"))) foreach (var n in Strs(m["param_names"])) pats.Add(PatOf(n));
                foreach (var p in f.Params)
                {
                    if (ptypes != null && !ptypes.Contains(p.Type ?? "\u0000")) continue;
                    if (ImportJx.Truthy(m.GetValueOrDefault("param_names")) && !pats.Any(q => HasSeq(p.Tokens, q))) continue;
                    if (ImportJx.Truthy(m.GetValueOrDefault("param_formats")) && (p.Format == null || !Strs(m["param_formats"]).Contains(p.Format))) continue;
                    matched.Add(p);
                }
                if (matched.Count == 0) continue;
            }
            if (ImportJx.Truthy(m.GetValueOrDefault("param_names_all")))
            {
                bool ok = true;
                foreach (var n in Strs(m["param_names_all"]))
                {
                    var q = PatOf(n);
                    bool has = f.Params.Any(p => HasSeq(p.Tokens, q) && (ptypes == null || ptypes.Contains(p.Type ?? "\u0000") || p.Type == "string"));
                    if (!has) { ok = false; break; }
                }
                if (!ok) continue;
            }
            fired.Add(rule["id"]);
            foreach (var a in Strs(rule["adds"]))
            {
                if (a.StartsWith("tag:", StringComparison.Ordinal))
                {
                    foreach (var p in matched)
                    {
                        if (!tags.TryGetValue(p.Name, out var ts)) tags[p.Name] = ts = new SortedSet<string>(StringComparer.Ordinal);
                        ts.Add(a.Substring(4));
                    }
                }
                else if (!Actions.IsRole(a))
                {
                    if (registry == null || registry.ContainsKey(a)) traits.Add(a);
                }
                else
                {
                    foreach (var p in matched) if (p.Role == null && roles.GetValueOrDefault(p.Name) == null && RoleFits(a, p.Type)) roles[p.Name] = a;
                }
            }
        }
        traits.Remove("pca.unreviewed");
        var tagOut = new D();
        foreach (var k in tags.Keys.OrderBy(x => x, StringComparer.Ordinal)) tagOut[k] = Ak.ToL(tags[k]);
        return ImportJx.Obj(("traits", Ak.ToL(traits)), ("roles", roles), ("tags", tagOut), ("fired", fired));
    }

    static L SortedUnion(params object?[] ls)
    {
        var s = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var l in ls) if (l is L ll) foreach (var x in ll) s.Add(ImportJx.JsStr(x));
        return Ak.ToL(s);
    }

    /// <summary>Union two suggestions (the restrictive direction, so no intersection is needed).</summary>
    public static D UnionSuggestions(D a, D b)
    {
        var roles = new D((D)b["roles"]!);
        ImportJx.PutAll(roles, (D)a["roles"]!);
        var tags = new D();
        var ks = new List<string>(((D)a["tags"]!).Keys);
        foreach (var k in ((D)b["tags"]!).Keys) if (!ks.Contains(k)) ks.Add(k);
        foreach (var k in ks) tags[k] = SortedUnion(((D)a["tags"]!).GetValueOrDefault(k), ((D)b["tags"]!).GetValueOrDefault(k));
        var fired = new L((L)a["fired"]!);
        fired.AddRange((L)b["fired"]!);
        return ImportJx.Obj(("traits", SortedUnion(a["traits"], b["traits"])), ("roles", roles), ("tags", tags), ("fired", fired));
    }

    /// <summary>Apply a suggestion to a def. UNION ONLY: traits are added, a role is set only on a param without one, tags are added; nothing is removed or
    /// replaced, no attestation is created, and review.state goes from unreviewed to suggested. by: {rules?: {version, digest, fired}, models?: [...]}.</summary>
    public static D ApplySuggestion(D d, D s, D by)
    {
        var parms = new D();
        var addedRoles = new D();
        var addedTags = new D();
        var sroles = (D)s["roles"]!; var stags = (D)s["tags"]!;
        foreach (var (name, po) in (D)d["params"]!)
        {
            var p = (D)po!;
            var q = p;
            var role = sroles.GetValueOrDefault(name);
            if (role != null && p.GetValueOrDefault("role") == null && RoleFits((string)role, (string?)p.GetValueOrDefault("type"))) { q = new D(q) { ["role"] = role }; addedRoles[name] = role; }
            var t = stags.GetValueOrDefault(name);
            if (t != null)
            {
                var have = p.GetValueOrDefault("tags") as L ?? new L();
                var fresh = new L();
                foreach (var x in (L)t) if (!have.Contains(x)) fresh.Add(x);
                if (fresh.Count > 0) { q = new D(q) { ["tags"] = SortedUnion(have, fresh) }; addedTags[name] = fresh; }
            }
            parms[name] = q;
        }
        var dtraits = d.GetValueOrDefault("traits") as L ?? new L();
        var freshTraits = new L();
        foreach (var t in (L)s["traits"]!) if (!dtraits.Contains(t)) freshTraits.Add(t);
        // a money-moving action must be safe to repeat (lint LD-004): add the optional idempotency key the pack generator adds
        var idempotency = d.GetValueOrDefault("idempotency");
        if (((L)s["traits"]!).Contains("pca.money_moving") && (idempotency == null || ImportJx.Get(idempotency, "mode") is "none"))
        {
            idempotency = ImportJx.Obj(("mode", "key_param"), ("param", "idempotency_key"));
            if (!parms.ContainsKey("idempotency_key")) parms["idempotency_key"] = ImportJx.Obj(("type", "string"), ("max_len", ImportJx.N(64)), ("required", false));
        }
        var review = (D)d["review"]!;
        var prev = review.GetValueOrDefault("suggested_by") as D ?? new D();
        var prevAdded = prev.GetValueOrDefault("added") != null ? (D)prev["added"]! : ImportJx.Obj(("traits", new L()), ("roles", new D()), ("tags", new D()));
        var addedRolesAll = new D((D)prevAdded["roles"]!);
        ImportJx.PutAll(addedRolesAll, addedRoles);
        var prevTags = (D)prevAdded["tags"]!;
        var tagKeys = new SortedSet<string>(prevTags.Keys, StringComparer.Ordinal);
        foreach (var k in addedTags.Keys) tagKeys.Add(k);
        var tagsAll = new D();
        foreach (var k in tagKeys) tagsAll[k] = SortedUnion(prevTags.GetValueOrDefault(k), addedTags.GetValueOrDefault(k));
        var added = ImportJx.Obj(("traits", SortedUnion(prevAdded["traits"], freshTraits)), ("roles", addedRolesAll), ("tags", tagsAll));
        var rules = by.GetValueOrDefault("rules") ?? prev.GetValueOrDefault("rules");
        var models = new L();
        if (prev.GetValueOrDefault("models") is L pm) models.AddRange(pm);
        if (by.GetValueOrDefault("models") is L bm) models.AddRange(bm);
        var suggestedBy = new D();
        if (rules != null) suggestedBy["rules"] = rules;
        if (models.Count > 0) suggestedBy["models"] = models;
        suggestedBy["added"] = added;
        var st = review.GetValueOrDefault("state");
        object? state = (st is "unreviewed" or "suggested") ? "suggested" : st;
        var o = new D(d) { ["params"] = parms };
        if (idempotency != null) o["idempotency"] = idempotency;
        if (freshTraits.Count > 0 || dtraits.Count > 0) o["traits"] = SortedUnion(dtraits, s["traits"]);
        var nr = new D(review) { ["state"] = state, ["suggested_by"] = suggestedBy };
        o["review"] = nr;
        return o;
    }
}

/// <summary>The shipped suggestion rules: DATA, versioned. Every rule only ADDS. These are heuristics measured against a labeled corpus; none is a safety guarantee.</summary>
public static class ImportRules
{
    public const string DefaultRulesVersion = "1.1.0";
    public static readonly D DefaultRules = (D)Pca.ParseJson(ImportRulesData.Json())!;
    /// <summary>The default rule set with its digest.</summary>
    public static readonly D DefaultRulesSealed = ImportSuggest.SealRules(DefaultRules);
    /// <summary>The digest recorded when the rule set was published.</summary>
    public static string PublishedDigest() => ImportRulesData.SealedDigest;
}
