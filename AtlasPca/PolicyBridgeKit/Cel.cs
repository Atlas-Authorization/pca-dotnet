using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using static AtlasPca.PolicyBridgeKit.PbJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyBridgeKit;

/// <summary>Strict CEL import (Google IAM Conditions, Kubernetes ValidatingAdmissionPolicy, SpiceDB caveat expressions): one boolean CEL expression
/// becomes a PCA condition or is REJECTED, naming the construct. There is no best-effort mode: a condition that was dropped or approximated would
/// widen what a policy admits. No CEL runs anywhere; the predicate DSL is the only evaluator. Results are JSON maps:
/// <c>{ok:true, condition, fields}</c> / <c>{ok:false, code, message, at}</c>.</summary>
public static class Cel
{
    const int MaxExpr = 4096;
    const int MaxDepth = 32;
    const int MaxNodes = 256;
    const int MaxList = 64;
    const int MaxStr = 256;
    static readonly HashSet<string> Forbidden = new() { "__proto__", "constructor", "prototype" };
    static readonly HashSet<string> Types = new() { "string", "int", "bool", "timestamp_ms" };

    /// <summary>A refusal: a stable error code, the message and the offset in the expression.</summary>
    sealed class Reject(string code, string message, int at) : Exception(message)
    {
        public readonly string Code = code;
        public readonly int At = at;
    }

    static Reject Rej(string code, string message, int at) => new(code, message, at);

    // ---- tokens ----

    sealed record Tok(char K, string V, int At); // K: 'i' id, 'n' int, 's' str, 'p' punct

    static readonly string[] Punct = { "&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "(", ")", "[", "]", ",", ".", "-" };

    static string? UnsupportedChar(char c) => c switch
    {
        '+' => "arithmetic (+)",
        '*' => "arithmetic (*)",
        '/' => "arithmetic (/)",
        '%' => "arithmetic (%)",
        '?' => "the conditional operator",
        ':' => "the conditional operator / map literal",
        '{' or '}' => "map or message literal",
        '@' => "@",
        '&' => "bitwise &",
        '|' => "bitwise |",
        '^' => "^",
        '~' => "~",
        '=' => "assignment",
        '`' => "quoted identifier",
        _ => null,
    };

    static List<Tok> Lex(string src)
    {
        var outp = new List<Tok>();
        int i = 0;
        while (i < src.Length)
        {
            char c = src[i];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') { i++; continue; }
            if (c == '/' && i + 1 < src.Length && src[i + 1] == '/') throw Rej("unsupported", "comments", i);
            if (IsIdentStart(c))
            {
                int j = i + 1;
                while (j < src.Length && IsIdentPart(src[j])) j++;
                var w = src[i..j];
                char nx = j < src.Length ? src[j] : '\0';
                if ((w == "r" || w == "b" || w == "R" || w == "B") && (nx == '"' || nx == '\''))
                    throw Rej("unsupported", (w.ToLowerInvariant() == "r" ? "raw string" : "bytes") + " literal", i);
                outp.Add(new Tok('i', w, i));
                i = j;
                continue;
            }
            if (IsDigit(c))
            {
                int j = i;
                while (j < src.Length && IsDigit(src[j])) j++;
                bool has = j < src.Length;
                char nxt = has ? src[j] : '\0';
                if (has && nxt == '.' && j + 1 < src.Length && IsDigit(src[j + 1])) throw Rej("unsupported", "double literal", i);
                if (has && (nxt == 'e' || nxt == 'E')) throw Rej("unsupported", "double literal", i);
                if (has && (nxt == 'u' || nxt == 'U')) throw Rej("unsupported", "unsigned integer literal", i);
                if (has && (nxt == 'x' || nxt == 'X')) throw Rej("unsupported", "hexadecimal literal", i);
                var w = src[i..j];
                if (w.Length > 1 && w[0] == '0') throw Rej("unsupported", "integer literal with a leading zero", i);
                outp.Add(new Tok('n', w, i));
                i = j;
                continue;
            }
            if (c == '"' || c == '\'')
            {
                var triple = new string(c, 3);
                if (string.CompareOrdinal(src, i, triple, 0, 3) == 0) throw Rej("unsupported", "triple-quoted string", i);
                int j = i + 1;
                var s = new StringBuilder();
                for (;;)
                {
                    if (j >= src.Length) throw Rej("syntax", "unterminated string", i);
                    char d = src[j];
                    if (d == '\n' || d == '\r') throw Rej("syntax", "unterminated string", i);
                    if (d == c) break;
                    if (d == '\\')
                    {
                        bool has = j + 1 < src.Length;
                        char e = has ? src[j + 1] : '\0';
                        string? mapped = !has ? null : e == '\\' ? "\\" : e == '"' ? "\"" : e == '\'' ? "'" : e == 'n' ? "\n" : e == 't' ? "\t" : e == 'r' ? "\r" : null;
                        if (mapped == null) throw Rej("unsupported", "string escape \\" + (has ? e.ToString() : ""), j);
                        s.Append(mapped);
                        j += 2;
                        continue;
                    }
                    s.Append(d);
                    j++;
                }
                if (s.Length > MaxStr) throw Rej("too_complex", "string literal longer than " + MaxStr, i);
                outp.Add(new Tok('s', s.ToString(), i));
                i = j + 1;
                continue;
            }
            string? p = null;
            foreach (var x in Punct) if (string.CompareOrdinal(src, i, x, 0, x.Length) == 0) { p = x; break; }
            if (p == null)
            {
                var u = UnsupportedChar(c);
                throw Rej(u != null ? "unsupported" : "syntax", u ?? "unexpected character '" + c + "'", i);
            }
            outp.Add(new Tok('p', p, i));
            i += p.Length;
        }
        return outp;
    }

    // ---- parser ----

    /// <summary>An AST node of the parsed subset (see <see cref="ToJson"/>).</summary>
    sealed class Node(string t, int at)
    {
        public readonly string T = t; // or and not rel int str bool ts list var has method
        public int At = at;
        public string Op = "", Name = "", Fn = "";
        public Node? L, R, E, Target, Arg;
        public long Iv;
        public string Sv = "";
        public bool Bv;
        public List<Node> Items = new();
        public Node CopyWithName(string name) => new("var", At) { Name = name };
    }

    static readonly HashSet<string> RelOps = new() { "==", "!=", "<", "<=", ">", ">=" };
    static readonly HashSet<string> RejectedFuncs = new()
    {
        "size", "matches", "exists", "all", "exists_one", "map", "filter", "int", "uint", "double", "string", "bytes", "bool",
        "duration", "type", "dyn", "min", "max", "getHours", "getDayOfWeek", "getMinutes", "getSeconds", "getFullYear", "getMonth", "getDate", "getDayOfMonth", "getDayOfYear",
        "getMilliseconds", "extract", "format", "lowerAscii", "upperAscii", "trim", "split", "join", "replace", "substring", "indexOf", "lastIndexOf", "charAt", "isIpv4",
        "inIpRange", "cidr", "ip", "isCIDR", "containsIp", "url", "quantity", "semver", "optional",
    };

    sealed class Parser(string src, List<Tok> toks)
    {
        int pos = 0, nodes = 0;

        Tok? Peek() => pos < toks.Count ? toks[pos] : null;
        bool IsP(string v) { var t = Peek(); return t != null && t.K == 'p' && t.V == v; }
        bool Eat(string v) { if (IsP(v)) { pos++; return true; } return false; }
        int PeekAt(int dflt) => Peek()?.At ?? dflt;
        void Need(string v) { if (!Eat(v)) throw Rej("syntax", "expected '" + v + "'", PeekAt(src.Length)); }
        void Tick(int at) { if (++nodes > MaxNodes) throw Rej("too_complex", "more than " + MaxNodes + " nodes", at); }

        Node Expr(int d)
        {
            if (d > MaxDepth) throw Rej("too_complex", "nesting deeper than " + MaxDepth, PeekAt(0));
            return Or(d);
        }

        Node Or(int d)
        {
            var l = And(d);
            while (IsP("||"))
            {
                int at = Peek()!.At;
                pos++;
                Tick(at);
                var n = new Node("or", at) { L = l };
                n.R = And(d);
                l = n;
            }
            return l;
        }

        Node And(int d)
        {
            var l = Rel(d);
            while (IsP("&&"))
            {
                int at = Peek()!.At;
                pos++;
                Tick(at);
                var n = new Node("and", at) { L = l };
                n.R = Rel(d);
                l = n;
            }
            return l;
        }

        static bool IsRelTok(Tok? u) => u != null && ((u.K == 'p' && RelOps.Contains(u.V)) || (u.K == 'i' && u.V == "in"));

        Node Rel(int d)
        {
            var l = Unary(d);
            var t = Peek();
            if (t == null) return l;
            bool isIn = t.K == 'i' && t.V == "in";
            if (!isIn && !(t.K == 'p' && RelOps.Contains(t.V))) return l;
            pos++;
            Tick(t.At);
            var n = new Node("rel", t.At) { Op = isIn ? "in" : t.V, L = l };
            n.R = Unary(d);
            var u = Peek();
            if (IsRelTok(u)) throw Rej("unsupported", "chained comparison", u!.At);
            return n;
        }

        Node Unary(int d)
        {
            var t = Peek();
            if (t != null && t.K == 'p' && t.V == "!")
            {
                pos++;
                Tick(t.At);
                if (d + 1 > MaxDepth) throw Rej("too_complex", "nesting deeper than " + MaxDepth, t.At);
                var n = new Node("not", t.At);
                n.E = Unary(d + 1);
                return n;
            }
            if (t != null && t.K == 'p' && t.V == "-")
            {
                var nx = pos + 1 < toks.Count ? toks[pos + 1] : null;
                if (nx == null || nx.K != 'n') throw Rej("unsupported", "unary minus on a non-literal", t.At);
                pos += 2;
                return IntNode("-" + nx.V, t.At);
            }
            return Member(d);
        }

        Node IntNode(string text, int at)
        {
            Tick(at);
            var v = double.Parse(text, NumberStyles.Float, CultureInfo.InvariantCulture);
            if (!(v == Math.Round(v) && Math.Abs(v) <= 9007199254740991.0)) throw Rej("unsupported", "integer literal outside the safe-integer range", at);
            return new Node("int", at) { Iv = (long)v };
        }

        List<Node> Args(int d)
        {
            var a = new List<Node>();
            if (!IsP(")")) { do a.Add(Expr(d + 1)); while (Eat(",")); }
            Need(")");
            return a;
        }

        Node Member(int d)
        {
            var n = Primary(d);
            while (IsP("."))
            {
                var dot = Peek()!;
                pos++;
                var id = Peek();
                if (id == null || id.K != 'i') throw Rej("syntax", "expected a name after '.'", dot.At);
                pos++;
                if (IsP("("))
                {
                    pos++;
                    var a = Args(d);
                    if (id.V != "startsWith" && id.V != "endsWith" && id.V != "contains") throw Rej("unsupported", "method '" + id.V + "'", id.At);
                    if (a.Count != 1) throw Rej("syntax", "'" + id.V + "' takes one argument", id.At);
                    Tick(id.At);
                    n = new Node("method", id.At) { Target = n, Fn = id.V, Arg = a[0] };
                }
                else
                {
                    if (n.T != "var") throw Rej("unsupported", "field selection on something that is not a declared variable", dot.At);
                    n = n.CopyWithName(n.Name + "." + id.V);
                }
            }
            if (IsP("[")) throw Rej("unsupported", "index operator", Peek()!.At);
            return n;
        }

        Node Primary(int d)
        {
            var t = Peek();
            if (t == null) throw Rej("syntax", "unexpected end of expression", src.Length);
            if (t.K == 'n') { pos++; return IntNode(t.V, t.At); }
            if (t.K == 's') { pos++; Tick(t.At); return new Node("str", t.At) { Sv = t.V }; }
            if (t.K == 'p' && t.V == "(") { pos++; var e = Expr(d + 1); Need(")"); return e; }
            if (t.K == 'p' && t.V == "[")
            {
                pos++;
                var items = new List<Node>();
                if (!IsP("]"))
                {
                    do
                    {
                        if (items.Count >= MaxList) throw Rej("too_complex", "list longer than " + MaxList, t.At);
                        items.Add(Expr(d + 1));
                    } while (Eat(","));
                }
                Need("]");
                Tick(t.At);
                return new Node("list", t.At) { Items = items };
            }
            if (t.K == 'i')
            {
                pos++;
                if (t.V == "true" || t.V == "false") { Tick(t.At); return new Node("bool", t.At) { Bv = t.V == "true" }; }
                if (t.V == "null") throw Rej("unsupported", "null", t.At);
                if (IsP("("))
                {
                    pos++;
                    var a = Args(d);
                    if (t.V == "has")
                    {
                        if (a.Count != 1 || a[0].T != "var") throw Rej("syntax", "has() takes one declared variable", t.At);
                        Tick(t.At);
                        return new Node("has", t.At) { E = a[0] };
                    }
                    if (t.V == "timestamp")
                    {
                        var s = a.Count == 0 ? null : a[0];
                        if (a.Count != 1 || s == null || s.T != "str") throw Rej("unsupported", "timestamp() of a non-literal", t.At);
                        return new Node("ts", t.At) { Iv = ParseTimestamp(s.Sv, t.At) };
                    }
                    throw Rej("unsupported", RejectedFuncs.Contains(t.V) ? "function '" + t.V + "'" : "unknown function '" + t.V + "'", t.At);
                }
                if (t.V == "in") throw Rej("syntax", "unexpected 'in'", t.At);
                Tick(t.At);
                return new Node("var", t.At) { Name = t.V };
            }
            throw Rej("syntax", "unexpected '" + t.V + "'", t.At);
        }

        public Node Root()
        {
            var r = Expr(0);
            if (pos < toks.Count) throw Rej("syntax", "unexpected '" + toks[pos].V + "'", toks[pos].At);
            return r;
        }
    }

    static readonly Regex TimestampRe = Full("([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.([0-9]{1,3}))?Z");

    static bool IsLeap(int y) => y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    static int DaysInMonth(int y, int m) => m == 2 ? (IsLeap(y) ? 29 : 28) : m is 4 or 6 or 9 or 11 ? 30 : 31;

    /// <summary>Days since 1970-01-01 of a proleptic Gregorian date (year 0 allowed, as ISO 8601 and JavaScript read it).</summary>
    static long DaysFromCivil(long y, int m, int d)
    {
        y -= m <= 2 ? 1 : 0;
        long era = (y >= 0 ? y : y - 399) / 400;
        long yoe = y - era * 400;
        long doy = (153L * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + doe - 719468;
    }

    static long ParseTimestamp(string s, int at)
    {
        var m = TimestampRe.Match(s);
        if (!m.Success) throw Rej("unsupported", "timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision", at);
        var frac = m.Groups[7].Success ? m.Groups[7].Value : "";
        while (frac.Length < 3) frac += "0";
        int y = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture), mo = int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture), d = int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture);
        int h = int.Parse(m.Groups[4].Value, CultureInfo.InvariantCulture), mi = int.Parse(m.Groups[5].Value, CultureInfo.InvariantCulture), sec = int.Parse(m.Groups[6].Value, CultureInfo.InvariantCulture);
        if (mo < 1 || mo > 12 || d < 1 || d > DaysInMonth(y, mo) || h > 23 || mi > 59 || sec > 59) throw Rej("unsupported", "timestamp() is not a real instant", at);
        long days = DaysFromCivil(y, mo, d);
        return (((days * 24 + h) * 60 + mi) * 60 + sec) * 1000 + int.Parse(frac, CultureInfo.InvariantCulture);
    }

    static Node Parse(string? src)
    {
        if (string.IsNullOrEmpty(src)) throw Rej("syntax", "empty expression", 0);
        if (src.Length > MaxExpr) throw Rej("too_complex", "expression longer than " + MaxExpr + " characters", 0);
        return new Parser(src, Lex(src)).Root();
    }

    /// <summary>The AST as the reference prints it (a node is <c>{t, ..., at}</c>).</summary>
    static D ToJson(Node x)
    {
        var m = new D { ["t"] = x.T };
        switch (x.T)
        {
            case "or": case "and": m["l"] = ToJson(x.L!); m["r"] = ToJson(x.R!); break;
            case "not": m["e"] = ToJson(x.E!); break;
            case "rel": m["op"] = x.Op; m["l"] = ToJson(x.L!); m["r"] = ToJson(x.R!); break;
            case "int": case "ts": m["v"] = N(x.Iv); break;
            case "str": m["v"] = x.Sv; break;
            case "bool": m["v"] = x.Bv; break;
            case "list": m["items"] = x.Items.Select(i => (object?)ToJson(i)).ToList(); break;
            case "var": m["name"] = x.Name; break;
            case "has": m["e"] = ToJson(x.E!); break;
            default: m["target"] = ToJson(x.Target!); m["fn"] = x.Fn; m["arg"] = ToJson(x.Arg!); break;
        }
        m["at"] = N(x.At);
        return m;
    }

    /// <summary>Parse a CEL expression of the supported subset into its tree <c>{ok:true, ast}</c>, or the refusal.</summary>
    public static D ParseCel(string? expression)
    {
        try { return Obj("ok", true, "ast", ToJson(Parse(expression))); }
        catch (Reject e) { return Fail(e); }
        catch (Exception) { return Obj("ok", false, "code", "syntax", "message", "internal error", "at", N(0)); }
    }

    static D Fail(Reject e) => Obj("ok", false, "code", e.Code, "message", e.Message, "at", N(e.At));

    // ---- translation ----

    static bool IsIdent(string s)
    {
        if (s.Length == 0 || !IsIdentStart(s[0])) return false;
        for (int i = 1; i < s.Length; i++) if (!IsIdentPart(s[i])) return false;
        return true;
    }

    static bool IsDottedIdent(string s, int minParts, HashSet<string>? roots)
    {
        var parts = s.Split('.');
        if (parts.Length < minParts) return false;
        for (int i = 0; i < parts.Length; i++)
        {
            if (i == 0 && roots != null) { if (!roots.Contains(parts[0])) return false; continue; }
            if (!IsIdent(parts[i])) return false;
        }
        return true;
    }

    static bool ForbiddenPart(string s) => s.Split('.').Any(Forbidden.Contains);

    static readonly HashSet<string> PcaRoots = new() { "action", "subject", "env" };

    static string? SchemaError(object? s)
    {
        if (s is not D sm) return "the schema must be an object";
        if (sm.GetValueOrDefault("vars") is not D vm) return "the schema needs a vars object";
        foreach (var name in EntryKeys(vm))
        {
            var v = vm[name];
            if (!IsDottedIdent(name, 1, null) || ForbiddenPart(name)) return "bad variable name '" + name + "'";
            var path = v is D vd ? vd.GetValueOrDefault("path") : null;
            if (v is not D || path is not string ps || !IsDottedIdent(ps, 2, PcaRoots) || ForbiddenPart(ps))
                return "variable '" + name + "' needs a path rooted at action, subject or env";
            var vv = (D)v;
            if (vv.GetValueOrDefault("type") is not string type || !Types.Contains(type)) return "variable '" + name + "' has an unsupported type";
            if (vv.ContainsKey("optional") && vv["optional"] is not bool) return "variable '" + name + "': optional must be a boolean";
        }
        return null;
    }

    /// <summary>A comparison operand: a declared variable or a typed literal.</summary>
    sealed record Operand(bool IsVar, string Type, string? Path, string? Name, bool Optional, object? Value);

    sealed class Translator(D vars)
    {
        public readonly SortedSet<string> Fields = new(StringComparer.Ordinal);

        Operand OperandOf(Node n)
        {
            switch (n.T)
            {
                case "var":
                {
                    if (!vars.TryGetValue(n.Name, out var v) || v == null) throw Rej("unknown_identifier", "'" + n.Name + "' is not declared in the schema", n.At);
                    var vm = (D)v;
                    return new Operand(true, (string)vm["type"]!, (string)vm["path"]!, n.Name, vm.GetValueOrDefault("optional") is true, null);
                }
                case "int": return new Operand(false, "int", null, null, false, N(n.Iv));
                case "str": return new Operand(false, "string", null, null, false, n.Sv);
                case "bool": return new Operand(false, "bool", null, null, false, n.Bv);
                case "ts": return new Operand(false, "timestamp_ms", null, null, false, N(n.Iv));
                default: throw Rej("unsupported", "a computed value as a comparison operand", n.At);
            }
        }

        string Read(Operand o) { Fields.Add(o.Path!); return o.Path!; }

        void Flat(Node n, string t, List<Node> outp)
        {
            if (n.T == t) { Flat(n.L!, t, outp); Flat(n.R!, t, outp); } else outp.Add(n);
        }

        public D Tr(Node n)
        {
            switch (n.T)
            {
                case "or": case "and":
                {
                    var parts = new List<Node>();
                    Flat(n, n.T, parts);
                    var outp = new L();
                    foreach (var p in parts) outp.Add(Tr(p));
                    return Obj(n.T == "or" ? "any_of" : "all_of", outp);
                }
                case "not": return Obj("not", Tr(n.E!));
                case "has":
                {
                    var o = OperandOf(n.E!);
                    if (!o.Optional) throw Rej("has_requires_optional", "has(" + o.Name + "): mark the variable optional in the schema (its container must always be present)", n.At);
                    return Obj("field", Read(o), "op", "exists", "value", true);
                }
                case "var":
                {
                    var o = OperandOf(n);
                    throw Rej("unsupported", "a bare variable '" + n.Name + "' as a condition" + (o.IsVar && o.Type == "bool" ? " (write " + n.Name + " == true)" : ""), n.At);
                }
                case "method":
                {
                    var t = OperandOf(n.Target!);
                    if (!t.IsVar || t.Type != "string") throw Rej("type_mismatch", n.Fn + " needs a string variable", n.At);
                    if (n.Arg!.T != "str" || n.Arg.Sv.Length == 0) throw Rej("unsupported", n.Fn + " of anything but a non-empty string literal", n.At);
                    var lit = n.Arg.Sv;
                    if (n.Fn == "startsWith") return Obj("field", Read(t), "op", "prefix", "value", lit);
                    var esc = new StringBuilder();
                    foreach (var c in lit)
                    {
                        if (c == '\\' || c == '*' || c == '?') esc.Append('\\');
                        esc.Append(c);
                    }
                    var glob = n.Fn == "endsWith" ? "*" + esc : "*" + esc + "*";
                    if (glob.Length > 512) throw Rej("too_complex", "literal too long for a glob", n.At);
                    return Obj("field", Read(t), "op", "like", "value", glob);
                }
                case "rel": return Rel(n);
                default: throw Rej("constant_expression", "a bare constant is not a condition", n.At);
            }
        }

        D Rel(Node n)
        {
            if (n.Op == "in")
            {
                var l0 = OperandOf(n.L!);
                if (!l0.IsVar) throw Rej("constant_expression", "the left side of \"in\" must be a declared variable", n.At);
                if (n.R!.T != "list" || n.R.Items.Count == 0) throw Rej("unsupported", "\"in\" against anything but a non-empty list literal", n.At);
                var items = n.R.Items.Select(OperandOf).ToList();
                foreach (var i in items) if (i.IsVar || i.Type != l0.Type) throw Rej("type_mismatch", "list items must be " + l0.Type + " literals", n.At);
                var field = Read(l0);
                var values = new L(items.Select(i => i.Value));
                return Obj("field", field, "op", "in", "value", values);
            }
            var l = OperandOf(n.L!);
            var r = OperandOf(n.R!);
            if (!l.IsVar && !r.IsVar) throw Rej("constant_expression", "a comparison of two literals", n.At);
            if (l.Type != r.Type) throw Rej("type_mismatch", l.Type + " against " + r.Type, n.At);
            var ty = l.Type;
            bool eqOp = n.Op == "==" || n.Op == "!=";
            if (!eqOp && ty == "bool") throw Rej("type_mismatch", "ordering of booleans", n.At);
            var pcaOp = n.Op == "==" ? "eq" : n.Op == "!=" ? "ne" : n.Op == "<" ? "lt" : n.Op == "<=" ? "lte" : n.Op == ">" ? "gt" : "gte";
            if (l.IsVar && r.IsVar) return Obj("field", Read(l), "op", pcaOp, "ref", Read(r));
            if (l.IsVar) return Obj("field", Read(l), "op", pcaOp, "value", r.Value);
            var flip = pcaOp == "lt" ? "gt" : pcaOp == "lte" ? "gte" : pcaOp == "gt" ? "lt" : pcaOp == "gte" ? "lte" : pcaOp;
            return Obj("field", Read(r), "op", flip, "value", l.Value);
        }
    }

    /// <summary>Translate one boolean CEL expression over <paramref name="schema"/> (<c>{vars: {name: {path, type, optional?}}}</c>) into a PCA condition.</summary>
    public static D CelToCondition(string? expression, object? schema)
    {
        var se = SchemaError(schema);
        if (se != null) return Obj("ok", false, "code", "bad_schema", "message", se, "at", N(0));
        try
        {
            var ast = Parse(expression);
            var t = new Translator((D)((D)schema!)["vars"]!);
            var condition = t.Tr(ast);
            if (t.Fields.Count == 0) throw Rej("constant_expression", "the expression reads no variable", 0);
            return Obj("ok", true, "condition", condition, "fields", new L(t.Fields));
        }
        catch (Reject e) { return Fail(e); }
        catch (Exception) { return Obj("ok", false, "code", "syntax", "message", "internal error", "at", N(0)); }
    }

    /// <summary>One expression as a permit predicate for <paramref name="verb"/> (a string or a list of strings) and optionally <paramref name="resource"/>.</summary>
    public static D CelToPredicate(string? expression, object? schema, object? verb, string? resource)
    {
        var r = CelToCondition(expression, schema);
        if (r.GetValueOrDefault("ok") is not true) return r;
        var predicate = new D { ["verb"] = verb };
        if (resource != null) predicate["resource"] = resource;
        predicate["where"] = new L { r["condition"] };
        return Obj("ok", true, "predicate", predicate, "fields", r["fields"]);
    }

    /// <summary>A batch (an IAM policy's bindings, a VAP's validations): every item (<c>{name, expression, verb, resource?}</c>) is translated or reported.
    /// One rejection makes the report's errors non-empty, and <see cref="PolicyBridge.Decide"/> then denies everything (an incomplete import never grants).</summary>
    public static D CelConditionsToPca(List<object?> items, object? schema)
    {
        var predicates = new L(); var translated = new L(); var errors = new L();
        foreach (var itv in items)
        {
            var it = (D)itv!;
            var res = it.GetValueOrDefault("resource");
            var r = CelToPredicate((string?)it.GetValueOrDefault("expression"), schema, it.GetValueOrDefault("verb"), (string?)res);
            var name = it.TryGetValue("name", out var nv) ? AtlasPca.Js.JsJson.ToJsString(nv) : "undefined";
            if (r.GetValueOrDefault("ok") is true)
            {
                predicates.Add(r["predicate"]);
                var fs = (L)r["fields"]!;
                translated.Add(name + ": translated exactly (reads " + string.Join(", ", fs.Select(f => (string)f!)) + ")");
            }
            else errors.Add(name + ": rejected (" + r["code"] + ") at " + ((Num)r["at"]!).Raw + ": " + r["message"]);
        }
        var report = new D { ["source"] = "cel", ["translated"] = translated, ["skipped"] = new L(), ["errors"] = errors };
        return PolicyBridge.Result(predicates, new L(), report);
    }
}
