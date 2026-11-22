// The authoring-file text loader: YAML 1.2 core schema or JSON text, with source positions. The syntax layer is YamlDotNet's scanner and parser;
// only its EVENT stream is used. Everything the reference decides about meaning is done here, so the result does not depend on YamlDotNet's own
// resolver or alias handling: the tree is built from events, plain scalars are resolved with the YAML 1.2 core schema (null, bool, int, 0o / 0x,
// float, .inf, .nan; everything else a string), mapping keys are stringified the way JavaScript does, aliases are refused, "<<" is an ordinary
// key, and positions are the 1-based start of each action and each param key.
//
// Where this differs from the reference it is STRICTER (it refuses): an explicit tag other than !!str / !!map / !!seq, a complex (non-scalar)
// mapping key, two keys that are equal once stringified, a bare carriage return used as a line break, more than one document. Syntax error
// wording and line/column of a syntax error are the parser's own.
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

/// <summary>A syntax or policy refusal of the YAML front end (message plus 1-based position).</summary>
public sealed class YamlLoadError(string message, int line = 1, int column = 1) : Exception(message)
{
    public int Line { get; } = line;
    public int Column { get; } = column;
}

public static class ActionsText
{
    const string StrTag = "tag:yaml.org,2002:str", MapTag = "tag:yaml.org,2002:map", SeqTag = "tag:yaml.org,2002:seq";
    const long Safe = 1L << 53;

    static readonly Regex IntRe = new(@"\A[-+]?[0-9]+\z"), OctRe = new(@"\A0o[0-7]+\z"), HexRe = new(@"\A0x[0-9a-fA-F]+\z"),
        FloatRe = new(@"\A[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?\z"), InfRe = new(@"\A[-+]?\.(?:inf|Inf|INF)\z"), NanRe = new(@"\A\.(?:nan|NaN|NAN)\z");

    sealed class N(string kind, int line, int col)
    {
        public readonly string Kind = kind; // scalar | map | seq
        public readonly int Line = line, Col = col;
        public object? Value;
        public readonly List<N> Seq = new();
        public readonly List<(N Key, N Val)> Map = new();
    }

    static object JsNumber(double d) => d switch
    {
        _ when double.IsNaN(d) || double.IsInfinity(d) => d,
        _ => new Num(JsX.JsNumString(d)),
    };

    static object JsInt(string text, int radix)
    {
        var neg = text.StartsWith('-');
        var digits = text.TrimStart('+', '-');
        BigInteger n = 0;
        foreach (var ch in digits) n = n * radix + Convert.ToInt32(ch.ToString(), 16);
        if (neg && n.IsZero) return JsNumber(-0.0);
        if (neg) n = -n;
        return BigInteger.Abs(n) <= Safe ? new Num(n.ToString(CultureInfo.InvariantCulture)) : JsNumber((double)n);
    }

    /// <summary>The YAML 1.2 core schema value of a plain scalar, as a JSON tree value (number, bool, null or string).</summary>
    public static object? ResolveCorePlain(string text)
    {
        if (text is "" or "~" or "null" or "Null" or "NULL") return null;
        if (text is "true" or "True" or "TRUE") return true;
        if (text is "false" or "False" or "FALSE") return false;
        if (IntRe.IsMatch(text)) return JsInt(text, 10);
        if (OctRe.IsMatch(text)) return JsInt(text[2..], 8);
        if (HexRe.IsMatch(text)) return JsInt(text[2..], 16);
        if (InfRe.IsMatch(text)) return text[0] == '-' ? double.NegativeInfinity : double.PositiveInfinity;
        if (NanRe.IsMatch(text)) return double.NaN;
        if (FloatRe.IsMatch(text))
        {
            var f = double.Parse(text, NumberStyles.Float, CultureInfo.InvariantCulture);
            return f == Math.Floor(f) && Math.Abs(f) <= Safe && !(f == 0 && text.TrimStart('+').StartsWith('-')) ? new Num(((long)f).ToString(CultureInfo.InvariantCulture)) : JsNumber(f);
        }
        return text;
    }

    static string JsKey(object? v) => v switch
    {
        null => "null",
        bool b => b ? "true" : "false",
        Num n => double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? JsX.JsNumString(d) : n.Raw,
        double d => double.IsNaN(d) ? "NaN" : d > 0 ? "Infinity" : "-Infinity",
        _ => (string)v,
    };

    static string? TagOf(string? t) => string.IsNullOrEmpty(t) ? null : t;

    static N? ParseDocument(string text, bool strict)
    {
        if (Regex.IsMatch(text, @"\r(?!\n)")) throw new YamlLoadError("bare carriage return is not accepted as a line break");
        var events = new List<ParsingEvent>();
        try
        {
            var parser = new Parser(new StringReader(text));
            while (parser.MoveNext()) events.Add(parser.Current!);
        }
        catch (YamlException e) { throw new YamlLoadError(e.Message, (int) e.Start.Line, (int) e.Start.Column); }
        int pos = 0, docs = 0;

        N Node()
        {
            var ev = events[pos++];
            int line = (int) ev.Start.Line, col = (int) ev.Start.Column;
            if (ev is AnchorAlias) throw new YamlLoadError("Alias resolution is disabled", line, col);
            var tag = ev switch { Scalar s => TagOf(s.Tag.IsEmpty ? null : s.Tag.Value), SequenceStart q => TagOf(q.Tag.IsEmpty ? null : q.Tag.Value), MappingStart m => TagOf(m.Tag.IsEmpty ? null : m.Tag.Value), _ => null };
            if (tag != null && tag != StrTag && tag != MapTag && tag != SeqTag) throw new YamlLoadError("Unresolved or unsupported tag: " + tag, line, col);
            switch (ev)
            {
                case Scalar sc:
                {
                    var n = new N("scalar", line, col);
                    n.Value = sc.Style == ScalarStyle.Plain && tag == null ? ResolveCorePlain(sc.Value) : sc.Value;
                    return n;
                }
                case SequenceStart:
                {
                    var n = new N("seq", line, col);
                    while (events[pos] is not SequenceEnd) n.Seq.Add(Node());
                    pos++;
                    return n;
                }
                case MappingStart:
                {
                    var n = new N("map", line, col);
                    var seen = new HashSet<string>(StringComparer.Ordinal);
                    while (events[pos] is not MappingEnd)
                    {
                        var key = Node();
                        var val = Node();
                        if (strict)
                        {
                            if (key.Kind != "scalar") throw new YamlLoadError("complex mapping keys are not accepted", key.Line, key.Col);
                            if (!seen.Add(JsKey(key.Value))) throw new YamlLoadError("Map keys must be unique", key.Line, key.Col);
                        }
                        n.Map.Add((key, val));
                    }
                    pos++;
                    return n;
                }
                default: throw new YamlLoadError("unexpected parser event " + ev.GetType().Name, line, col);
            }
        }

        N? root = null;
        while (pos < events.Count)
        {
            if (events[pos] is DocumentStart)
            {
                if (++docs > 1) throw new YamlLoadError("Source contains multiple documents; please use YAML.parseAllDocuments()");
                pos++;
                if (events[pos] is not DocumentEnd) root = Node();
            }
            else pos++;
        }
        return root;
    }

    static object? ToValue(N? n)
    {
        if (n == null) return null;
        if (n.Kind == "scalar") return n.Value;
        if (n.Kind == "seq") return n.Seq.Select(ToValue).ToList();
        var o = new D();
        foreach (var (k, v) in n.Map)
        {
            if (k.Kind != "scalar") throw new YamlLoadError("complex mapping keys are not accepted", k.Line, k.Col);
            o[JsKey(k.Value)] = ToValue(v);
        }
        return o;
    }

    // per-entry positions of an authoring document (actions items and their params keys), by entry index; null when not a mapping
    static List<(int Line, int Col, D Params)>? PositionsOf(N? root)
    {
        if (root == null || root.Kind != "map") return null;
        N? actions = null;
        foreach (var (k, v) in root.Map) if (k.Kind == "scalar" && k.Value is "actions") actions = v;
        var items = actions is { Kind: "seq" } ? actions.Seq : new List<N> { root };
        var res = new List<(int, int, D)>();
        foreach (var it in items)
        {
            var ps = new D();
            if (it.Kind == "map")
            {
                N? pm = null;
                foreach (var (k, v) in it.Map) if (k.Kind == "scalar" && k.Value is "params") pm = v;
                if (pm is { Kind: "map" })
                    foreach (var (k, _) in pm.Map)
                        if (k.Kind == "scalar") ps[k.Value == null ? "" : JsKey(k.Value)] = new D { ["line"] = (long)k.Line, ["column"] = (long)k.Col };
            }
            res.Add((it.Line, it.Col, ps));
        }
        return res;
    }

    static void AttachPositions(D res, List<(int Line, int Col, D Params)> pos)
    {
        var errors = (L)res["errors"]!;
        var failed = new HashSet<long>(errors.OfType<D>().Select(e => e.GetValueOrDefault("index")).OfType<long>());
        var order = Enumerable.Range(0, pos.Count).Where(i => !failed.Contains(i)).ToList();
        var defs = (L)res["defs"]!;
        for (int k = 0; k < defs.Count; k++)
            if (k < order.Count)
            {
                var p = pos[order[k]];
                ((D)res["locs"]!)[(string)((D)defs[k]!)["verb"]!] = new D { ["line"] = (long)p.Line, ["column"] = (long)p.Col, ["params"] = p.Params };
            }
        foreach (var e in errors.OfType<D>())
        {
            if (e.GetValueOrDefault("index") is long ix)
            {
                if (ix >= 0 && ix < pos.Count) { e["line"] = (long)pos[(int)ix].Line; e["column"] = (long)pos[(int)ix].Col; }
            }
            else { e["line"] = 1L; e["column"] = 1L; }
        }
    }

    static D Fail(string message, int line = 1, int column = 1) => new()
    {
        ["defs"] = new L(), ["notes"] = new L(), ["errors"] = new L { new D { ["message"] = message, ["line"] = (long)line, ["column"] = (long)column } },
        ["locs"] = new D(), ["rules"] = new D(),
    };

    /// <summary>Load an authoring file (YAML 1.2 core or JSON, <paramref name="fmt"/> "yaml" or "json") with source positions. Input above
    /// <see cref="ActionAuthor.MaxAuthorBytes"/> is refused. Never throws.</summary>
    public static D LoadActionsText(string text, string fmt = "yaml")
    {
        if (Encoding.UTF8.GetByteCount(text) > ActionAuthor.MaxAuthorBytes) return Fail($"the file is larger than {ActionAuthor.MaxAuthorBytes} bytes");
        List<(int Line, int Col, D Params)>? positions = null;
        object? value;
        if (fmt == "json")
        {
            try { value = Pca.ParseJson(text); }
            catch (Exception e) { return Fail("not JSON: " + e.Message); }
            try { positions = PositionsOf(ParseDocument(text, false)); } // JSON is YAML: only the positions come from the YAML parse
            catch (Exception) { positions = null; }
        }
        else
        {
            try
            {
                var root = ParseDocument(text.StartsWith('\uFEFF') ? text[1..] : text, true); // a byte-order mark opens a YAML stream without being part of it
                value = ToValue(root);
                positions = PositionsOf(root);
            }
            catch (YamlLoadError e) { return Fail("not YAML: " + e.Message, e.Line, e.Column); }
        }
        var res = ActionAuthor.LoadActionsValue(value);
        if (positions != null) AttachPositions(res, positions);
        return res;
    }
}
