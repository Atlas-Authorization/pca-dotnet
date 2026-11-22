using System.Collections;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

/// <summary>
/// A YAML 1.2 emitter for parsed JSON trees (Dictionary, List, string, bool, number, null) that writes byte for byte what the <c>yaml</c> package's
/// default <c>stringify</c> writes: block collections with two-space indentation (sequences indented under their key), plain scalars unless they
/// would read back as another type (then quoted), literal or folded block scalars for multi-line text, double quotes with YAML escapes, and lines
/// folded at 80 columns. A direct port of that library's string, number, pair and collection stringifiers for the node kinds a JSON tree has.
/// A collection that appears more than once in a tree (the same instance) is written once with an anchor (<c>&amp;a1</c>) and then as an alias
/// (<c>*a1</c>), as the reference does; a cycle becomes an alias too. A non-finite number or a value that is not a JSON value is refused.
/// </summary>
public static class YamlEmit
{
    const int LineWidth = 80, MinContentWidth = 20, DqMinMultiline = 40;
    const string Flow = "flow", Block = "block", Quoted = "quoted";

    /// <summary>The document text of <paramref name="value"/>: the block-style YAML followed by a newline.</summary>
    public static string Stringify(object? value)
    {
        var ctx = new Ctx { Anchors = new Anchors(value) };
        return StringifyNode(value, ctx) + "\n";
    }

    /// <summary>The anchor names of the collections met more than once (numbered at the second sighting) and which are already written.</summary>
    sealed class Anchors
    {
        public readonly Dictionary<object, string> Names = new(ReferenceEqualityComparer.Instance);
        public readonly HashSet<object> Written = new(ReferenceEqualityComparer.Instance);
        readonly HashSet<object> _seen = new(ReferenceEqualityComparer.Instance);
        int _count;

        public Anchors(object? root) => Walk(root);

        void Walk(object? v)
        {
            if (v is not D && v is not L) return;
            if (!_seen.Add(v))
            {
                if (!Names.ContainsKey(v)) Names[v] = "a" + (++_count);
                return;
            }
            if (v is D m) { foreach (var k in JsKeys(m)) Walk(m[k]); }
            else foreach (var x in (L)v) Walk(x);
        }

        /// <summary>True when <paramref name="v"/> is a repeat of a collection whose anchor is already written (it is emitted as an alias).</summary>
        public bool IsAlias(object? v) => v != null && Written.Contains(v);
    }

    sealed class Ctx
    {
        public string Indent = "";
        public string IndentStep = "  ";
        public int? IndentAtStart;
        public bool ImplicitKey, ActualString, ForceBlockIndent;
        public Anchors Anchors = null!;

        public Ctx Copy() => (Ctx)MemberwiseClone();
    }

    // ---- nodes ----

    static string StringifyNode(object? v, Ctx ctx)
    {
        if (v is D || v is L)
        {
            ctx.Anchors.Names.TryGetValue(v, out var anchor);
            if (anchor != null && !ctx.Anchors.Written.Add(v)) return "*" + anchor;
            var props = anchor == null ? null : "&" + anchor;
            if (props != null) ctx.IndentAtStart = (ctx.IndentAtStart ?? 0) + props.Length + 1;
            var str = v is D m ? StringifyMap(m, ctx) : StringifySeq((L)v, ctx);
            if (props == null) return str;
            return str[0] == '{' || str[0] == '[' ? props + " " + str : props + "\n" + ctx.Indent + str;
        }
        if (v is string s) { var c = ctx.Copy(); c.ActualString = true; return StringifyString(s, c); }
        if (v == null) return "null";
        if (v is bool b) return b ? "true" : "false";
        return StringifyNumber(v);
    }

    static string StringifyNumber(object v)
    {
        double? d = v switch
        {
            Num n => double.TryParse(n.Raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var x) ? x : null,
            int i => i,
            long l => l,
            double dd => dd,
            _ => null,
        };
        if (d == null || double.IsNaN(d.Value) || double.IsInfinity(d.Value)) throw new ArgumentException("YAML: not a JSON number: " + v);
        if (d == 0 && double.IsNegative(d.Value)) return "-0";
        return AtlasPca.InteropJs.JsX.JsNumString(d.Value);
    }

    static List<string> JsKeys(D m) => IntentJs.JsKeys(m.Keys).ToList();

    static string StringifyMap(D m, Ctx ctx)
    {
        var itemCtx = ctx.Copy();
        itemCtx.Indent = ctx.Indent;
        var lines = new List<string>();
        foreach (var k in JsKeys(m)) lines.Add(StringifyPair(k, m[k], itemCtx));
        return Join(lines, ctx.Indent, "{}");
    }

    static string StringifySeq(L l, Ctx ctx)
    {
        var itemCtx = ctx.Copy();
        itemCtx.Indent = ctx.Indent + "  ";
        var lines = new List<string>();
        foreach (var x in l) lines.Add("- " + StringifyNode(x, itemCtx));
        return Join(lines, ctx.Indent, "[]");
    }

    static string Join(List<string> lines, string indent, string empty)
    {
        if (lines.Count == 0) return empty;
        var b = new StringBuilder(lines[0]);
        for (int i = 1; i < lines.Count; i++)
        {
            var line = lines[i];
            if (line.Length > 0) b.Append('\n').Append(indent).Append(line); else b.Append('\n');
        }
        return b.ToString();
    }

    static string StringifyPair(string key, object? value, Ctx ctx0)
    {
        var indent = ctx0.Indent;
        var ctx = ctx0.Copy();
        ctx.Indent = indent + ctx0.IndentStep;
        ctx.ImplicitKey = true;
        var str = StringifyNode(key, ctx);
        var explicitKey = str.Length > 1024;
        str = explicitKey ? "? " + str + "\n" + indent + ":" : str + ":";
        ctx.ImplicitKey = false;
        var alias = ctx.Anchors.IsAlias(value);
        var collection = !alias && (value is D || value is L);
        if (!explicitKey && !collection && !alias) ctx.IndentAtStart = str.Length + 1;
        var valueStr = StringifyNode(value, ctx);
        var ws = " ";
        if (!explicitKey && collection)
        {
            var hasNewline = valueStr.Contains('\n');
            var empty = value is D vm ? vm.Count == 0 : ((L)value!).Count == 0;
            if (hasNewline || !empty)
            {
                var sp0 = valueStr.IndexOf(' ');
                var propsLine = hasNewline && valueStr[0] == '&' && (sp0 == -1 || valueStr.IndexOf('\n') < sp0); // "&a1" alone on its line
                if (!propsLine) ws = "\n" + ctx.Indent;
            }
        }
        else if (valueStr.Length == 0 || valueStr[0] == '\n') ws = "";
        return str + ws + valueStr;
    }

    // ---- strings ----

    static readonly Regex DocMarker = new(@"(?:^|[\n\r\u2028\u2029])(?:%|---|\.\.\.)", RegexOptions.CultureInvariant);
    static readonly Regex PlainForbidden = new(@"^[\n\t ,\[\]{}#&*!|>'""%@`]|^[?-]\z|^[?-][ \t]|[\n:][ \t]|[ \t]\n|[\n\t ]#|[\n\t :]\z", RegexOptions.CultureInvariant);
    // the core schema's default tags that would read a plain scalar back as a non-string
    static readonly Regex[] NonString =
    {
        new(@"^(?:~|[Nn]ull|NULL)?\z"), new(@"^(?:[Tt]rue|TRUE|[Ff]alse|FALSE)\z"), new(@"^0o[0-7]+\z"), new(@"^[-+]?[0-9]+\z"),
        new(@"^0x[0-9a-fA-F]+\z"), new(@"^(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)\z"), new(@"^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+\z"),
        new(@"^[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)\z"),
    };
    static readonly Regex WsAroundNl = new(@"[ \t]\n|\n[ \t]");
    static readonly Regex NlRun = new(@"\n+");

    static bool ContainsDocumentMarker(string s) => DocMarker.IsMatch(s);

    // s.replace(/\n+/g, '$&' + suffix): every newline run followed by suffix
    static string AfterNewlines(string s, string suffix) => NlRun.Replace(s, m => m.Value + suffix);

    static bool ForcesDoubleQuotes(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c <= 0x08 || (c >= 0x0b && c <= 0x1f) || (c >= 0x7f && c <= 0x9f)) return true;
            if (char.IsHighSurrogate(c)) { if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) i++; else return true; }
            else if (char.IsLowSurrogate(c)) return true;
        }
        return false;
    }

    static string StringifyString(string value, Ctx ctx) => ForcesDoubleQuotes(value) ? DoubleQuotedString(value, ctx) : PlainString(value, ctx);

    static string PlainString(string value, Ctx ctx)
    {
        var hasNl = value.Contains('\n');
        if (ctx.ImplicitKey && hasNl) return QuotedString(value, ctx);
        if (PlainForbidden.IsMatch(value)) return ctx.ImplicitKey || !hasNl ? QuotedString(value, ctx) : BlockString(value, ctx);
        if (!ctx.ImplicitKey && hasNl) return BlockString(value, ctx); // the string has no explicit type: block style is preferred where allowed
        if (ContainsDocumentMarker(value))
        {
            if (ctx.Indent.Length == 0) { ctx.ForceBlockIndent = true; return BlockString(value, ctx); }
            else if (ctx.ImplicitKey && ctx.Indent == ctx.IndentStep) return QuotedString(value, ctx);
        }
        var str = AfterNewlines(value, "\n" + ctx.Indent);
        if (ctx.ActualString) foreach (var p in NonString) if (p.IsMatch(str)) return QuotedString(value, ctx);
        return ctx.ImplicitKey ? str : FoldFlowLines(str, ctx.Indent, Flow, ctx.IndentAtStart, null);
    }

    static string QuotedString(string value, Ctx ctx)
    {
        var hasDouble = value.Contains('"'); var hasSingle = value.Contains('\'');
        return hasDouble && !hasSingle ? SingleQuotedString(value, ctx) : DoubleQuotedString(value, ctx);
    }

    static string SingleQuotedString(string value, Ctx ctx)
    {
        if ((ctx.ImplicitKey && value.Contains('\n')) || WsAroundNl.IsMatch(value)) return DoubleQuotedString(value, ctx);
        var indent = ctx.Indent.Length > 0 ? ctx.Indent : ContainsDocumentMarker(value) ? "  " : "";
        var res = "'" + AfterNewlines(value.Replace("'", "''"), "\n" + indent) + "'";
        return ctx.ImplicitKey ? res : FoldFlowLines(res, indent, Flow, ctx.IndentAtStart, null);
    }

    static char At(string s, int i) => i >= 0 && i < s.Length ? s[i] : '\0';

    static string DoubleQuotedString(string value, Ctx ctx)
    {
        var json = JsJson.Stringify(value);
        var indent = ctx.Indent.Length > 0 ? ctx.Indent : ContainsDocumentMarker(value) ? "  " : "";
        var str = new StringBuilder();
        void Add(int from, int to) => str.Append(json, from, to - from);
        int start = 0;
        for (int i = 0; i < json.Length; i++)
        {
            var ch = json[i];
            if (ch == ' ' && At(json, i + 1) == '\\' && At(json, i + 2) == 'n')
            {
                // a space before a newline is escaped so it is not folded
                Add(start, i); str.Append("\\ ");
                i += 1;
                start = i;
                ch = '\\';
            }
            if (ch == '\\')
            {
                switch (At(json, i + 1))
                {
                    case 'u':
                    {
                        Add(start, i);
                        var code = json.Substring(Math.Min(i + 2, json.Length), Math.Min(i + 6, json.Length) - Math.Min(i + 2, json.Length));
                        switch (code)
                        {
                            case "0000": str.Append("\\0"); break;
                            case "0007": str.Append("\\a"); break;
                            case "000b": str.Append("\\v"); break;
                            case "001b": str.Append("\\e"); break;
                            case "0085": str.Append("\\N"); break;
                            case "00a0": str.Append("\\_"); break;
                            case "2028": str.Append("\\L"); break;
                            case "2029": str.Append("\\P"); break;
                            default:
                                if (code.StartsWith("00", StringComparison.Ordinal)) str.Append("\\x").Append(code.AsSpan(2));
                                else Add(i, Math.Min(i + 6, json.Length));
                                break;
                        }
                        i += 5;
                        start = i + 1;
                        break;
                    }
                    case 'n':
                        if (ctx.ImplicitKey || At(json, i + 2) == '"' || json.Length < DqMinMultiline) i += 1;
                        else
                        {
                            // folding eats the first newline
                            Add(start, i); str.Append("\n\n");
                            while (At(json, i + 2) == '\\' && At(json, i + 3) == 'n' && At(json, i + 4) != '"') { str.Append('\n'); i += 2; }
                            str.Append(indent);
                            // a space after a newline is escaped so it is not folded
                            if (At(json, i + 2) == ' ') str.Append('\\');
                            i += 1;
                            start = i + 1;
                        }
                        break;
                    default:
                        i += 1;
                        break;
                }
            }
        }
        string res;
        if (start != 0) { Add(Math.Min(start, json.Length), json.Length); res = str.ToString(); }
        else res = json;
        return ctx.ImplicitKey ? res : FoldFlowLines(res, indent, Quoted, ctx.IndentAtStart, null);
    }

    static bool LineLengthOverLimit(string str, int lineWidth, int indentLength)
    {
        var limit = lineWidth - indentLength;
        var strLen = str.Length;
        if (strLen <= limit) return false;
        for (int i = 0, start = 0; i < strLen; ++i)
        {
            if (str[i] == '\n')
            {
                if (i - start > limit) return true;
                start = i + 1;
                if (strLen - start <= limit) return false;
            }
        }
        return true;
    }

    static readonly Regex BlockEndNl = new(@"(^|(?<!\n))\n+(?!\n|\z)");
    static readonly Regex TrailingWsLine = new(@"\n[\t ]+\z");
    // JavaScript's . excludes \n \r \u2028 \u2029 (not \u0085, which never reaches a block scalar: it forces double quotes)
    static readonly Regex MoreIndented = new(@"(?:^|\n)([\t ][^\n\r\u2028\u2029]*)(?:([\n\t ]*)\n(?![\n\t ]))?");

    static string BlockString(string value, Ctx ctx)
    {
        // a block cannot end in whitespace unless its last line is non-empty
        if (TrailingWsLine.IsMatch(value)) return QuotedString(value, ctx);
        var indent = ctx.Indent.Length > 0 ? ctx.Indent : ctx.ForceBlockIndent || ContainsDocumentMarker(value) ? "  " : "";
        var literal = !LineLengthOverLimit(value, LineWidth, indent.Length);
        if (value.Length == 0) return literal ? "|\n" : ">\n";
        // chomping from the whitespace at the value's end
        string chomp;
        int endStart;
        for (endStart = value.Length; endStart > 0; --endStart)
        {
            var ch = value[endStart - 1];
            if (ch != '\n' && ch != '\t' && ch != ' ') break;
        }
        var end = value[endStart..];
        var endNlPos = end.IndexOf('\n');
        if (endNlPos == -1) chomp = "-";
        else if (value == end || endNlPos != end.Length - 1) chomp = "+";
        else chomp = "";
        if (end.Length > 0)
        {
            value = value[..^end.Length];
            if (end[^1] == '\n') end = end[..^1];
            end = BlockEndNl.Replace(end, m => m.Value + indent);
        }
        // indent indicator from the whitespace at the value's start
        var startWithSpace = false;
        int startEnd, startNlPos = -1;
        for (startEnd = 0; startEnd < value.Length; ++startEnd)
        {
            var ch = value[startEnd];
            if (ch == ' ') startWithSpace = true;
            else if (ch == '\n') startNlPos = startEnd;
            else break;
        }
        var start = value[..(startNlPos < startEnd ? startNlPos + 1 : startEnd)];
        if (start.Length > 0)
        {
            value = value[start.Length..];
            start = AfterNewlines(start, indent);
        }
        var indentSize = indent.Length > 0 ? "2" : "1"; // the root is at -1
        var header = (startWithSpace ? indentSize : "") + chomp;
        if (!literal)
        {
            var prefixed = NlRun.Replace(value, m => "\n" + m.Value); // value.replace(/\n+/g, '\n$&')
            var unfolded = MoreIndented.Replace(prefixed, m => m.Groups[1].Value + (m.Groups[2].Success ? m.Groups[2].Value : ""));
            var foldedValue = AfterNewlines(unfolded, indent);
            var overflow = false;
            var body = FoldFlowLines(start + foldedValue + end, indent, Block, ctx.Indent.Length, o => overflow = o);
            if (!overflow) return ">" + header + "\n" + indent + body;
        }
        value = AfterNewlines(value, indent);
        return "|" + header + "\n" + indent + start + value + end;
    }

    // ---- folding ----

    static int ConsumeMoreIndentedLines(string text, int i, int indent)
    {
        int end = i, start = i + 1;
        var ch = At(text, start);
        while (ch == ' ' || ch == '\t')
        {
            if (i < start + indent) ch = At(text, ++i);
            else
            {
                do { ch = At(text, ++i); } while (ch != '\0' && ch != '\n');
                end = i;
                start = i + 1;
                ch = At(text, start);
            }
        }
        return end;
    }

    /// <summary>Keeps text at up to the line width by splitting on spaces not followed by newlines or spaces (anywhere in quoted mode); lines end with a
    /// newline and start with <paramref name="indent"/>. <paramref name="indentAtStart"/> is where the first line already starts (null = the indent).</summary>
    static string FoldFlowLines(string text, string indent, string mode, int? indentAtStart, Action<bool>? overflowOut)
    {
        int lineWidth = LineWidth, minContentWidth = MinContentWidth;
        if (lineWidth < minContentWidth) minContentWidth = 0;
        var endStep = Math.Max(1 + minContentWidth, 1 + lineWidth - indent.Length);
        if (text.Length <= endStep) return text;
        var folds = new List<int>();
        var escapedFolds = new HashSet<int>();
        var end = lineWidth - indent.Length;
        if (indentAtStart is int ias)
        {
            if (ias > lineWidth - Math.Max(2, minContentWidth)) folds.Add(0);
            else end = lineWidth - ias;
        }
        int? split = null;
        var prev = '\0';
        var overflow = false;
        int i = -1, escStart = -1, escEnd = -1;
        if (mode == Block)
        {
            i = ConsumeMoreIndentedLines(text, i, indent.Length);
            if (i != -1) end = i + endStep;
        }
        for (char ch; (ch = At(text, i += 1)) != '\0';)
        {
            if (mode == Quoted && ch == '\\')
            {
                escStart = i;
                switch (At(text, i + 1))
                {
                    case 'x': i += 3; break;
                    case 'u': i += 5; break;
                    case 'U': i += 9; break;
                    default: i += 1; break;
                }
                escEnd = i;
            }
            if (ch == '\n')
            {
                if (mode == Block) i = ConsumeMoreIndentedLines(text, i, indent.Length);
                end = i + indent.Length + endStep;
                split = null;
            }
            else
            {
                if (ch == ' ' && prev != '\0' && prev != ' ' && prev != '\n' && prev != '\t')
                {
                    // a space surrounded by non-space can become a newline plus indent
                    var next = At(text, i + 1);
                    if (next != '\0' && next != ' ' && next != '\n' && next != '\t') split = i;
                }
                if (i >= end)
                {
                    if (split is int sp)
                    {
                        folds.Add(sp);
                        end = sp + endStep;
                        split = null;
                    }
                    else if (mode == Quoted)
                    {
                        // white space collected at the end may stretch past the line width
                        while (prev == ' ' || prev == '\t')
                        {
                            prev = ch;
                            ch = At(text, i += 1);
                            overflow = true;
                        }
                        // account for the newline escape, but do not break a preceding escape
                        var j = i > escEnd + 1 ? i - 2 : escStart - 1;
                        if (escapedFolds.Contains(j)) return text;
                        folds.Add(j);
                        escapedFolds.Add(j);
                        end = j + endStep;
                        split = null;
                    }
                    else overflow = true;
                }
            }
            prev = ch;
        }
        overflowOut?.Invoke(overflow);
        if (folds.Count == 0) return text;
        var res = new StringBuilder(text[..Math.Min(folds[0], text.Length)]);
        for (int k = 0; k < folds.Count; ++k)
        {
            var fold = folds[k];
            var e = k + 1 < folds.Count && folds[k + 1] != 0 ? folds[k + 1] : text.Length;
            if (fold == 0) res = new StringBuilder("\n" + indent + text[..Math.Min(e, text.Length)]);
            else
            {
                if (mode == Quoted && escapedFolds.Contains(fold)) res.Append(text[fold]).Append('\\');
                var from = Math.Min(fold + 1, text.Length);
                var to = Math.Min(Math.Max(e, fold + 1), text.Length);
                res.Append('\n').Append(indent).Append(text, from, Math.Max(0, to - from));
            }
        }
        return res.ToString();
    }

    // ---- the import writer ----

    /// <summary>The YAML an import writes: <c>{ns, actions: [def...]}</c> with each def written in full form. <paramref name="rules"/> (verb to a
    /// business-rules value; may be null) re-attaches each action's rules block, so a rewrite never drops them.</summary>
    public static string DefsToYaml(string ns, IEnumerable<D> defs, D? rules = null)
    {
        var actions = new L();
        foreach (var d in defs)
        {
            if (rules != null && d.GetValueOrDefault("verb") is string verb && rules.ContainsKey(verb)) actions.Add(new D(d) { ["rules"] = rules[verb] });
            else actions.Add(d);
        }
        return Stringify(new D { ["ns"] = ns, ["actions"] = actions });
    }
}
