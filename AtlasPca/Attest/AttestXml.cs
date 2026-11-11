// A small XML reader and a canonicaliser (inclusive C14N; identical to C14N 1.1 for documents without xml:* attributes, which the
// RIM profile refuses) for the NVIDIA RIM XMLDSig check. Only the subset the profile needs is supported: elements, attributes,
// namespaces, text, CDATA and the predefined and numeric character references. A comment, processing instruction or DOCTYPE is not
// interpreted: the first of them (in document order) is recorded as a profile violation, and the verifier refuses the document
// before any cryptography.
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace AtlasPca;

internal sealed class XmlAttr
{
    public string Name = "", Prefix = "", Local = "", Ns = "", Value = "";
}

internal sealed class XmlNode
{
    public bool Elem;
    public string Name = "", Prefix = "", Local = "", Ns = "";
    public List<XmlAttr> Attrs = new();
    public List<(string Prefix, string Uri)> Decls = new();
    public List<XmlNode> Children = new();
    public string Text = "";
    public XmlNode? Parent;

    /// <summary>Resolves a prefix ("" is the default namespace) through the element's ancestors.</summary>
    public string? LookupNs(string prefix)
    {
        for (var e = this; e != null; e = e.Parent)
            foreach (var d in e.Decls) if (d.Prefix == prefix) return d.Uri;
        return prefix == "xml" ? "http://www.w3.org/XML/1998/namespace" : null; // bound without a declaration, so xml:* reaches the profile check
    }

    public void AppendText(string t)
    {
        if (Children.Count > 0 && !Children[^1].Elem) { Children[^1].Text += t; return; }
        Children.Add(new XmlNode { Text = t, Parent = this });
    }

    public void ResolveNames()
    {
        foreach (var d in Decls)
        {
            if (d.Prefix == "") continue;
            if (!d.Prefix.All(c => c < 0x80)) throw new AttestError($"namespace prefix {d.Prefix} is not ASCII");
            if (Parent?.LookupNs(d.Prefix) is { } bound && bound != d.Uri) throw new AttestError($"namespace prefix {d.Prefix} is redeclared to a different URI");
        }
        (Prefix, Local) = AttestXml.SplitQName(Name);
        var uri = LookupNs(Prefix);
        if (Prefix != "" && uri == null) throw new AttestError($"namespace prefix {Prefix} is not bound");
        Ns = uri ?? "";
        foreach (var a in Attrs)
        {
            if (a.Prefix == "") continue;
            var u = LookupNs(a.Prefix);
            if (u == null) throw new AttestError($"namespace prefix {a.Prefix} is not bound");
            a.Ns = u;
        }
    }

    public string Attr(string name) => Attrs.FirstOrDefault(a => a.Name == name)?.Value ?? "";

    public string TextContent() => !Elem ? Text : string.Concat(Children.Select(c => c.TextContent()));

    public List<XmlNode> ElementChildren() => Children.Where(c => c.Elem).ToList();

    public List<XmlNode> ElementChildrenNs(string ns, string local) => ElementChildren().Where(c => c.Ns == ns && c.Local == local).ToList();

    /// <summary>Counts the descendant elements with the given namespace and local name.</summary>
    public int DescendantsNs(string ns, string local)
    {
        int total = 0;
        foreach (var c in ElementChildren())
        {
            if (c.Ns == ns && c.Local == local) total++;
            total += c.DescendantsNs(ns, local);
        }
        return total;
    }

    public void RemoveChild(XmlNode c) => Children.Remove(c);

    /// <summary>The in-scope namespace bindings of the element (its own declarations included).</summary>
    public Dictionary<string, string> Scope()
    {
        var chain = new List<XmlNode>();
        for (var e = this; e != null; e = e.Parent) chain.Add(e);
        var o = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = chain.Count - 1; i >= 0; i--) foreach (var d in chain[i].Decls) o[d.Prefix] = d.Uri;
        return o;
    }
}

internal sealed class XmlDoc
{
    public XmlNode? Root;
    public string Violation = "";
}

internal static class AttestXml
{
    /// <summary>The verifier and the canonicaliser recurse per level: a stack overflow would end the process, not fail closed (the reference's RangeError is caught).</summary>
    internal const int MaxDepth = 256;

    // The reference parser's Name:(Name)? pattern (xmldom 0.8.15 conventions.js tagNamePattern), checked on every element and attribute name.
    const string NameStart = @"[A-Z_a-z\xC0-\xD6\xD8-\xF6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]";
    const string NameRest = @"[\-\.0-9A-Z_a-z\xC0-\xD6\xD8-\xF6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\u00B7\u0300-\u036F\u203F-\u2040]";
    const string NamePattern = "^" + NameStart + NameRest + "*(?::" + NameStart + NameRest + "*)?\\z";
    static Regex NameRe => Rx.Get(NamePattern, RegexOptions.CultureInvariant);

    static bool IsSpace(char c) => c is ' ' or '\t' or '\n' or '\r';

    internal static (string Prefix, string Local) SplitQName(string name)
    {
        int i = name.IndexOf(':');
        return i > 0 ? (name[..i], name[(i + 1)..]) : ("", name);
    }

    static string Decode(string s)
    {
        if (!s.Contains('&')) return s;
        var sb = new StringBuilder();
        for (int i = 0; i < s.Length;)
        {
            if (s[i] != '&') { sb.Append(s[i]); i++; continue; }
            int j = s.IndexOf(';', i);
            if (j < 0) throw new AttestError("unterminated entity reference");
            var ent = s[(i + 1)..j];
            i = j + 1;
            switch (ent)
            {
                case "lt": sb.Append('<'); break;
                case "gt": sb.Append('>'); break;
                case "amp": sb.Append('&'); break;
                case "quot": sb.Append('"'); break;
                case "apos": sb.Append('\''); break;
                default:
                    {
                        if (!ent.StartsWith('#')) throw new AttestError($"undefined entity &{ent};");
                        bool hex = ent.StartsWith("#x", StringComparison.Ordinal);
                        var digits = hex ? ent[2..] : ent[1..];
                        bool ok = long.TryParse(digits, hex ? NumberStyles.AllowHexSpecifier : NumberStyles.None, CultureInfo.InvariantCulture, out var n);
                        if (hex && ok && digits.Length > 8) ok = false;
                        if (!ok || !(n == 0x9 || n == 0xa || n == 0xd || (n >= 0x20 && n <= 0xd7ff) || (n >= 0xe000 && n <= 0xfffd) || (n >= 0x10000 && n <= 0x10ffff)))
                            throw new AttestError($"invalid character reference &{ent};");
                        sb.Append(char.ConvertFromUtf32((int)n));
                        break;
                    }
            }
        }
        return sb.ToString();
    }

    internal static XmlDoc Parse(string s)
    {
        // the reference's DOMParser normalises line endings first: a signed CRLF document digests the same here
        s = s.Replace("\r\n", "\n").Replace("\r\u0085", "\n").Replace('\r', '\n').Replace('\u0085', '\n').Replace('\u2028', '\n');
        var doc = new XmlDoc();
        void Note(string v) { if (doc.Violation.Length == 0) doc.Violation = v; }
        XmlNode? cur = null;
        int i = 0, depth = 0;
        while (i < s.Length)
        {
            if (s[i] != '<')
            {
                int end = s.IndexOf('<', i);
                if (end < 0) end = s.Length;
                var txt = s[i..end];
                i = end;
                if (cur == null)
                {
                    if (txt.Trim(' ', '\t', '\n', '\r').Length != 0) throw new AttestError("text outside the document element");
                    continue;
                }
                cur.AppendText(Decode(txt));
                continue;
            }
            var rest = s.AsSpan(i);
            if (rest.StartsWith("<!--", StringComparison.Ordinal))
            {
                int j = rest[4..].IndexOf("-->", StringComparison.Ordinal);
                if (j < 0) throw new AttestError("unterminated comment");
                Note("XML comments are not permitted");
                i += 4 + j + 3;
            }
            else if (rest.StartsWith("<?", StringComparison.Ordinal))
            {
                int j = rest.IndexOf("?>", StringComparison.Ordinal);
                if (j < 0) throw new AttestError("unterminated processing instruction");
                Note("XML processing instructions are not permitted");
                i += j + 2;
            }
            else if (rest.StartsWith("<![CDATA[", StringComparison.Ordinal))
            {
                int j = rest.IndexOf("]]>", StringComparison.Ordinal);
                if (j < 0 || cur == null) throw new AttestError("misplaced or unterminated CDATA section");
                cur.AppendText(rest[9..j].ToString());
                i += j + 3;
            }
            else if (rest.StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase))
            {
                int brackets = 0, j = 0;
                for (; j < rest.Length; j++)
                {
                    if (rest[j] == '[') brackets++;
                    else if (rest[j] == ']') brackets--;
                    else if (rest[j] == '>' && brackets <= 0) break;
                }
                if (j >= rest.Length) throw new AttestError("unterminated DOCTYPE");
                Note("DTD / DOCTYPE is not permitted");
                i += j + 1;
            }
            else if (rest.StartsWith("</", StringComparison.Ordinal))
            {
                int j = rest.IndexOf('>');
                if (j < 0 || cur == null) throw new AttestError("unexpected end tag");
                var name = rest[2..j].ToString().TrimEnd(' ', '\t', '\r', '\n');
                if (name != cur.Name) throw new AttestError($"end tag </{name}> does not match <{cur.Name}>");
                cur = cur.Parent;
                depth--;
                i += j + 1;
            }
            else
            {
                var (node, selfClose, n) = ParseStartTag(rest, Note);
                i += n;
                node.Parent = cur;
                if (cur == null)
                {
                    if (doc.Root != null) throw new AttestError("more than one document element");
                    doc.Root = node;
                }
                else cur.Children.Add(node);
                node.ResolveNames();
                if (depth == MaxDepth) throw new AttestError($"elements nested deeper than {MaxDepth}");
                if (!selfClose) { cur = node; depth++; }
            }
        }
        if (cur != null) throw new AttestError($"element <{cur.Name}> is not closed");
        if (doc.Root == null) throw new AttestError("no document element");
        return doc;
    }

    /// <summary>Reads one start tag at the beginning of <paramref name="rest"/>; n is the number of chars consumed.</summary>
    static (XmlNode Node, bool SelfClose, int N) ParseStartTag(ReadOnlySpan<char> rest, Action<string> note)
    {
        int i = 1, j = i;
        while (j < rest.Length && !IsSpace(rest[j]) && rest[j] != '/' && rest[j] != '>') j++;
        var name = rest[i..j].ToString(); // a span: copying the rest of the document at every tag is quadratic in attacker input
        if (name.Length == 0) throw new AttestError("malformed start tag");
        var nameRe = NameRe;
        if (!nameRe.IsMatch(name)) throw new AttestError($"invalid tagName:{name}");
        var node = new XmlNode { Elem = true, Name = name };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        i = j;
        while (true)
        {
            while (i < rest.Length && IsSpace(rest[i])) i++;
            if (i >= rest.Length) throw new AttestError("unterminated start tag");
            if (rest[i] == '>') return (node, false, i + 1);
            if (rest[i] == '/')
            {
                if (i + 1 < rest.Length && rest[i + 1] == '>') return (node, true, i + 2);
                throw new AttestError("malformed start tag");
            }
            int k = i;
            while (k < rest.Length && !IsSpace(rest[k]) && rest[k] != '=' && rest[k] != '>' && rest[k] != '/') k++;
            var aname = rest[i..k].ToString();
            while (k < rest.Length && IsSpace(rest[k])) k++;
            if (aname.Length == 0 || k >= rest.Length || rest[k] != '=') throw new AttestError("malformed attribute");
            k++;
            while (k < rest.Length && IsSpace(rest[k])) k++;
            if (k >= rest.Length || (rest[k] != '"' && rest[k] != '\'')) throw new AttestError("unquoted attribute value");
            char q = rest[k];
            var tail = rest[(k + 1)..];
            int e = tail.IndexOf(q);
            if (e < 0) throw new AttestError("unterminated attribute value");
            var raw = tail[..e].ToString();
            e += k + 1;
            if (raw.Contains('<')) throw new AttestError("'<' in an attribute value");
            var val = Decode(raw.Replace('\t', ' ').Replace('\n', ' ')); // attribute value normalisation; Parse already turned every CR into LF
            i = e + 1;
            if (!seen.Add(aname)) throw new AttestError($"attribute {aname} is repeated");
            if (!nameRe.IsMatch(aname)) throw new AttestError($"invalid attribute:{aname}");
            if (aname.ToLowerInvariant().StartsWith("xml:", StringComparison.Ordinal)) note($"xml:* attribute '{aname}' is not permitted (C14N 1.1 profile)");
            if (aname == "xmlns") node.Decls.Add(("", val));
            else if (aname.StartsWith("xmlns:", StringComparison.Ordinal)) node.Decls.Add((aname[6..], val));
            else
            {
                var (p, l) = SplitQName(aname);
                node.Attrs.Add(new XmlAttr { Name = aname, Prefix = p, Local = l, Value = val });
            }
        }
    }

    static string EscapeText(string s)
    {
        var sb = new StringBuilder();
        foreach (var r in s)
            sb.Append(r switch { '&' => "&amp;", '<' => "&lt;", '>' => "&gt;", '\r' => "&#xD;", _ => r.ToString() });
        return sb.ToString();
    }

    static string EscapeAttr(string s)
    {
        var sb = new StringBuilder();
        foreach (var r in s)
            sb.Append(r switch { '&' => "&amp;", '<' => "&lt;", '"' => "&quot;", '\t' => "&#x9;", '\n' => "&#xA;", '\r' => "&#xD;", _ => r.ToString() });
        return sb.ToString();
    }

    /// <summary>The canonical form of the subtree at <paramref name="n"/> exactly as the reference's canonicaliser (xml-crypto's <c>C14nCanonicalization</c>) renders it,
    /// omitting the subtree <paramref name="skip"/> (the enveloped-signature transform). <paramref name="parentScope"/> is the in-scope bindings of n's ancestors (its
    /// <c>ancestorNamespaces</c>). The reference departs from the C14N text in places that decide whether a signature verifies, and this follows it byte for byte: a
    /// namespace declaration is judged by its PREFIX only (a prefix already rendered is never rendered again; <see cref="Parse"/> refuses a document that redeclares a
    /// prefix to another URI), the default namespace is rendered when an unprefixed element's namespace differs from the one its parent rendered, an apex element that
    /// lies in a default namespace renders it once (the ancestor default binding is not repeated, as C14N requires), and the declarations are
    /// ordered by JavaScript <c>localeCompare</c> on the prefix (see <see cref="XcCompare"/>).</summary>
    internal static string Canonicalize(XmlNode n, Dictionary<string, string> parentScope, XmlNode? skip)
    {
        var ancestors = parentScope.Select(kv => (Prefix: kv.Key, Uri: kv.Value)).ToList();
        var sb = new StringBuilder();
        C14nElement(sb, n, ancestors.Select(a => a.Prefix).ToList(), "", ancestors, skip);
        return sb.ToString();
    }

    /// <summary>JavaScript <c>a.localeCompare(b)</c> (ICU root collation) for the ASCII prefixes <see cref="Parse"/> admits: primary order <c>_ - .</c>, digits, then letters
    /// ignoring case; on a tie of the whole string at the primary level the first case difference decides, lower case first.</summary>
    internal static int XcCompare(string a, string b)
    {
        static int Primary(char c) => c switch { '_' => 1, '-' => 2, '.' => 3, >= '0' and <= '9' => 10 + (c - '0'), >= 'a' and <= 'z' => 100 + (c - 'a'), >= 'A' and <= 'Z' => 100 + (c - 'A'), _ => 1000 + c };
        for (int i = 0; i < a.Length && i < b.Length; i++)
        {
            int d = Primary(a[i]) - Primary(b[i]);
            if (d != 0) return d < 0 ? -1 : 1;
        }
        if (a.Length != b.Length) return a.Length < b.Length ? -1 : 1;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return char.IsLower(a[i]) ? -1 : 1;
        return 0;
    }

    static void C14nElement(StringBuilder sb, XmlNode n, List<string> prefixesInScope, string defaultNs, List<(string Prefix, string Uri)> ancestorNs, XmlNode? skip)
    {
        var list = new List<(string Prefix, string Uri)>();
        var newDefault = defaultNs;
        var defaultDecl = "";
        if (n.Prefix != "")
        {
            if (!prefixesInScope.Contains(n.Prefix)) { list.Add((n.Prefix, n.Ns)); prefixesInScope.Add(n.Prefix); }
        }
        else if (defaultNs != n.Ns)
        {
            newDefault = n.Ns;
            defaultDecl = " xmlns=\"" + n.Ns + "\"";
        }
        foreach (var d in n.Decls)
            if (d.Prefix != "" && !prefixesInScope.Contains(d.Prefix)) { list.Add((d.Prefix, d.Uri)); prefixesInScope.Add(d.Prefix); }
        foreach (var a in n.Attrs)
            if (a.Prefix != "" && a.Prefix != "xmlns" && a.Prefix != "xml" && !prefixesInScope.Contains(a.Prefix)) { list.Add((a.Prefix, a.Ns)); prefixesInScope.Add(a.Prefix); }
        foreach (var a in ancestorNs)
        {
            if (a.Prefix == "" && defaultDecl.Length > 0) continue; // an unprefixed element that declares its default namespace does not repeat the ancestor's (C14N: each namespace once)
            if (!list.Any(x => x.Prefix == a.Prefix && x.Uri == a.Uri)) list.Add(a);
        }
        list.Sort((x, y) => XcCompare(x.Prefix, y.Prefix)); // List.Sort is unstable, but two entries share a prefix only through ancestorNs, whose prefixes are unique
        sb.Append('<').Append(n.Name).Append(defaultDecl);
        foreach (var (p, uri) in list) sb.Append(p == "" ? " xmlns=\"" : " xmlns:" + p + "=\"").Append(uri).Append('"');
        var attrs = n.Attrs.OrderBy(a => a, Comparer<XmlAttr>.Create((a, b) =>
        {
            if ((a.Ns == "") != (b.Ns == "")) return a.Ns == "" ? -1 : 1;
            return string.CompareOrdinal(a.Ns + a.Local, b.Ns + b.Local); // JavaScript string order (UTF-16 code units), as the reference
        })).ToList();
        foreach (var a in attrs) sb.Append(' ').Append(a.Name).Append("=\"").Append(EscapeAttr(a.Value)).Append('"');
        sb.Append('>');
        foreach (var c in n.Children)
        {
            if (c == skip) continue;
            if (c.Elem) C14nElement(sb, c, prefixesInScope.ToList(), newDefault, new List<(string, string)>(), skip);
            else sb.Append(EscapeText(c.Text));
        }
        sb.Append("</").Append(n.Name).Append('>');
    }
}
