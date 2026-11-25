using System.Text;

namespace AtlasPca.Corpus.Tests;

/// <summary>An UNMUTATED copy of the lenient JSON reader of Pca.ParseJson (Pca.cs, hand-written; lone surrogates and every RFC 8259 number kept),
/// used only to load fixtures that tests cache for the whole test host. Stryker reuses one test host across mutants: a fixture parsed with
/// Pca.ParseJson while a parser mutant is active would stay broken for every later mutant and falsely kill them. Same tree: null, bool, string,
/// Num, List&lt;object?&gt;, Dictionary&lt;string, object?&gt;. The depth cap is the lenient one (512).</summary>
static class FixtureJson
{
    public static object? Parse(string text) => new Reader(text, 512).Run();

    sealed class Reader
    {
        readonly string t; readonly int maxDepth; int i;
        public Reader(string text, int maxDepth) { t = text; this.maxDepth = maxDepth; }
        Exception Err(string m) => new InvalidDataException($"{m} (at offset {i})");

        public object? Run()
        {
            var v = Value(1);
            Ws();
            if (i < t.Length) throw Err("trailing characters after the JSON value");
            return v;
        }

        void Ws()
        {
            while (i < t.Length)
            {
                char c = t[i];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++; else break;
            }
        }

        object? Value(int depth)
        {
            Ws();
            if (i >= t.Length) throw Err("unexpected end of input");
            char ch = t[i];
            if (ch == '{')
            {
                if (depth > maxDepth) throw Err("nesting too deep");
                i++;
                var o = new Dictionary<string, object?>();
                Ws();
                if (i < t.Length && t[i] == '}') { i++; return o; }
                for (; ; )
                {
                    Ws();
                    if (i >= t.Length || t[i] != '"') throw Err("expected a string key");
                    var k = Str();
                    Ws();
                    if (i >= t.Length || t[i] != ':') throw Err("expected ':'");
                    i++;
                    o[k] = Value(depth + 1);
                    Ws();
                    if (i < t.Length && t[i] == ',') { i++; continue; }
                    if (i < t.Length && t[i] == '}') { i++; return o; }
                    throw Err("expected ',' or '}'");
                }
            }
            if (ch == '[')
            {
                if (depth > maxDepth) throw Err("nesting too deep");
                i++;
                var a = new List<object?>();
                Ws();
                if (i < t.Length && t[i] == ']') { i++; return a; }
                for (; ; )
                {
                    a.Add(Value(depth + 1));
                    Ws();
                    if (i < t.Length && t[i] == ',') { i++; continue; }
                    if (i < t.Length && t[i] == ']') { i++; return a; }
                    throw Err("expected ',' or ']'");
                }
            }
            if (ch == '"') return Str();
            if (ch == '-' || (ch >= '0' && ch <= '9')) return Number();
            if (string.CompareOrdinal(t, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (string.CompareOrdinal(t, i, "false", 0, 5) == 0) { i += 5; return false; }
            if (string.CompareOrdinal(t, i, "null", 0, 4) == 0) { i += 4; return null; }
            throw Err("unexpected token");
        }

        string Str()
        {
            i++; // opening quote
            var sb = new StringBuilder();
            for (; ; )
            {
                if (i >= t.Length) throw Err("unterminated string");
                char c = t[i];
                if (c == '"') { i++; break; }
                if (c < 0x20) throw Err("raw control character in string");
                if (c == '\\')
                {
                    i++;
                    if (i >= t.Length) throw Err("unterminated string");
                    switch (t[i])
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            {
                                if (i + 4 >= t.Length) throw Err("bad \\u escape");
                                int cp = 0;
                                for (int k = 1; k <= 4; k++)
                                {
                                    int h = HexVal(t[i + k]);
                                    if (h < 0) throw Err("bad \\u escape");
                                    cp = cp * 16 + h;
                                }
                                sb.Append((char)cp);
                                i += 4;
                                break;
                            }
                        default: throw Err("unknown escape");
                    }
                    i++;
                    continue;
                }
                sb.Append(c);
                i++;
            }
            var s = sb.ToString();
            return s;
        }

        static int HexVal(char c) =>
            c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

        object Number()
        {
            int s = i;
            if (t[i] == '-') i++;
            if (i >= t.Length) throw Err("bad number");
            if (t[i] == '0') i++;
            else if (t[i] >= '1' && t[i] <= '9') { while (i < t.Length && char.IsAsciiDigit(t[i])) i++; }
            else throw Err("bad number");
            if (i < t.Length && t[i] == '.')
            {
                i++;
                int d = i;
                while (i < t.Length && char.IsAsciiDigit(t[i])) i++;
                if (i == d) throw Err("bad number");
            }
            if (i < t.Length && (t[i] == 'e' || t[i] == 'E'))
            {
                i++;
                if (i < t.Length && (t[i] == '+' || t[i] == '-')) i++;
                int d = i;
                while (i < t.Length && char.IsAsciiDigit(t[i])) i++;
                if (i == d) throw Err("bad number");
            }
            var raw = t.Substring(s, i - s);
            return new Num(raw);
        }
    }
}
