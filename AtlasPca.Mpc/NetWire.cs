using System.Collections;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc;

/// <summary>
/// The wire layer of the networked MPC runner: the length-prefixed JSON frame codec with strict envelope validation, the canonical hex
/// field-element encoding, and the structured abort (NetAbort) that blames a party only when the evidence names one. Sockets, TLS and the
/// distributed protocol driver are not part of this class (see AtlasPca.Mpc.Net).
/// </summary>
public static class NetWire
{
    /// <summary>Frame envelope version; a peer on another version is rejected as a version mismatch.</summary>
    public const int WIRE_VERSION = 2;
    /// <summary>Largest frame body accepted or produced (4 MiB).</summary>
    public const int MAX_FRAME_BYTES = 4 * 1024 * 1024;

    public static readonly IReadOnlySet<string> ABORT_KINDS = new HashSet<string>
    {
        "timeout", "disconnect", "version", "malformed", "oversize", "duplicate", "out-of-order", "wrong-round",
        "wrong-session", "identity", "commitment", "ot-check", "mac-check", "dealer", "equivocation", "flood", "peer-abort", "local",
    };
    static readonly HashSet<string> FrameTypes = new() { "hello", "msg", "abort" };

    /// <summary>A protocol abort; <c>Blamed</c> is null when the evidence names no culprit (then <c>Reason</c> explains why).</summary>
    public sealed class NetAbort : Exception
    {
        public readonly string Kind;
        public readonly int? Blamed;
        public readonly int Reporter;
        public readonly string? ClaimedKind;
        public readonly int? ClaimedBlame;
        public readonly string? Reason;
        public readonly object? Evidence;
        public readonly int? DeadlineMs;

        public NetAbort(string kind, int? blamed, int reporter, string detail, string? claimedKind = null, int? claimedBlame = null, string? reason = null,
            object? evidence = null, int? deadlineMs = null)
            : base("[" + kind + "] blamed=" + (blamed == null ? "none" : blamed.Value.ToString(CultureInfo.InvariantCulture)) + " reporter=" + reporter + ": " + detail)
        {
            Kind = kind;
            Blamed = blamed;
            Reporter = reporter;
            ClaimedKind = claimedKind;
            ClaimedBlame = claimedBlame;
            Reason = blamed == null ? (!string.IsNullOrEmpty(reason) ? reason : "unattributable: the evidence available to this party does not identify a culprit") : null;
            Evidence = evidence;
            DeadlineMs = deadlineMs;
        }
    }

    // ---- JSON text (JSON.stringify semantics for the value shapes the protocol uses) ----

    /// <summary>JSON text of a value with insertion-ordered maps and JavaScript string escaping.</summary>
    public static string Stringify(object? v)
    {
        var sb = new StringBuilder();
        Write(sb, v);
        return sb.ToString();
    }

    static void Write(StringBuilder sb, object? v)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case string s: Quote(sb, s); break;
            case Num n: sb.Append(FmtNumber(n.Raw)); break;
            case int or long or short: sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); break;
            case BigInteger bi: sb.Append(bi.ToString(CultureInfo.InvariantCulture)); break;
            case IDictionary m:
            {
                sb.Append('{');
                bool first = true;
                foreach (DictionaryEntry e in m)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    Quote(sb, (string)e.Key);
                    sb.Append(':');
                    Write(sb, e.Value);
                }
                sb.Append('}');
                break;
            }
            case IEnumerable l:
            {
                sb.Append('[');
                bool first = true;
                foreach (var x in l) { if (!first) sb.Append(','); first = false; Write(sb, x); }
                sb.Append(']');
                break;
            }
            default: throw new ArgumentException("stringify: unsupported value " + v.GetType().FullName);
        }
    }

    // lenient number formatting: a canonical lexeme prints as written, anything else as JavaScript's String(n) of the double it reads as
    static string FmtNumber(string raw)
    {
        if (Pca.NumberError(raw) == null) return raw;
        if (!double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var f) || double.IsInfinity(f) || double.IsNaN(f))
            throw new ArgumentException("canonicalize: non-finite number");
        return JsJson.NumberToString(f);
    }

    static void Quote(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[++i]); }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    /// <summary>A frame: {v, ty, sid, seq, rd, d}. Numbers are carried as parsed JSON values so they print as the sender wrote them.</summary>
    public sealed record Frame(object? V, string Ty, string Sid, object? Seq, string Rd, object? D);

    /// <summary>Length-prefixed (4-byte big-endian) JSON frame; throws when the body exceeds MAX_FRAME_BYTES.</summary>
    public static byte[] EncodeFrame(Frame f)
    {
        var m = new D { ["v"] = f.V, ["ty"] = f.Ty, ["sid"] = f.Sid, ["seq"] = f.Seq, ["rd"] = f.Rd, ["d"] = f.D };
        var body = new UTF8Encoding(false).GetBytes(Stringify(m));
        if (body.Length > MAX_FRAME_BYTES) throw new ArgumentException("frame too large");
        var o = new byte[4 + body.Length];
        o[0] = (byte)(body.Length >> 24);
        o[1] = (byte)(body.Length >> 16);
        o[2] = (byte)(body.Length >> 8);
        o[3] = (byte)body.Length;
        Buffer.BlockCopy(body, 0, o, 4, body.Length);
        return o;
    }

    /// <summary>Reassembles length-prefixed frames from arbitrary chunking; an oversize length prefix throws.</summary>
    public sealed class FrameSplitter
    {
        byte[] _data = Array.Empty<byte>();

        public List<byte[]> Push(byte[] chunk)
        {
            if (chunk.Length > 0)
            {
                var n = new byte[_data.Length + chunk.Length];
                Buffer.BlockCopy(_data, 0, n, 0, _data.Length);
                Buffer.BlockCopy(chunk, 0, n, _data.Length, chunk.Length);
                _data = n;
            }
            var o = new List<byte[]>();
            int off = 0;
            for (;;)
            {
                if (_data.Length - off < 4) break;
                long len = ((long)_data[off] << 24) | ((long)_data[off + 1] << 16) | ((long)_data[off + 2] << 8) | _data[off + 3];
                if (len > MAX_FRAME_BYTES) throw new InvalidOperationException("oversize");
                if (_data.Length - off < 4 + len) break;
                var body = new byte[(int)len];
                Buffer.BlockCopy(_data, off + 4, body, 0, (int)len);
                o.Add(body);
                off += 4 + (int)len;
            }
            if (off > 0)
            {
                var rest = new byte[_data.Length - off];
                Buffer.BlockCopy(_data, off, rest, 0, rest.Length);
                _data = rest;
            }
            return o;
        }
    }

    // ---- envelope validation ----

    /// <summary>The JavaScript number value of a parsed JSON number (null for anything else).</summary>
    static double? NumOf(object? o) =>
        o is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;

    static bool SafeInt(double? d) => d is double x && !double.IsInfinity(x) && !double.IsNaN(x) && x == Math.Round(x, MidpointRounding.ToEven) && Math.Abs(x) <= 9007199254740991.0;

    static bool NegZero(double d) => d == 0 && double.IsNegative(d);

    static D? ParseObject(byte[] body)
    {
        object? j;
        try { j = Pca.ParseJson(new UTF8Encoding(false, false).GetString(body)); }
        catch (Exception) { return null; }
        return j as D;
    }

    /// <summary>The envelope version of a body, or null when it is not a JSON object with a safe-integer v.</summary>
    public static long? PeekVersion(byte[] body)
    {
        var o = ParseObject(body);
        if (o == null) return null;
        var v = NumOf(o.GetValueOrDefault("v"));
        return SafeInt(v) && !NegZero(v!.Value) ? (long)v!.Value : null;
    }

    static bool EnvelopeShapeOk(D o)
    {
        if (o.Count != 6 || !o.ContainsKey("v")) return false;
        if (o.GetValueOrDefault("ty") is not string ty || !FrameTypes.Contains(ty)) return false;
        if (o.GetValueOrDefault("sid") is not string || o.GetValueOrDefault("rd") is not string) return false;
        var seq = NumOf(o.GetValueOrDefault("seq"));
        if (!SafeInt(seq) || seq!.Value < 0 || NegZero(seq.Value)) return false;
        return o.ContainsKey("d");
    }

    /// <summary>The frame as a map when it is a well-formed envelope of the current version, else null.</summary>
    public static D? ParseFrame(byte[] body)
    {
        var o = ParseObject(body);
        if (o == null) return null;
        var v = NumOf(o.GetValueOrDefault("v"));
        if (v == null || v.Value != WIRE_VERSION || !EnvelopeShapeOk(o)) return null;
        return o;
    }

    /// <summary>The peer's version when the body is a well-formed envelope of a DIFFERENT version, else null.</summary>
    public static long? VersionMismatch(byte[] body)
    {
        var o = ParseObject(body);
        if (o == null) return null;
        var v = NumOf(o.GetValueOrDefault("v"));
        if (v == null || !SafeInt(v) || NegZero(v.Value) || v.Value == WIRE_VERSION) return null;
        return EnvelopeShapeOk(o) ? (long)v.Value : null;
    }

    // ---- canonical field-element hex ----

    public static string Hx(BigInteger x) => Field.Hex(x);

    // \A..\z, never ^..$: $ would also accept a trailing newline
    static readonly Regex Hex61 = new(@"\A(0|[1-9a-f][0-9a-f]{0,15})\z", RegexOptions.CultureInvariant);

    /// <summary>Canonical lowercase hex without leading zeros of an element below the field prime; null otherwise.</summary>
    public static BigInteger? Unhx(object? s)
    {
        if (s is not string t || !Hex61.IsMatch(t)) return null;
        var v = Field.ParseHex(t);
        return v < Field.PRIME ? v : null;
    }

    public static BigInteger[]? UnhxArray(object? a, int len)
    {
        if (a is not IList l || l.Count != len) return null;
        var o = new BigInteger[len];
        for (int i = 0; i < len; i++)
        {
            var v = Unhx(l[i]);
            if (v == null) return null;
            o[i] = v.Value;
        }
        return o;
    }
}
