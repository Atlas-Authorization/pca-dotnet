// Deterministic CBOR (RFC 8949 section 4.2.1 core deterministic encoding), the minimal profile COSE_Sign1 needs: unsigned / negative
// integers within the JavaScript safe range, byte and text strings, arrays, maps (int or text keys, sorted by encoded key bytes, no
// duplicates), tags, booleans and null. Floats and indefinite-length items are refused on encode and on decode (fail closed).
//
// Model: long / int / Num (an integer within +-(2^53 - 1)), string, byte[], bool, null, List<object?>, CborMap, CborTag.
using System.Globalization;
using System.Text;

namespace AtlasPca.Scitt;

/// <summary>A refusal of the CBOR codec or of a COSE / SCITT structure. <see cref="Code"/> is set only where the reference throws a coded error.</summary>
public class ScittException(string message, string? code = null) : Exception(message)
{
    public string? Code { get; } = code;
}

/// <summary>A CBOR tagged value (major type 6).</summary>
public sealed class CborTag(object tag, object? value)
{
    public object Tag { get; } = tag;
    public object? Value { get; } = value;
}

/// <summary>An insertion-ordered CBOR map with int (long) or text keys; setting an existing key replaces its value in place (JavaScript Map semantics).</summary>
public sealed class CborMap
{
    readonly List<KeyValuePair<object, object?>> _items = new();
    public int Count => _items.Count;
    public IReadOnlyList<KeyValuePair<object, object?>> Items => _items;

    // a numeric key compares by value whatever its CLR type, a text key by ordinal content (SameValueZero)
    static bool SameKey(object a, object b)
    {
        if (a is string x) return b is string y && string.Equals(x, y, StringComparison.Ordinal);
        if (b is string) return false;
        return NumKey(a) is { } p && NumKey(b) is { } q && p == q;
    }

    static double? NumKey(object k) => k switch
    {
        long l => l,
        int i => i,
        Num n => double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? (d == 0 ? 0 : d) : null,
        _ => null,
    };

    public CborMap Set(object key, object? value)
    {
        for (int i = 0; i < _items.Count; i++)
            if (SameKey(_items[i].Key, key)) { _items[i] = new(_items[i].Key, value); return this; }
        _items.Add(new(key, value));
        return this;
    }

    /// <summary>The value of an integer key, or <see cref="Missing"/> when absent.</summary>
    public object? Get(long key)
    {
        foreach (var e in _items) if (e.Key is long l && l == key) return e.Value;
        return Missing;
    }

    public object? Get(string key)
    {
        foreach (var e in _items) if (e.Key is string s && s == key) return e.Value;
        return Missing;
    }

    /// <summary>Marks an absent key (JavaScript <c>undefined</c>), distinct from a CBOR null.</summary>
    public static readonly object Missing = new();
}

public static class Cbor
{
    const long MaxSafe = 9007199254740991L;
    const int MaxDepth = 1500; // the reference throws a RangeError on a stack overflow; this refuses before one

    static ScittException Err(string m, string? code = null) => new(m, code);

    /// <summary>The safe integer a number value stands for (JavaScript <c>isInt</c>: an integer, |n| &lt;= 2^53 - 1, not negative zero), or null.</summary>
    internal static long? SafeInt(object? v)
    {
        switch (v)
        {
            case long l: return l >= -MaxSafe && l <= MaxSafe ? l : null;
            case int i: return i;
            case Num n:
                if (!double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d)) return null;
                if (double.IsNaN(d) || double.IsInfinity(d) || d != Math.Floor(d) || Math.Abs(d) > MaxSafe) return null;
                if (d == 0 && n.Raw.StartsWith('-')) return null;
                return (long)d;
            default: return null;
        }
    }

    static bool IsNumber(object? v) => v is long or int or Num;

    static void Head(List<byte> o, int major, long arg)
    {
        int mt = major << 5;
        if (arg < 24) o.Add((byte)(mt | (int)arg));
        else if (arg < 0x100) { o.Add((byte)(mt | 24)); o.Add((byte)arg); }
        else if (arg < 0x10000) { o.Add((byte)(mt | 25)); o.Add((byte)(arg >> 8)); o.Add((byte)arg); }
        else if (arg < 0x100000000L) { o.Add((byte)(mt | 26)); for (int s = 24; s >= 0; s -= 8) o.Add((byte)(arg >> s)); }
        else { o.Add((byte)(mt | 27)); for (int s = 56; s >= 0; s -= 8) o.Add((byte)(arg >> s)); }
    }

    static void Text(List<byte> o, string s)
    {
        if (Pca.HasLoneSurrogate(s)) throw Err("cbor: text string contains a lone surrogate");
        var b = Encoding.UTF8.GetBytes(s);
        Head(o, 3, b.Length);
        o.AddRange(b);
    }

    static void IntHead(List<byte> o, long n)
    {
        if (n >= 0) Head(o, 0, n); else Head(o, 1, -1 - n);
    }

    static int CmpBytes(byte[] a, byte[] b)
    {
        int n = Math.Min(a.Length, b.Length);
        for (int i = 0; i < n; i++) { int d = a[i] - b[i]; if (d != 0) return d; }
        return a.Length - b.Length;
    }

    /// <summary>Deterministically encode a value. Anything outside the supported profile throws <see cref="ScittException"/>.</summary>
    public static byte[] Encode(object? v)
    {
        var o = new List<byte>();
        Put(o, v);
        return o.ToArray();
    }

    static void Put(List<byte> o, object? v)
    {
        switch (v)
        {
            case null: o.Add(0xf6); return;
            case bool b: o.Add(b ? (byte)0xf5 : (byte)0xf4); return;
            case long or int or Num:
                if (SafeInt(v) is not long n) throw Err("cbor: only safe-integer numbers are supported");
                IntHead(o, n);
                return;
            case string s: Text(o, s); return;
            case byte[] bs: Head(o, 2, bs.Length); o.AddRange(bs); return;
            case List<object?> a:
                Head(o, 4, a.Count);
                foreach (var x in a) Put(o, x);
                return;
            case CborMap m:
                {
                    var entries = new List<(byte[] K, byte[] V)>();
                    foreach (var e in m.Items) entries.Add((EncodeKey(e.Key), Encode(e.Value)));
                    entries.Sort((x, y) => CmpBytes(x.K, y.K)); // List.Sort is unstable, which is harmless: equal keys are refused below
                    for (int i = 1; i < entries.Count; i++)
                        if (CmpBytes(entries[i - 1].K, entries[i].K) == 0) throw Err("cbor: duplicate map key");
                    Head(o, 5, m.Count);
                    foreach (var e in entries) { o.AddRange(e.K); o.AddRange(e.V); }
                    return;
                }
            case CborTag t:
                if (SafeInt(t.Tag) is not long tag || tag < 0) throw Err("cbor: bad tag");
                Head(o, 6, tag);
                Put(o, t.Value);
                return;
            default: throw Err("cbor: unsupported value");
        }
    }

    static byte[] EncodeKey(object k)
    {
        var o = new List<byte>();
        if (IsNumber(k))
        {
            // a negative-zero key is the key 0 (a value of -0 stays refused)
            if ((k is Num nz && double.TryParse(nz.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var kz) && kz == 0 ? 0L : SafeInt(k)) is not long n) throw Err("cbor: bad integer map key");
            IntHead(o, n);
        }
        else if (k is string s) Text(o, s);
        else throw Err("cbor: unsupported value");
        return o.ToArray();
    }

    static readonly UTF8Encoding StrictUtf8 = new(false, true);

    sealed class Reader(byte[] buf)
    {
        public int Pos;
        int _depth;

        byte Byte()
        {
            if (Pos >= buf.Length) throw Err("cbor: unexpected end of input");
            return buf[Pos++];
        }

        byte[] Bytes(long n)
        {
            if (Pos + n > buf.Length) throw Err("cbor: unexpected end of input");
            var r = buf.AsSpan(Pos, (int)n).ToArray();
            Pos += (int)n;
            return r;
        }

        long ReadUint(int n)
        {
            ulong v = 0;
            for (int i = 0; i < n; i++) v = v * 256 + Byte();
            if (v > (ulong)MaxSafe) throw Err("cbor: integer out of safe range");
            return (long)v;
        }

        (int Major, long Arg) ReadHead()
        {
            int ib = Byte();
            int major = ib >> 5, info = ib & 0x1f;
            if (major == 7 && info >= 24) throw Err("cbor: unsupported simple/float value");
            if (info < 24) return (major, info);
            long arg;
            switch (info)
            {
                case 24: arg = ReadUint(1); if (arg < 24) throw Err("cbor: non-minimal integer"); return (major, arg);
                case 25: arg = ReadUint(2); if (arg < 0x100) throw Err("cbor: non-minimal integer"); return (major, arg);
                case 26: arg = ReadUint(4); if (arg < 0x10000) throw Err("cbor: non-minimal integer"); return (major, arg);
                case 27: arg = ReadUint(8); if (arg < 0x100000000L) throw Err("cbor: non-minimal integer"); return (major, arg);
                default: throw Err("cbor: unsupported additional information (indefinite/reserved)");
            }
        }

        public object? Value()
        {
            if (++_depth > MaxDepth) throw Err("cbor: nesting too deep");
            try
            {
                var (major, arg) = ReadHead();
                switch (major)
                {
                    case 0: return arg;
                    case 1:
                        if (arg == MaxSafe) throw Err("cbor: integer out of safe range"); // -1 - arg would be -2^53
                        return -1 - arg;
                    case 2: return Bytes(arg);
                    case 3:
                        {
                            var raw = Bytes(arg);
                            try { return StrictUtf8.GetString(raw); }
                            catch (ArgumentException) { throw Err("The encoded data was not valid for encoding utf-8", "ERR_ENCODING_INVALID_ENCODED_DATA"); }
                        }
                    case 4:
                        {
                            var list = new List<object?>();
                            for (long i = 0; i < arg; i++) list.Add(Value());
                            return list;
                        }
                    case 5:
                        {
                            var map = new CborMap();
                            byte[]? prev = null;
                            for (long i = 0; i < arg; i++)
                            {
                                int keyStart = Pos;
                                var key = Value();
                                if (key is not (long or string)) throw Err("cbor: map key must be int or text");
                                var keyBytes = buf.AsSpan(keyStart, Pos - keyStart).ToArray();
                                if (prev != null && CmpBytes(prev, keyBytes) >= 0) throw Err("cbor: map keys not canonically ordered / duplicate");
                                prev = keyBytes;
                                map.Set(key, Value());
                            }
                            return map;
                        }
                    case 6: return new CborTag(arg, Value());
                    case 7:
                        if (arg == 20) return false;
                        if (arg == 21) return true;
                        if (arg == 22) return null;
                        throw Err("cbor: unsupported simple/float value");
                    default: throw Err("cbor: unsupported major type");
                }
            }
            finally { _depth--; }
        }
    }

    /// <summary>Strictly decode one canonical CBOR value; the whole buffer must be consumed.</summary>
    public static object? Decode(byte[] bytes)
    {
        var r = new Reader(bytes);
        var v = r.Value();
        if (r.Pos != bytes.Length) throw Err("cbor: trailing bytes");
        return v;
    }
}
