// Reference verifier for the CORE PCActn checks, wire format v2 (strict JSON profile, strict canonical form,
// strict base64url, freshness binding, capability chain, Merkle plan inclusion, strict Ed25519 leaf signature,
// counter). Byte-matches @atlasauth/pca and the other language SDKs; see packages/pca/conformance/README.md.
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace AtlasPca;

/// <summary>B4 post-quantum crypto-agility (mirrors packages/pca/src/pq.ts). ML-DSA-65 (FIPS-204) via
/// BouncyCastle. Absent <c>alg</c> (or "ed25519") is byte-identical to the classical wire. <c>alg</c>/<c>pq_pk</c>
/// are signed; <c>sig</c>/<c>pq_sig</c> are stripped from the signed body. pk 1952 bytes, sig 3309 bytes.</summary>
public static class Pq
{
    public const int MlDsa65PublicKeyBytes = 1952;
    public const int MlDsa65SignatureBytes = 3309;
    public const int Ed25519SignatureBytes = 64;

    public readonly record struct Suite(int SigBytes, bool NeedsPqPk, bool NeedsPqSig);

    public static readonly Dictionary<string, Suite> Suites = new()
    {
        ["ed25519"] = new Suite(Ed25519SignatureBytes, false, false),
        ["ml-dsa-65"] = new Suite(MlDsa65SignatureBytes, true, false),
        ["hybrid-ed25519-ml-dsa-65"] = new Suite(Ed25519SignatureBytes, true, true),
    };

    public static bool MlDsa65Verify(byte[] pk, byte[] msg, byte[] sig)
    {
        if (pk.Length != MlDsa65PublicKeyBytes || sig.Length != MlDsa65SignatureBytes) return false;
        try
        {
            var pub = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, pk);
            var v = new MLDsaSigner(MLDsaParameters.ml_dsa_65, false); // empty context, matching @noble/post-quantum
            v.Init(false, pub);
            v.BlockUpdate(msg, 0, msg.Length);
            return v.VerifySignature(sig);
        }
        catch { return false; }
    }
}

/// <summary>A JSON number kept as its exact source text.</summary>
public sealed record Num(string Raw);

public sealed class Verdict
{
    public bool Allow;
    /// <summary>All eight checks, or only { wire:false } when the wire form is rejected (terminal).</summary>
    public Dictionary<string, bool> Checks = new();
    public string Reason = "";
}

public sealed class StrictJsonException : Exception
{
    public StrictJsonException(string m) : base("strict JSON: " + m) { }
}

public static class Pca
{
    const string SigDomain = "atlas-pca/actn/v2\0";
    const string CapDomain = "atlas-pca/cap/v1\0";
    // v2.1 agent-leaf threshold-share binding (README sections 9 + "v2.1 AGENT-LEAF BINDING").
    const string ShareDomainPrefix = "atlas-pca/share/";
    const string SignersetDomain = "atlas-pca/signerset/v1\0";
    const string DefaultRev = "reversible";
    public const int MaxJsonDepth = 32;
    public const int MaxJsonChars = 1 << 20; // UTF-8 bytes;
    public const int MaxDecimalDigits = 15;
    public const int MaxChainHops = 16;
    public const long MaxLifetimeMs = 3_600_000;
    public const long MaxSkewMs = 60_000;
    public const long MaxSafeInt = 9007199254740991L;

    // ================= JSON parsing (hand-written; never System.Text.Json) =================
    // tree: null, bool, string, Num, List<object?>, Dictionary<string,object?>

    /// <summary>STRICT profile for signed bytes (README section 2/3). Throws StrictJsonException.</summary>
    public static object? ParseStrict(string text) => new Parser(text, true).Run();

    /// <summary>Plain RFC 8259 parse (used only for trusted fixtures such as vectors.json): no profile checks.</summary>
    public static object? ParseJson(string text) => new Parser(text, false).Run();

    sealed class Parser
    {
        readonly string t; readonly bool strict; int i;
        public Parser(string text, bool strict) { t = text; this.strict = strict; }
        Exception Err(string m) => new StrictJsonException($"{m} (at offset {i})");

        public object? Run()
        {
            if (strict && Encoding.UTF8.GetByteCount(t) > MaxJsonChars) throw new StrictJsonException("input too large");
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
                if (strict && depth > MaxJsonDepth) throw Err("nesting too deep");
                if (depth > 4096) throw Err("nesting too deep");
                i++;
                var o = new Dictionary<string, object?>();
                Ws();
                if (i < t.Length && t[i] == '}') { i++; return o; }
                for (; ; )
                {
                    Ws();
                    if (i >= t.Length || t[i] != '"') throw Err("expected a string key");
                    var k = Str();
                    if (strict && o.ContainsKey(k)) throw Err("duplicate key");
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
                if (strict && depth > MaxJsonDepth) throw Err("nesting too deep");
                if (depth > 4096) throw Err("nesting too deep");
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
            if (strict && HasLoneSurrogate(s)) throw Err("lone surrogate in string");
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
            if (strict)
            {
                var e = NumberError(raw);
                if (e != null) throw Err(e);
            }
            return new Num(raw);
        }
    }

    public static bool HasLoneSurrogate(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (char.IsHighSurrogate(c)) { if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) i++; else return true; }
            else if (char.IsLowSurrogate(c)) return true;
        }
        return false;
    }

    /// <summary>Canonical wire number form (README section 3). Returns an error string, or null when valid.</summary>
    public static string? NumberError(string raw)
    {
        // grammar: -?(0|[1-9][0-9]*)(\.[0-9]+)?  (no exponent)
        int i = 0;
        bool neg = false;
        if (raw.Length > 0 && raw[0] == '-') { neg = true; i++; }
        int ds = i;
        if (i >= raw.Length) return "bad number";
        if (raw[i] == '0') i++;
        else if (raw[i] >= '1' && raw[i] <= '9') { while (i < raw.Length && char.IsAsciiDigit(raw[i])) i++; }
        else return "bad number (leading '+' / '.')";
        string intPart = raw.Substring(ds, i - ds);
        bool frac = false;
        string fracPart = "";
        if (i < raw.Length && raw[i] == '.')
        {
            frac = true; i++;
            int fs = i;
            while (i < raw.Length && char.IsAsciiDigit(raw[i])) i++;
            if (i == fs) return "bad number (empty fraction)";
            fracPart = raw.Substring(fs, i - fs);
        }
        if (i != raw.Length) return raw.IndexOfAny(new[] { 'e', 'E' }) >= 0 ? "exponent form is not allowed" : "bad number";
        if (!frac)
        {
            if (neg && intPart == "0") return "negative zero is not allowed";
            if (intPart.Length > 16 || BigInteger.Parse(intPart, CultureInfo.InvariantCulture) > MaxSafeInt) return "integer outside the safe range";
            return null;
        }
        if (fracPart.EndsWith('0')) return "trailing fractional zero is not canonical";
        var digits = (intPart + fracPart).TrimStart('0');
        if (digits.Length > MaxDecimalDigits) return "more than 15 significant digits";
        var v = double.Parse(raw, NumberStyles.Float, CultureInfo.InvariantCulture);
        if (v != 0 && Math.Abs(v) < 1e-6) return "magnitude below 1e-6";
        return null;
    }

    /// <summary>Integer lexeme (safe integer, not -0) -> long.</summary>
    static bool TryInt(object? v, out long n)
    {
        n = 0;
        if (v is Num x && x.Raw.IndexOf('.') < 0 && NumberError(x.Raw) == null) { n = long.Parse(x.Raw, CultureInfo.InvariantCulture); return true; }
        return false;
    }

    // ================= strict canonical form =================
    public static string Canonicalize(object? v)
    {
        var sb = new StringBuilder();
        Ser(sb, v, 1);
        return sb.ToString();
    }

    static void JsString(StringBuilder sb, string s)
    {
        if (HasLoneSurrogate(s)) throw new InvalidOperationException("canonicalize: lone surrogate in string");
        sb.Append('"');
        foreach (char c in s)
        {
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
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    static void Ser(StringBuilder sb, object? v, int depth)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case string s: JsString(sb, s); break;
            case Num n:
                {
                    var e = NumberError(n.Raw);
                    if (e != null) throw new InvalidOperationException("canonicalize: " + e);
                    sb.Append(n.Raw); // a valid lexeme IS the shortest round-trip decimal
                    break;
                }
            case int i: sb.Append(i.ToString(CultureInfo.InvariantCulture)); break;
            case long l:
                if (Math.Abs(l) > MaxSafeInt) throw new InvalidOperationException("canonicalize: unsafe integer");
                sb.Append(l.ToString(CultureInfo.InvariantCulture)); break;
            case List<object?> a:
                if (depth > MaxJsonDepth) throw new InvalidOperationException("canonicalize: nesting too deep");
                sb.Append('[');
                for (int k = 0; k < a.Count; k++) { if (k > 0) sb.Append(','); Ser(sb, a[k], depth + 1); }
                sb.Append(']');
                break;
            case Dictionary<string, object?> m:
                {
                    if (depth > MaxJsonDepth) throw new InvalidOperationException("canonicalize: nesting too deep");
                    var keys = m.Keys.Select(k =>
                    {
                        if (HasLoneSurrogate(k)) throw new InvalidOperationException("canonicalize: lone surrogate in key");
                        return (Key: k, Bytes: Encoding.UTF8.GetBytes(k));
                    }).ToList();
                    keys.Sort((x, y) => x.Bytes.AsSpan().SequenceCompareTo(y.Bytes)); // bytewise UTF-8
                    sb.Append('{');
                    for (int k = 0; k < keys.Count; k++)
                    {
                        if (k > 0) sb.Append(',');
                        JsString(sb, keys[k].Key); sb.Append(':'); Ser(sb, m[keys[k].Key], depth + 1);
                    }
                    sb.Append('}');
                    break;
                }
            default: throw new InvalidOperationException("canonicalize: unsupported type " + v.GetType());
        }
    }

    // ================= hashing / base64url =================
    static byte[] Sha(byte[] b) => SHA256.HashData(b);
    static byte[] Canon(object? v) => Encoding.UTF8.GetBytes(Canonicalize(v));
    static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    public static string B64u(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>STRICT base64url (README section 5): alphabet only, no pad/whitespace, len%4!=1, canonical
    /// trailing bits (re-encode must reproduce the input), optional exact decoded length.</summary>
    public static byte[]? B64uDecode(object? o, int? len = null)
    {
        if (o is not string s) return null;
        if (s.Length % 4 == 1) return null;
        foreach (char c in s)
            if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_')) return null;
        if (len is int n && s.Length != (n * 4 + 2) / 3) return null;
        try
        {
            var t = s.Replace('-', '+').Replace('_', '/');
            switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
            var bytes = Convert.FromBase64String(t);
            if (B64u(bytes) != s) return null; // non-canonical trailing bits
            if (len is int m && bytes.Length != m) return null;
            return bytes;
        }
        catch (FormatException) { return null; }
    }

    public static string HashCanonical(object? v) => B64u(Sha(Canon(v)));

    // ================= Merkle =================
    static byte[] LeafHash(object? leaf) => Sha(Cat(new byte[] { 0x00 }, Canon(leaf)));
    static byte[] NodeHash(byte[] l, byte[] r) => Sha(Cat(new byte[] { 0x01 }, l, r));

    static long Split(long n) { long k = 1; while (k * 2 < n) k *= 2; return k; }

    static byte[] Build(List<byte[]> hs)
    {
        if (hs.Count == 1) return hs[0];
        int k = (int)Split(hs.Count);
        return NodeHash(Build(hs.GetRange(0, k)), Build(hs.GetRange(k, hs.Count - k)));
    }

    public static string MerkleRoot(List<object?> leaves)
    {
        if (leaves.Count == 0) throw new InvalidOperationException("empty leaf set");
        return B64u(Build(leaves.Select(LeafHash).ToList()));
    }

    /// <summary>Sibling sides (leaf -> root) for leaf `index` in a tree of `size` leaves (RFC 6962 split).</summary>
    static List<char> PathShape(long index, long size)
    {
        var o = new List<char>();
        long idx = index, n = size;
        while (n > 1)
        {
            long k = Split(n);
            if (idx < k) { o.Add('R'); n = k; }
            else { o.Add('L'); idx -= k; n -= k; }
        }
        o.Reverse();
        return o;
    }

    public static bool VerifyInclusion(string root, Dictionary<string, object?>? proof, object? leaf)
    {
        try
        {
            if (proof == null || Get(proof, "path") is not List<object?> path) return false;
            if (!TryInt(Get(proof, "index"), out var index) || !TryInt(Get(proof, "size"), out var size)) return false;
            if (size < 1 || index < 0 || index >= size) return false;
            var shape = PathShape(index, size);
            if (shape.Count != path.Count) return false;
            var h = LeafHash(leaf);
            for (int i = 0; i < path.Count; i++)
            {
                if (path[i] is not Dictionary<string, object?> step) return false;
                var side = Get(step, "side") as string;
                if (side == null || side.Length != 1 || side[0] != shape[i]) return false;
                var sib = B64uDecode(Get(step, "hash"), 32);
                if (sib == null) return false;
                h = side == "L" ? NodeHash(sib, h) : NodeHash(h, sib);
            }
            return B64u(h) == root;
        }
        catch { return false; }
    }

    public static string ParamsDigest(object? p) => HashCanonical(p ?? new Dictionary<string, object?>());

    static string ConditionsDigest(object? pre, object? post) =>
        HashCanonical(new Dictionary<string, object?> { ["pre"] = pre, ["post"] = post });

    static Dictionary<string, object?>? PlanLeaf(object? nodeId, Dictionary<string, object?>? action, string cond)
    {
        if (nodeId == null) return null;
        var pd = Get(action, "params_digest") ?? ParamsDigest(null);
        var rc = Get(action, "reversibility_class") ?? DefaultRev;
        return new Dictionary<string, object?>
        {
            ["node_id"] = nodeId, ["verb"] = Get(action, "verb"), ["resource"] = Get(action, "resource"),
            ["params_digest"] = pd, ["reversibility_class"] = rc, ["conditions"] = cond,
        };
    }

    // ================= strict Ed25519 (RFC 8032) =================
    static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);
    static readonly BigInteger D = Mod(-121665 * BigInteger.ModPow(121666, P - 2, P));
    static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);
    static BigInteger Mod(BigInteger a) { var r = a % P; return r < 0 ? r + P : r; }

    // extended coordinates (X,Y,Z,T)
    readonly record struct Pt(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T);
    static readonly Pt Identity = new(0, 1, 1, 0);

    static Pt Add(Pt a, Pt b)
    {
        var A = Mod((a.Y - a.X) * (b.Y - b.X));
        var B = Mod((a.Y + a.X) * (b.Y + b.X));
        var C = Mod(2 * D * a.T * b.T);
        var Dd = Mod(2 * a.Z * b.Z);
        var E = Mod(B - A); var F = Mod(Dd - C); var G = Mod(Dd + C); var H = Mod(B + A);
        return new Pt(Mod(E * F), Mod(G * H), Mod(F * G), Mod(E * H));
    }

    static bool IsIdentity(Pt p) => Mod(p.X) == 0 && Mod(p.Y - p.Z) == 0;

    static Pt MulL(Pt p)
    {
        var r = Identity; var q = p; var k = L;
        while (k > 0) { if (!k.IsEven) r = Add(r, q); q = Add(q, q); k >>= 1; }
        return r;
    }

    static Pt? Decode(byte[] b)
    {
        int sign = b[31] >> 7;
        var yb = (byte[])b.Clone(); yb[31] &= 0x7f;
        var y = new BigInteger(yb, isUnsigned: true, isBigEndian: false);
        if (y >= P) return null; // non-canonical y
        var y2 = Mod(y * y);
        var u = Mod(y2 - 1); var v = Mod(D * y2 + 1);
        var x2 = Mod(u * BigInteger.ModPow(v, P - 2, P));
        var x = BigInteger.ModPow(x2, (P + 3) / 8, P);
        if (Mod(x * x) != x2) x = Mod(x * SqrtM1);
        if (Mod(x * x) != x2) return null; // not on the curve
        if (x == 0 && sign == 1) return null;
        if ((int)(x & 1) != sign) x = Mod(-x);
        return new Pt(x, y, 1, Mod(x * y));
    }

    /// <summary>True iff the encoding is a canonical point of exactly prime order (not identity, no torsion).</summary>
    static bool IsPrimeOrderPoint(byte[] enc)
    {
        var p = Decode(enc);
        if (p == null) return false;
        if (IsIdentity(p.Value)) return false;
        return IsIdentity(MulL(p.Value));
    }

    static bool VerifyEd25519Strict(byte[] pk, byte[] msg, byte[] sig)
    {
        if (pk.Length != 32 || sig.Length != 64) return false;
        var s = new BigInteger(sig.AsSpan(32), isUnsigned: true, isBigEndian: false);
        if (s >= L) return false; // non-canonical S
        if (!IsPrimeOrderPoint(pk)) return false; // small-order / mixed-order / non-canonical key
        if (!IsPrimeOrderPoint(sig[..32])) return false; // same for R
        try
        {
            var v = new Ed25519Signer();
            v.Init(false, new Ed25519PublicKeyParameters(pk, 0));
            v.BlockUpdate(msg, 0, msg.Length);
            return v.VerifySignature(sig);
        }
        catch { return false; }
    }

    static bool VerifyB64u(object? pub, byte[] msg, object? sig)
    {
        var pk = B64uDecode(pub, 32); var sg = B64uDecode(sig, 64);
        if (pk == null || sg == null) return false;
        return VerifyEd25519Strict(pk, msg, sg);
    }

    // ================= B4 crypto-agility: suite resolution, wire validation, leaf seam =================

    /// <summary>Resolve the suite for a PCActn. Returns (name, null) for the default/known suite, else
    /// (null, reason). An absent `alg` defaults to ed25519; any unknown/non-string value fails closed.</summary>
    static (string? Name, string? Err) ResolveSuite(Dictionary<string, object?> p)
    {
        if (!p.TryGetValue("alg", out var alg)) return ("ed25519", null);
        if (alg is not string s) return (null, "'alg' must be a string");
        if (!Pq.Suites.ContainsKey(s)) return (null, $"unknown signature alg '{s}'");
        return (s, null);
    }

    /// <summary>Validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. Null when well-formed, else a short reason.</summary>
    static string? ValidateSignatureWire(Dictionary<string, object?> p)
    {
        var (name, err) = ResolveSuite(p);
        if (name == null) return err;
        var suite = Pq.Suites[name];
        if (B64uDecode(Get(p, "sig"), suite.SigBytes) == null)
            return $"'sig' is not canonical base64url ({suite.SigBytes} bytes) for alg '{name}'";
        if (suite.NeedsPqPk)
        {
            if (B64uDecode(Get(p, "pq_pk"), Pq.MlDsa65PublicKeyBytes) == null)
                return $"'pq_pk' is not canonical base64url ({Pq.MlDsa65PublicKeyBytes} bytes)";
        }
        else if (p.ContainsKey("pq_pk")) return $"'pq_pk' must be absent for alg '{name}'";
        if (suite.NeedsPqSig)
        {
            if (B64uDecode(Get(p, "pq_sig"), Pq.MlDsa65SignatureBytes) == null)
                return $"'pq_sig' is not canonical base64url ({Pq.MlDsa65SignatureBytes} bytes)";
        }
        else if (p.ContainsKey("pq_sig")) return $"'pq_sig' must be absent for alg '{name}'";
        return null;
    }

    static bool MlDsaVerifyB64u(object? pkB64u, byte[] msg, object? sigB64u)
    {
        var pk = B64uDecode(pkB64u, Pq.MlDsa65PublicKeyBytes);
        var sg = B64uDecode(sigB64u, Pq.MlDsa65SignatureBytes);
        if (pk == null || sg == null) return false;
        return Pq.MlDsa65Verify(pk, msg, sg);
    }

    /// <summary>Verify the leaf signature under the PCActn's suite. FAIL-CLOSED.</summary>
    static bool VerifyLeafSuite(Dictionary<string, object?> p, object? holder, byte[] msg)
    {
        var (name, _) = ResolveSuite(p);
        if (name == null) return false;
        var sig = Get(p, "sig");
        return name switch
        {
            "ed25519" => VerifyB64u(holder, msg, sig),
            "ml-dsa-65" => MlDsaVerifyB64u(Get(p, "pq_pk"), msg, sig),
            "hybrid-ed25519-ml-dsa-65" =>
                VerifyB64u(holder, msg, sig) && MlDsaVerifyB64u(Get(p, "pq_pk"), msg, Get(p, "pq_sig")),
            _ => false,
        };
    }

    /// <summary>Suite-aware signature verification over an arbitrary <paramref name="msg"/>, exposed for the
    /// threshold-share and PQ-artifact conformance surfaces (same agility seam as the leaf). An absent
    /// <paramref name="alg"/> defaults to ed25519. FAIL-CLOSED: any unimplemented suite (and any malformed
    /// key / signature) returns false, never throws.</summary>
    public static bool VerifySuiteSig(string? alg, object? edPk, object? pqPk, byte[] msg, object? sig, object? pqSig)
    {
        var name = alg ?? "ed25519";
        return name switch
        {
            "ed25519" => VerifyB64u(edPk, msg, sig),
            "ml-dsa-65" => MlDsaVerifyB64u(pqPk, msg, sig),
            "hybrid-ed25519-ml-dsa-65" => VerifyB64u(edPk, msg, sig) && MlDsaVerifyB64u(pqPk, msg, pqSig),
            _ => false, // unimplemented / unknown suite: fail-closed
        };
    }

    // ================= v2.1 threshold-share binding (README section 9) =================

    /// <summary>Recompute the signer-set hash committed by a threshold share (v2.1):
    /// <c>sha256("atlas-pca/signerset/v1\0" || canonical(sort_by(role, publicKey)[{publicKey, role}]))</c>.
    /// FAIL-CLOSED: null on any malformed entry (never trusts a precomputed <c>signer_set_hash</c>).</summary>
    static byte[]? SignerSetHash(List<object?> signerSet)
    {
        var entries = new List<(string Role, string Pk)>(signerSet.Count);
        foreach (var e in signerSet)
        {
            if (e is not Dictionary<string, object?> o) return null;
            if (Get(o, "role") is not string role || Get(o, "publicKey") is not string pk) return null;
            entries.Add((role, pk));
        }
        // bytewise ordering (ASCII roles/base64url keys): role, then publicKey — matches the reference impls.
        entries.Sort((a, b) =>
        {
            int c = string.CompareOrdinal(a.Role, b.Role);
            return c != 0 ? c : string.CompareOrdinal(a.Pk, b.Pk);
        });
        var arr = entries
            .Select(e => (object?)new Dictionary<string, object?> { ["publicKey"] = e.Pk, ["role"] = e.Role })
            .ToList();
        try { return Sha(Cat(Encoding.UTF8.GetBytes(SignersetDomain), Canon(arr))); }
        catch { return null; }
    }

    /// <summary>Verify a single <c>primitives.threshold_share[]</c> entry under the v2.1 agent-leaf share
    /// binding. RECOMPUTES the bound message from scratch (does NOT trust the stored <c>share_message</c> /
    /// <c>signer_set_hash</c>):
    /// <c>"atlas-pca/share/&lt;role&gt;\0" || sha256(thresholdMessage) || signerSetHash(signer_set) || t(1 byte)</c>,
    /// then confirms <c>share.sig</c> verifies over it under <c>share.publicKey</c> (routed through the SAME
    /// suite seam as the leaf, so a PQ/hybrid share would use <c>share.pq_pk</c>/<c>share.pq_sig</c>).
    /// FAIL-CLOSED: false on any malformed input, never throws. Consequently the PRE-v2.1 bare agent share
    /// (a <c>sig</c> over the bare threshold message) and a cross-signer-set replay both fail.</summary>
    public static bool VerifyThresholdShare(Dictionary<string, object?> entry)
    {
        try
        {
            if (Get(entry, "role") is not string role) return false;
            if (!TryInt(Get(entry, "t"), out var t) || t < 0 || t > 255) return false;
            if (Get(entry, "signer_set") is not List<object?> signerSet) return false;
            var tm = B64uDecode(Get(entry, "threshold_message")); // strict base64url, no fixed length
            if (tm == null) return false;
            var ssh = SignerSetHash(signerSet);
            if (ssh == null) return false;
            if (Get(entry, "share") is not Dictionary<string, object?> share) return false;
            if (Get(share, "publicKey") is not string) return false;
            // Bound share message: domain(role) || sha256(thresholdMessage) || signerSetHash || t.
            var msg = Cat(
                Encoding.UTF8.GetBytes(ShareDomainPrefix), Encoding.UTF8.GetBytes(role), new byte[] { 0 },
                Sha(tm), ssh, new byte[] { (byte)t });
            return VerifySuiteSig(Get(share, "alg") as string, Get(share, "publicKey"),
                Get(share, "pq_pk"), msg, Get(share, "sig"), Get(share, "pq_sig"));
        }
        catch { return false; }
    }

    // ================= capability chain =================
    static object? Get(Dictionary<string, object?>? m, string k) => m != null && m.TryGetValue(k, out var v) ? v : null;
    static bool Has(Dictionary<string, object?>? m, string k) => m != null && m.ContainsKey(k);

    public static string CapHash(object? c) => HashCanonical(c);

    /// <summary>bodyOf + the suite fields (`alg`, `pq_pk`) bound in for a non-default suite (so a downgrade
    /// or ML-DSA key-swap breaks the hop digest), byte-identical to bodyOf for ed25519. Mirrors signableBody
    /// in capability.ts. Returns null for an unknown `alg` (fail-closed).</summary>
    static Dictionary<string, object?>? SignableHopBody(Dictionary<string, object?> c)
    {
        var (name, _) = ResolveSuite(c);
        if (name == null) return null;
        var body = new Dictionary<string, object?>
        {
            ["issuer"] = Get(c, "issuer"), ["holder"] = Get(c, "holder"), ["caveats"] = Get(c, "caveats"), ["parent"] = Get(c, "parent"),
        };
        if (name != "ed25519")
        {
            body["alg"] = name;
            if (Pq.Suites[name].NeedsPqPk && Get(c, "pq_pk") is string pk) body["pq_pk"] = pk;
        }
        return body;
    }

    static string CheckSig(Dictionary<string, object?> c, object? signer, string label)
    {
        // Unknown suite => fail-closed (before any hashing), mirroring capability.ts checkSig.
        var body = SignableHopBody(c);
        if (body == null) return label + $": unknown signature alg '{Get(c, "alg")}'";
        string digest;
        try { digest = HashCanonical(body); } catch { return label + ": malformed body"; }
        var bd = Get(c, "body_digest") as string; var id = Get(c, "id") as string;
        if (digest != bd || id != bd) return label + ": body digest mismatch";
        var d = B64uDecode(bd, 32);
        if (d == null) return label + ": bad signature (not signed by expected key)";
        // Suite-agile hop verification (mirrors VerifyLeafSuite): ed25519 == VerifyB64u(signer, msg, sig);
        // hybrid requires BOTH the Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under `pq_pk`);
        // pure ml-dsa-65 verifies `sig` under `pq_pk`. The signer is the expected Ed25519 key.
        if (!VerifyLeafSuite(c, signer, Cat(Encoding.UTF8.GetBytes(CapDomain), d)))
            return label + ": bad signature (not signed by expected key)";
        return "";
    }

    static bool StrEq(object? a, object? b) => a is string x && b is string y && x == y;

    static bool WellTyped(object? o) =>
        o is Dictionary<string, object?> c
        && Get(c, "id") is string && Get(c, "issuer") is string && Get(c, "holder") is string
        && Get(c, "body_digest") is string && Get(c, "sig") is string
        && (!Has(c, "parent") || Get(c, "parent") is string)
        && Get(c, "caveats") is List<object?> cv
        && cv.All(x => x is Dictionary<string, object?> d && Get(d, "type") is string);

    public static (string Why, bool Ok) VerifyChain(List<object?> chain, object? expectedRootIssuer, bool haveIssuer)
    {
        if (chain.Count == 0) return ("empty chain", false);
        if (chain.Count > MaxChainHops) return ($"chain too long (max {MaxChainHops} hops)", false); // before any signature work
        for (int i = 0; i < chain.Count; i++) if (!WellTyped(chain[i])) return ($"hop {i}: malformed capability", false);
        var root = (Dictionary<string, object?>)chain[0]!;
        if (Has(root, "parent")) return ("hop 0: root must not have a parent", false);
        if (haveIssuer && !StrEq(Get(root, "issuer"), expectedRootIssuer)) return ("hop 0: root issuer is not the expected principal", false);
        var e = CheckSig(root, Get(root, "issuer"), "hop 0");
        if (e != "") return (e, false);
        for (int i = 1; i < chain.Count; i++)
        {
            var label = $"hop {i}";
            var parent = (Dictionary<string, object?>)chain[i - 1]!;
            var c = (Dictionary<string, object?>)chain[i]!;
            if (!StrEq(Get(c, "parent"), CapHash(parent))) return (label + ": broken parent link", false);
            if (!StrEq(Get(c, "issuer"), Get(parent, "holder"))) return (label + ": issuer is not the parent's bound holder", false);
            e = CheckSig(c, Get(parent, "holder"), label);
            if (e != "") return (e, false);
            var pc = (List<object?>)Get(parent, "caveats")!;
            var cc = (List<object?>)Get(c, "caveats")!;
            if (cc.Count < pc.Count) return (label + ": drops parent caveat(s)", false);
            for (int j = 0; j < pc.Count; j++)
                if (HashCanonical(cc[j]) != HashCanonical(pc[j])) return ($"{label}: caveat {j} altered or reordered", false);
        }
        return ("", true);
    }

    // ================= wire form (README sections 1, 3, 5) =================
    static readonly string[] Required = { "ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig" };
    static readonly string[] Optional = { "nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding", "threshold", "zk_compliance", "bond_ref",
        // B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as today.
        "alg", "pq_pk", "pq_sig" };

    static bool OnlyKeys(Dictionary<string, object?> d, params string[] allowed) => d.Keys.All(k => allowed.Contains(k));
    static bool IsNum(object? v) => v is Num n && NumberError(n.Raw) == null;

    /// <summary>Returns null when well-formed, else a short reason. Never throws.</summary>
    public static string? ValidateWire(object? o)
    {
        try
        {
            if (o is not Dictionary<string, object?> p) return "PCActn is not an object";
            foreach (var k in p.Keys) if (!Required.Contains(k) && !Optional.Contains(k)) return $"unknown field '{k}'";
            foreach (var k in Required) if (!p.ContainsKey(k)) return $"missing field '{k}'";
            var body = p.Where(kv => kv.Key != "sig" && kv.Key != "threshold" && kv.Key != "pq_sig").ToDictionary(kv => kv.Key, kv => kv.Value);
            try { Canonicalize(body); } catch (Exception e) { return e.Message; }

            foreach (var k in new[] { "ver", "counter", "iat", "exp" }) if (!TryInt(p[k], out _)) return $"'{k}' must be a safe integer";
            if (p["aud"] is not string aud || aud.Length == 0 || Encoding.UTF8.GetByteCount(aud) > 256) return "'aud' must be a non-empty string";
            if (p.TryGetValue("nonce", out var nonce) && (nonce is not string ns || ns.Length == 0 || Encoding.UTF8.GetByteCount(ns) > 128)) return "'nonce' must be a non-empty string";
            // B4 crypto-agility: validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite (absent `alg` == classical 64-byte sig).
            var sigErr = ValidateSignatureWire(p);
            if (sigErr != null) return sigErr;
            if (B64uDecode(p["grant_ref"], 32) == null) return "'grant_ref' is not canonical base64url (32 bytes)";

            if (p["action"] is not Dictionary<string, object?> a) return "'action' must be an object";
            if (!OnlyKeys(a, "verb", "resource", "params_digest", "reversibility_class")) return "unknown field in 'action'";
            if (Get(a, "verb") is not string || Get(a, "resource") is not string || Get(a, "reversibility_class") is not string) return "action.verb/resource/reversibility_class must be strings";
            if (B64uDecode(Get(a, "params_digest"), 32) == null) return "'action.params_digest' is not canonical base64url (32 bytes)";

            if (p["plan"] is not Dictionary<string, object?> pl) return "'plan' must be an object";
            if (!OnlyKeys(pl, "root", "inclusion_proof", "node_id", "conditions_digest")) return "unknown field in 'plan'";
            if (B64uDecode(Get(pl, "root"), 32) == null) return "'plan.root' is not canonical base64url (32 bytes)";
            if (Get(pl, "node_id") is not string) return "'plan.node_id' must be a string";
            if (pl.TryGetValue("conditions_digest", out var cd) && B64uDecode(cd, 32) == null) return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)";
            if (Get(pl, "inclusion_proof") is not Dictionary<string, object?> ip) return "'plan.inclusion_proof' must be an object";
            if (!OnlyKeys(ip, "index", "size", "path")) return "unknown field in 'plan.inclusion_proof'";
            if (!TryInt(Get(ip, "index"), out _)) return "'plan.inclusion_proof.index' must be a safe integer";
            if (!TryInt(Get(ip, "size"), out _)) return "'plan.inclusion_proof.size' must be a safe integer";
            if (Get(ip, "path") is not List<object?> path) return "'plan.inclusion_proof.path' must be an array";
            for (int i = 0; i < path.Count; i++)
            {
                if (path[i] is not Dictionary<string, object?> st) return $"proof step {i} must be an object";
                if (!OnlyKeys(st, "side", "hash")) return $"unknown field in path[{i}]";
                if (Get(st, "side") is not string side || (side != "L" && side != "R")) return $"proof step {i}: side must be 'L' or 'R'";
                if (B64uDecode(Get(st, "hash"), 32) == null) return $"proof step {i}: hash is not canonical base64url (32 bytes)";
            }

            if (p["cap_chain"] is not List<object?> chain) return "'cap_chain' must be an array";
            for (int i = 0; i < chain.Count; i++)
            {
                if (chain[i] is not Dictionary<string, object?> c) return $"cap_chain[{i}] must be an object";
                if (!OnlyKeys(c, "id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig")) return $"unknown field in cap_chain[{i}]";
                foreach (var k in new[] { "id", "issuer", "holder", "body_digest" })
                    if (B64uDecode(Get(c, k), 32) == null) return $"cap_chain[{i}].{k} is not canonical base64url (32 bytes)";
                // B4 crypto-agility: validate the hop's `alg`/`sig`/`pq_pk`/`pq_sig` per suite, exactly as the
                // leaf. Absent `alg` asserts a 64-byte `sig` and that `pq_pk`/`pq_sig` are absent (byte-identical).
                var hopSigErr = ValidateSignatureWire(c);
                if (hopSigErr != null) return $"cap_chain[{i}]: {hopSigErr}";
                if (c.ContainsKey("parent") && B64uDecode(c["parent"], 32) == null) return $"cap_chain[{i}].parent is not canonical base64url (32 bytes)";
                if (Get(c, "caveats") is not List<object?> cv || !cv.All(x => x is Dictionary<string, object?> d && Get(d, "type") is string)) return $"cap_chain[{i}].caveats must be an array of {{type,...}} objects";
            }

            if (p["attestation"] is not Dictionary<string, object?> at || !TryInt(Get(at, "epoch"), out _)) return "'attestation' must be an object with an integer 'epoch'";
            if (Get(at, "quote_digest") is not string || Get(at, "model_id") is not string || Get(at, "measurement") is not string || Get(at, "operator") is not string) return "attestation string fields must be strings";
            if (p["provenance"] is not Dictionary<string, object?> pv || Get(pv, "causal_hash") is not string || !IsNum(Get(pv, "taint_level"))
                || Get(pv, "trusted_refs") is not List<object?> tr || !tr.All(x => x is string)) return "'provenance' is malformed";
            if (p["freshness"] is not Dictionary<string, object?> fr || !TryInt(Get(fr, "epoch"), out _) || Get(fr, "beacon_ref") is not string || Get(fr, "accumulator_witness") is not string) return "'freshness' is malformed";
            if (p["risk_claim"] is not Dictionary<string, object?> rc || !IsNum(Get(rc, "r")) || Get(rc, "inputs") is not Dictionary<string, object?>) return "'risk_claim' is malformed";

            if (p.TryGetValue("caution", out var cau))
            {
                if (!IsNum(cau)) return "'caution' must be a number in [0,1]";
                var cv2 = double.Parse(((Num)cau!).Raw, NumberStyles.Float, CultureInfo.InvariantCulture);
                if (cv2 < 0 || cv2 > 1) return "'caution' must be a number in [0,1]";
            }
            if (p.TryGetValue("rationale_commitment", out var rcm) && B64uDecode(rcm, 32) == null) return "'rationale_commitment' is not canonical base64url (32 bytes)";
            if (p.TryGetValue("tool_binding", out var tb) && B64uDecode(tb, 32) == null) return "'tool_binding' is not canonical base64url (32 bytes)";
            if (p.TryGetValue("progress_step", out var ps) && ps is not Dictionary<string, object?>) return "'progress_step' must be an object";
            if (p.TryGetValue("prohibition_evidence", out var pe) && pe is not Dictionary<string, object?> && pe is not List<object?>) return "'prohibition_evidence' must be an object or array";
            if (p.TryGetValue("threshold", out var th))
            {
                if (th is not Dictionary<string, object?> td || Get(td, "shares") is not List<object?> shares) return "'threshold' must be {shares:[...]}";
                for (int i = 0; i < shares.Count; i++)
                {
                    if (shares[i] is not Dictionary<string, object?> s || Get(s, "role") is not string) return $"threshold.shares[{i}] is malformed";
                    if (B64uDecode(Get(s, "publicKey"), 32) == null) return $"threshold.shares[{i}].publicKey is not canonical base64url (32 bytes)";
                    if (B64uDecode(Get(s, "sig"), 64) == null) return $"threshold.shares[{i}].sig is not canonical base64url (64 bytes)";
                }
            }
            return null;
        }
        catch (Exception e) { return "malformed: " + e.Message; }
    }

    // ================= PCActn =================
    public static byte[] ThresholdMessage(Dictionary<string, object?> p)
    {
        // `sig`, `threshold` and the B4 `pq_sig` are unsigned (stripped); `alg`/`pq_pk` ARE signed.
        var body = p.Where(kv => kv.Key != "sig" && kv.Key != "threshold" && kv.Key != "pq_sig").ToDictionary(kv => kv.Key, kv => kv.Value);
        return Cat(Encoding.UTF8.GetBytes(SigDomain), Sha(Canon(body)));
    }

    /// <summary>Verify RAW signed bytes: strict-parse (a parse failure or non-object is a `wire` failure), then verify.</summary>
    public static Verdict VerifyRaw(string pcactnJson, Dictionary<string, object?> grant, long now, string audience)
    {
        object? tree;
        try { tree = ParseStrict(pcactnJson); }
        catch (Exception e)
        {
            var v = new Verdict { Allow = false, Reason = "wire: " + e.Message };
            v.Checks["wire"] = false;
            return v;
        }
        return VerifyPcactnCore(tree, grant, now, audience);
    }

    public static Verdict VerifyPcactnCore(object? pcactn, Dictionary<string, object?> grant, long now, string audience)
    {
        var v = new Verdict();
        var wire = ValidateWire(pcactn);
        if (wire != null)
        {
            v.Checks["wire"] = false; v.Allow = false; v.Reason = "wire: " + wire;
            return v; // terminal
        }
        var p = (Dictionary<string, object?>)pcactn!;
        v.Checks["wire"] = true;
        foreach (var k in new[] { "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter" }) v.Checks[k] = false;
        bool failed = false;
        void Fail(string name, string why)
        {
            failed = true; v.Checks[name] = false;
            if (v.Reason == "") v.Reason = name + ": " + why;
        }
        try
        {
            TryInt(p["ver"], out var ver); TryInt(p["iat"], out var iat); TryInt(p["exp"], out var exp); TryInt(p["counter"], out var counter);

            if (ver == 2) v.Checks["version"] = true; else Fail("version", $"unsupported ver {ver} (this verifier requires 2)");

            if ((string)p["aud"]! == audience) v.Checks["audience"] = true; else Fail("audience", "aud does not match this resource server / instance");

            if (!(exp > iat)) Fail("validity", "exp must be greater than iat");
            else if (exp - iat > MaxLifetimeMs) Fail("validity", $"lifetime exceeds {MaxLifetimeMs} ms");
            else if (iat > now + MaxSkewMs) Fail("validity", "iat is in the future (clock skew)");
            else if (now > exp) Fail("validity", "the PCActn has expired");
            else v.Checks["validity"] = true;

            var chain = (List<object?>)p["cap_chain"]!;
            if (chain.Count == 0) Fail("chain", "empty chain");
            else if (chain.Count > MaxChainHops) Fail("chain", $"chain too long (max {MaxChainHops} hops)"); // before any signature work
            else if (CapHash(chain[0]) != CapHash(grant)) Fail("chain", "chain root is not the grant");
            else
            {
                var gi = Get(grant, "issuer");
                var (why, ok) = VerifyChain(chain, gi, gi != null);
                if (ok) v.Checks["chain"] = true; else Fail("chain", why);
            }

            // grant_ref_bound (normative): the signed grant_ref MUST be a non-empty string byte-equal to the id of the
            // ROOT capability of the presented chain (cap_chain[0].id). Independent of the chain verdict; fail-closed
            // on an empty / malformed chain. Replay state is keyed on grant_ref, so it must not be attacker-chosen.
            if (p.TryGetValue("grant_ref", out var grefObj) && grefObj is string gref && gref.Length > 0
                && chain.Count > 0 && chain[0] is Dictionary<string, object?> rootCap
                && rootCap.TryGetValue("id", out var rootIdObj) && rootIdObj is string rootId
                && string.Equals(gref, rootId, StringComparison.Ordinal)) v.Checks["grant_ref_bound"] = true;
            else Fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain");

            var plan = (Dictionary<string, object?>)p["plan"]!;
            var action = (Dictionary<string, object?>)p["action"]!;
            var cond = Get(plan, "conditions_digest") as string ?? ConditionsDigest(null, null);
            var root = (string)plan["root"]!;
            var proof = (Dictionary<string, object?>)plan["inclusion_proof"]!;
            var leaf = PlanLeaf(Get(plan, "node_id"), action, cond);
            if (leaf != null && VerifyInclusion(root, proof, leaf)) v.Checks["plan_inclusion"] = true;
            else Fail("plan_inclusion", "action is not a node of the committed plan");

            if (chain.Count > 0 && chain[^1] is Dictionary<string, object?> leafCap
                && VerifyLeafSuite(p, Get(leafCap, "holder"), ThresholdMessage(p))) v.Checks["leaf_signature"] = true;
            else Fail("leaf_signature", "signature does not verify under the leaf holder key");

            if (counter >= 0) v.Checks["counter"] = true;
            else Fail("counter", "missing or not a non-negative safe integer");

            v.Allow = !failed;
        }
        catch (Exception ex)
        {
            v.Allow = false;
            v.Reason = "malformed PCActn: " + ex.Message;
        }
        return v;
    }
}
