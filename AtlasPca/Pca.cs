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
    const string ShareSuiteTag = "\0atlas-pca/share-suite/v1\0";
    const string DefaultRev = "reversible";
    public const int MaxJsonDepth = 32;
    public const int MaxJsonChars = 1 << 20; // UTF-8 bytes;
    public const int MaxDecimalDigits = 15;
    public const int MaxChainHops = 16;
    /// <summary>Shared hard caveat caps (all PCA verifiers): per-hop cumulative list, and the sum over every hop of a chain.</summary>
    public const int MaxCaveatsPerHop = 256;
    public const int MaxCaveatsPerChain = 1024;
    public const string CaveatLimitReason = "chain exceeds caveat limit (max 256 per hop, 1024 per chain)";
    /// <summary>Shared raw wire-size cap of a PCActn JSON document (UTF-8 bytes), checked before any parsing.</summary>
    public const int MaxArtifactBytes = 524288;
    public const string ArtifactSizeReason = "artifact exceeds size limit (max 524288 bytes)";

    /// <summary>True when the raw PCActn document exceeds <see cref="MaxArtifactBytes"/> UTF-8 bytes (O(1) for clearly small/large strings).</summary>
    public static bool ArtifactTooLarge(string text)
    {
        if (text.Length > MaxArtifactBytes) return true;
        if ((long)text.Length * 3 <= MaxArtifactBytes) return false;
        return Encoding.UTF8.GetByteCount(text) > MaxArtifactBytes;
    }

    /// <summary>True when the chain breaks the caveat caps; reads raw list sizes only, so it runs before any hashing/signature work.</summary>
    public static bool CaveatLimitExceeded(List<object?> chain)
    {
        long total = 0;
        foreach (var c in chain)
        {
            int n = c is Dictionary<string, object?> m && m.TryGetValue("caveats", out var cv) && cv is List<object?> l ? l.Count : 0;
            if (n > MaxCaveatsPerHop) return true;
            total += n;
            if (total > MaxCaveatsPerChain) return true;
        }
        return false;
    }
    public const long MaxLifetimeMs = 3_600_000;
    public const long MaxSkewMs = 60_000;
    public const long MaxSafeInt = 9007199254740991L;

    // ================= JSON parsing (hand-written; never System.Text.Json) =================
    // tree: null, bool, string, Num, List<object?>, Dictionary<string,object?>

    /// <summary>STRICT profile for signed bytes (README section 2/3). Throws StrictJsonException.</summary>
    public static object? ParseStrict(string text) => new Parser(text, true, MaxJsonDepth).Run();

    /// <summary>Plain RFC 8259 parse (used only for trusted fixtures such as vectors.json): no profile checks.</summary>
    public static object? ParseJson(string text) => new Parser(text, false, LenientMaxDepth).Run();

    /// <summary>Recursion cap of the lenient parser (same bound as the PHP loader). Enforced BEFORE recursing, so a hostile document can
    /// never exhaust the thread stack (a .NET stack overflow is unrecoverable and kills the process).</summary>
    public const int LenientMaxDepth = 512;

    /// <summary>Lenient parse with an explicit (small) depth cap: for untrusted transport envelopes such as {"pcactn": ...}, whose PCActn
    /// is re-validated strictly afterwards. Throws StrictJsonException("nesting too deep") beyond <paramref name="maxDepth"/>.</summary>
    public static object? ParseBounded(string text, int maxDepth) => new Parser(text, false, maxDepth).Run();

    /// <summary>R6-01: STRICT profile for an untrusted transport envelope that WRAPS a PCActn one level deep, e.g. the
    /// middleware body <c>{"pcactn": ...}</c>. Identical to <see cref="ParseStrict"/> (duplicate keys refused at ANY depth,
    /// strict numbers, no lone surrogates, 1 MiB cap, depth cap <see cref="MaxJsonDepth"/> counted from the ENVELOPE, exactly like
    /// the reference's strictParse of the whole body in require-pca.ts defaultExtract and the Go / Python middleware). A lenient
    /// envelope parse would collapse duplicate keys last-wins before verification while a first-wins downstream parser of the
    /// (rewound) body saw the other value.</summary>
    public static object? ParseStrictEnvelope(string text) => new Parser(text, true, MaxJsonDepth).Run();

    sealed class Parser
    {
        readonly string t; readonly bool strict; readonly int maxDepth; int i;
        public Parser(string text, bool strict, int maxDepth) { t = text; this.strict = strict; this.maxDepth = maxDepth; }
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
                if (l < -MaxSafeInt || l > MaxSafeInt) throw new InvalidOperationException("canonicalize: unsafe integer");
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

    /// <summary>An opaque PQ verification key (R3-01 choke point). Instances are minted ONLY inside this class
    /// (private constructor): <see cref="Resolve"/> (the single key-resolution function, mirroring
    /// <c>resolvePqVerifyKey</c> in packages/pca/src/pq.ts) and <see cref="CallerVouched"/>. The low-level suite verify
    /// (<see cref="VerifySuite"/>) accepts ONLY this type, so PQ verification cannot be reached with a <c>pq_pk</c>
    /// read straight off the artifact being verified.</summary>
    sealed class PinnedPq
    {
        public string Key { get; }
        PinnedPq(string key) { Key = key; }

        /// <summary>THE choke point. Returns the key to verify under, or null (REFUSE) when no verifier-side authority
        /// vouches for the artifact's <c>pq_pk</c>: (1) <paramref name="trustedPk"/>, a key the verifier itself holds (the
        /// stored grant); (2) <paramref name="pqPins"/>[<paramref name="identity"/>] (own entry only): the artifact's
        /// pq_pk MUST equal the pin, a differing pin is a refusal; (3) <paramref name="holderPq"/>: pq_pk must hash to
        /// the signer's committed holder_pq (F-2). Natives have no allowUnboundPq.</summary>
        public static PinnedPq? Resolve(string? identity, object? artifactPk, object? holderPq = null,
            IReadOnlyDictionary<string, string>? pqPins = null, string? trustedPk = null)
        {
            if (!string.IsNullOrEmpty(trustedPk)) return new PinnedPq(trustedPk);
            if (artifactPk is not string pk || pk.Length == 0) return null;
            if (pqPins != null && identity != null && pqPins.TryGetValue(identity, out var pin))
                return pin == pk ? new PinnedPq(pk) : null;
            if (holderPq is string cm && HolderPqCommitment(pk) == cm) return new PinnedPq(pk);
            return null;
        }

        /// <summary>EXPLICITLY caller-vouched: the key is authorised by the caller out of band (threshold shares,
        /// the pq_artifact conformance primitives). Proves nothing about who issued the artifact; chain hops and the
        /// PCActn leaf never use it.</summary>
        public static PinnedPq? CallerVouched(object? pk) => pk is string s && s.Length > 0 ? new PinnedPq(s) : null;
    }

    static bool MlDsaVerifyPinned(PinnedPq? pq, byte[] msg, object? sigB64u) =>
        pq != null && MlDsaVerifyB64u(pq.Key, msg, sigB64u);

    /// <summary>Verify <paramref name="p"/>'s signature(s) under its suite. The PQ half verifies ONLY under
    /// <paramref name="pq"/>, never under <c>p["pq_pk"]</c>. FAIL-CLOSED.</summary>
    static bool VerifySuite(Dictionary<string, object?> p, object? holder, byte[] msg, PinnedPq? pq)
    {
        var (name, _) = ResolveSuite(p);
        if (name == null) return false;
        var sig = Get(p, "sig");
        return name switch
        {
            "ed25519" => VerifyB64u(holder, msg, sig),
            "ml-dsa-65" => MlDsaVerifyPinned(pq, msg, sig),
            "hybrid-ed25519-ml-dsa-65" =>
                VerifyB64u(holder, msg, sig) && MlDsaVerifyPinned(pq, msg, Get(p, "pq_sig")),
            _ => false,
        };
    }

    /// <summary>Suite-aware signature verification over an arbitrary <paramref name="msg"/>, exposed for the
    /// threshold-share and PQ-artifact conformance surfaces (same agility seam as the leaf). An absent
    /// <paramref name="alg"/> defaults to ed25519. FAIL-CLOSED: any unimplemented suite (and any malformed
    /// key / signature) returns false, never throws. CALLER-VOUCHED: <paramref name="pqPk"/> is trusted as given, so this
    /// proves nothing about who issued the artifact; use it only where the key is authorised elsewhere.</summary>
    public static bool VerifySuiteSig(string? alg, object? edPk, object? pqPk, byte[] msg, object? sig, object? pqSig)
    {
        var name = alg ?? "ed25519";
        return name switch
        {
            "ed25519" => VerifyB64u(edPk, msg, sig),
            "ml-dsa-65" => MlDsaVerifyPinned(PinnedPq.CallerVouched(pqPk), msg, sig),
            "hybrid-ed25519-ml-dsa-65" => VerifyB64u(edPk, msg, sig) && MlDsaVerifyPinned(PinnedPq.CallerVouched(pqPk), msg, pqSig),
            _ => false, // unimplemented / unknown suite: fail-closed
        };
    }

    // ================= v2.1 threshold-share binding (README section 9) =================

    /// <summary>Recompute the signer-set hash committed by a threshold share (v2.1):
    /// <c>sha256("atlas-pca/signerset/v1\0" || canonical(sort_by(role, publicKey)[{publicKey, role}]))</c>.
    /// FAIL-CLOSED: null on any malformed entry (never trusts a precomputed <c>signer_set_hash</c>).</summary>
    static int Utf8Compare(string a, string b) =>
        ((ReadOnlySpan<byte>)Encoding.UTF8.GetBytes(a)).SequenceCompareTo(Encoding.UTF8.GetBytes(b));

    /// <summary>Registered PQ public-key lengths of every suite (ml-dsa-65/87, slh-dsa-128f/256s, fn-dsa-512/1024, less-cat1),
    /// whether or not this SDK implements the suite: a signer set is validated exactly like the reference.</summary>
    static readonly HashSet<int> PqPkLengths = new() { 1952, 2592, 32, 64, 897, 1793, 97484 };
    static readonly HashSet<string> SignerRoles = new() { "agent", "guardian", "principal" };

    /// <summary>R6-03: validate the WHOLE signer set like the reference (decideThreshold BuildReg): every entry an object with
    /// a known role and a canonical 32-byte publicKey; a present pq_pk (JSON null is present) canonical base64url of a
    /// registered PQ key length; one key per role; one role per key; a duplicate (role, key) only with the same pq_pk.
    /// Returns role -> (publicKey, pq_pk or null), or null when the set is malformed.</summary>
    static Dictionary<string, (string Pk, string? Pq)>? ValidateSignerSet(List<object?> signerSet)
    {
        var reg = new Dictionary<string, (string Pk, string? Pq)>();
        foreach (var e in signerSet)
        {
            if (e is not Dictionary<string, object?> o) return null;
            if (Get(o, "role") is not string role || !SignerRoles.Contains(role)) return null;
            if (Get(o, "publicKey") is not string pk || B64uDecode(pk, 32) == null) return null;
            string? pq = null;
            if (Has(o, "pq_pk"))
            {
                if (Get(o, "pq_pk") is not string ps) return null;
                var pb = B64uDecode(ps);
                if (pb == null || !PqPkLengths.Contains(pb.Length)) return null;
                pq = ps;
            }
            if (reg.TryGetValue(role, out var prev))
            {
                if (prev.Pk != pk) return null;   // two keys for one role
                if (prev.Pq != pq) return null;   // duplicate (role, key) with a conflicting pq_pk
                continue;
            }
            foreach (var kv in reg) if (kv.Value.Pk == pk) return null; // one key under two roles
            reg[role] = (pk, pq);
        }
        return reg;
    }

    static byte[]? SignerSetHash(List<object?> signerSet)
    {
        var entries = new List<(string Role, string Pk, string? Pq)>(signerSet.Count);
        foreach (var e in signerSet)
        {
            if (e is not Dictionary<string, object?> o) return null;
            if (Get(o, "role") is not string role || Get(o, "publicKey") is not string pk) return null;
            entries.Add((role, pk, Get(o, "pq_pk") as string));
        }
        // R6-04: UTF-8 BYTE ordering (role, then publicKey) like the reference's compareUtf8. string.CompareOrdinal
        // compares UTF-16 code units, which orders a non-BMP character (surrogate pair) before U+E000..U+FFFF.
        entries.Sort((a, b) =>
        {
            int c = Utf8Compare(a.Role, b.Role);
            return c != 0 ? c : Utf8Compare(a.Pk, b.Pk);
        });
        var arr = entries
            .Select(e =>
            {
                var row = new Dictionary<string, object?> { ["publicKey"] = e.Pk, ["role"] = e.Role };
                if (e.Pq != null) row["pq_pk"] = e.Pq; // additive: a registered PQ key is part of the bound set
                return (object?)row;
            })
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
    /// <summary>The signer-set hash as base64url (null on a set with a non-object entry or a non-string role / publicKey).</summary>
    public static string? SignerSetHashB64u(List<object?> signerSet) { if (signerSet == null) return null; var h = SignerSetHash(signerSet); return h == null ? null : B64u(h); }

    /// <summary>Total entry point for an entry of ANY JSON shape (R6-05): a non-object is false.</summary>
    public static bool VerifyThresholdShare(object? entry) => entry is Dictionary<string, object?> d && VerifyThresholdShare(d);

    public static bool VerifyThresholdShare(Dictionary<string, object?> entry)
    {
        try
        {
            if (Get(entry, "role") is not string role) return false;
            // R6-04: t is exactly 1, 2 or 3 (the reference refuses every other value; a wider range would sign t mod 256).
            if (!TryInt(Get(entry, "t"), out var t) || t < 1 || t > 3) return false;
            if (Get(entry, "signer_set") is not List<object?> signerSet) return false;
            var tm = B64uDecode(Get(entry, "threshold_message")); // strict base64url, no fixed length
            if (tm == null) return false;
            // R6-03: the WHOLE set is validated before the share is looked at.
            var reg = ValidateSignerSet(signerSet);
            if (reg == null) return false;
            var ssh = SignerSetHash(signerSet);
            if (ssh == null) return false;
            if (Get(entry, "share") is not Dictionary<string, object?> share) return false;
            if (Get(share, "publicKey") is not string pk) return false;
            if (Get(share, "role") is not string srole || srole != role) return false;
            // R5-A1: the share must be for the ONE key the verifier's signer set registers for `role`; the
            // share's own publicKey / pq_pk never vouch for themselves.
            if (!reg.TryGetValue(role, out var r) || r.Pk != pk) return false;
            var alg = Get(share, "alg") as string;
            if (Has(share, "alg") && alg == null) return false;
            // A share that NAMES a pq_pk must name exactly its role's registered one (any suite; a role registering
            // none has nothing it could equal). The key used is always the registered one.
            if (Has(share, "pq_pk") && (r.Pq == null || Get(share, "pq_pk") is not string sp || sp != r.Pq)) return false;
            // R6-02: a role that registers a pq_pk REQUIRES a PQ (pure or hybrid) share; an ed25519-only share
            // for it is refused (otherwise an Ed25519 break would still forge the role).
            if (r.Pq != null && (alg ?? "ed25519") == "ed25519") return false;
            object? pqPk = Get(share, "pq_pk");
            var tag = Array.Empty<byte>();
            if ((alg ?? "ed25519") != "ed25519")
            {
                // PQ key = the signer set's registered pq_pk, never the share's own.
                if (r.Pq == null) return false;
                pqPk = r.Pq;
                if (alg != null && Pq.Suites.ContainsKey(alg)) tag = Encoding.UTF8.GetBytes(ShareSuiteTag + alg);
            }
            // Bound share message: domain(role) || sha256(thresholdMessage) || signerSetHash || t [|| suite tag].
            var msg = Cat(
                Encoding.UTF8.GetBytes(ShareDomainPrefix), Encoding.UTF8.GetBytes(role), new byte[] { 0 },
                Sha(tm), ssh, new byte[] { (byte)t }, tag);
            return VerifySuiteSig(alg, pk, pqPk, msg, Get(share, "sig"), Get(share, "pq_sig"));
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
        if (Get(c, "holder_pq") is string hpq) body["holder_pq"] = hpq; // TS bodyOf: included iff defined
        if (name != "ed25519")
        {
            body["alg"] = name;
            if (Pq.Suites[name].NeedsPqPk && Get(c, "pq_pk") is string pk) body["pq_pk"] = pk;
        }
        return body;
    }

    static string CheckSig(Dictionary<string, object?> c, object? signer, string label, PinnedPq? pq = null)
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
        // Suite-agile hop verification (mirrors VerifySuite): ed25519 == VerifyB64u(signer, msg, sig);
        // hybrid requires BOTH the Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under the resolved `pq` key);
        // pure ml-dsa-65 verifies `sig` under it (never the hop's own pq_pk). The signer is the expected Ed25519 key.
        if (!VerifySuite(c, signer, Cat(Encoding.UTF8.GetBytes(CapDomain), d), pq))
            return label + ": bad signature (not signed by expected key)";
        return "";
    }

    static bool StrEq(object? a, object? b) => a is string x && b is string y && x == y;

    static bool WellTyped(object? o) =>
        o is Dictionary<string, object?> c
        && Get(c, "id") is string && Get(c, "issuer") is string && Get(c, "holder") is string
        && Get(c, "body_digest") is string && Get(c, "sig") is string
        && (!Has(c, "parent") || Get(c, "parent") is string)
        && (!Has(c, "holder_pq") || Get(c, "holder_pq") is string)
        && (!Has(c, "alg") || Get(c, "alg") is string)
        && (!Has(c, "pq_pk") || Get(c, "pq_pk") is string)
        && (!Has(c, "pq_sig") || Get(c, "pq_sig") is string)
        && Get(c, "caveats") is List<object?> cv
        && cv.All(x => x is Dictionary<string, object?> d && Get(d, "type") is string);

    /// <summary>F-2 commitment to a holder's PQ key: b64u(sha256("atlas-pca/holder-pq/v1\0" || utf8(pq_pk))).</summary>
    public static string HolderPqCommitment(string pqPk) => B64u(Sha(Cat(Encoding.UTF8.GetBytes("atlas-pca/holder-pq/v1\0"), Encoding.UTF8.GetBytes(pqPk))));

    /// <summary>`allowedSuites` policy for one hop / leaf (absent `alg` == ed25519). Null policy == no restriction.</summary>
    static string? SuitePolicyError(object? alg, string label, IReadOnlyCollection<string>? allowed)
    {
        if (allowed == null) return null;
        var a = alg ?? "ed25519";
        return a is string s && allowed.Contains(s) ? null : $"{label}: signature suite '{a}' is not allowed by this verifier's suite policy";
    }

    /// <summary>F-2/F-4: a suite that carries a PQ key is accepted only if pq_pk hashes to the signer's committed holder_pq.</summary>
    static string? PqBindingError(Dictionary<string, object?> signed, object? committed, string label)
    {
        var (name, _) = ResolveSuite(signed);
        if (name == null || !Pq.Suites[name].NeedsPqPk) return null;
        if (committed is not string cm)
            return $"{label}: suite '{name}' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)";
        if (Get(signed, "pq_pk") is not string pk || HolderPqCommitment(pk) != cm)
            return $"{label}: pq_pk does not match the signer's committed holder_pq (F-2)";
        return null;
    }

    /// <summary>The root hop has no parent holding a holder_pq commitment, so a non-ed25519 root's PQ key must come from a
    /// verifier-side authority: the verifier's stored copy of this very grant (trustedRoot, same content hash) or a pin
    /// for root.issuer. Mirrors <c>rootPq</c> in capability.ts. Returns (key, null) / (null, null) for ed25519 / (null, reason).</summary>
    static (PinnedPq? Key, string? Err) ResolveRootPq(Dictionary<string, object?> root, IReadOnlyDictionary<string, string>? pqPins, Dictionary<string, object?>? trustedRoot)
    {
        var (name, _) = ResolveSuite(root);
        if (name == null || !Pq.Suites[name].NeedsPqPk) return (null, null);
        var pk = Get(root, "pq_pk");
        string? trusted = null;
        if (trustedRoot != null && pk is string tpk)
        {
            try { if (CapHash(trustedRoot) == CapHash(root)) trusted = tpk; } catch { trusted = null; }
        }
        var key = PinnedPq.Resolve(Get(root, "issuer") as string, pk, pqPins: pqPins, trustedPk: trusted);
        if (key == null)
            return (null, $"hop 0: root suite '{name}' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)");
        return (key, null);
    }

    /// <summary>Verify a capability chain. A non-ed25519 (pure-PQ or hybrid) ROOT is accepted only if
    /// <paramref name="pqPins"/>[root.issuer] equals the root's pq_pk, or <paramref name="trustedRoot"/> is the root
    /// itself (the verifier's own stored grant); otherwise it is refused (R4-01). Ed25519 roots need neither.</summary>
    public static (string Why, bool Ok) VerifyChain(List<object?> chain, object? expectedRootIssuer, bool haveIssuer, IReadOnlyCollection<string>? allowedSuites = null,
        IReadOnlyDictionary<string, string>? pqPins = null, Dictionary<string, object?>? trustedRoot = null)
    {
        // TOTAL (R6-05): a hostile chain is a verdict, never an exception.
        try { return VerifyChainUnchecked(chain, expectedRootIssuer, haveIssuer, allowedSuites, pqPins, trustedRoot); }
        catch (Exception ex) { return ("malformed capability chain: " + ex.GetType().Name, false); }
    }

    static (string Why, bool Ok) VerifyChainUnchecked(List<object?> chain, object? expectedRootIssuer, bool haveIssuer, IReadOnlyCollection<string>? allowedSuites,
        IReadOnlyDictionary<string, string>? pqPins, Dictionary<string, object?>? trustedRoot)
    {
        if (chain == null) return ("empty chain", false);
        if (chain.Count == 0) return ("empty chain", false);
        if (chain.Count > MaxChainHops) return ($"chain too long (max {MaxChainHops} hops)", false); // before any signature work
        if (CaveatLimitExceeded(chain)) return (CaveatLimitReason, false);
        for (int i = 0; i < chain.Count; i++) if (!WellTyped(chain[i])) return ($"hop {i}: malformed capability", false);
        var root = (Dictionary<string, object?>)chain[0]!;
        if (Has(root, "parent")) return ("hop 0: root must not have a parent", false);
        if (haveIssuer && !StrEq(Get(root, "issuer"), expectedRootIssuer)) return ("hop 0: root issuer is not the expected principal", false);
        var rootPol = SuitePolicyError(Get(root, "alg"), "hop 0", allowedSuites);
        if (rootPol != null) return (rootPol, false);
        var (rootPq, rootPqErr) = ResolveRootPq(root, pqPins, trustedRoot);
        if (rootPqErr != null) return (rootPqErr, false);
        var e = CheckSig(root, Get(root, "issuer"), "hop 0", rootPq);
        if (e != "") return (e, false);
        for (int i = 1; i < chain.Count; i++)
        {
            var label = $"hop {i}";
            var parent = (Dictionary<string, object?>)chain[i - 1]!;
            var c = (Dictionary<string, object?>)chain[i]!;
            if (!StrEq(Get(c, "parent"), CapHash(parent))) return (label + ": broken parent link", false);
            if (!StrEq(Get(c, "issuer"), Get(parent, "holder"))) return (label + ": issuer is not the parent's bound holder", false);
            var pol = SuitePolicyError(Get(c, "alg"), label, allowedSuites);
            if (pol != null) return (pol, false);
            var unbound = PqBindingError(c, Get(parent, "holder_pq"), label);
            if (unbound != null) return (unbound, false);
            e = CheckSig(c, Get(parent, "holder"), label,
                PinnedPq.Resolve(Get(parent, "holder") as string, Get(c, "pq_pk"), holderPq: Get(parent, "holder_pq")));
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
                if (!OnlyKeys(c, "id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig", "holder_pq")) return $"unknown field in cap_chain[{i}]";
                foreach (var k in new[] { "id", "issuer", "holder", "body_digest" })
                    if (B64uDecode(Get(c, k), 32) == null) return $"cap_chain[{i}].{k} is not canonical base64url (32 bytes)";
                // B4 crypto-agility: validate the hop's `alg`/`sig`/`pq_pk`/`pq_sig` per suite, exactly as the
                // leaf. Absent `alg` asserts a 64-byte `sig` and that `pq_pk`/`pq_sig` are absent (byte-identical).
                var hopSigErr = ValidateSignatureWire(c);
                if (hopSigErr != null) return $"cap_chain[{i}]: {hopSigErr}";
                if (c.ContainsKey("parent") && B64uDecode(c["parent"], 32) == null) return $"cap_chain[{i}].parent is not canonical base64url (32 bytes)";
                if (c.ContainsKey("holder_pq") && B64uDecode(c["holder_pq"], 32) == null) return $"cap_chain[{i}].holder_pq is not canonical base64url (32 bytes)";
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
    public static Verdict VerifyRaw(string pcactnJson, Dictionary<string, object?> grant, long now, string audience, IReadOnlyCollection<string>? allowedSuites = null)
    {
        object? tree;
        if (pcactnJson == null) // R6-05: total entry point (a null document is a wire failure, not a NullReferenceException)
        {
            var nul = new Verdict { Allow = false, Reason = "wire: PCActn is not an object" };
            nul.Checks["wire"] = false;
            return nul;
        }
        if (ArtifactTooLarge(pcactnJson)) // FIRST: before any parsing
        {
            var big = new Verdict { Allow = false, Reason = "wire: " + ArtifactSizeReason };
            big.Checks["wire"] = false;
            return big;
        }
        try { tree = ParseStrict(pcactnJson); }
        catch (Exception e)
        {
            var v = new Verdict { Allow = false, Reason = "wire: " + e.Message };
            v.Checks["wire"] = false;
            return v;
        }
        return VerifyPcactnCore(tree, grant, now, audience, allowedSuites);
    }

    public static Verdict VerifyPcactnCore(object? pcactn, Dictionary<string, object?> grant, long now, string audience, IReadOnlyCollection<string>? allowedSuites = null)
    {
        // TOTAL (R6-05): the wire check runs outside the per-check try below, so guard the whole entry point.
        try { return VerifyPcactnCoreUnchecked(pcactn, grant, now, audience, allowedSuites); }
        catch (Exception ex)
        {
            var v = new Verdict { Allow = false, Reason = "wire: malformed input (" + ex.GetType().Name + ")" };
            v.Checks.Clear();
            v.Checks["wire"] = false;
            return v;
        }
    }

    static Verdict VerifyPcactnCoreUnchecked(object? pcactn, Dictionary<string, object?> grant, long now, string audience, IReadOnlyCollection<string>? allowedSuites)
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
            else if (CaveatLimitExceeded(chain)) Fail("chain", CaveatLimitReason); // before any hashing or signature work
            else if (CapHash(chain[0]) != CapHash(grant)) Fail("chain", "chain root is not the grant");
            else
            {
                var gi = Get(grant, "issuer");
                var (why, ok) = VerifyChain(chain, gi, gi != null, allowedSuites, trustedRoot: grant); // chain[0] == grant was checked above
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

            var leafCapObj = chain.Count > 0 ? chain[^1] as Dictionary<string, object?> : null;
            var leafErr = leafCapObj == null ? null
                : SuitePolicyError(Get(p, "alg"), "leaf", allowedSuites) ?? PqBindingError(p, Get(leafCapObj, "holder_pq"), "leaf");
            if (leafErr != null) Fail("leaf_signature", leafErr);
            else if (leafCapObj != null && VerifySuite(p, Get(leafCapObj, "holder"), ThresholdMessage(p),
                PinnedPq.Resolve(Get(leafCapObj, "holder") as string, Get(p, "pq_pk"), holderPq: Get(leafCapObj, "holder_pq")))) v.Checks["leaf_signature"] = true;
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
