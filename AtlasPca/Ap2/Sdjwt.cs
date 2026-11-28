// AP2 mandates as SD-JWT credentials (the AP2 package's own strict SD-JWT layer): strict base64url, duplicate-key-refusing JSON, ES256 over
// P-256 (BouncyCastle), RFC 7638 thumbprints, selective-disclosure processing and issuance. Values are the house JSON tree (D / L / string /
// bool / Num / null); an absent member is JavaScript `undefined`.
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;
using BcInt = Org.BouncyCastle.Math.BigInteger;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ap2;

/// <summary>The reference's Ap2Error (and the plain Errors / RangeErrors of its helpers): a refusal with its message.</summary>
public sealed class Ap2Exception(string message) : Exception(message)
{
    /// <summary>The Node error code the reference carries for this refusal, when it has one.</summary>
    public string? Code { get; init; }
}

/// <summary>A P-256 key pair: the public JWK <c>{kty, crv, x, y, kid?}</c> and the private scalar.</summary>
public sealed class Ap2KeyPair(D publicJwk, byte[] privateScalar)
{
    public D PublicJwk { get; } = publicJwk;
    public byte[] PrivateScalar { get; } = privateScalar;
}

/// <summary>A parsed SD-JWT hop <c>jwt~disclosure~...~</c>.</summary>
public sealed class SdJwtHop
{
    public string Raw = "";
    public string Jwt = "";
    public D Header = new();
    public D Payload = new();
    public List<string> Disclosures = new();
    public string SdAlg = "sha-256";
    public string SigningInput = "";
    public byte[] Signature = Array.Empty<byte>();
}

/// <summary>A parsed compact JWT.</summary>
public sealed class ParsedJwt
{
    public D Header = new();
    public D Payload = new();
    public string SigningInput = "";
    public byte[] Signature = Array.Empty<byte>();
}

public static partial class Ap2
{
    // ---- JavaScript-ish helpers ----
    static object? G(object? o, string k) => JsX.At(o, k);
    static bool IsUndef(object? v) => ReferenceEquals(v, JsX.Undef);
    static bool Nullish(object? v) => v == null || IsUndef(v);
    static object? Nn(object? v, object? dflt) => Nullish(v) ? dflt : v;
    static bool IsObject(object? v) => v is D;
    static string S(object? v) => JsX.Str(v);
    static Num N(long v) => IntentJs.OfLong(v);
    static object? Num_(double d) => JsX.Number(d);
    static void Put(D d, string k, object? v) { if (!IsUndef(v)) d[k] = v; }
    static bool IsStr(object? v) => v is string;
    static bool IsNonEmptyStr(object? v) => v is string s && s.Length > 0;
    static bool IsInt(object? v) => IntentJs.IsInt(v);
    static bool IsNonNegInt(object? v) => IntentJs.IsNonNeg(v);
    static double Dbl(object? v) => JsX.NumOf(v)!.Value;
    static long NowSeconds() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    static bool IsUpper3(object? v) => v is string s && s.Length == 3 && s.All(c => c >= 'A' && c <= 'Z');

    /// <summary>JavaScript <c>Math.round</c> (ties toward +infinity).</summary>
    internal static double JsRound(double x)
    {
        if (!double.IsFinite(x)) return x;
        var f = Math.Floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    // ===== base64url =====

    const string B64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    static string B64uOf(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Node's Buffer.from(s, 'base64url') for a string of alphabet characters: a dangling sextet is dropped, trailing bits ignored.</summary>
    static byte[] NodeB64Url(string s)
    {
        var bytes = new List<byte>();
        int acc = 0, bits = 0;
        foreach (var c in s)
        {
            acc = (acc << 6) | B64Alphabet.IndexOf(c);
            bits += 6;
            if (bits >= 8) { bits -= 8; bytes.Add((byte)((acc >> bits) & 0xff)); acc &= (1 << bits) - 1; }
        }
        return bytes.ToArray();
    }

    public static string B64uEncode(string s) => B64uOf(Encoding.UTF8.GetBytes(s));
    public static string B64uEncode(byte[] b) => B64uOf(b);

    static readonly Regex B64uChars = new(@"\A[A-Za-z0-9_-]*\z", RegexOptions.CultureInvariant);
    static readonly Regex B64u43 = new(@"\A[A-Za-z0-9_-]{43}\z", RegexOptions.CultureInvariant);
    static readonly Regex AsciiPrintable = new(@"\A[\x20-\x7e]*\z", RegexOptions.CultureInvariant);

    public static byte[] B64uDecode(string s, string what)
    {
        if (!B64uChars.IsMatch(s)) throw new Ap2Exception($"{what}: not base64url");
        var buf = NodeB64Url(s);
        if (B64uOf(buf) != s) throw new Ap2Exception($"{what}: non-canonical base64url");
        return buf;
    }

    // ===== JSON =====

    static void AssertNoDuplicateKeys(string text, string what)
    {
        var stack = new List<HashSet<string>?>();
        bool expectKey = false;
        for (int i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '"')
            {
                int j = i + 1;
                while (j < text.Length && text[j] != '"') j += text[j] == '\\' ? 2 : 1;
                var top = stack.Count > 0 ? stack[^1] : null;
                if (expectKey && top != null)
                {
                    var key = (string)Pca.ParseJson(text.Substring(i, j + 1 - i))!;
                    if (top.Contains(key)) throw new Ap2Exception($"{what}: duplicate key {JsJson.Quote(key)}");
                    top.Add(key);
                    expectKey = false;
                }
                i = j;
            }
            else if (c == '{') { stack.Add(new HashSet<string>(StringComparer.Ordinal)); expectKey = true; }
            else if (c == '[') { stack.Add(null); expectKey = false; }
            else if (c == '}' || c == ']') { if (stack.Count > 0) stack.RemoveAt(stack.Count - 1); expectKey = false; }
            else if (c == ',') expectKey = stack.Count > 0 && stack[^1] != null;
        }
    }

    /// <summary>JSON.parse with a duplicate-key refusal at any depth.</summary>
    public static object? ParseJson(string text, string what)
    {
        object? v;
        try { v = Pca.ParseJson(text); }
        catch (Exception e) { throw new Ap2Exception($"{what}: invalid JSON ({e.Message})"); }
        AssertNoDuplicateKeys(text, what);
        return v;
    }

    static string Utf8Text(byte[] bytes, string what)
    {
        try { return new UTF8Encoding(false, true).GetString(bytes); }
        catch (ArgumentException) { throw new Ap2Exception($"{what}: not valid UTF-8"); }
    }

    static D DecodeJsonSegment(string segment, string what)
    {
        var v = ParseJson(Utf8Text(B64uDecode(segment, what), what), what);
        return v as D ?? throw new Ap2Exception($"{what}: must be a JSON object");
    }

    // ===== digests =====

    public static bool IsSdAlg(object? v) => v is "sha-256" or "sha-384" or "sha-512";

    /// <summary>Base64url of the hash of an ASCII string under <c>sha-256</c> | <c>sha-384</c> | <c>sha-512</c>.</summary>
    public static string SdDigest(object? value, string alg = "sha-256")
    {
        if (value is not string v) throw new Ap2Exception("digest input must be a string");
        if (!AsciiPrintable.IsMatch(v)) throw new Ap2Exception("digest input must be ASCII");
        var b = Encoding.ASCII.GetBytes(v);
        return alg switch
        {
            "sha-256" => B64uOf(SHA256.HashData(b)),
            "sha-384" => B64uOf(SHA384.HashData(b)),
            "sha-512" => B64uOf(SHA512.HashData(b)),
            _ => throw new Ap2Exception("unsupported hash algorithm") { Code = "ERR_INVALID_ARG_TYPE" },
        };
    }

    // ===== P-256 keys =====

    static readonly X9ECParameters P256 = NistNamedCurves.GetByName("P-256");
    static readonly ECDomainParameters P256Domain = new(P256);

    static Org.BouncyCastle.Math.EC.ECPoint? PointOf(string x, string y)
    {
        try { return P256.Curve.ValidatePoint(new BcInt(1, NodeB64Url(x)), new BcInt(1, NodeB64Url(y))); }
        catch (Exception) { return null; }
    }

    /// <summary>A public P-256 JWK: EC / P-256, 43-character x and y on the curve, no private member, alg absent or ES256. Returns the JWK itself.</summary>
    public static D AssertP256Jwk(object? jwk, string what)
    {
        if (jwk is not D j) throw new Ap2Exception($"{what}: JWK must be an object");
        if (!JsX.StrictEq(G(j, "kty"), "EC") || !JsX.StrictEq(G(j, "crv"), "P-256")) throw new Ap2Exception($"{what}: JWK must be EC P-256");
        if (G(j, "x") is not string x || !B64u43.IsMatch(x)) throw new Ap2Exception($"{what}: bad JWK x");
        if (G(j, "y") is not string y || !B64u43.IsMatch(y)) throw new Ap2Exception($"{what}: bad JWK y");
        if (j.ContainsKey("d")) throw new Ap2Exception($"{what}: JWK carries private material");
        var alg = G(j, "alg");
        if (!IsUndef(alg) && !JsX.StrictEq(alg, "ES256")) throw new Ap2Exception($"{what}: JWK alg must be ES256");
        if (PointOf(x, y) == null) throw new Ap2Exception($"{what}: JWK is not a valid P-256 point");
        return j;
    }

    static byte[] Fixed32(BcInt v) => BigIntegers.AsUnsignedByteArray(32, v);

    /// <summary>The key pair of a private P-256 JWK <c>{kty, crv, d, x?, y?, kid?}</c>; a given x / y must match d. Throws on an invalid key.</summary>
    public static Ap2KeyPair Ap2KeyPairFromPrivateJwk(D jwk)
    {
        if (!JsX.StrictEq(G(jwk, "kty"), "EC") || !JsX.StrictEq(G(jwk, "crv"), "P-256")) throw new Ap2Exception("Invalid JWK EC key") { Code = "ERR_CRYPTO_INVALID_JWK" };
        if (G(jwk, "d") is not string ds || !B64uChars.IsMatch(ds)) throw new Ap2Exception("Invalid JWK EC key") { Code = "ERR_CRYPTO_INVALID_JWK" };
        var d = new BcInt(1, NodeB64Url(ds));
        if (NodeB64Url(ds).Length != 32 || d.SignValue == 0 || d.CompareTo(P256.N) >= 0) throw new Ap2Exception("Invalid JWK EC key") { Code = "ERR_CRYPTO_INVALID_JWK" };
        var q = P256.G.Multiply(d).Normalize();
        var x = B64uOf(Fixed32(q.AffineXCoord.ToBigInteger()));
        var y = B64uOf(Fixed32(q.AffineYCoord.ToBigInteger()));
        foreach (var (k, want) in new[] { ("x", x), ("y", y) })
        {
            var given = G(jwk, k);
            if (!IsUndef(given) && !(given is string gs && B64uChars.IsMatch(gs) && NodeB64Url(gs).AsSpan().SequenceEqual(NodeB64Url(want)))) throw new Ap2Exception("Invalid JWK EC key") { Code = "ERR_CRYPTO_INVALID_JWK" };
        }
        var pub = new D { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = x, ["y"] = y };
        if (G(jwk, "kid") is string kid) pub["kid"] = kid;
        return new Ap2KeyPair(pub, d.ToByteArrayUnsigned());
    }

    /// <summary>RFC 7638 thumbprint of a public P-256 JWK (members interpolated as the reference does).</summary>
    public static string JwkThumbprint(object? jwk)
    {
        var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{S(G(jwk, "x"))}\",\"y\":\"{S(G(jwk, "y"))}\"}}";
        return B64uOf(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    static string Es256Sign(Ap2KeyPair key, string signingInput)
    {
        var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
        signer.Init(true, new ECPrivateKeyParameters(new BcInt(1, key.PrivateScalar), P256Domain));
        var rs = signer.GenerateSignature(SHA256.HashData(Encoding.ASCII.GetBytes(signingInput)));
        return B64uOf(Fixed32(rs[0]).Concat(Fixed32(rs[1])).ToArray());
    }

    static bool Es256Verify(D jwk, string signingInput, byte[] signature)
    {
        if (signature.Length != 64) return false;
        var pt = PointOf((string)jwk["x"]!, (string)jwk["y"]!);
        if (pt == null) return false;
        var signer = new ECDsaSigner();
        signer.Init(false, new ECPublicKeyParameters(pt, P256Domain));
        return signer.VerifySignature(SHA256.HashData(Encoding.ASCII.GetBytes(signingInput)), new BcInt(1, signature[..32]), new BcInt(1, signature[32..]));
    }

    // ===== hops =====

    public static string HopSdJwt(string jwt, IEnumerable<string> disclosures) => jwt + "~" + string.Concat(disclosures.Select(d => d + "~"));

    /// <summary>Parse an AP2 SD-JWT hop (<c>jwt~d1~...~</c>, no trailing KB-JWT).</summary>
    public static SdJwtHop ParseSdJwtHop(object? token)
    {
        if (token is not string t || t.Length == 0) throw new Ap2Exception("SD-JWT: empty");
        if (t.StartsWith('~')) throw new Ap2Exception("SD-JWT: empty issuer JWT");
        if (!t.EndsWith('~')) throw new Ap2Exception("SD-JWT: must end with \"~\" (a trailing KB-JWT is not an AP2 form)");
        var parts = t[..^1].Split('~');
        var jwt = parts[0];
        var disclosures = parts.Skip(1).ToList();
        if (disclosures.Any(d => d.Length == 0)) throw new Ap2Exception("SD-JWT: empty disclosure segment");
        var seg = jwt.Split('.');
        if (seg.Length != 3 || seg.Any(s => s.Length == 0)) throw new Ap2Exception("SD-JWT: issuer JWT must be header.payload.signature");
        var header = DecodeJsonSegment(seg[0], "JWT header");
        var payload = DecodeJsonSegment(seg[1], "JWT payload");
        var signature = B64uDecode(seg[2], "JWT signature");
        var rawAlg = G(payload, "_sd_alg");
        if (!IsUndef(rawAlg) && !IsSdAlg(rawAlg)) throw new Ap2Exception($"SD-JWT: unsupported _sd_alg {JsJson.Stringify(rawAlg)}");
        return new SdJwtHop
        {
            Raw = t, Jwt = jwt, Header = header, Payload = payload, Disclosures = disclosures,
            SdAlg = IsSdAlg(rawAlg) ? (string)rawAlg! : "sha-256", SigningInput = seg[0] + "." + seg[1], Signature = signature,
        };
    }

    public static string SdHashOf(SdJwtHop hop, string? alg = null) => SdDigest(HopSdJwt(hop.Jwt, hop.Disclosures), alg ?? hop.SdAlg);
    public static string IssuerJwtHashOf(SdJwtHop hop, string? alg = null) => SdDigest(hop.Jwt, alg ?? hop.SdAlg);

    public static bool VerifyHopSignature(SdJwtHop hop, object? key)
    {
        if (!JsX.StrictEq(G(hop.Header, "alg"), "ES256")) return false;
        return Es256Verify(AssertP256Jwk(key, "verification key"), hop.SigningInput, hop.Signature);
    }

    // ===== disclosures =====

    sealed class Disclosure
    {
        public bool IsProperty;
        public string Name = "";
        public object? Value;
    }

    static Disclosure DecodeDisclosure(string raw)
    {
        var arr = ParseJson(Utf8Text(B64uDecode(raw, "disclosure"), "disclosure"), "disclosure");
        if (arr is not L a) throw new Ap2Exception("disclosure: must be a JSON array");
        if (a.Count == 0 || a[0] is not string salt || salt.Length == 0) throw new Ap2Exception("disclosure: salt must be a non-empty string");
        if (a.Count == 3)
        {
            if (a[1] is not string name) throw new Ap2Exception("disclosure: claim name must be a string");
            if (name == "_sd" || name == "...") throw new Ap2Exception($"disclosure: claim name {name} is reserved");
            return new Disclosure { IsProperty = true, Name = name, Value = a[2] };
        }
        if (a.Count == 2) return new Disclosure { Value = a[1] };
        throw new Ap2Exception("disclosure: array must have 2 or 3 elements");
    }

    /// <summary>Resolve a payload's digest placeholders against its disclosures. Refuses duplicates, unreferenced or doubly-referenced digests,
    /// colliding claims and over-deep nesting.</summary>
    public static D ProcessDisclosures(D payload, IReadOnlyList<string> disclosures, string alg)
    {
        var byDigest = new Dictionary<string, Disclosure>(StringComparer.Ordinal);
        foreach (var raw in disclosures)
        {
            var d = DecodeDisclosure(raw);
            var digest = SdDigest(raw, alg);
            if (byDigest.ContainsKey(digest)) throw new Ap2Exception("SD-JWT: duplicate disclosure");
            byDigest[digest] = d;
        }
        var used = new HashSet<string>(StringComparer.Ordinal);
        Disclosure? Take(string digest, bool wantProperty)
        {
            if (!byDigest.TryGetValue(digest, out var d)) return null;
            if (used.Contains(digest)) throw new Ap2Exception("SD-JWT: a digest is referenced more than once");
            if (d.IsProperty != wantProperty) throw new Ap2Exception($"SD-JWT: a {(d.IsProperty ? "property" : "element")} disclosure is referenced from a {(wantProperty ? "property" : "element")} position");
            used.Add(digest);
            return d;
        }
        object? Walk(object? node, int depth)
        {
            if (depth > 32) throw new Ap2Exception("SD-JWT: nesting too deep");
            if (node is L list)
            {
                var o = new L();
                foreach (var el in list)
                {
                    if (el is D eo && eo.ContainsKey("..."))
                    {
                        if (eo.Count != 1 || eo["..."] is not string dg) throw new Ap2Exception("SD-JWT: malformed array digest placeholder");
                        var d = Take(dg, false);
                        if (d != null) o.Add(Walk(d.Value, depth + 1));
                    }
                    else o.Add(Walk(el, depth + 1));
                }
                return o;
            }
            if (node is D obj)
            {
                var o = new D();
                foreach (var k in IntentJs.JsKeys(obj.Keys))
                {
                    if (k == "_sd" || k == "_sd_alg") continue;
                    if (k == "...") throw new Ap2Exception("SD-JWT: \"...\" is only valid as the sole key of an array element");
                    o[k] = Walk(obj[k], depth + 1);
                }
                var sd = G(obj, "_sd");
                if (!IsUndef(sd))
                {
                    if (sd is not L sl || sl.Any(x => x is not string)) throw new Ap2Exception("SD-JWT: _sd must be an array of strings");
                    foreach (string digest in sl)
                    {
                        var d = Take(digest, true);
                        if (d == null || !d.IsProperty) continue;
                        if (o.ContainsKey(d.Name)) throw new Ap2Exception($"SD-JWT: disclosed claim {d.Name} collides with an existing claim");
                        o[d.Name] = Walk(d.Value, depth + 1);
                    }
                }
                return o;
            }
            return node;
        }
        var result = (D)Walk(payload, 0)!;
        if (used.Count != byDigest.Count) throw new Ap2Exception("SD-JWT: a disclosure is not referenced by the signed payload");
        return result;
    }

    public static string NewSalt() => B64uOf(RandomNumberGenerator.GetBytes(16));

    /// <summary>Builds disclosures and the digest placeholders that reference them.</summary>
    public sealed class DisclosureBuilder(string alg, Func<string>? salt)
    {
        readonly Func<string> salt_ = salt ?? (() => NewSalt());
        public List<string> Disclosures { get; } = new();

        public D Element(object? value)
        {
            var raw = B64uEncode(JsJson.Stringify(new L { salt_(), value }));
            Disclosures.Add(raw);
            return new D { ["..."] = SdDigest(raw, alg) };
        }

        public string Property(string name, object? value)
        {
            var raw = B64uEncode(JsJson.Stringify(new L { salt_(), name, value }));
            Disclosures.Add(raw);
            return SdDigest(raw, alg);
        }
    }

    public static DisclosureBuilder NewDisclosureBuilder(string? alg = null, Func<string>? salt = null) => new(alg ?? "sha-256", salt);

    // ===== signing =====

    static D WithFirst(string k, object? v, D rest)
    {
        var d = new D { [k] = v };
        foreach (var e in rest) d[e.Key] = e.Value;
        return d;
    }

    /// <summary>Sign an SD-JWT: header <c>{alg: ES256, ...header}</c>, the payload, then the disclosures.</summary>
    public static string SignSdJwt(D header, D payload, IEnumerable<string> disclosures, Ap2KeyPair key)
    {
        var h = B64uEncode(JsJson.Stringify(WithFirst("alg", "ES256", header)));
        var p = B64uEncode(JsJson.Stringify(payload));
        return HopSdJwt($"{h}.{p}.{Es256Sign(key, h + "." + p)}", disclosures);
    }

    /// <summary>Sign a compact ES256 JWT: header <c>{alg: ES256, typ: JWT, ...header}</c>.</summary>
    public static string SignJwtEs256(D header, D payload, Ap2KeyPair key)
    {
        var h = B64uEncode(JsJson.Stringify(WithFirst("alg", "ES256", WithFirst("typ", "JWT", header))));
        var p = B64uEncode(JsJson.Stringify(payload));
        return $"{h}.{p}.{Es256Sign(key, h + "." + p)}";
    }

    public static ParsedJwt ParseJwt(string jwt, string what)
    {
        var seg = jwt.Split('.');
        if (seg.Length != 3 || seg.Any(s => s.Length == 0)) throw new Ap2Exception($"{what}: must be header.payload.signature");
        return new ParsedJwt
        {
            Header = DecodeJsonSegment(seg[0], $"{what} header"),
            Payload = DecodeJsonSegment(seg[1], $"{what} payload"),
            SigningInput = seg[0] + "." + seg[1],
            Signature = B64uDecode(seg[2], $"{what} signature"),
        };
    }

    public static bool VerifyJwtEs256(ParsedJwt parsed, object? key)
    {
        if (!JsX.StrictEq(G(parsed.Header, "alg"), "ES256")) return false;
        return Es256Verify(AssertP256Jwk(key, "verification key"), parsed.SigningInput, parsed.Signature);
    }
}
