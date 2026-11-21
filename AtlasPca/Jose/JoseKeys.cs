// Key side of the shared JOSE kit: JWK import, the key-versus-algorithm agreement rules, signature verification and signing.
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using AtlasPca;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Jose;

/// <summary>A key imported from a JWK (the reference's <c>KeyObject</c> from <c>importJWK</c>): OKP Ed25519 / Ed448 (and the X curves, which no
/// JWS algorithm accepts), EC P-256 / P-384 / P-521 on the curve, RSA. A private JWK imports as a private key that can sign and verify.</summary>
public sealed class JoseKey
{
    /// <summary>ed25519 | ed448 | x25519 | x448 | ec | rsa</summary>
    public string Kind { get; internal init; } = "";
    /// <summary>The curve of an EC key (P-256 | P-384 | P-521).</summary>
    public string? Crv { get; internal init; }
    public bool IsPrivate => PrivateJwk != null;
    /// <summary>The reference's <c>key.type</c>.</summary>
    public string Type => IsPrivate ? "private" : "public";
    internal byte[]? Raw { get; init; }
    internal ECParameters? Ec { get; init; }
    internal RSAParameters? Rsa { get; init; }
    internal int RsaBits { get; init; }
    internal D? PrivateJwk { get; init; }

    /// <summary>The reference's <c>exportJWK</c> of the public half: kty, crv, x (OKP); kty, crv, x, y (EC); kty, n, e (RSA).</summary>
    public D ExportJwk() => Kind switch
    {
        "ec" => new D { ["kty"] = "EC", ["crv"] = Crv, ["x"] = Pca.B64u(Ec!.Value.Q.X!), ["y"] = Pca.B64u(Ec!.Value.Q.Y!) },
        "rsa" => new D { ["kty"] = "RSA", ["n"] = Pca.B64u(Rsa!.Value.Modulus!), ["e"] = Pca.B64u(Rsa!.Value.Exponent!) },
        _ => new D { ["kty"] = "OKP", ["crv"] = Kind switch { "ed25519" => "Ed25519", "ed448" => "Ed448", "x25519" => "X25519", _ => "X448" }, ["x"] = Pca.B64u(Raw!) },
    };
}

public static partial class Jose
{
    // ===================== import =====================

    static int FieldBytes(string crv) => crv switch { "P-256" => 32, "P-384" => 48, "P-521" => 66, _ => 0 };

    static byte[] TrimZeros(byte[] b)
    {
        int i = 0;
        while (i < b.Length - 1 && b[i] == 0) i++;
        return i == 0 ? b : b[i..];
    }

    static byte[] PadLeft(byte[] b, int len)
    {
        b = TrimZeros(b);
        if (b.Length > len) throw new JoseTypeError("Invalid JWK: value too long");
        if (b.Length == len) return b;
        var o = new byte[len];
        Buffer.BlockCopy(b, 0, o, len - b.Length, b.Length);
        return o;
    }

    // Node's base64url reader drops a dangling sixth-bit character instead of refusing the string
    static byte[] NodeB64(string s)
    {
        var t = s.TrimEnd('=');
        return DecodeB64Lenient(t.Length % 4 == 1 ? t[..^1] : t);
    }

    static byte[] Member(D jwk, string name)
    {
        if (jwk.GetValueOrDefault(name) is not string s) throw new JoseTypeError($"Invalid JWK: missing \"{name}\"");
        // node's base64 reader skips whitespace inside a JWK member
        try { return NodeB64(string.Concat(s.Where(c => c is not (' ' or '\t' or '\r' or '\n')))); }
        catch (JoseException) { throw new JoseTypeError($"Invalid JWK: \"{name}\" is not base64url"); }
    }

    static ECPoint? CurvePoint(string crv, byte[] x, byte[] y)
    {
        int n = FieldBytes(crv);
        var px = PadLeft(x, n);
        var py = PadLeft(y, n);
        try
        {
            var curve = Org.BouncyCastle.Asn1.Nist.NistNamedCurves.GetByName(crv).Curve;
            curve.ValidatePoint(new Org.BouncyCastle.Math.BigInteger(1, px), new Org.BouncyCastle.Math.BigInteger(1, py)); // on the curve, coordinates below the field prime
        }
        catch (Exception) { throw new JoseTypeError("Invalid EC JWK: point is not on the curve"); }
        return new ECPoint { X = px, Y = py };
    }

    static ECCurve CurveOf(string crv) => crv switch
    {
        "P-256" => ECCurve.NamedCurves.nistP256,
        "P-384" => ECCurve.NamedCurves.nistP384,
        "P-521" => ECCurve.NamedCurves.nistP521,
        _ => throw new JoseTypeError("Unsupported key curve for this operation"),
    };

    /// <summary>The reference's <c>importJWK</c>: <c>oct</c> gives the secret bytes (<c>byte[]</c>); OKP / EC / RSA give a <see cref="JoseKey"/>
    /// (private when the JWK carries <c>d</c>). Failures are JoseTypeError (a key the platform rejects) or JoseException (unsupported kty / RSA <c>oth</c>).</summary>
    public static object ImportJwk(D jwk, string? alg = null)
    {
        switch (jwk.GetValueOrDefault("kty"))
        {
            case "oct":
                if (jwk.GetValueOrDefault("k") is not string k || k.Length == 0) throw new JoseTypeError("missing \"k\" (Key Value) Parameter value");
                try { return NodeB64(k); }
                catch (JoseException) { throw new JoseTypeError("Invalid JWK: \"k\" is not base64url"); }
            case "RSA":
                if (jwk.ContainsKey("oth")) throw JoseException.NotSupported("RSA JWK \"oth\" (Other Primes Info) Parameter value is not supported");
                return ImportAsKey(jwk);
            case "EC":
            case "OKP":
                return ImportAsKey(jwk);
            default:
                throw JoseException.NotSupported("Unsupported \"kty\" (Key Type) Parameter value");
        }
    }

    static JoseKey ImportAsKey(D jwk)
    {
        bool priv = jwk.TryGetValue("d", out var dv) && dv is not null && !(dv is string ds && ds.Length == 0) && !(dv is bool bf && !bf);
        if (priv && dv is not string) throw new JoseTypeError("Invalid JWK: \"d\" must be a string");
        switch (jwk.GetValueOrDefault("kty"))
        {
            case "OKP":
                {
                    if (jwk.GetValueOrDefault("crv") is not string crv) throw new JoseTypeError("Invalid JWK: missing \"crv\"");
                    (string kind, int len) = crv switch
                    {
                        "Ed25519" => ("ed25519", 32), "Ed448" => ("ed448", 57), "X25519" => ("x25519", 32), "X448" => ("x448", 56),
                        _ => throw new JoseTypeError("Invalid JWK: unsupported OKP curve"),
                    };
                    byte[]? x = jwk.ContainsKey("x") ? Member(jwk, "x") : null;
                    if (priv)
                    {
                        var d = Member(jwk, "d");
                        if (d.Length != len) throw new JoseTypeError("Invalid JWK: bad private key length");
                        if (kind == "ed25519") x = new Ed25519PrivateKeyParameters(d, 0).GeneratePublicKey().GetEncoded();
                        else if (kind == "ed448") x = new Ed448PrivateKeyParameters(d, 0).GeneratePublicKey().GetEncoded();
                        else if (x == null) throw new JoseTypeError("Invalid JWK: missing \"x\"");
                    }
                    if (x == null || x.Length != len) throw new JoseTypeError("Invalid JWK: bad public key length");
                    if (priv && jwk.ContainsKey("x") && !Member(jwk, "x").AsSpan().SequenceEqual(x)) throw new JoseTypeError("Invalid JWK: public key does not match the private key");
                    return new JoseKey { Kind = kind, Crv = crv, Raw = x, PrivateJwk = priv ? new D(jwk) : null };
                }
            case "EC":
                {
                    if (jwk.GetValueOrDefault("crv") is not string crv || FieldBytes(crv) == 0) throw new JoseTypeError("Unsupported key curve for this operation");
                    var q = CurvePoint(crv, Member(jwk, "x"), Member(jwk, "y"));
                    var p = new ECParameters { Curve = CurveOf(crv), Q = q!.Value };
                    if (priv) p.D = PadLeft(Member(jwk, "d"), FieldBytes(crv));
                    return new JoseKey { Kind = "ec", Crv = crv, Ec = p, PrivateJwk = priv ? new D(jwk) : null };
                }
            default: // RSA
                {
                    var nRaw = Member(jwk, "n");
                    var n = TrimZeros(nRaw);
                    var e = TrimZeros(Member(jwk, "e"));
                    var bn = new System.Numerics.BigInteger(n, isUnsigned: true, isBigEndian: true);
                    var be = new System.Numerics.BigInteger(e, isUnsigned: true, isBigEndian: true);
                    if (!bn.IsZero && (be.IsEven || be < 3 || be >= bn)) throw new JoseTypeError("Invalid RSA JWK");
                    var p = new RSAParameters { Modulus = n, Exponent = e };
                    if (priv)
                    {
                        int half = (n.Length + 1) / 2;
                        p.D = PadLeft(Member(jwk, "d"), n.Length);
                        p.P = PadLeft(Member(jwk, "p"), half); p.Q = PadLeft(Member(jwk, "q"), half);
                        p.DP = PadLeft(Member(jwk, "dp"), half); p.DQ = PadLeft(Member(jwk, "dq"), half); p.InverseQ = PadLeft(Member(jwk, "qi"), half);
                    }
                    return new JoseKey { Kind = "rsa", Rsa = p, RsaBits = (int)bn.GetBitLength(), PrivateJwk = priv ? new D(jwk) : null };
                }
        }
    }

    /// <summary>The OKP Ed25519 private JWK of a 32-byte seed (the public <c>x</c> derived), the way the packages hold a raw PCA secret.</summary>
    public static D Ed25519SeedJwk(byte[] seed)
    {
        if (seed.Length != 32) throw new JoseTypeError("an Ed25519 seed is 32 bytes");
        var x = new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded();
        return new D { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = B64u(x), ["d"] = B64u(seed) };
    }

    /// <summary>The OKP Ed25519 public JWK of a 32-byte public key.</summary>
    public static D Ed25519PublicJwk(byte[] pub) => new() { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = B64u(pub) };

    // ===================== key / algorithm agreement =====================

    static bool IsJwk(object? k) => k is D d && d.GetValueOrDefault("kty") is string;

    static void JwkMatchesOp(string alg, D k, string usage)
    {
        if (k.TryGetValue("use", out var u) && !(u is string us && us == "sig")) throw new JoseTypeError("Invalid key for this operation, when present its use must be sig");
        if (k.TryGetValue("key_ops", out var ko) && !(ko is L l ? l.Any(o => o is string s && s == usage) : ko is string ks && ks.Contains(usage, StringComparison.Ordinal)))
            throw new JoseTypeError($"Invalid key for this operation, when present its key_ops must include {usage}");
        if (k.TryGetValue("alg", out var a) && !(a is string asr && asr == alg)) throw new JoseTypeError($"Invalid key for this operation, when present its alg must be {alg}");
    }

    /// <summary>The reference's <c>checkKeyTypeWithJwk</c> for usage <c>verify</c> (or <c>sign</c>): throws JoseTypeError when the key cannot serve the algorithm.</summary>
    internal static void CheckKeyType(string alg, object? key, string usage = "verify")
    {
        if (alg.StartsWith("HS", StringComparison.Ordinal))
        {
            if (key is byte[]) return;
            if (key is D j && IsJwk(j))
            {
                if (j["kty"] is "oct" && j.GetValueOrDefault("k") is string) { JwkMatchesOp(alg, j, usage); return; }
                throw new JoseTypeError("JSON Web Key for symmetric algorithms must have JWK \"kty\" (Key Type) equal to \"oct\" and the JWK \"k\" (Key Value) present");
            }
            if (key is JoseKey) throw new JoseTypeError("KeyObject instances for symmetric algorithms must be of type \"secret\"");
            throw new JoseTypeError($"Key for the {alg} algorithm must be one of type CryptoKey, KeyObject, JSON Web Key, or Uint8Array.");
        }
        if (key is D jw && IsJwk(jw))
        {
            if (usage == "sign")
            {
                if (jw["kty"] is not "oct" && jw.GetValueOrDefault("d") is string) { JwkMatchesOp(alg, jw, usage); return; }
                throw new JoseTypeError("JSON Web Key for this operation be a private JWK");
            }
            if (jw["kty"] is not "oct" && !jw.ContainsKey("d")) { JwkMatchesOp(alg, jw, usage); return; }
            throw new JoseTypeError("JSON Web Key for this operation be a public JWK");
        }
        if (key is JoseKey jk)
        {
            if (usage == "sign" && !jk.IsPrivate) throw new JoseTypeError("KeyObject instances for asymmetric algorithm signing must be of type \"private\"");
            return;
        }
        if (key is byte[]) throw new JoseTypeError($"Key for the {alg} algorithm must be one of type KeyObject, CryptoKey, or JSON Web Key. Received an instance of Uint8Array");
        throw new JoseTypeError($"Key for the {alg} algorithm must be one of type KeyObject, CryptoKey, or JSON Web Key.");
    }

    static string DigestFor(string alg) => alg switch
    {
        "PS256" or "RS256" or "ES256" or "ES256K" => "sha256",
        "PS384" or "RS384" or "ES384" => "sha384",
        "PS512" or "RS512" or "ES512" => "sha512",
        "EdDSA" => "",
        _ => throw JoseException.NotSupported($"alg {alg} is not supported either by JOSE or your javascript runtime"),
    };

    static HashAlgorithmName Hash(string alg) => DigestFor(alg) switch
    {
        "sha256" => HashAlgorithmName.SHA256, "sha384" => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512,
    };

    /// <summary>The reference's <c>keyForCrypto</c>: the kind of the key (a JWK is classified by <c>kty</c> / <c>crv</c>) must suit the algorithm.</summary>
    static void KeyForCrypto(string alg, object key)
    {
        string kind; string? crv = null; int bits = 0;
        if (key is JoseKey jk) { kind = jk.Kind; crv = jk.Crv; bits = jk.RsaBits; }
        else
        {
            var j = (D)key;
            switch (j.GetValueOrDefault("kty"))
            {
                case "RSA":
                    kind = "rsa";
                    try { bits = DecodeB64Lenient((string)j["n"]!).Length << 3; } catch (Exception) { bits = 0; }
                    break;
                case "EC": kind = "ec"; crv = j.GetValueOrDefault("crv") as string; break;
                case "OKP":
                    if (j.GetValueOrDefault("crv") is "Ed25519") kind = "ed25519";
                    else if (j.GetValueOrDefault("crv") is "Ed448") kind = "ed448";
                    else throw new JoseTypeError("Invalid key for this operation, its crv must be Ed25519 or Ed448");
                    break;
                default: throw new JoseTypeError("Invalid key for this operation, its kty must be RSA, OKP, or EC");
            }
        }
        switch (alg)
        {
            case "EdDSA":
                if (kind is not ("ed25519" or "ed448")) throw new JoseTypeError("Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448");
                break;
            case "RS256": case "RS384": case "RS512":
                if (kind != "rsa") throw new JoseTypeError("Invalid key for this operation, its asymmetricKeyType must be rsa");
                if (bits < 2048) throw new JoseTypeError($"{alg} requires key modulusLength to be 2048 bits or larger");
                break;
            case "PS256": case "PS384": case "PS512":
                if (kind != "rsa") throw new JoseTypeError("Invalid key for this operation, its asymmetricKeyType must be rsa or rsa-pss");
                if (bits < 2048) throw new JoseTypeError($"{alg} requires key modulusLength to be 2048 bits or larger");
                break;
            case "ES256": case "ES256K": case "ES384": case "ES512":
                {
                    if (kind != "ec") throw new JoseTypeError("Invalid key for this operation, its asymmetricKeyType must be ec");
                    var want = alg == "ES256" ? "P-256" : alg == "ES256K" ? "secp256k1" : alg == "ES384" ? "P-384" : "P-521";
                    if (crv != want) throw new JoseTypeError($"Invalid key curve for the algorithm, its curve must be {want}, got {crv}");
                    break;
                }
            default: throw JoseException.NotSupported($"alg {alg} is not supported either by JOSE or your javascript runtime");
        }
    }

    // ===================== verify =====================

    static byte[] HmacSecret(object key) => key switch
    {
        byte[] b => b,
        D j => DecodeB64Lenient((string)j["k"]!),
        _ => throw new JoseTypeError("Key must be a secret"),
    };

    static byte[] Hmac(string alg, byte[] secret, byte[] data) => alg switch
    {
        "HS256" => HMACSHA256.HashData(secret, data),
        "HS384" => HMACSHA384.HashData(secret, data),
        "HS512" => HMACSHA512.HashData(secret, data),
        _ => throw JoseException.NotSupported($"alg {alg} is not supported either by JOSE or your javascript runtime"),
    };

    /// <summary>The reference's runtime <c>verify</c>: false for a bad signature or a key the platform cannot import; JoseTypeError / JoseException when
    /// the key does not suit the algorithm (or the algorithm is unsupported).</summary>
    internal static bool VerifyWith(string alg, object key, byte[] sig, byte[] data)
    {
        if (alg.StartsWith("HS", StringComparison.Ordinal))
        {
            var secret = HmacSecret(key);
            var expected = Hmac(alg, secret, data);
            return sig.Length == expected.Length && CryptographicOperations.FixedTimeEquals(sig, expected);
        }
        if (key is byte[]) throw new JoseTypeError("Key must be one of type CryptoKey, KeyObject, or JSON Web Key. Received an instance of Uint8Array");
        DigestFor(alg);
        KeyForCrypto(alg, key);
        JoseKey k;
        if (key is JoseKey jk) k = jk;
        else
        {
            try { k = ImportAsKey((D)key); }
            catch (JoseTypeError) { return false; } // the platform rejects the key inside the verify call: a failed verification
            catch (JoseException) { return false; }
        }
        return VerifyRaw(alg, k, sig, data);
    }

    static bool VerifyRaw(string alg, JoseKey k, byte[] sig, byte[] data)
    {
        try
        {
            switch (alg)
            {
                case "EdDSA":
                    if (k.Kind == "ed25519") return Pca.VerifyEd25519Strict(k.Raw!, data, sig);
                    {
                        var s = new Ed448Signer(Array.Empty<byte>());
                        s.Init(false, new Ed448PublicKeyParameters(k.Raw!, 0));
                        s.BlockUpdate(data, 0, data.Length);
                        return s.VerifySignature(sig);
                    }
                case "ES256": case "ES384": case "ES512":
                    {
                        var pub = new ECParameters { Curve = k.Ec!.Value.Curve, Q = k.Ec!.Value.Q };
                        using var ec = ECDsa.Create(pub);
                        return ec.VerifyData(data, sig, Hash(alg), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    }
                case "RS256": case "RS384": case "RS512":
                case "PS256": case "PS384": case "PS512":
                    {
                        var pub = new RSAParameters { Modulus = k.Rsa!.Value.Modulus, Exponent = k.Rsa!.Value.Exponent };
                        using var rsa = RSA.Create();
                        rsa.ImportParameters(pub);
                        return rsa.VerifyData(data, sig, Hash(alg), alg[0] == 'R' ? RSASignaturePadding.Pkcs1 : RSASignaturePadding.Pss);
                    }
                default: return false;
            }
        }
        catch (Exception) { return false; }
    }

    // ===================== sign =====================

    /// <summary>Signs <paramref name="data"/> under <paramref name="key"/> (a private JWK, a private <see cref="JoseKey"/>, or an HS secret) the way the
    /// reference's runtime <c>sign</c> does. ECDSA and RSA-PSS signatures are randomized.</summary>
    public static byte[] SignRaw(string alg, object key, byte[] data)
    {
        CheckKeyType(alg, key, "sign");
        if (alg.StartsWith("HS", StringComparison.Ordinal)) return Hmac(alg, HmacSecret(key), data);
        DigestFor(alg);
        KeyForCrypto(alg, key);
        JoseKey k;
        try { k = key as JoseKey ?? ImportAsKey((D)key); }
        catch (JoseException e) { throw new JoseTypeError(e.Message); }
        if (!k.IsPrivate) throw new JoseTypeError("key must be private to sign");
        var jwk = k.PrivateJwk!;
        try
        {
            switch (alg)
            {
                case "EdDSA":
                    if (k.Kind == "ed25519")
                    {
                        var s = new Ed25519Signer();
                        s.Init(true, new Ed25519PrivateKeyParameters(Member(jwk, "d"), 0));
                        s.BlockUpdate(data, 0, data.Length);
                        return s.GenerateSignature();
                    }
                    else
                    {
                        var s = new Ed448Signer(Array.Empty<byte>());
                        s.Init(true, new Ed448PrivateKeyParameters(Member(jwk, "d"), 0));
                        s.BlockUpdate(data, 0, data.Length);
                        return s.GenerateSignature();
                    }
                case "ES256": case "ES384": case "ES512":
                    {
                        using var ec = ECDsa.Create(k.Ec!.Value);
                        return ec.SignData(data, Hash(alg), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    }
                default:
                    {
                        using var rsa = RSA.Create();
                        rsa.ImportParameters(k.Rsa!.Value);
                        return rsa.SignData(data, Hash(alg), alg[0] == 'R' ? RSASignaturePadding.Pkcs1 : RSASignaturePadding.Pss);
                    }
            }
        }
        catch (CryptographicException e) { throw new JoseTypeError("signing failed: " + e.Message); }
    }
}
