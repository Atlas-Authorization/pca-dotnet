using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Webauthn;

/// <summary>
/// Phishing-resistant human co-sign for PCA step-up via WebAuthn / FIDO2: the server-side assertion verifier. The WebAuthn challenge
/// is the PCA step-up challenge (the action digest), so a valid assertion proves a human holding a hardware-bound credential approved
/// THIS action. ES256 (P-256, DER or raw r||s) and strict RFC 8032 EdDSA, SHA-256 and a minimal COSE_Key / CBOR reader.
/// Port of the TypeScript <c>@atlasauth/pca-webauthn</c>; every verification entry point fails CLOSED and never throws on hostile input.
/// The assertion and expectations are JSON-shaped dictionaries with the reference's member names: byte members are <c>byte[]</c>,
/// numbers are <see cref="Num"/>, <c>onSignCountRegression</c> is an <c>Action&lt;Dictionary&lt;string, object?&gt;&gt;</c>.
/// </summary>
public static class Webauthn
{
    public const int MaxAuthenticatorDataBytes = 4096;
    public const int MaxClientDataBytes = 8192;
    public const int MaxSignatureBytes = 1024;

    static byte[] Sha(byte[] b) => SHA256.HashData(b);

    static bool BytesEqual(byte[] a, byte[] b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);

    static D? AsRecord(object? v) => v as D;

    static double? NumberOf(object? o) => o is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;

    /// <summary>JavaScript String(v) for the values a parsed clientDataJSON can hold; <paramref name="present"/> false is undefined.</summary>
    static string JsString(object? v, bool present = true)
    {
        if (!present) return "undefined";
        switch (v)
        {
            case null: return "null";
            case string s: return s;
            case bool b: return b ? "true" : "false";
            case Num n:
                var t = IntentJs.NormNum(n.Raw).Raw;
                return t == "-0" ? "0" : t;
            case L l:
                return string.Join(",", l.Select(x => x == null ? "" : JsString(x)));
            default: return "[object Object]";
        }
    }

    /// <summary>Tolerant base64url (URL alphabet, optional padding, '+' and '/' accepted), canonical bits only; null when undecodable.</summary>
    static byte[]? Base64UrlToBytes(object? s)
    {
        if (s is not string str) return null;
        var t = str.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return Pca.B64uDecode(t);
    }

    // ---- minimal COSE_Key / CBOR reader ----

    sealed record Item(object Value, int Next); // Value: long | byte[] | Dictionary<long, object>

    static int U8(byte[] b, int at)
    {
        if (at < 0 || at >= b.Length) throw new ArgumentException("Offset is outside the bounds of the DataView");
        return b[at];
    }

    static Item ReadItem(byte[] b, int offset)
    {
        int initial = U8(b, offset);
        int major = initial >> 5, ai = initial & 0x1f;
        int p = offset + 1;
        long arg;
        if (ai < 24) arg = ai;
        else if (ai == 24) { arg = U8(b, p); p += 1; }
        else if (ai == 25) { arg = (U8(b, p) << 8) | U8(b, p + 1); p += 2; }
        else if (ai == 26) { arg = ((long)U8(b, p) << 24) | ((long)U8(b, p + 1) << 16) | ((long)U8(b, p + 2) << 8) | (long)U8(b, p + 3); p += 4; }
        else throw new ArgumentException("cose: unsupported CBOR argument encoding (8-byte or indefinite length)");
        switch (major)
        {
            case 0: return new Item(arg, p);
            case 1: return new Item(-1 - arg, p);
            case 2:
                {
                    long end = p + arg;
                    if (end > b.Length) throw new ArgumentException("cose: byte string length out of range");
                    return new Item(b[p..(int)end], (int)end);
                }
            case 5:
                {
                    var map = new Dictionary<long, object>();
                    int q = p;
                    for (long i = 0; i < arg; i++)
                    {
                        var key = ReadItem(b, q);
                        if (key.Value is not long k) throw new ArgumentException("cose: non-integer map key");
                        var val = ReadItem(b, key.Next);
                        map[k] = val.Value;
                        q = val.Next;
                    }
                    return new Item(map, q);
                }
            default:
                throw new ArgumentException($"cose: unsupported CBOR major type {major}");
        }
    }

    static bool IsLong(object? o, long v) => o is long l && l == v;

    /// <summary>Decode a raw COSE_Key into a JWK: ES256 (EC2 / P-256) or EdDSA (OKP / Ed25519), with <c>alg</c>. Throws on malformed input or an unsupported key type.</summary>
    public static D CoseKeyToJwk(byte[] bytes)
    {
        if (bytes == null) throw new ArgumentException("coseKeyToJwk: expected a Uint8Array");
        var value = ReadItem(bytes, 0).Value;
        if (value is not Dictionary<long, object> m) throw new ArgumentException("coseKeyToJwk: COSE_Key is not a CBOR map");
        m.TryGetValue(1, out var kty);
        if (IsLong(kty, 2))
        {
            m.TryGetValue(-1, out var crv); m.TryGetValue(-2, out var x); m.TryGetValue(-3, out var y);
            if (!IsLong(crv, 1)) throw new ArgumentException("coseKeyToJwk: EC2 key is not P-256 (crv != 1)");
            if (x is not byte[] xb || y is not byte[] yb) throw new ArgumentException("coseKeyToJwk: EC2 key missing an x/y coordinate");
            if (xb.Length != 32 || yb.Length != 32) throw new ArgumentException("coseKeyToJwk: EC2 coordinate is not 32 bytes");
            return new D { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Pca.B64u(xb), ["y"] = Pca.B64u(yb), ["alg"] = "ES256" };
        }
        if (IsLong(kty, 1))
        {
            m.TryGetValue(-1, out var crv); m.TryGetValue(-2, out var x);
            if (!IsLong(crv, 6)) throw new ArgumentException("coseKeyToJwk: OKP key is not Ed25519 (crv != 6)");
            if (x is not byte[] xb) throw new ArgumentException("coseKeyToJwk: OKP key missing its public key");
            if (xb.Length != 32) throw new ArgumentException("coseKeyToJwk: Ed25519 public key is not 32 bytes");
            return new D { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = Pca.B64u(xb), ["alg"] = "EdDSA" };
        }
        throw new ArgumentException("coseKeyToJwk: unsupported COSE key type (kty=" + (kty == null ? "undefined" : Convert.ToString(kty, CultureInfo.InvariantCulture)) + ")");
    }

    static (string Alg, byte[] Raw) ResolveKey(object? pub, bool present = true)
    {
        D? jwk = pub is byte[] pb ? CoseKeyToJwk(pb) : AsRecord(pub);
        if (jwk == null)
        {
            if (pub == null) throw new ArgumentException($"Cannot read properties of {(present ? "null" : "undefined")} (reading 'kty')");
            throw new ArgumentException("resolveKey: unsupported public key");
        }
        jwk.TryGetValue("kty", out var kty);
        if (kty is "EC")
        {
            if (jwk.GetValueOrDefault("crv") is not "P-256") throw new ArgumentException("resolveKey: EC JWK is not P-256");
            var x = Base64UrlToBytes(jwk.GetValueOrDefault("x")); var y = Base64UrlToBytes(jwk.GetValueOrDefault("y"));
            if (x == null || y == null || x.Length != 32 || y.Length != 32) throw new ArgumentException("resolveKey: invalid EC JWK coordinates");
            var raw = new byte[65];
            raw[0] = 4;
            x.CopyTo(raw, 1);
            y.CopyTo(raw, 33);
            return ("ES256", raw);
        }
        if (kty is "OKP")
        {
            if (jwk.GetValueOrDefault("crv") is not "Ed25519") throw new ArgumentException("resolveKey: OKP JWK is not Ed25519");
            var x = Base64UrlToBytes(jwk.GetValueOrDefault("x"));
            if (x == null || x.Length != 32) throw new ArgumentException("resolveKey: invalid OKP JWK public key");
            return ("EdDSA", x);
        }
        throw new ArgumentException("resolveKey: unsupported public key");
    }

    // ---- authenticatorData ----

    /// <summary>Parse the fixed header of authenticatorData (rpIdHash[32] || flags[1] || signCount[4]) into
    /// <c>{rpIdHash, flags: {up, uv, be, bs, at, ed}, signCount}</c>; null when missing or shorter than 37 bytes.</summary>
    public static D? ParseAuthenticatorData(byte[]? authData)
    {
        if (authData == null || authData.Length < 37) return null;
        int f = authData[32];
        long sc = ((long)authData[33] << 24) | ((long)authData[34] << 16) | ((long)authData[35] << 8) | authData[36];
        return new D
        {
            ["rpIdHash"] = authData[..32],
            ["flags"] = new D { ["up"] = (f & 0x01) != 0, ["uv"] = (f & 0x04) != 0, ["be"] = (f & 0x08) != 0, ["bs"] = (f & 0x10) != 0, ["at"] = (f & 0x40) != 0, ["ed"] = (f & 0x80) != 0 },
            ["signCount"] = sc,
        };
    }

    // ---- step-up challenge binding ----

    /// <summary>The WebAuthn challenge bytes for a PCA step-up: sha256(thresholdMessage(pcactn)), the bytes whose base64url form is the FROST
    /// action digest. Accepts a PCActn (or body) dictionary, the base64url digest string, or raw 32-byte digest bytes; throws for a digest
    /// that is not 32 bytes / not canonical base64url.</summary>
    public static byte[] BuildStepUpChallenge(object? pcActnOrDigest)
    {
        if (pcActnOrDigest is byte[] d)
        {
            if (d.Length != 32) throw new ArgumentException("buildStepUpChallenge: digest bytes must be 32 bytes");
            return (byte[])d.Clone();
        }
        if (pcActnOrDigest is string s)
        {
            var b = Pca.B64uDecode(s, 32);
            if (b == null) throw new ArgumentException("buildStepUpChallenge: digest is not a canonical base64url 32-byte value");
            return b;
        }
        D body;
        if (pcActnOrDigest is D m) body = m;
        else if (pcActnOrDigest is L l) // object rest of an array: its index members
        {
            body = new D();
            for (int i = 0; i < l.Count; i++) body[i.ToString(CultureInfo.InvariantCulture)] = l[i];
        }
        else if (pcActnOrDigest == null) throw new ArgumentException("Cannot destructure property 'sig' of 'p' as it is null.");
        else body = new D(); // a number or boolean has no own members
        return Sha(Pca.ThresholdMessage(body));
    }

    /// <summary>The challenge for an approval that commits to the canonical render: SHA-256(domain || action_digest || H(R)).</summary>
    public static byte[] BuildApprovalChallenge(object? pcActnOrDigest, object? renderDigest) =>
        Pca.B64uDecode(ApprovalChallengeForActn(pcActnOrDigest, renderDigest))!;

    /// <summary>The base64url form of <see cref="BuildApprovalChallenge"/>.</summary>
    public static string ApprovalChallengeForActn(object? pcActnOrDigest, object? renderDigest) =>
        Approval.Challenge(Pca.B64u(BuildStepUpChallenge(pcActnOrDigest)), renderDigest);

    /// <summary>The base64url step-up challenge (the FROST action_digest) for a PCActn / body / digest.</summary>
    public static string StepUpChallengeB64u(object? pcActnOrDigest) => Pca.B64u(BuildStepUpChallenge(pcActnOrDigest));

    // ---- Secure Payment Confirmation ----

    /// <summary>JS member read of a value that may not be an object: a non-record has no members; null / undefined throw.</summary>
    static (bool Has, object? Val) Member(object? o, string k)
    {
        if (o == null) throw new ArgumentException($"Cannot read properties of null (reading '{k}')");
        return o is D d && d.TryGetValue(k, out var v) ? (true, v) : (false, null);
    }

    /// <summary>a[ka] === b[kb] for parsed JSON members: both absent is equal, one absent is not, strings / numbers / booleans / null by value, objects never.</summary>
    static bool Same((bool Has, object? Val) a, (bool Has, object? Val) b)
    {
        if (!a.Has || !b.Has) return !a.Has && !b.Has;
        if (a.Val is string x && b.Val is string y) return x == y;
        if (a.Val == null && b.Val == null) return true;
        if (a.Val is bool p && b.Val is bool q) return p == q;
        var dx = NumberOf(a.Val); var dy = NumberOf(b.Val);
        return dx != null && dy != null && dx.Value == dy.Value;
    }

    /// <summary>Null if the signed payment data equals the expectation (<c>topOrigin</c>, <c>total</c>, payee). Total over hostile <paramref name="payment"/>.</summary>
    public static string? SpcPaymentError(object? payment, object? expectation, string rpId)
    {
        var p = AsRecord(payment);
        if (p == null) return "clientData.payment is missing";
        var (hn, _) = Member(expectation, "payeeName");
        var (ho, _) = Member(expectation, "payeeOrigin");
        if (!hn && !ho) return "the expectation names no payee (refused: a payment approval must bind the payee)";
        var e = (D)expectation!; // a payee member exists, so it is a record
        if (!(p.GetValueOrDefault("rpId") is string r && r == rpId)) return "clientData.payment.rpId is not the verifier rpId";
        if (!Same(Member(p, "topOrigin"), Member(e, "topOrigin"))) return "clientData.payment.topOrigin is not the verifier approval origin";
        var total = AsRecord(p.GetValueOrDefault("total"));
        if (total == null) return "clientData.payment.total does not equal the canonical render";
        var et = Member(e, "total");
        if (!et.Has || et.Val == null) throw new ArgumentException($"Cannot read properties of {(et.Has ? "null" : "undefined")} (reading 'currency')");
        if (!Same(Member(total, "currency"), Member(et.Val, "currency")) || !Same(Member(total, "value"), Member(et.Val, "value")))
            return "clientData.payment.total does not equal the canonical render";
        foreach (var k in new[] { "payeeName", "payeeOrigin" })
        {
            var ev = Member(e, k);
            // an expected member (even a null one) must equal the signed one
            if (ev.Has && !Same(Member(p, k), ev)) return "clientData.payment." + k + " does not equal the canonical render";
        }
        return null;
    }

    // ---- ECDSA P-256 ----

    static readonly BigInteger N = BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    static byte[] Pad32(BigInteger v)
    {
        var b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        var o = new byte[32];
        if (b.Length > 32) Array.Copy(b, b.Length - 32, o, 0, 32); else Array.Copy(b, 0, o, 32 - b.Length, b.Length);
        return o;
    }

    /// <summary>Strict DER ECDSA signature (single-byte total length, minimal positive INTEGERs, no trailing bytes) to {r, s}; null when invalid.</summary>
    static BigInteger[]? ParseDer(byte[] d)
    {
        if (d.Length < 2 || d[0] != 0x30 || d[1] != d.Length - 2) return null;
        int pos = 2;
        var r = DerInt(d, ref pos);
        if (r == null) return null;
        var s = DerInt(d, ref pos);
        if (s == null || pos != d.Length) return null;
        return new[] { r.Value, s.Value };
    }

    static BigInteger? DerInt(byte[] d, ref int pos)
    {
        int i = pos;
        if (d.Length - i < 2 || d[i] != 0x02) return null;
        int len = d[i + 1];
        if (len == 0 || i + 2 + len > d.Length) return null;
        int b0 = d[i + 2];
        if ((b0 & 0x80) != 0) return null;
        if (b0 == 0 && len > 1 && (d[i + 3] & 0x80) == 0) return null;
        if (b0 == 0 && len == 1) { pos = i + 3; return BigInteger.Zero; }
        pos = i + 2 + len;
        return new BigInteger(d.AsSpan(i + 2, len), isUnsigned: true, isBigEndian: true);
    }

    static bool VerifyEs256(byte[] sig, byte[] msg, byte[] rawPoint, bool lowS, bool der)
    {
        try
        {
            BigInteger r, s;
            if (der)
            {
                var rs = ParseDer(sig);
                if (rs == null) return false;
                r = rs[0]; s = rs[1];
            }
            else
            {
                if (sig.Length != 64) return false;
                r = new BigInteger(sig.AsSpan(0, 32), isUnsigned: true, isBigEndian: true);
                s = new BigInteger(sig.AsSpan(32, 32), isUnsigned: true, isBigEndian: true);
            }
            if (r.IsZero || s.IsZero || r >= N || s >= N) return false;
            if (lowS && s > (N >> 1)) return false;
            var raw = new byte[64];
            Pad32(r).CopyTo(raw, 0);
            Pad32(s).CopyTo(raw, 32);
            using var ec = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = rawPoint[1..33], Y = rawPoint[33..65] },
            });
            return ec.VerifyData(msg, raw, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception) { return false; } // an off-curve key or any primitive error is a failed verification
    }

    // ---- assertion verification ----

    static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length != 0,
        Num n => NumberOf(n) is double d && d != 0 && !double.IsNaN(d),
        _ => true,
    };

    static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Verify a WebAuthn / FIDO2 assertion as a human step-up co-sign. <paramref name="assertion"/>: <c>authenticatorData</c>,
    /// <c>clientDataJSON</c>, <c>signature</c> (byte[]) and <c>publicKey</c> (a JWK dictionary or a raw COSE_Key byte[]).
    /// <paramref name="expect"/>: <c>expectedChallenge</c> (byte[] or base64url string), <c>rpId</c>, <c>origins</c>, <c>requireUV</c>,
    /// <c>requireLowS</c>, <c>storedSignCount</c> (required), <c>onSignCountRegression</c>, <c>rejectCrossOrigin</c>, <c>payment</c>.
    /// Returns <c>{ok:true, alg, signCount, flags}</c> or <c>{ok:false, reason}</c>; never throws.</summary>
    public static D VerifyAssertion(D assertion, D expect)
    {
        try
        {
            var publicKey = assertion.GetValueOrDefault("publicKey");
            if (assertion.GetValueOrDefault("authenticatorData") is not byte[] authenticatorData) return Fail("authenticatorData is not bytes");
            if (assertion.GetValueOrDefault("clientDataJSON") is not byte[] clientDataJson) return Fail("clientDataJSON is not bytes");
            if (assertion.GetValueOrDefault("signature") is not byte[] signature) return Fail("signature is not bytes");
            if (authenticatorData.Length > MaxAuthenticatorDataBytes) return Fail("authenticatorData is too large");
            if (clientDataJson.Length > MaxClientDataBytes) return Fail("clientDataJSON is too large");
            if (signature.Length > MaxSignatureBytes) return Fail("signature is too large");
            if (expect.GetValueOrDefault("rpId") is not string rpId || rpId.Length == 0) return Fail("rpId is required");
            if (expect.GetValueOrDefault("origins") is not L origins || origins.Count == 0) return Fail("origins allowlist is empty");
            if (!expect.ContainsKey("storedSignCount")) return Fail("storedSignCount is required (use 0 for a credential never used)");
            bool spc = expect.ContainsKey("payment");

            // clientDataJSON (TextDecoder: fatal UTF-8, a leading BOM is consumed)
            string clientText;
            try { clientText = StrictUtf8.GetString(clientDataJson); }
            catch (ArgumentException) { return Fail("clientDataJSON is not valid UTF-8"); }
            if (clientText.Length > 0 && clientText[0] == '﻿') clientText = clientText[1..];
            object? clientParsed;
            try { clientParsed = NoDuplicateKeys.Parse(clientText); } // a duplicate member is refused (a plain parse keeps the last)
            catch (Exception) { return Fail("clientDataJSON is not valid JSON"); }
            var client = AsRecord(clientParsed);
            if (client == null) return Fail("clientDataJSON is not a JSON object");
            var wantType = spc ? "payment.get" : "webauthn.get";
            client.TryGetValue("type", out var type);
            if (!(type is string ts && ts == wantType)) return Fail($"clientData.type is not \"{wantType}\" ({JsString(type, client.ContainsKey("type"))})");
            if (spc)
            {
                var pe = SpcPaymentError(client.GetValueOrDefault("payment"), expect["payment"], rpId);
                if (pe != null) return Fail(pe);
            }

            var gotChallenge = Pca.B64uDecode(client.GetValueOrDefault("challenge"));
            if (gotChallenge == null) return Fail("clientData.challenge is missing or not canonical base64url");
            var ec = expect.GetValueOrDefault("expectedChallenge");
            var expChallenge = ec as byte[] ?? Pca.B64uDecode(ec);
            if (expChallenge == null) return Fail("expectedChallenge is not decodable");
            if (!BytesEqual(gotChallenge, expChallenge)) return Fail("clientData.challenge does not match the step-up challenge");

            var origin = client.GetValueOrDefault("origin");
            if (!(expect.GetValueOrDefault("rejectCrossOrigin") is bool rc && !rc))
            {
                if (client.TryGetValue("crossOrigin", out var co))
                {
                    if (co is bool cb && cb) return Fail("clientData.crossOrigin is true");
                    if (!(co is bool cf && !cf)) return Fail("clientData.crossOrigin is not a boolean");
                }
            }
            if (origin is not string originS) return Fail("clientData.origin is missing");
            if (!origins.Any(o => o is string os && os == originS)) return Fail($"clientData.origin \"{originS}\" is not in the allowlist");

            // authenticatorData
            var parsed = ParseAuthenticatorData(authenticatorData);
            if (parsed == null) return Fail("authenticatorData is too short (< 37 bytes)");
            var flags = (D)parsed["flags"]!;
            long signCount = (long)parsed["signCount"]!;
            if (!BytesEqual((byte[])parsed["rpIdHash"]!, Sha(Encoding.UTF8.GetBytes(rpId)))) return Fail("rpIdHash does not match sha256(rpId)");
            if (!(bool)flags["up"]!) return Fail("User Present (UP) flag is not set");
            if (Truthy(expect.GetValueOrDefault("requireUV")) && !(bool)flags["uv"]!) return Fail("User Verified (UV) flag is required but not set");

            // signature over authenticatorData || sha256(clientDataJSON)
            var signedData = Pca.Cat(authenticatorData, Sha(clientDataJson));
            (string Alg, byte[] Raw) key;
            try { key = ResolveKey(publicKey, assertion.ContainsKey("publicKey")); }
            catch (Exception e) { return Fail("public key could not be resolved: " + e.Message); }
            bool valid;
            if (key.Alg == "ES256")
            {
                bool isDer = signature.Length > 0 && signature[0] == 0x30 && signature.Length != 64;
                valid = VerifyEs256(signature, signedData, key.Raw, expect.GetValueOrDefault("requireLowS") is bool ls && ls, isDer);
            }
            else valid = Pca.VerifyEd25519Strict(key.Raw, signedData, signature);
            if (!valid) return Fail("assertion signature did not verify");

            // signature counter (clone detection), only after the signature verified
            var storedRaw = expect.GetValueOrDefault("storedSignCount");
            var stored = NumberOf(storedRaw);
            if (stored is not double st || !double.IsFinite(st) || st != Math.Round(st) || st < 0 || double.IsNegative(st) || st > 4294967295d)
                return Fail("storedSignCount is not a uint32");
            if ((signCount != 0 || st != 0) && signCount <= st)
            {
                if (expect.GetValueOrDefault("onSignCountRegression") is Action<D> hook)
                    hook(new D { ["storedSignCount"] = storedRaw, ["reportedSignCount"] = signCount });
                return Fail("signCount did not increase (possible cloned authenticator)");
            }

            return new D { ["ok"] = true, ["alg"] = key.Alg, ["signCount"] = signCount, ["flags"] = flags };
        }
        catch (Exception e)
        {
            return Fail("verification error (fail closed): " + e.Message);
        }
    }
}
