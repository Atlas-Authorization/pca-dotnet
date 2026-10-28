// Compact-JWS plumbing shared by the Azure MAA and Google Confidential Space verifiers: the canonical base64url gate, the parsed
// token and the signature checks (ES256 and RS256) under a certificate or JWK key. Also the wording of the reference's JSON.parse
// failures (the token verifiers embed the engine's message for a malformed header or payload segment into the reason they return).
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

internal sealed class JwtParsed
{
    public string Alg = "";
    public string Kid = ""; public bool HasKid;
    public List<string> X5c = new(); public bool HasX5c;
    public JD Payload = new();
    public byte[] SigningInput = Array.Empty<byte>();
    public byte[] Signature = Array.Empty<byte>();
}

internal static class AttestJws
{
    /// <summary>Decodes one strictly canonical unpadded base64url segment (one spelling per value).</summary>
    internal static byte[] DecodeCanonicalBase64url(string seg)
    {
        if (!seg.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-')) throw new AttestError("non-canonical compact JWS: bad-character");
        if (seg.Length % 4 == 1) throw new AttestError("non-canonical compact JWS: non-canonical-base64url (impossible length)");
        byte[] b;
        try
        {
            var t = seg.Replace('-', '+').Replace('_', '/');
            switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
            b = Convert.FromBase64String(t);
        }
        catch (FormatException) { throw new AttestError("non-canonical compact JWS: non-canonical-base64url"); }
        if (Pca.B64u(b) != seg) throw new AttestError("non-canonical compact JWS: non-canonical-base64url");
        return b;
    }

    static object? Lenient(byte[] b) => Pca.ParseJson(Encoding.UTF8.GetString(b));

    /// <summary>Parses a compact JWS into header fields, payload and signing input; it verifies nothing. <paramref name="prefix"/> is the
    /// reference parser's name (it leads every message).</summary>
    internal static JwtParsed ParseJwt(string token, string prefix)
    {
        if (token.Length == 0) throw new AttestError($"{prefix}: empty token");
        var parts = token.Split('.');
        if (parts.Length != 3) throw new AttestError($"{prefix}: a compact JWS has exactly three dot-separated parts");
        string h = parts[0], p = parts[1], s = parts[2];
        if (h.Length == 0 || p.Length == 0 || s.Length == 0) throw new AttestError($"{prefix}: empty JWS segment");
        object? headerObj, payloadObj;
        try
        {
            headerObj = Lenient(DecodeCanonicalBase64url(h));
            payloadObj = Lenient(DecodeCanonicalBase64url(p));
        }
        catch (Exception e) { throw new AttestError($"{prefix}: malformed JSON segment: {JsonSegmentError(h, p, e)}"); }
        if (headerObj is not JD hdr) throw new AttestError($"{prefix}: header is not a JSON object");
        if (payloadObj is not JD payload) throw new AttestError($"{prefix}: payload is not a JSON object");
        var alg = hdr.GetValueOrDefault("alg") as string ?? "";
        if (alg.Length == 0) throw new AttestError($"{prefix}: header has no alg");
        var o = new JwtParsed { Alg = alg, Payload = payload, SigningInput = Encoding.UTF8.GetBytes(h + "." + p) };
        if (hdr.GetValueOrDefault("kid") is string kid) { o.Kid = kid; o.HasKid = true; }
        if (AttestUtil.AsStrList(hdr.GetValueOrDefault("x5c")) is { } l) { o.X5c = l; o.HasX5c = true; }
        try { o.Signature = DecodeCanonicalBase64url(s); }
        catch (AttestError e) { throw new AttestError($"{prefix}: malformed signature segment: {e.Message}"); }
        return o;
    }

    /// <summary>The kty / crv of a key's JWK export ("undefined" for a key type without a curve).</summary>
    internal static (string Kty, string Crv) JwkKtyCrv(CertKey k)
    {
        if (k.Ec != null) return ("EC", k.GoCurve);
        if (k.Rsa != null) return ("RSA", "undefined");
        if (k.Type == "ed25519") return ("OKP", "Ed25519");
        return (k.Type, "undefined");
    }

    /// <summary>Verifies a raw r||s ES256 signature over the signing input under a P-256 key.</summary>
    internal static bool Es256Ok(byte[] sig, byte[] input, CertKey k)
    {
        if (k.Ec == null || k.GoCurve != "P-256" || sig.Length != 64) return false;
        try { return k.Ec.VerifyHash(AttestUtil.Sha256(input), sig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception) { return false; }
    }

    /// <summary>Verifies an RSASSA-PKCS1-v1_5 / SHA-256 signature under an RSA key.</summary>
    internal static bool Rs256Ok(byte[] sig, byte[] input, CertKey k)
    {
        if (k.Rsa == null) return false;
        try { return k.Rsa.VerifyHash(AttestUtil.Sha256(input), sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); }
        catch (Exception) { return false; }
    }

    const string Unsupported = "error:1E08010C:DECODER routines::unsupported";

    static byte[] TrimZeros(byte[] b)
    {
        int i = 0;
        while (i < b.Length && b[i] == 0) i++;
        return b[i..];
    }

    /// <summary>Builds a public RSA key from base64url n / e.</summary>
    internal static CertKey JwkRsaKey(string n, string e)
    {
        byte[] nb = AttestUtil.NodeB64(n), eb = AttestUtil.NodeB64(e);
        if (nb.Length == 0 || eb.Length == 0) throw new AttestError(Unsupported);
        var ev = new BigInteger(eb, isUnsigned: true, isBigEndian: true);
        if (ev < 3 || ev > int.MaxValue) throw new AttestError(Unsupported);
        try
        {
            var rsa = RSA.Create(new RSAParameters { Modulus = TrimZeros(nb), Exponent = TrimZeros(eb) });
            var pr = rsa.ExportParameters(false);
            return new CertKey
            {
                Type = "rsa", Rsa = rsa, Spki = rsa.ExportSubjectPublicKeyInfo(),
                RsaBc = new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(false, new Org.BouncyCastle.Math.BigInteger(1, pr.Modulus!), new Org.BouncyCastle.Math.BigInteger(1, pr.Exponent!)),
            };
        }
        catch (Exception) { throw new AttestError(Unsupported); }
    }

    /// <summary>Builds a public EC key from crv / x / y (on-curve points only).</summary>
    internal static CertKey JwkEcKey(string crv, string x, string y)
    {
        (string Oid, string Ossl, int Size) c = crv switch
        {
            "P-256" => ("1.2.840.10045.3.1.7", "prime256v1", 32),
            "P-384" => ("1.3.132.0.34", "secp384r1", 48),
            "P-521" => ("1.3.132.0.35", "secp521r1", 66),
            _ => throw new AttestError(Unsupported),
        };
        byte[] xb = TrimZeros(AttestUtil.NodeB64(x)), yb = TrimZeros(AttestUtil.NodeB64(y));
        if (xb.Length > c.Size || yb.Length > c.Size) throw new AttestError(Unsupported);
        var xp = new byte[c.Size]; var yp = new byte[c.Size];
        xb.CopyTo(xp, c.Size - xb.Length); yb.CopyTo(yp, c.Size - yb.Length);
        try
        {
            var ec = ECDsa.Create(new ECParameters { Curve = ECCurve.CreateFromValue(c.Oid), Q = new ECPoint { X = xp, Y = yp } });
            var spki = ec.ExportSubjectPublicKeyInfo();
            var point = new byte[1 + 2 * c.Size];
            point[0] = 0x04; xp.CopyTo(point, 1); yp.CopyTo(point, 1 + c.Size);
            return new CertKey { Type = "ec", Curve = c.Ossl, GoCurve = crv, Ec = ec, EcPoint = point, Spki = spki };
        }
        catch (Exception) { throw new AttestError(Unsupported); }
    }

    /// <summary>The message to report for a header or payload segment that did not decode or parse: the canonical-form message of the
    /// base64url gate, else the engine's JSON.parse wording of the segment that failed.</summary>
    static string JsonSegmentError(string h, string p, Exception err)
    {
        if (err.Message.StartsWith("non-canonical compact JWS", StringComparison.Ordinal)) return err.Message;
        foreach (var seg in new[] { h, p })
        {
            byte[] b;
            try { b = DecodeCanonicalBase64url(seg); }
            catch (AttestError d) { return d.Message; }
            try { Lenient(b); }
            catch (Exception j)
            {
                var msg = V8Json.Error(Encoding.UTF8.GetString(b));
                return msg.Length > 0 ? msg : j.Message;
            }
        }
        return err.Message;
    }
}

/// <summary>Validates a document with the grammar of JSON.parse and, when it is not valid, returns the message V8 reports for it ("" for a valid
/// document). Only the reason text depends on this; whether a segment parses never does.</summary>
internal sealed class V8Json
{
    readonly string src;
    int pos;
    string err = "";

    V8Json(string text) { src = text; }

    internal static string Error(string text)
    {
        // an invalid UTF-8 sequence was already replaced by U+FFFD when the bytes were decoded
        var p = new V8Json(text);
        p.Value();
        if (p.err.Length > 0) return p.err;
        p.Ws();
        if (p.pos < p.src.Length) p.Fail("Unexpected non-whitespace character after JSON at position {0} (line {1} column {2})", p.pos);
        return p.err;
    }

    (int Line, int Col) Location(int at)
    {
        int line = 1, last = -1;
        for (int i = 0; i < at && i < src.Length; i++)
        {
            char c = src[i];
            if (c == '\n' || (c == '\r' && !(i + 1 < src.Length && src[i + 1] == '\n'))) { line++; last = i; }
        }
        return (line, at - last);
    }

    void Fail(string format, int at)
    {
        if (err.Length > 0) return;
        var (line, col) = Location(at);
        err = string.Format(System.Globalization.CultureInfo.InvariantCulture, format, at, line, col);
    }

    void FailExpected(string what, int at) => Fail(what.Replace("{", "{{").Replace("}", "}}") + " in JSON at position {0} (line {1} column {2})", at);

    void UnexpectedEnd() { if (err.Length == 0) err = "Unexpected end of JSON input"; }

    void UnexpectedToken(int at)
    {
        if (err.Length > 0) return;
        var whole = src;
        if (whole is "NaN" or "Infinity" or "undefined" or "[object Object]") { err = $"\"{whole}\" is not valid JSON"; return; }
        const int ctx = 10;
        var tok = src.Substring(at, 1);
        int n = src.Length;
        err = n < ctx * 2 + 1 ? $"Unexpected token '{tok}', \"{whole}\" is not valid JSON"
            : at < ctx ? $"Unexpected token '{tok}', \"{src[..(at + ctx)]}\"... is not valid JSON"
            : at < n - ctx ? $"Unexpected token '{tok}', ...\"{src[(at - ctx)..(at + ctx)]}\"... is not valid JSON"
            : $"Unexpected token '{tok}', ...\"{src[(at - ctx)..]}\" is not valid JSON";
    }

    void Ws()
    {
        while (pos < src.Length && src[pos] is ' ' or '\t' or '\n' or '\r') pos++;
    }

    int Peek() => pos >= src.Length ? -1 : src[pos];

    static bool IsDigit(int c) => c >= '0' && c <= '9';

    void Value()
    {
        Ws();
        if (err.Length > 0) return;
        int c = Peek();
        if (c < 0) UnexpectedEnd();
        else if (c == '"') Str();
        else if (c == '{') Obj();
        else if (c == '[') Arr();
        else if (c == '-' || IsDigit(c)) Number();
        else if (c == 't') Literal("true");
        else if (c == 'f') Literal("false");
        else if (c == 'n') Literal("null");
        else UnexpectedToken(pos);
    }

    void Literal(string word)
    {
        foreach (char w in word)
        {
            if (pos >= src.Length) { UnexpectedEnd(); return; }
            if (src[pos] != w) { UnexpectedToken(pos); return; }
            pos++;
        }
    }

    void Number()
    {
        if (Peek() == '-')
        {
            pos++;
            if (!IsDigit(Peek())) { FailExpected("No number after minus sign", pos); return; }
        }
        if (Peek() == '0')
        {
            pos++;
            if (IsDigit(Peek())) { Fail("Unexpected number in JSON at position {0} (line {1} column {2})", pos); return; }
        }
        else while (IsDigit(Peek())) pos++;
        if (Peek() == '.')
        {
            pos++;
            if (!IsDigit(Peek())) { FailExpected("Unterminated fractional number", pos); return; }
            while (IsDigit(Peek())) pos++;
        }
        int c = Peek();
        if (c == 'e' || c == 'E')
        {
            pos++;
            int s = Peek();
            if (s == '+' || s == '-') pos++;
            if (!IsDigit(Peek())) { FailExpected("Exponent part is missing a number", pos); return; }
            while (IsDigit(Peek())) pos++;
        }
    }

    void Str()
    {
        pos++; // opening quote
        while (true)
        {
            int c = Peek();
            if (c < 0) { FailExpected("Unterminated string", pos); return; }
            if (c == '"') { pos++; return; }
            if (c < 0x20) { FailExpected("Bad control character in string literal", pos); return; }
            if (c == '\\')
            {
                pos++;
                int e = Peek();
                if (e is '"' or '\\' or '/' or 'b' or 'f' or 'n' or 'r' or 't') pos++;
                else if (e == 'u')
                {
                    pos++;
                    for (int i = 0; i < 4; i++)
                    {
                        int h = Peek();
                        if (!(IsDigit(h) || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F'))) { FailExpected("Bad Unicode escape", pos); return; }
                        pos++;
                    }
                }
                else if (e == -1) { FailExpected("Unterminated string", pos); return; }
                else { FailExpected("Bad escaped character", pos); return; }
            }
            else pos++;
        }
    }

    void Obj()
    {
        pos++; // {
        Ws();
        if (Peek() == '}') { pos++; return; }
        if (Peek() != '"') { FailExpected("Expected property name or '}'", pos); return; }
        while (true)
        {
            Str();
            if (err.Length > 0) return;
            Ws();
            if (Peek() != ':') { FailExpected("Expected ':' after property name", pos); return; }
            pos++;
            Value();
            if (err.Length > 0) return;
            Ws();
            int c = Peek();
            if (c == ',')
            {
                pos++;
                Ws();
                if (Peek() != '"') { FailExpected("Expected double-quoted property name", pos); return; }
            }
            else if (c == '}') { pos++; return; }
            else { FailExpected("Expected ',' or '}' after property value", pos); return; }
        }
    }

    void Arr()
    {
        pos++; // [
        Ws();
        if (Peek() == ']') { pos++; return; }
        while (true)
        {
            Value();
            if (err.Length > 0) return;
            Ws();
            int c = Peek();
            if (c == ',') pos++;
            else if (c == ']') { pos++; return; }
            else { FailExpected("Expected ',' or ']' after array element", pos); return; }
        }
    }
}
