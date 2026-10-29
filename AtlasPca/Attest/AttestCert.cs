// Certificates as the reference's X.509 engine (OpenSSL through node:crypto) reads them. A general certificate library refuses a
// certificate for many reasons OpenSSL does not (a trailing byte after a DER certificate, a non-minimal length, a duplicated or
// ill-formed extension, a second extensions block), and those are precisely the inputs on which the strict readers of the attestation
// verifiers must give their own, specific answer. So a certificate is parsed here with the structure checks of the OpenSSL template
// decoder (nothing more), the strict rules are applied afterwards by the readers of AttestDer, and the platform / BouncyCastle
// primitives are used only for what they are good at: public keys and signature verification.
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

internal sealed record LenientExt(string Oid, bool Critical, byte[] Value);

/// <summary>A parsed certificate: the raw parts the verifiers compare, and the parameters of its signature.</summary>
internal sealed class AttCert
{
    public byte[] Raw = Array.Empty<byte>();        // the certificate as DER (outer length in minimal form)
    public byte[] RawTbs = Array.Empty<byte>();     // tbsCertificate, header included
    public byte[] RawIssuer = Array.Empty<byte>();
    public byte[] RawSubject = Array.Empty<byte>();
    public byte[] RawSpki = Array.Empty<byte>();
    public byte[] Serial = Array.Empty<byte>();     // the INTEGER content
    public string SigOid = "";
    public byte[]? SigParams;                       // the parameters element of the signature algorithm, header included (null: absent)
    public byte[] Signature = Array.Empty<byte>();  // the signature BIT STRING content without the unused-bits octet
    public List<LenientExt> Exts = new();

    internal byte[]? ExtValue(string oid) => Exts.FirstOrDefault(e => e.Oid == oid)?.Value;

    /// <summary>The OCSP responder URLs of the Authority Information Access extension.</summary>
    internal List<string> OcspServers()
    {
        var o = new List<string>();
        var v = ExtValue("1.3.6.1.5.5.7.1.1");
        if (v == null) return o;
        try
        {
            var seq = AttestCerts.ReadElem(v, 0, v.Length, 0x30);
            foreach (var d in AttestCerts.Kids(v, seq))
            {
                List<CertElem> parts;
                try { parts = AttestCerts.Kids(v, d); } catch (AttestError) { continue; }
                if (parts.Count != 2 || parts[0].Tag != 0x06) continue;
                string method;
                try { method = AttestCerts.Dotted(v, parts[0]); } catch (AttestError) { continue; }
                if (method != "1.3.6.1.5.5.7.48.1" || parts[1].Tag != 0x86) continue;
                o.Add(Encoding.Latin1.GetString(v, parts[1].Start, parts[1].End - parts[1].Start));
            }
        }
        catch (AttestError) { return new List<string>(); }
        return o;
    }

    /// <summary>The extended key usage extension lists id-kp-OCSPSigning.</summary>
    internal bool HasOcspSigningEku()
    {
        var v = ExtValue("2.5.29.37");
        if (v == null) return false;
        try
        {
            var seq = AttestCerts.ReadElem(v, 0, v.Length, 0x30);
            foreach (var p in AttestCerts.Kids(v, seq))
            {
                try { if (AttestCerts.Dotted(v, p) == "1.3.6.1.5.5.7.3.9") return true; } catch (AttestError) { }
            }
        }
        catch (AttestError) { }
        return false;
    }

    internal bool SelfIssued => RawSubject.AsSpan().SequenceEqual(RawIssuer);

    /// <summary>The serial number as lowercase hex without leading zeros.</summary>
    internal string SerialHex => AttestUtil.Hex(Serial).TrimStart('0');
}

internal readonly record struct CertElem(byte Tag, int Hdr, int Start, int End);

/// <summary>A certificate's public key with the details the rules ask about (Node's asymmetricKeyType / namedCurve).</summary>
internal sealed class CertKey
{
    public string Type = "unknown";         // "ec", "rsa", "rsa-pss", "ed25519", ...
    public string Curve = "";               // OpenSSL curve name for "ec"
    public string GoCurve = "";             // "P-256" / "P-384" / "P-521" / "P-224" for "ec"
    public byte[] Spki = Array.Empty<byte>();
    public ECDsa? Ec;
    public byte[]? EcPoint;                 // uncompressed SEC1 point
    public RSA? Rsa;
    public RsaKeyParameters? RsaBc;
    public byte[]? Ed25519;

    internal string SpkiSha256() => AttestUtil.Hex(AttestUtil.Sha256(Spki));
    internal string SpkiSha384() => AttestUtil.Hex(AttestUtil.Sha384(Spki));

    /// <summary>The uncompressed SEC1 point of an EC key on exactly the named curve (P-256 or P-384).</summary>
    internal byte[] EcPointOn(string curveName)
    {
        if (Type != "ec" || EcPoint == null) throw new AttestError($"public key is not EC (got {Type})");
        if (GoCurve != curveName) throw new AttestError($"public key is not on {curveName} (got {GoCurve})");
        return EcPoint;
    }
}

internal static class AttestCerts
{
    const string WrongTag = "error:068000A8:asn1 encoding routines::wrong tag";
    const string Nested = "error:0688010A:asn1 encoding routines::nested asn1 error";
    const string Bits = "error:0680007D:asn1 encoding routines::invalid bit string bits left";
    const string ObjectEnc = "error:0688010A:asn1 encoding routines::invalid object encoding";
    const string Unsupported = "error:1E08010C:DECODER routines::unsupported";

    /// <summary>A lenient TLV at <paramref name="off"/> (any definite length form up to 4 bytes; the strict rules are applied later).</summary>
    static DerTlv TlvAt(byte[] der, int limit, int off)
    {
        if (off + 2 > limit) throw new AttestError("truncated");
        byte tag = der[off];
        long l = der[off + 1];
        int start = off + 2;
        if ((l & 0x80) != 0)
        {
            int n = (int)(l & 0x7f);
            if (n == 0 || n > 4 || start + n > limit) throw new AttestError("bad length");
            l = 0;
            for (int i = 0; i < n; i++) l = l * 256 + der[start + i];
            start += n;
        }
        long end = start + l;
        if (end > limit) throw new AttestError("truncated");
        return new DerTlv(tag, start, (int)end);
    }

    internal static CertElem ReadElem(byte[] b, int off, int limit, byte tag)
    {
        if (off >= limit) throw new AttestError("error:0680007B:asn1 encoding routines::not enough data");
        DerTlv t;
        try { t = TlvAt(b, limit, off); } catch (AttestError) { throw new AttestError(Nested); }
        if (tag != 0 && t.Tag != tag) throw new AttestError(WrongTag);
        return new CertElem(t.Tag, off, t.Start, t.End);
    }

    internal static List<CertElem> Kids(byte[] b, CertElem e)
    {
        var o = new List<CertElem>();
        for (int p = e.Start; p < e.End;)
        {
            var k = ReadElem(b, p, e.End, 0);
            o.Add(k);
            p = k.End;
        }
        return o;
    }

    internal static string Dotted(byte[] b, CertElem e) => DottedOid(b, new DerTlv(e.Tag, e.Start, e.End));

    internal static string DottedOid(byte[] b, DerTlv t)
    {
        if (t.Tag != 0x06 || t.End <= t.Start) throw new AttestError("extension OID is malformed");
        var arcs = new List<BigInteger>();
        BigInteger v = 0;
        bool open = false;
        for (int i = t.Start; i < t.End; i++)
        {
            byte by = b[i];
            if (!open && by == 0x80) throw new AttestError("extension OID has a non-minimal arc");
            v = (v << 7) | (by & 0x7f);
            open = (by & 0x80) != 0;
            if (!open) { arcs.Add(v); v = 0; }
        }
        if (open) throw new AttestError("extension OID is truncated");
        var first = arcs[0];
        var parts = new List<string>();
        if (first < 40) { parts.Add("0"); parts.Add(first.ToString()); }
        else if (first < 80) { parts.Add("1"); parts.Add((first - 40).ToString()); }
        else { parts.Add("2"); parts.Add((first - 80).ToString()); }
        foreach (var a in arcs.Skip(1)) parts.Add(a.ToString());
        return string.Join(".", parts);
    }

    /// <summary>The OpenSSL object-identifier content check: not empty, no arc starting with 0x80, no dangling continuation.</summary>
    static bool ValidOid(byte[] b, CertElem e)
    {
        if (e.Tag != 0x06 || e.End <= e.Start || (b[e.End - 1] & 0x80) != 0) return false;
        for (int i = e.Start; i < e.End; i++)
            if (b[i] == 0x80 && (i == e.Start || (b[i - 1] & 0x80) == 0)) return false;
        return true;
    }

    /// <summary>AlgorithmIdentifier: SEQUENCE { OID, parameters ANY OPTIONAL }.</summary>
    internal static (string Oid, byte[]? Params) AlgId(byte[] b, CertElem e)
    {
        var kids = Kids(b, e);
        if (kids.Count == 0 || kids.Count > 2 || !ValidOid(b, kids[0])) throw new AttestError(Nested);
        string dotted;
        try { dotted = Dotted(b, kids[0]); } catch (AttestError) { throw new AttestError(ObjectEnc); }
        return (dotted, kids.Count == 2 ? b[kids[1].Hdr..kids[1].End] : null);
    }

    static void CheckBitString(byte[] b, CertElem e)
    {
        if (e.Tag != 0x03 || e.End - e.Start < 1) throw new AttestError(WrongTag);
        if (b[e.Start] > 7) throw new AttestError(Bits);
    }

    static readonly HashSet<byte> NameValueTags = new() { 0x0c, 0x12, 0x13, 0x14, 0x16, 0x1c, 0x1e, 0x03, 0x30 };

    /// <summary>Validates a Name: SEQUENCE OF SET OF SEQUENCE { OID, string }.</summary>
    static void CheckName(byte[] b, CertElem e)
    {
        foreach (var rdn in Kids(b, e))
        {
            if (rdn.Tag != 0x31) throw new AttestError(WrongTag);
            foreach (var atv in Kids(b, rdn))
            {
                if (atv.Tag != 0x30) throw new AttestError(WrongTag);
                var kv = Kids(b, atv);
                if (kv.Count != 2 || !ValidOid(b, kv[0]) || !NameValueTags.Contains(kv[1].Tag)) throw new AttestError(Nested);
            }
        }
    }

    /// <summary>Parses a DER certificate like d2i_X509: its structure is checked, trailing bytes after it are ignored.</summary>
    internal static AttCert ParseDer(byte[] der)
    {
        var outer = ReadElem(der, 0, der.Length, 0x30);
        var tbs = ReadElem(der, outer.Start, outer.End, 0x30);
        var alg = ReadElem(der, tbs.End, outer.End, 0x30);
        var sig = ReadElem(der, alg.End, outer.End, 0x03);
        if (sig.End != outer.End) throw new AttestError(Nested);
        CheckBitString(der, sig);
        var c = new AttCert { RawTbs = der[tbs.Hdr..tbs.End], Signature = der[(sig.Start + 1)..sig.End] };
        (c.SigOid, c.SigParams) = AlgId(der, alg);

        int p = tbs.Start;
        if (p < tbs.End && der[p] == 0xa0)
        {
            var v = ReadElem(der, p, tbs.End, 0xa0);
            var inner0 = ReadElem(der, v.Start, v.End, 0x02);
            if (inner0.End != v.End) throw new AttestError(Nested);
            p = v.End;
        }
        var serial = ReadElem(der, p, tbs.End, 0x02);
        if (serial.End == serial.Start) throw new AttestError("error:0688010A:asn1 encoding routines::illegal zero content");
        c.Serial = der[serial.Start..serial.End];
        p = serial.End;
        var inner = ReadElem(der, p, tbs.End, 0x30); // signature algorithm
        AlgId(der, inner);
        p = inner.End;
        var issuer = ReadElem(der, p, tbs.End, 0x30);
        CheckName(der, issuer);
        c.RawIssuer = der[issuer.Hdr..issuer.End];
        p = issuer.End;
        var validity = ReadElem(der, p, tbs.End, 0x30);
        var times = Kids(der, validity);
        if (times.Count != 2 || (times[0].Tag != 0x17 && times[0].Tag != 0x18) || (times[1].Tag != 0x17 && times[1].Tag != 0x18)) throw new AttestError(Nested);
        p = validity.End;
        var subject = ReadElem(der, p, tbs.End, 0x30);
        CheckName(der, subject);
        c.RawSubject = der[subject.Hdr..subject.End];
        p = subject.End;
        var spki = ReadElem(der, p, tbs.End, 0x30);
        var sk = Kids(der, spki);
        if (sk.Count != 2 || sk[0].Tag != 0x30) throw new AttestError(Nested);
        AlgId(der, sk[0]);
        CheckBitString(der, sk[1]);
        c.RawSpki = der[spki.Hdr..spki.End];
        p = spki.End;
        foreach (byte uid in new byte[] { 0x81, 0x82 })
        {
            if (p < tbs.End && der[p] == uid)
            {
                var u = ReadElem(der, p, tbs.End, uid);
                p = u.End;
            }
        }
        if (p < tbs.End && der[p] == 0xa3)
        {
            var wrap = ReadElem(der, p, tbs.End, 0xa3);
            var seq = ReadElem(der, wrap.Start, wrap.End, 0x30);
            if (seq.End != wrap.End) throw new AttestError(Nested);
            foreach (var e in Kids(der, seq))
            {
                if (e.Tag != 0x30) throw new AttestError(WrongTag);
                var parts = Kids(der, e);
                if (parts.Count < 2 || parts.Count > 3 || !ValidOid(der, parts[0])) throw new AttestError(Nested);
                string oid;
                try { oid = Dotted(der, parts[0]); } catch (AttestError) { throw new AttestError(ObjectEnc); }
                bool critical = false;
                int next = 1;
                if (parts.Count == 3)
                {
                    if (parts[1].Tag != 0x01 || parts[1].End - parts[1].Start != 1) throw new AttestError(Nested);
                    critical = der[parts[1].Start] != 0;
                    next = 2;
                }
                if (parts[next].Tag != 0x04) throw new AttestError(WrongTag);
                c.Exts.Add(new LenientExt(oid, critical, der[parts[next].Start..parts[next].End]));
            }
            p = wrap.End;
        }
        if (p != tbs.End) throw new AttestError(Nested);

        // the certificate as DER: the outer length in its minimal form, the content as supplied
        var content = der[outer.Start..outer.End];
        c.Raw = Pca.Concat(LengthHeader(0x30, content.Length), content);
        return c;
    }

    static byte[] LengthHeader(byte tag, int n) =>
        n < 0x80 ? new[] { tag, (byte)n }
        : n < 0x100 ? new[] { tag, (byte)0x81, (byte)n }
        : n < 0x10000 ? new[] { tag, (byte)0x82, (byte)(n >> 8), (byte)n }
        : n < 0x1000000 ? new[] { tag, (byte)0x83, (byte)(n >> 16), (byte)(n >> 8), (byte)n }
        : new[] { tag, (byte)0x84, (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n };

    static readonly Regex PemBlockRe = new(@"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", RegexOptions.Singleline | RegexOptions.CultureInvariant);
    static readonly Regex PemBodyRe = new(@"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", RegexOptions.Singleline | RegexOptions.CultureInvariant);

    internal static List<string> PemBlocks(string text) => PemBlockRe.Matches(text).Select(m => m.Value).ToList();

    /// <summary>Parses the first certificate block of a PEM text (PEM_read_bio_X509_AUX: bytes after the certificate inside the block are an error).</summary>
    internal static AttCert FromPem(string text)
    {
        var m = PemBodyRe.Match(text);
        if (!m.Success) throw new AttestError("error:0480006C:PEM routines::no start line");
        var body = new string(m.Groups[1].Value.Where(r => r is not (' ' or '\t' or '\r' or '\n')).ToArray());
        byte[] der;
        try { der = Convert.FromBase64String(body); }
        catch (FormatException) { throw new AttestError(Unsupported); }
        var c = ParseDer(der);
        var outer = ReadElem(der, 0, der.Length, 0x30);
        if (outer.End != der.Length) throw new AttestError(Nested);
        return c;
    }

    // ---- keys and signatures

    const string OidRsaEncryption = "1.2.840.113549.1.1.1", OidRsaPssKey = "1.2.840.113549.1.1.10", OidEcPublicKey = "1.2.840.10045.2.1", OidEd25519 = "1.3.101.112";

    static readonly Dictionary<string, (string Ossl, string Go, int Size)> Curves = new()
    {
        ["1.2.840.10045.3.1.7"] = ("prime256v1", "P-256", 32),
        ["1.3.132.0.34"] = ("secp384r1", "P-384", 48),
        ["1.3.132.0.35"] = ("secp521r1", "P-521", 66),
        ["1.3.132.0.33"] = ("secp224r1", "P-224", 28),
    };

    /// <summary>The certificate's subject public key. An RSASSA-PSS key is read from its SubjectPublicKeyInfo as the RSAPublicKey it carries.</summary>
    internal static CertKey KeyOf(AttCert c) => KeyOfSpki(c.RawSpki);

    /// <summary>The public key of a DER SubjectPublicKeyInfo.</summary>
    internal static CertKey KeyOfSpki(byte[] rawSpki)
    {
        var spki = ReadElem(rawSpki, 0, rawSpki.Length, 0x30);
        var kids = Kids(rawSpki, spki);
        if (kids.Count != 2) throw new AttestError(Nested);
        var (oid, prm) = AlgId(rawSpki, kids[0]);
        var bits = rawSpki[(kids[1].Start + 1)..kids[1].End];
        var k = new CertKey { Spki = rawSpki };
        switch (oid)
        {
            case OidRsaEncryption:
            case OidRsaPssKey:
                {
                    try
                    {
                        var rsa = RSA.Create();
                        rsa.ImportRSAPublicKey(bits, out int used);
                        if (used != bits.Length) throw new CryptographicException("trailing data");
                        var pr = rsa.ExportParameters(false);
                        k.Rsa = rsa;
                        k.RsaBc = new RsaKeyParameters(false, new Org.BouncyCastle.Math.BigInteger(1, pr.Modulus!), new Org.BouncyCastle.Math.BigInteger(1, pr.Exponent!));
                    }
                    catch (Exception) { throw new AttestError(Unsupported); }
                    k.Type = oid == OidRsaPssKey ? "rsa-pss" : "rsa";
                    return k;
                }
            case OidEcPublicKey:
                {
                    try
                    {
                        if (prm == null || prm[0] != 0x06) throw new AttestError(Unsupported);
                        var curveOid = Dotted(prm, ReadElem(prm, 0, prm.Length, 0x06));
                        if (!Curves.TryGetValue(curveOid, out var cv) || bits.Length != 1 + 2 * cv.Size || bits[0] != 0x04) throw new AttestError(Unsupported);
                        var q = new ECPoint { X = bits[1..(1 + cv.Size)], Y = bits[(1 + cv.Size)..] };
                        k.Ec = ECDsa.Create(new ECParameters { Curve = ECCurve.CreateFromValue(curveOid), Q = q });
                        k.Type = "ec"; k.Curve = cv.Ossl; k.GoCurve = cv.Go; k.EcPoint = bits;
                        return k;
                    }
                    catch (Exception e) when (e is not AttestError) { throw new AttestError(Unsupported); }
                }
            case OidEd25519:
                if (bits.Length != 32 || prm != null) throw new AttestError(Unsupported);
                k.Type = "ed25519"; k.Ed25519 = bits;
                return k;
        }
        throw new AttestError(Unsupported);
    }

    static readonly Dictionary<string, string> SigHashes = new()
    {
        ["1.2.840.10045.4.3.2"] = "SHA256", ["1.2.840.10045.4.3.3"] = "SHA384", ["1.2.840.10045.4.3.4"] = "SHA512",
        ["1.2.840.113549.1.1.11"] = "SHA256", ["1.2.840.113549.1.1.12"] = "SHA384", ["1.2.840.113549.1.1.13"] = "SHA512",
    };

    static readonly Dictionary<string, string> HashOids = new()
    {
        ["2.16.840.1.101.3.4.2.1"] = "SHA256", ["2.16.840.1.101.3.4.2.2"] = "SHA384", ["2.16.840.1.101.3.4.2.3"] = "SHA512", ["1.3.14.3.2.26"] = "SHA1",
    };

    internal static byte[] HashOf(string h, byte[] data) => h switch
    {
        "SHA1" => SHA1.HashData(data), "SHA256" => SHA256.HashData(data), "SHA384" => SHA384.HashData(data), _ => SHA512.HashData(data),
    };

    static Org.BouncyCastle.Crypto.IDigest BcDigest(string h) => h switch
    {
        "SHA1" => new Sha1Digest(), "SHA256" => new Sha256Digest(), "SHA384" => new Sha384Digest(), _ => new Sha512Digest(),
    };

    /// <summary>RSASSA-PSS-params: the hash, the salt length, and whether the profile is one this verifier checks (MGF1 over the same hash, trailer field 1).</summary>
    static (string Hash, int Salt, bool Ok) PssParams(byte[]? raw)
    {
        string h = "SHA1"; int salt = 20;
        if (raw == null || raw.Length == 0) return (h, salt, true);
        try
        {
            var seq = ReadElem(raw, 0, raw.Length, 0x30);
            string mgfHash = "SHA1";
            foreach (var k in Kids(raw, seq))
            {
                var inner = Kids(raw, k);
                if (inner.Count != 1) return default;
                switch (k.Tag)
                {
                    case 0xa0:
                        {
                            var (oid, _) = AlgId(raw, inner[0]);
                            if (!HashOids.TryGetValue(oid, out var hh)) return default;
                            h = hh; break;
                        }
                    case 0xa1:
                        {
                            var (oid, prm) = AlgId(raw, inner[0]);
                            if (oid != "1.2.840.113549.1.1.8" || prm == null) return default;
                            var pe = ReadElem(prm, 0, prm.Length, 0x30);
                            var (hoid, _) = AlgId(prm, pe);
                            if (!HashOids.TryGetValue(hoid, out var mh)) return default;
                            mgfHash = mh; break;
                        }
                    case 0xa2:
                    case 0xa3:
                        {
                            if (inner[0].Tag != 0x02) return default;
                            var v = new BigInteger(raw.AsSpan(inner[0].Start, inner[0].End - inner[0].Start), isUnsigned: true, isBigEndian: true);
                            if (v > (1 << 20)) return default;
                            if (k.Tag == 0xa2) salt = (int)v; else if (v != 1) return default;
                            break;
                        }
                    default: return default;
                }
            }
            return (h, salt, mgfHash == h);
        }
        catch (AttestError) { return default; }
    }

    /// <summary>X509Certificate.verify(publicKey): the certificate's signature under the key (no name or role checks).</summary>
    internal static bool SigOk(AttCert child, CertKey k)
    {
        try
        {
            if (child.SigOid == "1.3.101.112")
            {
                if (k.Type != "ed25519" || k.Ed25519 == null) return false;
                var v = new Ed25519Signer();
                v.Init(false, new Ed25519PublicKeyParameters(k.Ed25519, 0));
                v.BlockUpdate(child.RawTbs, 0, child.RawTbs.Length);
                return v.VerifySignature(child.Signature);
            }
            if (child.SigOid == "1.2.840.113549.1.1.10")
            {
                var (h, salt, good) = PssParams(child.SigParams);
                if (k.RsaBc == null || !good) return false;
                var signer = new PssSigner(new RsaEngine(), BcDigest(h), BcDigest(h), salt);
                signer.Init(false, k.RsaBc);
                signer.BlockUpdate(child.RawTbs, 0, child.RawTbs.Length);
                return signer.VerifySignature(child.Signature);
            }
            if (!SigHashes.TryGetValue(child.SigOid, out var hash)) return false;
            var digest = HashOf(hash, child.RawTbs);
            var name = new HashAlgorithmName(hash);
            if (k.Ec != null) return child.SigOid.StartsWith("1.2.840.10045.4.3.", StringComparison.Ordinal) && k.Ec.VerifyHash(digest, child.Signature, DSASignatureFormat.Rfc3279DerSequence);
            if (k.Rsa != null) return child.SigOid.StartsWith("1.2.840.113549.1.1.", StringComparison.Ordinal) && k.Rsa.VerifyHash(digest, child.Signature, name, RSASignaturePadding.Pkcs1);
            return false;
        }
        catch (Exception) { return false; }
    }

    /// <summary>SigOk under the subject key of <paramref name="parent"/> (false when that key cannot be read).</summary>
    internal static bool SigOkBy(AttCert child, AttCert parent)
    {
        try { return SigOk(child, KeyOf(parent)); }
        catch (AttestError) { return false; }
    }

    // ---- certificate names (OpenSSL's multi-line rendering)

    static readonly Dictionary<string, string> DnShortNames = new()
    {
        ["2.5.4.3"] = "CN", ["2.5.4.6"] = "C", ["2.5.4.7"] = "L", ["2.5.4.8"] = "ST", ["2.5.4.10"] = "O", ["2.5.4.11"] = "OU",
        ["2.5.4.5"] = "serialNumber", ["2.5.4.9"] = "street", ["2.5.4.17"] = "postalCode", ["2.5.4.4"] = "SN", ["2.5.4.42"] = "GN",
        ["2.5.4.12"] = "title", ["2.5.4.46"] = "dnQualifier", ["1.2.840.113549.1.9.1"] = "emailAddress",
        ["0.9.2342.19200300.100.1.25"] = "DC", ["0.9.2342.19200300.100.1.1"] = "UID",
    };

    static string EscapeDnValue(string s)
    {
        var sb = new StringBuilder();
        var rs = s.EnumerateRunes().ToList();
        for (int i = 0; i < rs.Count; i++)
        {
            int r = rs[i].Value;
            if (r is ',' or '+' or '"' or '\\' or '<' or '>' or ';') sb.Append('\\').Append(rs[i].ToString());
            else if ((i == 0 && (r == ' ' || r == '#')) || (i == rs.Count - 1 && r == ' ')) sb.Append('\\').Append(rs[i].ToString());
            else if (r < 0x20 || r == 0x7f) sb.Append('\\').Append(r.ToString("X2"));
            else sb.Append(rs[i].ToString());
        }
        return sb.ToString();
    }

    /// <summary>A string attribute value the way an ASN.1 library decodes it (null: an unsupported tag or an invalid character set).</summary>
    static string? AtvString(byte[] b, CertElem v)
    {
        var raw = b.AsSpan(v.Start, v.End - v.Start);
        switch (v.Tag)
        {
            case 0x0c: // UTF8String
                try { return new UTF8Encoding(false, true).GetString(raw); } catch (Exception) { return null; }
            case 0x13: // PrintableString
                foreach (var ch in raw) if (!(ch is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)' ' or (byte)'\'' or (byte)'(' or (byte)')' or (byte)'+' or (byte)',' or (byte)'-' or (byte)'.' or (byte)'/' or (byte)':' or (byte)'=' or (byte)'?')) return null;
                return Encoding.ASCII.GetString(raw);
            case 0x16: // IA5String
                foreach (var ch in raw) if (ch > 127) return null;
                return Encoding.ASCII.GetString(raw);
            case 0x12: // NumericString
                foreach (var ch in raw) if (!(ch is >= (byte)'0' and <= (byte)'9' or (byte)' ')) return null;
                return Encoding.ASCII.GetString(raw);
            case 0x14: return Encoding.Latin1.GetString(raw); // T61String
            case 0x1e: // BMPString
                if (raw.Length % 2 != 0) return null;
                return Encoding.BigEndianUnicode.GetString(raw);
        }
        return null;
    }

    /// <summary>Renders a DER Name the way Node renders a certificate subject / issuer: one "KEY=value" per attribute, in encoded
    /// order, joined by newlines ("" when the Name cannot be decoded).</summary>
    internal static string NameText(byte[] raw)
    {
        try
        {
            var name = ReadElem(raw, 0, raw.Length, 0x30);
            if (name.End != raw.Length) return "";
            var lines = new List<string>();
            foreach (var rdn in Kids(raw, name))
            {
                var parts = new List<string>();
                foreach (var atv in Kids(raw, rdn))
                {
                    var kv = Kids(raw, atv);
                    var key = Dotted(raw, kv[0]);
                    if (DnShortNames.TryGetValue(key, out var sn)) key = sn;
                    var val = AtvString(raw, kv[1]);
                    if (val == null) return "";
                    parts.Add(key + "=" + EscapeDnValue(val));
                }
                lines.Add(string.Join(" + ", parts));
            }
            return string.Join("\n", lines);
        }
        catch (AttestError) { return ""; }
    }
}
