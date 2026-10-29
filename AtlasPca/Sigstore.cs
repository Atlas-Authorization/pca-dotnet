// Offline Sigstore bundle verification for build provenance (track K9; port of packages/pca-attest-eat/src/sigstore.ts,
// replayed on conformance/sigstore-vectors.json). There is no .NET Sigstore library: System.Security.Cryptography (ECDSA, RSA,
// X.509), System.Formats.Asn1 (DER) and the BouncyCastle Ed25519 the package already depends on.
using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Math.EC.Rfc8032;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A pinned log. <see cref="V2Name"/> (the host of its base URL) and <see cref="Ed25519Key"/> are set for Rekor v2
/// (signed-note) logs; <see cref="Spki"/> is the ECDSA or RSA key otherwise.</summary>
public sealed record SigstorePinnedLog(byte[] KeyId, byte[]? Spki, bool Rsa, byte[]? Ed25519Key, long Start, long End, string? V2Name);
public sealed record SigstorePinnedCa(IReadOnlyList<X509Certificate2> Chain, long Start, long End);
public sealed record SigstorePinnedRoots(IReadOnlyList<SigstorePinnedLog> Tlogs, IReadOnlyList<SigstorePinnedLog> Ctlogs, IReadOnlyList<SigstorePinnedCa> Cas, IReadOnlyList<SigstorePinnedCa> Tsas);

/// <summary><c>{ok, core, statement}</c> or <c>{ok: false, code, detail}</c>; <see cref="Core"/> holds the shared vector's
/// <c>core</c> members (identity, oidc_issuer, source_*, predicate_type, subjects, signed_time, rekor_log_index, rekor, timestamps).</summary>
public sealed record SigstoreCoreResult(bool Ok, JD? Core, JD? Statement, string? Code, string? Detail);

/// <summary><c>{ok, facts}</c> (the <c>facts</c> of <see cref="ProvenanceGate.Gate"/>) or <c>{ok: false, code, detail}</c>.</summary>
public sealed record SigstoreResult(bool Ok, JD? Facts, string? Code, string? Detail);

/// <summary>
/// Verifies a Sigstore bundle carrying a DSSE in-toto Statement against a pinned <c>trusted_root.json</c>, with no network: every
/// RFC 3161 timestamp and the Rekor v1 SET when present (at least one verified time); one Rekor entry (<c>dsse/0.0.1</c>,
/// <c>intoto/0.0.2</c>, or Rekor v2 <c>hashedrekord/0.0.2</c> over the DSSE PAE); RFC 9162 inclusion to a checkpoint signed by
/// the pinned log (Ed25519 signed note under the base-URL host for v2, ECDSA for v1); the certificate path to a pinned Fulcio CA
/// at every verified time, the code-signing EKU, the embedded SCT when the root lists CT logs; the entry body names this envelope;
/// the DSSE signature; the Fulcio identity; the Statement. <see cref="VerifySigstoreBundle"/> then reads the SLSA v1 predicate.
/// Never throws on a bundle.
/// </summary>
public static class Sigstore
{
    public static readonly IReadOnlyList<string> BundleMediaTypes = new[]
    {
        "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "application/vnd.dev.sigstore.bundle.v0.3+json",
    };
    public const string IntotoPayloadType = "application/vnd.in-toto+json";
    const string OidFulcio = "1.3.6.1.4.1.57264.1.";
    const string OidSctList = "1.3.6.1.4.1.11129.2.4.2";
    const string OidSan = "2.5.29.17";
    const string EkuCodeSigning = "1.3.6.1.5.5.7.3.3";
    const string EkuTimeStamping = "1.3.6.1.5.5.7.3.8";
    const string OidSignedData = "1.2.840.113549.1.7.2";
    const string OidTstInfo = "1.2.840.113549.1.9.16.1.4";
    const string OidContentType = "1.2.840.113549.1.9.3";
    const string OidMessageDigest = "1.2.840.113549.1.9.4";
    static readonly Dictionary<string, string> DigestOids = new() { ["2.16.840.1.101.3.4.2.1"] = "sha256", ["2.16.840.1.101.3.4.2.2"] = "sha384", ["2.16.840.1.101.3.4.2.3"] = "sha512" };
    const long MaxSafe = 9_007_199_254_740_991;

    sealed class Bad : Exception { public Bad(string m) : base(m) { } }

    static JD? Obj(object? o) => o as JD;
    static JD ObjOrEmpty(object? o) => o as JD ?? new JD();
    static JL Arr(object? o) => o as JL ?? new JL();
    static object? At(object? o, string k) => o is JD d && d.TryGetValue(k, out var v) ? v : null;

    static readonly Regex B64Re = new(@"^[A-Za-z0-9+/]*={0,2}\z", RegexOptions.CultureInvariant);
    static byte[] B64(object? s)
    {
        if (s is not string t || !B64Re.IsMatch(t) || t.Length % 4 != 0) throw new Bad("not base64");
        return Convert.FromBase64String(t);
    }

    static long Ms(string s) => DateTimeOffset.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal).ToUnixTimeMilliseconds();
    static (long, long) Validity(object? v)
    {
        if (At(v, "start") is not string s) throw new Bad("validFor.start missing");
        return (Ms(s), At(v, "end") is string e ? Ms(e) : long.MaxValue);
    }

    static HashAlgorithmName HashName(string alg) => alg switch
    {
        "sha256" => HashAlgorithmName.SHA256,
        "sha384" => HashAlgorithmName.SHA384,
        "sha512" => HashAlgorithmName.SHA512,
        _ => throw new Bad("unsupported hash"),
    };
    static byte[] Sha(string alg, params byte[][] parts)
    {
        using var h = IncrementalHash.CreateHash(HashName(alg));
        foreach (var p in parts) h.AppendData(p);
        return h.GetHashAndReset();
    }

    static readonly byte[] Ed25519SpkiPrefix = { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };

    static SigstorePinnedLog? PinnedLog(object? t, bool transparency)
    {
        var pk = Obj(At(t, "publicKey"));
        if (pk == null || Obj(At(t, "logId")) == null) throw new Bad("log entry malformed");
        var der = B64(At(pk, "rawBytes"));
        var keyId = B64(At(At(t, "logId"), "keyId"));
        var (start, end) = Validity(At(pk, "validFor"));
        switch (At(pk, "keyDetails"))
        {
            case "PKIX_ECDSA_P256_SHA_256":
            {
                if (!Sha("sha256", der).AsSpan().SequenceEqual(keyId)) throw new Bad("log id is not the SHA-256 of its key");
                using var k = ECDsa.Create();
                k.ImportSubjectPublicKeyInfo(der, out var n);
                if (n != der.Length) throw new Bad("trailing key bytes");
                return new(keyId, der, false, null, start, end, null);
            }
            case "PKCS1_RSA_PKCS1V5":
            {
                if (transparency) return null;
                using var k = RSA.Create();
                k.ImportRSAPublicKey(der, out _);
                var spki = k.ExportSubjectPublicKeyInfo();
                if (!Sha("sha256", spki).AsSpan().SequenceEqual(keyId)) throw new Bad("log id is not the SHA-256 of its key");
                return new(keyId, spki, true, null, start, end, null);
            }
            case "PKIX_ED25519":
            {
                if (!transparency) return null;
                if (der.Length != 44 || !der.AsSpan(0, 12).SequenceEqual(Ed25519SpkiPrefix)) throw new Bad("not an Ed25519 key");
                var raw = der[12..];
                var name = At(t, "baseUrl") is string u ? new Uri(u).Host : "";
                if (name.Length == 0 || !Sha("sha256", Encoding.UTF8.GetBytes(name + "\n"), new byte[] { 1 }, raw).AsSpan().SequenceEqual(keyId))
                    throw new Bad("log id is not the signed-note key hash of its key");
                return new(keyId, null, false, raw, start, end, name);
            }
            default:
                return null;
        }
    }

#pragma warning disable SYSLIB0057 // net8 has no X509CertificateLoader
    static X509Certificate2 X509(byte[] der) => new(der);
#pragma warning restore SYSLIB0057

    static SigstorePinnedCa PinnedChain(object? c)
    {
        var certs = Arr(At(At(c, "certChain"), "certificates"));
        if (certs.Count == 0) throw new Bad("certificate authority entry malformed");
        var (start, end) = Validity(At(c, "validFor"));
        return new(certs.Select(x => X509(B64(At(x, "rawBytes")))).ToList(), start, end);
    }

    /// <summary>Parse a Sigstore <c>trusted_root.json</c> (v0.1) tree (<see cref="Pca.ParseJson"/>): transparency logs, CT logs,
    /// Fulcio CAs and timestamp authorities. Throws <see cref="ArgumentException"/> on anything malformed. A root with no CT log
    /// does not require SCTs.</summary>
    public static SigstorePinnedRoots ParseTrustedRoot(object? json)
    {
        try
        {
            var j = Obj(json);
            if (j == null || At(j, "mediaType") as string != "application/vnd.dev.sigstore.trustedroot+json;version=0.1") throw new Bad("not a trusted root v0.1");
            var tlogs = Arr(At(j, "tlogs")).Select(t => PinnedLog(t, true)).OfType<SigstorePinnedLog>().ToList();
            var ctlogs = Arr(At(j, "ctlogs")).Select(t => PinnedLog(t, false)).OfType<SigstorePinnedLog>().ToList();
            var cas = Arr(At(j, "certificateAuthorities")).Select(PinnedChain).ToList();
            var tsas = Arr(At(j, "timestampAuthorities")).Select(PinnedChain).ToList();
            if (tlogs.Count == 0 || cas.Count == 0) throw new Bad("a trusted root needs a transparency log and a CA");
            return new(tlogs, ctlogs, cas, tsas);
        }
        catch (Exception e)
        {
            throw new ArgumentException("trusted root malformed: " + e.Message, e);
        }
    }

    // ---- DER (System.Formats.Asn1 for the TLV framing; offsets are kept to rebuild the precertificate TBS) ----

    readonly record struct Tlv(int Tag, int Start, int Body, int End);

    static Tlv T(byte[] b, int off, int limit = -1)
    {
        if (limit < 0) limit = b.Length;
        if (off + 2 > limit) throw new Bad("DER truncated");
        int tag = b[off];
        if ((tag & 0x1f) == 0x1f) throw new Bad("DER multi-byte tag");
        AsnDecoder.ReadEncodedValue(b.AsSpan(off, limit - off), AsnEncodingRules.DER, out var co, out var cl, out _);
        return new(tag, off, off + co, off + co + cl);
    }

    static List<Tlv> Kids(byte[] b, Tlv t)
    {
        var o = new List<Tlv>();
        for (int p = t.Body; p < t.End;)
        {
            var c = T(b, p, t.End);
            o.Add(c);
            p = c.End;
        }
        return o;
    }

    static string Oid(byte[] b, Tlv t)
    {
        if (t.Tag != 0x06) throw new Bad("not an OID");
        return AsnDecoder.ReadObjectIdentifier(b.AsSpan(t.Start, t.End - t.Start), AsnEncodingRules.DER, out _);
    }

    static byte[] Cat(params byte[][] parts)
    {
        var o = new byte[parts.Sum(p => p.Length)];
        int i = 0;
        foreach (var p in parts) { p.CopyTo(o, i); i += p.Length; }
        return o;
    }

    static byte[] Enc(int tag, byte[] content)
    {
        int n = content.Length;
        byte[] len = n < 0x80 ? new[] { (byte)n } : n < 0x100 ? new byte[] { 0x81, (byte)n } : n < 0x10000 ? new byte[] { 0x82, (byte)(n >> 8), (byte)n } : new byte[] { 0x83, (byte)(n >> 16), (byte)(n >> 8), (byte)n };
        return Cat(new[] { (byte)tag }, len, content);
    }

    sealed record Ext(string OidText, byte[] Value, Tlv Tlv);
    sealed record ParsedCert(byte[] Der, List<Tlv> TbsKids, Tlv ExtsWrapper, List<Ext> Exts)
    {
        public Ext? Find(string oid) => Exts.FirstOrDefault(e => e.OidText == oid);
    }

    static ParsedCert ParseCert(byte[] der)
    {
        var cert = T(der, 0);
        if (cert.Tag != 0x30 || cert.End != der.Length) throw new Bad("certificate is not one SEQUENCE");
        var tbs = Kids(der, cert)[0];
        if (tbs.Tag != 0x30) throw new Bad("no TBSCertificate");
        var tbsKids = Kids(der, tbs);
        var w = tbsKids.FirstOrDefault(k => k.Tag == 0xa3);
        if (w.Tag != 0xa3) throw new Bad("no extensions");
        var seq = Kids(der, w)[0];
        if (seq.Tag != 0x30) throw new Bad("extensions malformed");
        var seen = new HashSet<string>();
        var exts = new List<Ext>();
        foreach (var e in Kids(der, seq))
        {
            var parts = Kids(der, e);
            var oct = parts[^1];
            if (oct.Tag != 0x04) throw new Bad("extension value is not an OCTET STRING");
            var oid = Oid(der, parts[0]);
            if (!seen.Add(oid)) throw new Bad("duplicate extension " + oid);
            exts.Add(new(oid, der[oct.Body..oct.End], e));
        }
        return new(der, tbsKids, w, exts);
    }

    static readonly UTF8Encoding StrictUtf8 = new(false, true);
    static string Utf8Strict(byte[] b)
    {
        string s;
        try { s = StrictUtf8.GetString(b); }
        catch (DecoderFallbackException) { throw new Bad("not UTF-8"); }
        return s.StartsWith('﻿') ? s[1..] : s; // TextDecoder drops a leading BOM
    }

    /// <summary>Fulcio extension <c>.1.n</c>: raw UTF-8 for n &lt;= 6, a DER UTF8String for n &gt;= 8.</summary>
    static string? FulcioExt(ParsedCert c, int n)
    {
        var e = c.Find(OidFulcio + n);
        if (e == null) return null;
        if (n <= 6) return Utf8Strict(e.Value);
        var t = T(e.Value, 0);
        if (t.Tag != 0x0c || t.End != e.Value.Length) throw new Bad($"extension .1.{n} is not a DER UTF8String");
        return Utf8Strict(e.Value[t.Body..t.End]);
    }

    /// <summary>Exactly one SAN, a URI or an email.</summary>
    static string SanIdentity(ParsedCert c)
    {
        var e = c.Find(OidSan) ?? throw new Bad("no subjectAltName");
        var seq = T(e.Value, 0);
        var names = Kids(e.Value, seq);
        if (seq.Tag != 0x30 || names.Count != 1) throw new Bad("subjectAltName must hold exactly one name");
        var n = names[0];
        if (n.Tag != 0x86 && n.Tag != 0x81) throw new Bad("subjectAltName must be a URI or an email");
        return Utf8Strict(e.Value[n.Body..n.End]);
    }

    // ---- crypto helpers ----

    /// <summary>ECDSA (DER signature) or RSA PKCS#1 v1.5 over <paramref name="data"/> with <paramref name="hash"/>, by the SPKI key type.</summary>
    static bool SigOk(string hash, byte[]? spki, byte[] data, byte[] sig)
    {
        try
        {
            if (spki == null) return false;
            var keyAlg = Oid(spki, Kids(spki, Kids(spki, T(spki, 0))[0])[0]);
            if (keyAlg == "1.2.840.10045.2.1")
            {
                using var ec = ECDsa.Create();
                ec.ImportSubjectPublicKeyInfo(spki, out _);
                return ec.VerifyData(data, sig, HashName(hash), DSASignatureFormat.Rfc3279DerSequence);
            }
            if (keyAlg == "1.2.840.113549.1.1.1")
            {
                using var r = RSA.Create();
                r.ImportSubjectPublicKeyInfo(spki, out _);
                return r.VerifyData(data, sig, HashName(hash), RSASignaturePadding.Pkcs1);
            }
            return false;
        }
        catch (Exception) { return false; }
    }

    static bool LogSigOk(SigstorePinnedLog log, byte[] data, byte[] sig)
    {
        if (log.Ed25519Key == null) return SigOk("sha256", log.Spki, data, sig);
        try { return sig.Length == Ed25519.SignatureSize && Ed25519.Verify(sig, 0, log.Ed25519Key, 0, data, 0, data.Length); }
        catch (Exception) { return false; }
    }

    static long UnixMs(DateTime d) => new DateTimeOffset(d.ToUniversalTime()).ToUnixTimeMilliseconds();
    static bool Inside(X509Certificate2 c, long at) => UnixMs(c.NotBefore) <= at && at <= UnixMs(c.NotAfter);
    static bool IsCa(X509Certificate2 c) => c.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()?.CertificateAuthority == true;
    static bool HasEku(X509Certificate2 c, string eku) =>
        c.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault() is { } x && x.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == eku);

    /// <summary>The certificate signature of <paramref name="c"/> under the key of <paramref name="up"/>: ECDSA, RSA PKCS#1 v1.5 or Ed25519.</summary>
    static bool CertSigOk(X509Certificate2 c, X509Certificate2 up)
    {
        try
        {
            var der = c.RawData;
            var k = Kids(der, T(der, 0));
            var tbs = der[k[0].Start..k[0].End];
            var alg = Oid(der, Kids(der, k[1])[0]);
            if (k[2].Tag != 0x03 || der[k[2].Body] != 0) return false;
            var sig = der[(k[2].Body + 1)..k[2].End];
            var spki = up.PublicKey.ExportSubjectPublicKeyInfo();
            switch (alg)
            {
                case "1.2.840.10045.4.3.2": case "1.2.840.113549.1.1.11": return SigOk("sha256", spki, tbs, sig);
                case "1.2.840.10045.4.3.3": case "1.2.840.113549.1.1.12": return SigOk("sha384", spki, tbs, sig);
                case "1.2.840.10045.4.3.4": case "1.2.840.113549.1.1.13": return SigOk("sha512", spki, tbs, sig);
                case "1.3.101.112":
                    return spki.Length == 44 && spki.AsSpan(0, 12).SequenceEqual(Ed25519SpkiPrefix) && sig.Length == Ed25519.SignatureSize
                        && Ed25519.Verify(sig, 0, spki[12..], 0, tbs, 0, tbs.Length);
                default: return false;
            }
        }
        catch (Exception) { return false; }
    }

    /// <summary><paramref name="c"/> names <paramref name="up"/> as issuer (and <paramref name="up"/> may sign certificates) and carries its signature.</summary>
    static bool IssuedBy(X509Certificate2 c, X509Certificate2 up)
    {
        if (!c.IssuerName.RawData.AsSpan().SequenceEqual(up.SubjectName.RawData) || !AkidOk(c, up)) return false;
        if (up.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault() is { } ku && (ku.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0) return false;
        return CertSigOk(c, up);
    }

    /// <summary>OpenSSL X509_check_akid: when <paramref name="c"/> has an AKI keyIdentifier and <paramref name="up"/> a SKI, they must be equal; malformed = not issued.</summary>
    static bool AkidOk(X509Certificate2 c, X509Certificate2 up)
    {
        try
        {
            // by OID, not OfType: the typed AKI wrapper is not guaranteed for every runtime's extension factory
            var akiExt = c.Extensions["2.5.29.35"];
            var skiExt = up.Extensions["2.5.29.14"];
            if (akiExt == null || skiExt == null) return true;
            var aki = new X509AuthorityKeyIdentifierExtension(akiExt.RawData, akiExt.Critical).KeyIdentifier;
            var ski = new X509SubjectKeyIdentifierExtension(skiExt, skiExt.Critical).SubjectKeyIdentifierBytes;
            return aki is not { } a || a.Span.SequenceEqual(ski.Span);
        }
        catch (CryptographicException) { return false; }
    }

    /// <summary>Chain (leaf first, self-signed root last): issuer links, signatures, CA flags; every certificate valid at <paramref name="at"/>.</summary>
    static bool ChainOk(IReadOnlyList<X509Certificate2> chain, long at)
    {
        for (int i = 0; i < chain.Count; i++)
        {
            var c = chain[i];
            var up = i + 1 < chain.Count ? chain[i + 1] : c;
            if (!IssuedBy(c, up) || !Inside(c, at)) return false;
            if (i > 0 && !IsCa(c)) return false;
        }
        return true;
    }

    // ---- SCT (RFC 6962 3.2) ----

    static int U16(byte[] b, int o) => (b[o] << 8) | b[o + 1];

    static string? VerifySct(ParsedCert leaf, X509Certificate2 issuer, SigstorePinnedRoots roots)
    {
        var e = leaf.Find(OidSctList);
        if (e == null) return "no embedded SCT";
        var outer = T(e.Value, 0);
        if (outer.Tag != 0x04) return "SCT list is not an OCTET STRING";
        var list = e.Value[outer.Body..outer.End];
        if (list.Length < 2 || U16(list, 0) != list.Length - 2) return "SCT list length";
        var der = leaf.Der;
        var extSeq = Kids(der, leaf.ExtsWrapper)[0];
        var kept = Cat(Kids(der, extSeq).Where(k => k.Start != e.Tlv.Start).Select(k => der[k.Start..k.End]).ToArray());
        var tbs = Enc(0x30, Cat(leaf.TbsKids.Select(k => k == leaf.ExtsWrapper ? Enc(0xa3, Enc(0x30, kept)) : der[k.Start..k.End]).ToArray()));
        var issuerKeyHash = Sha("sha256", issuer.PublicKey.ExportSubjectPublicKeyInfo());
        var why = "no SCT from a pinned CT log";
        for (int o = 2; o < list.Length;)
        {
            if (o + 2 > list.Length) return "SCT truncated";
            int n = U16(list, o);
            if (o + 2 + n > list.Length || n < 47) return "SCT truncated";
            var s = list[(o + 2)..(o + 2 + n)];
            o += 2 + n;
            if (s[0] != 0) continue;
            var logId = s[1..33];
            var ts = (long)System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(s.AsSpan(33, 8));
            int extLen = U16(s, 41);
            if (43 + extLen > s.Length) return "SCT truncated";
            var ext = s[43..(43 + extLen)];
            int p = 43 + extLen;
            if (p + 4 > s.Length) return "SCT truncated";
            int hashAlg = s[p], sigAlg = s[p + 1], sigLen = U16(s, p + 2);
            if (p + 4 + sigLen != s.Length) return "SCT malformed";
            var sig = s[(p + 4)..];
            var log = roots.Ctlogs.FirstOrDefault(l => l.KeyId.AsSpan().SequenceEqual(logId));
            if (log == null) continue;
            if (hashAlg != 4 || (sigAlg != 3 && sigAlg != 1)) { why = "SCT is not SHA-256 with ECDSA or RSA"; continue; }
            if (ts < log.Start || ts > log.End) { why = "SCT log key not valid at its timestamp"; continue; }
            var head = new byte[12];
            Array.Copy(s, 33, head, 2, 8); // v1, certificate_timestamp, timestamp
            head[11] = 1; // precert_entry
            var signed = Cat(head, issuerKeyHash, new[] { (byte)(tbs.Length >> 16), (byte)(tbs.Length >> 8), (byte)tbs.Length }, tbs, new[] { (byte)(ext.Length >> 8), (byte)ext.Length }, ext);
            if (SigOk("sha256", log.Spki, signed, sig)) return null;
            why = "SCT signature invalid";
        }
        return why;
    }

    // ---- RFC 3161 timestamps ----

    static string DigestOf(byte[] b, Tlv t) => DigestOids.TryGetValue(Oid(b, Kids(b, t)[0]), out var a) ? a : throw new Bad("unsupported digest algorithm");

    static readonly Regex GenTimeRe = new(@"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z\z", RegexOptions.CultureInvariant);
    static long GeneralizedTime(byte[] b, Tlv t)
    {
        if (t.Tag != 0x18) throw new Bad("genTime is not a GeneralizedTime");
        var m = GenTimeRe.Match(Encoding.Latin1.GetString(b, t.Body, t.End - t.Body));
        if (!m.Success) throw new Bad("genTime malformed");
        int G(int i) => int.Parse(m.Groups[i].Value, CultureInfo.InvariantCulture);
        long ms = new DateTimeOffset(G(1), G(2), G(3), G(4), G(5), G(6), TimeSpan.Zero).ToUnixTimeMilliseconds();
        // the reference's floor(Number("0.<frac>") * 1000), in the same double arithmetic
        return m.Groups[7].Success ? ms + (long)Math.Floor(double.Parse("0." + m.Groups[7].Value, CultureInfo.InvariantCulture) * 1000) : ms;
    }

    /// <summary>Verify an RFC 3161 TimeStampResp (or bare TimeStampToken) over <paramref name="data"/> (the raw signature bytes):
    /// CMS SignedData with TSTInfo content, messageImprint = hash of the data, signed attributes carrying the content type and the
    /// TSTInfo digest, the signature over the DER SET of signed attributes under the leaf of a pinned TSA whose chain and validFor
    /// cover genTime, with the timeStamping EKU. Returns genTime (unix ms); throws otherwise.</summary>
    public static long VerifyRfc3161(byte[] token, byte[] data, IReadOnlyList<SigstorePinnedCa> tsas)
    {
        var ci = T(token, 0);
        if (ci.End != token.Length || ci.Tag != 0x30) throw new Bad("timestamp is not one SEQUENCE");
        var parts = Kids(token, ci);
        if (parts.Count > 0 && parts[0].Tag == 0x30 && parts[0].End - parts[0].Body >= 3 && token[Kids(token, parts[0])[0].Start] == 0x02)
        {
            var st = Kids(token, parts[0])[0];
            var status = token[st.Body..st.End];
            if (!(status.Length == 1 && (status[0] == 0 || status[0] == 1))) throw new Bad("timestamp status is not granted");
            if (parts.Count < 2) throw new Bad("no timeStampToken");
            ci = parts[1];
            parts = Kids(token, ci);
        }
        if (parts.Count < 2 || Oid(token, parts[0]) != OidSignedData || parts[1].Tag != 0xa0) throw new Bad("not CMS SignedData");
        var sdk = Kids(token, Kids(token, parts[1])[0]);
        var encap = sdk.Where((k, i) => i > 1 && k.Tag == 0x30).Select(k => (Tlv?)k).FirstOrDefault() ?? throw new Bad("no encapsulated content");
        var ek = Kids(token, encap);
        if (ek.Count < 2 || Oid(token, ek[0]) != OidTstInfo || ek[1].Tag != 0xa0) throw new Bad("content is not TSTInfo");
        var octet = Kids(token, ek[1])[0];
        if (octet.Tag != 0x04) throw new Bad("TSTInfo is not an OCTET STRING");
        var tstBytes = token[octet.Body..octet.End];
        var tk = Kids(tstBytes, T(tstBytes, 0));
        var mi = Kids(tstBytes, tk[2]);
        var miAlg = DigestOf(tstBytes, mi[0]);
        if (!Sha(miAlg, data).AsSpan().SequenceEqual(tstBytes.AsSpan(mi[1].Body, mi[1].End - mi[1].Body))) throw new Bad("messageImprint is not the hash of the signature");
        var genTime = GeneralizedTime(tstBytes, tk[4]);
        var signerInfos = sdk[^1];
        if (signerInfos.Tag != 0x31) throw new Bad("no signerInfos");
        var sis = Kids(token, signerInfos);
        if (sis.Count != 1) throw new Bad("exactly one SignerInfo is required");
        var si = Kids(token, sis[0]);
        var dAlg = DigestOf(token, si[2]);
        var attrs = si[3];
        if (attrs.Tag != 0xa0) throw new Bad("signed attributes are required");
        bool ctOk = false, mdOk = false;
        foreach (var a in Kids(token, attrs))
        {
            var av = Kids(token, a);
            var vals = Kids(token, av[1]);
            var o = Oid(token, av[0]);
            if (vals.Count != 1) throw new Bad("an attribute must have one value");
            if (o == OidContentType) ctOk = Oid(token, vals[0]) == OidTstInfo;
            if (o == OidMessageDigest) mdOk = Sha(dAlg, tstBytes).AsSpan().SequenceEqual(token.AsSpan(vals[0].Body, vals[0].End - vals[0].Body));
        }
        if (!ctOk || !mdOk) throw new Bad("signed attributes do not commit to the TSTInfo");
        var signedAttrs = Cat(new byte[] { 0x31 }, token[(attrs.Start + 1)..attrs.End]);
        var sigT = si[5];
        if (sigT.Tag != 0x04) throw new Bad("signature is not an OCTET STRING");
        var sig = token[sigT.Body..sigT.End];
        foreach (var tsa in tsas)
        {
            if (genTime < tsa.Start || genTime > tsa.End) continue;
            var leaf = tsa.Chain[0];
            if (!HasEku(leaf, EkuTimeStamping)) continue;
            if (!SigOk(dAlg, leaf.PublicKey.ExportSubjectPublicKeyInfo(), signedAttrs, sig)) continue;
            if (!ChainOk(tsa.Chain, genTime)) continue;
            return genTime;
        }
        throw new Bad("no pinned timestamp authority signed it (valid at its time)");
    }

    // ---- Rekor ----

    static readonly Regex SizeRe = new(@"^[1-9][0-9]*\z", RegexOptions.CultureInvariant);
    static readonly Regex NoteSigRe = new("^— (\\S+) ([A-Za-z0-9+/=]+)\\z", RegexOptions.CultureInvariant);

    /// <summary>Signed-note checkpoint: origin, size, root, a blank line, then <c>— &lt;name&gt; &lt;b64(hint4 || sig)&gt;</c> lines. Null when good.</summary>
    static string? VerifyCheckpoint(string text, SigstorePinnedLog log, long size, byte[] root)
    {
        int cut = text.IndexOf("\n\n", StringComparison.Ordinal);
        if (cut < 0) return "checkpoint has no signature block";
        var body = text[..(cut + 1)];
        var lines = body.Split('\n');
        if (lines.Length < 4 || lines[0].Length == 0) return "checkpoint body too short or without an origin";
        if (!SizeRe.IsMatch(lines[1]) || BigInteger.Parse(lines[1], CultureInfo.InvariantCulture) != size) return "checkpoint size differs from the proof";
        if (!B64(lines[2]).AsSpan().SequenceEqual(root)) return "checkpoint root differs from the proof";
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        foreach (var l in text[(cut + 2)..].Split('\n'))
        {
            var m = NoteSigRe.Match(l);
            if (!m.Success) continue;
            var raw = B64(m.Groups[2].Value);
            if (raw.Length < 5 || !raw.AsSpan(0, 4).SequenceEqual(log.KeyId.AsSpan(0, 4))) continue;
            if (log.V2Name != null && m.Groups[1].Value != log.V2Name) continue;
            if (LogSigOk(log, bodyBytes, raw[4..])) return null;
        }
        return "no checkpoint signature by the pinned log key";
    }

    static readonly Regex DecRe = new(@"^(0|[1-9][0-9]{0,15})\z", RegexOptions.CultureInvariant);
    static long DecInt(object? v)
    {
        if (v is not string s || !DecRe.IsMatch(s)) throw new Bad("not a decimal integer string");
        var n = long.Parse(s, CultureInfo.InvariantCulture);
        if (n > MaxSafe) throw new Bad("integer out of range");
        return n;
    }

    /// <summary>DSSE PAE (secure-systems-lab/dsse protocol.md).</summary>
    public static byte[] DssePae(string payloadType, byte[] payload)
    {
        var t = Encoding.UTF8.GetBytes(payloadType);
        return Cat(Encoding.UTF8.GetBytes($"DSSEv1 {t.Length} "), t, Encoding.UTF8.GetBytes($" {payload.Length} "), payload);
    }

    static string? LeafHashAlg(X509Certificate2 c)
    {
        using var k = c.GetECDsaPublicKey();
        return k?.KeySize switch { 256 => "sha256", 384 => "sha384", _ => null };
    }

    static readonly Regex PemRe = new("^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?\\z", RegexOptions.CultureInvariant);
    static byte[] PemDer(string pem)
    {
        var m = PemRe.Match(pem);
        return m.Success ? B64(m.Groups[1].Value.Replace("\n", "")) : Array.Empty<byte>();
    }

    static SigstoreCoreResult No(string code, string detail) => new(false, null, null, code, detail);

    /// <summary>Verify a Sigstore bundle (a <see cref="Pca.ParseJson"/> tree) carrying a DSSE in-toto statement against pinned
    /// roots. Never throws; every refusal has the reference's code and a detail.</summary>
    public static SigstoreCoreResult VerifySigstoreBundleCore(object? bundle, SigstorePinnedRoots? roots)
    {
        var stage = "malformed";
        try
        {
            var b = Obj(bundle);
            var vm = Obj(At(b, "verificationMaterial"));
            if (b == null || roots == null || vm == null) return No("malformed", "not a bundle");
            var mt = At(b, "mediaType") as string;
            if (mt == null || !BundleMediaTypes.Contains(mt)) return No("media_type", "unsupported media type " + mt);
            var v03 = mt != BundleMediaTypes[0];
            var certRaw = v03 ? At(At(vm, "certificate"), "rawBytes") : At(Arr(At(At(vm, "x509CertificateChain"), "certificates")).FirstOrDefault(), "rawBytes");
            if (certRaw == null) return No("not_keyless", "no Fulcio certificate (public-key bundles are not supported)");
            var env = Obj(At(b, "dsseEnvelope"));
            if (env == null || b.ContainsKey("messageSignature")) return No("envelope", "not a DSSE bundle");
            if (At(env, "payloadType") as string != IntotoPayloadType) return No("envelope", "payloadType is not application/vnd.in-toto+json");
            if (At(env, "signatures") is not JL sigs0 || sigs0.Count != 1 || Obj(sigs0[0]) == null) return No("envelope", "a DSSE envelope must carry exactly one signature");
            var payload = B64(At(env, "payload"));
            var dsseSig = B64(At(sigs0[0], "sig"));
            var pae = DssePae(IntotoPayloadType, payload);
            stage = "cert_parse";
            var leafDer = B64(certRaw);
            using var leaf = X509(leafDer);
            var pc = ParseCert(leafDer);
            var alg = LeafHashAlg(leaf);

            // ---- the log entry and its log
            stage = "tlog_count";
            var entries = Arr(At(vm, "tlogEntries"));
            if (entries.Count != 1 || Obj(entries[0]) == null) return No("tlog_count", "exactly one transparency log entry is required");
            var t = Obj(entries[0])!;
            stage = "tlog_kind";
            var kvo = Obj(At(t, "kindVersion"));
            var kv = kvo != null ? $"{Str(At(kvo, "kind"))}/{Str(At(kvo, "version"))}" : "";
            if (kv is not ("dsse/0.0.1" or "intoto/0.0.2" or "hashedrekord/0.0.2")) return No("tlog_kind", "unsupported entry " + kv);
            var v2 = kv == "hashedrekord/0.0.2";
            stage = "tlog_key";
            var keyId = B64(At(At(t, "logId"), "keyId"));
            var log = roots.Tlogs.FirstOrDefault(l => l.KeyId.AsSpan().SequenceEqual(keyId));
            if (log == null) return No("tlog_key", "the entry names a log the verifier did not pin");
            if (v2 != (log.V2Name != null)) return No("tlog_key", "the entry type does not match the log version");
            var logIndex = DecInt(At(t, "logIndex"));
            var body = B64(At(t, "canonicalizedBody"));

            // ---- time first: every RFC 3161 timestamp must verify; a Rekor v1 SET must verify when present
            stage = "tsa";
            var times = new List<long>();
            foreach (var ts in Arr(At(At(vm, "timestampVerificationData"), "rfc3161Timestamps"))) times.Add(VerifyRfc3161(B64(At(ts, "signedTimestamp")), dsseSig, roots.Tsas));
            var tsaCount = times.Count;
            var set = false;
            if (!v2 && Obj(At(t, "inclusionPromise")) != null)
            {
                stage = "tlog_set";
                var integrated = DecInt(At(t, "integratedTime"));
                // canonicalizedBody passed B64() above, so it needs no JSON escaping
                var setMsg = $"{{\"body\":\"{At(t, "canonicalizedBody")}\",\"integratedTime\":{integrated},\"logID\":\"{Convert.ToHexString(keyId).ToLowerInvariant()}\",\"logIndex\":{logIndex}}}";
                if (!LogSigOk(log, Encoding.UTF8.GetBytes(setMsg), B64(At(At(t, "inclusionPromise"), "signedEntryTimestamp")))) return No("tlog_set", "signed entry timestamp invalid");
                times.Add(integrated * 1000);
                set = true;
            }
            if (times.Count == 0) return No("no_verified_time", "no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp");
            if (times.Any(w => w < log.Start || w > log.End)) return No("tlog_key", "the log key was not valid at a signing time");

            // ---- inclusion
            stage = "tlog_inclusion";
            var ip = Obj(At(t, "inclusionProof"));
            if (ip == null || At(ip, "hashes") is not JL hashes || Obj(At(ip, "checkpoint")) == null) return No("tlog_inclusion", "no inclusion proof");
            var root = B64(At(ip, "rootHash"));
            var size = DecInt(At(ip, "treeSize"));
            if (!ProvenanceGate.VerifyRfc9162Inclusion(ProvenanceGate.Rfc9162LeafHash(body), DecInt(At(ip, "logIndex")), size, hashes.Select(B64).ToList(), root))
                return No("tlog_inclusion", "the inclusion proof does not lead to the root");
            stage = "tlog_checkpoint";
            var cpe = VerifyCheckpoint(Str(At(At(ip, "checkpoint"), "envelope")), log, size, root);
            if (cpe != null) return No("tlog_checkpoint", cpe);

            // ---- certificate path at every verified time (hybrid model), CT
            stage = "cert_chain";
            X509Certificate2? issuer = null;
            foreach (var ca in roots.Cas)
            {
                if (times.Any(w => w < ca.Start || w > ca.End)) continue;
                var first = ca.Chain[0];
                if (!IssuedBy(leaf, first)) continue;
                if (times.All(w => ChainOk(ca.Chain, w)) && ca.Chain.All(IsCa)) { issuer = first; break; }
            }
            if (issuer == null) return No("cert_chain", "no pinned CA issued the certificate, valid at every signing time");
            if (IsCa(leaf)) return No("cert_chain", "the leaf is a CA certificate");
            if (!times.All(w => Inside(leaf, w))) return No("cert_time", "the certificate was not valid at a signing time");
            if (!HasEku(leaf, EkuCodeSigning)) return No("cert_eku", "the certificate lacks the code-signing EKU");
            if (roots.Ctlogs.Count > 0)
            {
                stage = "sct";
                var sct = VerifySct(pc, issuer, roots);
                if (sct != null) return No("sct", sct);
            }

            // ---- the entry body names this envelope
            stage = "tlog_body";
            var eb = ObjOrEmpty(Pca.ParseJson(Encoding.UTF8.GetString(body)));
            var spec = ObjOrEmpty(At(eb, "spec"));
            if ($"{Str(At(eb, "kind"))}/{Str(At(eb, "apiVersion"))}" != kv) return No("tlog_body", "the entry body is not the kind the bundle names");
            var payloadSha = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
            if (kv == "dsse/0.0.1")
            {
                var ph = ObjOrEmpty(At(spec, "payloadHash"));
                if (At(ph, "algorithm") as string != "sha256" || At(ph, "value") as string != payloadSha) return No("tlog_body", "the entry names another payload");
                var sigs = Arr(At(spec, "signatures"));
                if (sigs.Count != 1 || Obj(sigs[0]) == null) return No("tlog_body", "the entry must name exactly one signature");
                if (!B64(At(sigs[0], "signature")).AsSpan().SequenceEqual(dsseSig)) return No("tlog_body", "the entry names another signature");
                if (!PemDer(Encoding.UTF8.GetString(B64(At(sigs[0], "verifier")))).AsSpan().SequenceEqual(leafDer)) return No("tlog_body", "the entry names another certificate");
            }
            else if (kv == "intoto/0.0.2")
            {
                // Rekor intoto 0.0.2 stores the envelope signature and payload base64 twice, and the key as base64 PEM
                var c = ObjOrEmpty(At(spec, "content"));
                var ph = ObjOrEmpty(At(c, "payloadHash"));
                if (At(ph, "algorithm") as string != "sha256" || At(ph, "value") as string != payloadSha) return No("tlog_body", "the entry names another payload");
                var sigs = Arr(At(At(c, "envelope"), "signatures"));
                if (sigs.Count != 1 || Obj(sigs[0]) == null) return No("tlog_body", "the entry must name exactly one signature");
                if (!B64(Encoding.Latin1.GetString(B64(At(sigs[0], "sig")))).AsSpan().SequenceEqual(dsseSig)) return No("tlog_body", "the entry names another signature");
                if (!PemDer(Encoding.UTF8.GetString(B64(At(sigs[0], "publicKey")))).AsSpan().SequenceEqual(leafDer)) return No("tlog_body", "the entry names another certificate");
            }
            else
            {
                // Rekor v2 hashedrekord over DSSE: digest = Hash(PAE), content = the envelope signature, verifier = the leaf
                var h = ObjOrEmpty(At(spec, "hashedRekordV002"));
                var data = ObjOrEmpty(At(h, "data"));
                var hashName = (At(data, "algorithm") as string) switch { "SHA2_256" => "sha256", "SHA2_384" => "sha384", "SHA2_512" => "sha512", _ => null };
                if (hashName == null || hashName != alg) return No("tlog_body", "the entry digest algorithm is not the signing key's");
                if (!B64(At(data, "digest")).AsSpan().SequenceEqual(Sha(hashName, pae))) return No("tlog_body", "the entry names another envelope");
                var sg = ObjOrEmpty(At(h, "signature"));
                if (!B64(At(sg, "content")).AsSpan().SequenceEqual(dsseSig)) return No("tlog_body", "the entry names another signature");
                if (!B64(At(At(At(sg, "verifier"), "x509Certificate"), "rawBytes")).AsSpan().SequenceEqual(leafDer)) return No("tlog_body", "the entry names another certificate");
            }

            // ---- DSSE signature
            stage = "signature";
            if (alg == null) return No("signature", "unsupported leaf key type");
            if (!SigOk(alg, leaf.PublicKey.ExportSubjectPublicKeyInfo(), pae, dsseSig)) return No("signature", "DSSE signature invalid");

            // ---- identity
            stage = "identity";
            var identity = SanIdentity(pc);
            var issV2 = FulcioExt(pc, 8);
            var issV1 = FulcioExt(pc, 1);
            if (issV2 != null && issV1 != null && issV2 != issV1) return No("identity", "the two issuer extensions disagree");
            var oidcIssuer = issV2 ?? issV1;
            if (string.IsNullOrEmpty(oidcIssuer)) return No("identity", "no OIDC issuer extension");
            var sourceRepo = FulcioExt(pc, 12);
            var sourceDigest = FulcioExt(pc, 13);
            var sourceRef = FulcioExt(pc, 14);

            // ---- statement
            stage = "statement";
            var st = Obj(Pca.ParseJson(Utf8Strict(payload)));
            if (st == null || At(st, "_type") as string != ProvenanceGate.IntotoStatementV1) return No("statement", "not an in-toto Statement v1");
            if (At(st, "subject") is not JL subj || subj.Count == 0) return No("statement", "no subject");
            var subjects = new JL();
            foreach (var s in subj)
            {
                var d = ObjOrEmpty(At(s, "digest"));
                foreach (var a in new[] { "sha256", "sha512" })
                    if (At(d, a) is string dv) subjects.Add(new JD { ["alg"] = a, ["digest"] = dv });
            }
            if (subjects.Count == 0 || subjects.Count > 64) return No("statement", "no sha256/sha512 subject digest (or more than 64)");
            if (At(st, "predicateType") is not string predicateType) return No("statement", "no predicateType");
            var core = new JD { ["identity"] = identity, ["oidc_issuer"] = oidcIssuer };
            if (sourceRepo != null) core["source_repo"] = sourceRepo;
            if (sourceRef != null) core["source_ref"] = sourceRef;
            if (sourceDigest != null) core["source_digest"] = sourceDigest;
            core["predicate_type"] = predicateType;
            core["subjects"] = subjects;
            core["signed_time"] = (long)Math.Floor(times.Min() / 1000.0);
            core["rekor_log_index"] = logIndex;
            core["rekor"] = v2 ? "v2" : "v1";
            core["timestamps"] = new JD { ["tsa"] = (long)tsaCount, ["set"] = set };
            return new(true, core, st, null, null);
        }
        catch (Exception e)
        {
            return No(stage, "fail closed: " + e.Message);
        }
    }

    /// <summary>JavaScript <c>String(v)</c> for the members compared as text (only strings can match).</summary>
    static string Str(object? v) => v as string ?? (v == null ? "undefined" : "\u0000" + v);

    /// <summary><see cref="VerifySigstoreBundleCore"/>, then the SLSA v1 predicate: the <c>facts</c> <see cref="ProvenanceGate.Gate"/> checks.</summary>
    public static SigstoreResult VerifySigstoreBundle(object? bundle, SigstorePinnedRoots? roots)
    {
        var r = VerifySigstoreBundleCore(bundle, roots);
        if (!r.Ok) return new(false, null, r.Code, r.Detail);
        var st = r.Statement!;
        var c = r.Core!;
        if (At(st, "predicateType") as string != ProvenanceGate.SlsaProvenanceV1) return new(false, null, "predicate", $"predicate {At(st, "predicateType")} is not SLSA provenance v1");
        var pr = ObjOrEmpty(At(st, "predicate"));
        var bd = ObjOrEmpty(At(pr, "buildDefinition"));
        var rd = ObjOrEmpty(At(pr, "runDetails"));
        if (At(bd, "buildType") is not string buildType || At(At(rd, "builder"), "id") is not string builderId || Obj(At(bd, "externalParameters")) == null)
            return new(false, null, "predicate", "buildType, externalParameters and builder.id are required (SLSA Build L1)");
        var dep0 = Obj(Arr(At(bd, "resolvedDependencies")).FirstOrDefault());
        var f = new JD
        {
            ["v"] = 1L,
            ["predicate_type"] = ProvenanceGate.SlsaProvenanceV1,
            ["build_type"] = buildType,
            ["builder_id"] = builderId,
            ["subjects"] = c["subjects"],
            ["identity"] = c["identity"],
            ["oidc_issuer"] = c["oidc_issuer"],
        };
        foreach (var k in new[] { "source_repo", "source_ref", "source_digest" }) if (c.ContainsKey(k)) f[k] = c[k];
        if (At(dep0, "uri") is string uri)
        {
            var ps = new JD { ["uri"] = uri };
            if (At(At(dep0, "digest"), "gitCommit") is string gc) ps["git_commit"] = gc;
            f["provenance_source"] = ps;
        }
        f["integrated_time"] = c["signed_time"];
        f["rekor_log_index"] = c["rekor_log_index"];
        return new(true, f, null, null);
    }
}
