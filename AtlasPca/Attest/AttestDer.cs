// Strict DER readers shared by the hardware-attestation chain verifiers (the native counterpart of the strict X.509 helpers and
// the validity reader of @atlasauth/pca). A certificate library verifies signatures and names, but it exposes neither the raw
// extension table in the shape the CA-role rules need nor the validity instants without normalisation, so the rules are enforced
// from a small, strict walk of the certificate's own DER. Messages are the reference's, byte for byte.
using System.Globalization;
using System.Numerics;
using System.Text;

namespace AtlasPca;

/// <summary>A refusal of a malformed or rule-violating input; the message is the reference's reason text.</summary>
internal sealed class AttestError : Exception
{
    public AttestError(string message) : base(message) { }
}

internal readonly record struct DerTlv(byte Tag, int Start, int End);

/// <summary>The CA-role-relevant part of a certificate. PathLen is -1 when absent.</summary>
internal sealed class CertRoleInfo
{
    public bool HasBasicConstraints, Ca, HasKeyUsage, KeyCertSign;
    public int PathLen = -1;
}

/// <summary>One extension of a certificate: the critical flag and the extnValue OCTET STRING content.</summary>
internal sealed record CertExt(bool Critical, byte[] Value);

/// <summary>Extensions in encounter order (the reference iterates a Map).</summary>
internal sealed class ExtTable
{
    public readonly List<string> Oids = new();
    public readonly Dictionary<string, CertExt> Map = new(StringComparer.Ordinal);
    public CertExt? Get(string oid) => Map.TryGetValue(oid, out var e) ? e : null;
}

/// <summary>An epoch-millisecond instant, or not ok (the reference's NaN).</summary>
internal readonly record struct DerInstant(long Ms, bool Ok);

internal static class AttestDer
{
    /// <summary>Reads one definite-length element at <paramref name="off"/> (inside <paramref name="limit"/>). Minimal lengths only, no multi-byte tags.</summary>
    internal static DerTlv ReadTlvStrict(byte[] b, int off, int limit)
    {
        if (off + 2 > limit) throw new AttestError("DER: truncated header");
        byte tag = b[off];
        if ((tag & 0x1f) == 0x1f) throw new AttestError("DER: multi-byte tags are not supported");
        int l = b[off + 1];
        int p = off + 2;
        if ((l & 0x80) != 0)
        {
            int n = l & 0x7f;
            if (n == 0 || n > 3) throw new AttestError("DER: unsupported length form");
            if (p + n > limit) throw new AttestError("DER: truncated length");
            l = 0;
            if (n > 1 && b[p] == 0) throw new AttestError("DER: non-minimal length (leading zero)");
            for (int i = 0; i < n; i++) l = (l << 8) | b[p + i];
            if (l < 0x80) throw new AttestError("DER: non-minimal length (long form below 128)");
            p += n;
        }
        if (p + l > limit) throw new AttestError("DER: element overruns its parent");
        return new DerTlv(tag, p, p + l);
    }

    static readonly byte[] OidBasicConstraints = { 0x55, 0x1d, 0x13 };
    static readonly byte[] OidKeyUsage = { 0x55, 0x1d, 0x0f };

    static bool OidEquals(byte[] b, DerTlv t, byte[] want)
    {
        if (t.Tag != 0x06 || t.End - t.Start != want.Length) return false;
        for (int i = 0; i < want.Length; i++) if (b[t.Start + i] != want[i]) return false;
        return true;
    }

    /// <summary>Reads BasicConstraints and keyUsage of a DER certificate; throws on a malformed or duplicated extension.</summary>
    internal static CertRoleInfo ReadCertRoleInfo(byte[] cert)
    {
        var info = new CertRoleInfo();
        var outer = ReadTlvStrict(cert, 0, cert.Length);
        if (outer.Tag != 0x30) throw new AttestError("certificate is not a DER SEQUENCE");
        if (outer.End != cert.Length) throw new AttestError("trailing bytes after the certificate");
        var tbs = ReadTlvStrict(cert, outer.Start, outer.End);
        if (tbs.Tag != 0x30) throw new AttestError("certificate has no tbsCertificate");
        int p = tbs.Start;
        while (p < tbs.End)
        {
            var el = ReadTlvStrict(cert, p, tbs.End);
            p = el.End;
            if (el.Tag != 0xa3) continue;
            var seq = ReadTlvStrict(cert, el.Start, el.End);
            if (seq.Tag != 0x30) throw new AttestError("extensions is not a SEQUENCE");
            int q = seq.Start;
            while (q < seq.End)
            {
                var ext = ReadTlvStrict(cert, q, seq.End);
                q = ext.End;
                if (ext.Tag != 0x30) throw new AttestError("extension is not a SEQUENCE");
                var id = ReadTlvStrict(cert, ext.Start, ext.End);
                int r = id.End;
                var next = ReadTlvStrict(cert, r, ext.End);
                if (next.Tag == 0x01)
                {
                    r = next.End;
                    next = ReadTlvStrict(cert, r, ext.End);
                }
                if (next.Tag != 0x04) throw new AttestError("extension value is not an OCTET STRING");
                if (OidEquals(cert, id, OidBasicConstraints))
                {
                    if (info.HasBasicConstraints) throw new AttestError("duplicate BasicConstraints extension");
                    info.HasBasicConstraints = true;
                    var bc = ReadTlvStrict(cert, next.Start, next.End);
                    if (bc.Tag != 0x30) throw new AttestError("BasicConstraints is not a SEQUENCE");
                    int c = bc.Start;
                    if (c < bc.End)
                    {
                        var first = ReadTlvStrict(cert, c, bc.End);
                        if (first.Tag == 0x01)
                        {
                            if (first.End - first.Start != 1) throw new AttestError("BasicConstraints cA is not one byte");
                            info.Ca = cert[first.Start] != 0;
                            c = first.End;
                        }
                    }
                    if (c < bc.End)
                    {
                        var pl = ReadTlvStrict(cert, c, bc.End);
                        if (pl.Tag != 0x02 || pl.End - pl.Start < 1 || pl.End - pl.Start > 2 || (cert[pl.Start] & 0x80) != 0)
                            throw new AttestError("BasicConstraints pathLenConstraint malformed");
                        int n = 0;
                        for (int i = pl.Start; i < pl.End; i++) n = (n << 8) | cert[i];
                        info.PathLen = n;
                        c = pl.End;
                    }
                    if (c != bc.End) throw new AttestError("BasicConstraints has trailing data");
                }
                else if (OidEquals(cert, id, OidKeyUsage))
                {
                    if (info.HasKeyUsage) throw new AttestError("duplicate keyUsage extension");
                    info.HasKeyUsage = true;
                    var bs = ReadTlvStrict(cert, next.Start, next.End);
                    if (bs.Tag != 0x03 || bs.End - bs.Start < 2) throw new AttestError("keyUsage is not a BIT STRING");
                    if (cert[bs.Start] > 7) throw new AttestError("keyUsage BIT STRING has more than 7 unused bits");
                    info.KeyCertSign = (cert[bs.Start + 1] & 0x04) != 0;
                }
            }
        }
        return info;
    }

    static string OidToDotted(byte[] b, DerTlv t)
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

    /// <summary>The strict extension table of a tbsCertificate (the DER SEQUENCE including its header), keyed by dotted OID. It fails
    /// closed on a malformed element, a duplicate extension, more than one [3] block, a non-DER critical flag, trailing bytes, or an
    /// empty Extensions block.</summary>
    internal static ExtTable ParseTbsExtensions(byte[] tbsDer)
    {
        var tbs = ReadTlvStrict(tbsDer, 0, tbsDer.Length);
        if (tbs.Tag != 0x30) throw new AttestError("tbsCertificate is not a SEQUENCE");
        if (tbs.End != tbsDer.Length) throw new AttestError("trailing bytes after tbsCertificate");
        var o = new ExtTable();
        bool seen = false;
        int blockEnd = -1;
        int p = tbs.Start;
        while (p < tbs.End)
        {
            var el = ReadTlvStrict(tbsDer, p, tbs.End);
            p = el.End;
            if (el.Tag != 0xa3) continue;
            if (seen) throw new AttestError("duplicate [3] extensions block");
            seen = true;
            blockEnd = el.End;
            var seq = ReadTlvStrict(tbsDer, el.Start, el.End);
            if (seq.Tag != 0x30) throw new AttestError("extensions is not a SEQUENCE");
            if (seq.End != el.End) throw new AttestError("trailing bytes after the Extensions SEQUENCE");
            if (seq.Start == seq.End) throw new AttestError("empty Extensions SEQUENCE");
            int q = seq.Start;
            while (q < seq.End)
            {
                var ext = ReadTlvStrict(tbsDer, q, seq.End);
                q = ext.End;
                if (ext.Tag != 0x30) throw new AttestError("extension is not a SEQUENCE");
                var id = ReadTlvStrict(tbsDer, ext.Start, ext.End);
                var dotted = OidToDotted(tbsDer, id);
                int r = id.End;
                var next = ReadTlvStrict(tbsDer, r, ext.End);
                bool critical = false;
                if (next.Tag == 0x01)
                {
                    if (next.End - next.Start != 1 || tbsDer[next.Start] != 0xff) throw new AttestError($"extension {dotted} has a non-DER critical flag");
                    critical = true;
                    r = next.End;
                    next = ReadTlvStrict(tbsDer, r, ext.End);
                }
                if (next.Tag != 0x04) throw new AttestError($"extension {dotted} value is not an OCTET STRING");
                if (next.End != ext.End) throw new AttestError($"extension {dotted} has trailing bytes");
                if (o.Map.ContainsKey(dotted)) throw new AttestError($"duplicate extension {dotted}");
                o.Oids.Add(dotted);
                o.Map[dotted] = new CertExt(critical, tbsDer[next.Start..next.End]);
            }
        }
        if (seen && blockEnd != tbs.End) throw new AttestError("extensions block is not the last TBS element");
        return o;
    }

    /// <summary>The tbsCertificate bytes (header included) of a DER certificate; trailing bytes are refused.</summary>
    internal static byte[] TbsOfCertificate(byte[] cert)
    {
        var outer = ReadTlvStrict(cert, 0, cert.Length);
        if (outer.Tag != 0x30) throw new AttestError("certificate is not a DER SEQUENCE");
        if (outer.End != cert.Length) throw new AttestError("trailing bytes after the certificate");
        var tbs = ReadTlvStrict(cert, outer.Start, outer.End);
        if (tbs.Tag != 0x30) throw new AttestError("certificate has no tbsCertificate");
        return cert[outer.Start..tbs.End];
    }

    internal static ExtTable ParseCertExtensions(byte[] cert) => ParseTbsExtensions(TbsOfCertificate(cert));

    /// <summary>The only critical extensions the attestation chain verifiers understand.</summary>
    internal static readonly HashSet<string> RecognisedCriticalExtensions = new(StringComparer.Ordinal) { "2.5.29.19", "2.5.29.15" };

    /// <summary>The first critical extension OID the verifier does not recognise (RFC 5280 4.2), or null.</summary>
    internal static string? UnrecognisedCriticalExtension(byte[] cert, ISet<string>? recognised = null)
    {
        recognised ??= RecognisedCriticalExtensions;
        var t = ParseCertExtensions(cert);
        foreach (var oid in t.Oids) if (t.Map[oid].Critical && !recognised.Contains(oid)) return oid;
        return null;
    }

    /// <summary>Enforces the CA roles over an ordered chain (index 0 = leaf ... last = self-signed root). The failure reason, or null.</summary>
    internal static string? CheckChainRoles(IReadOnlyList<byte[]> ordered)
    {
        int n = ordered.Count;
        for (int i = 0; i < n; i++)
        {
            CertRoleInfo info;
            try { info = ReadCertRoleInfo(ordered[i]); }
            catch (AttestError e) { return "certificate extension parse failed: " + e.Message; }
            if (i == 0 && n > 1)
            {
                if (info.Ca) return "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)";
                continue;
            }
            if (i == 0) continue;
            if (!info.HasBasicConstraints) return $"issuer certificate at depth {i} has no BasicConstraints (not a CA)";
            if (!info.Ca) return $"issuer certificate at depth {i} is not a CA (BasicConstraints CA:FALSE)";
            if (info.HasKeyUsage && !info.KeyCertSign) return $"issuer certificate at depth {i} keyUsage lacks keyCertSign";
            if (info.PathLen >= 0 && info.PathLen < i - 1) return $"issuer certificate at depth {i} pathLenConstraint {info.PathLen} is exceeded ({i - 1} intermediate(s) below)";
        }
        return null;
    }

    // ---- validity (read from the certificate's own DER)

    internal static DerTlv TlvAt(byte[] der, int off)
    {
        if (off + 2 > der.Length) throw new AttestError("truncated");
        byte tag = der[off];
        long l = der[off + 1];
        int start = off + 2;
        if ((l & 0x80) != 0)
        {
            int n = (int)(l & 0x7f);
            if (n == 0 || n > 4 || start + n > der.Length) throw new AttestError("bad length");
            l = 0;
            for (int i = 0; i < n; i++) l = l * 256 + der[start + i];
            start += n;
        }
        long end = start + l;
        if (end > der.Length) throw new AttestError("truncated");
        return new DerTlv(tag, start, (int)end);
    }

    static bool AllAsciiDigits(string s) => s.Length > 0 && s.All(c => c is >= '0' and <= '9');

    /// <summary>The strict RFC 5280 Time: tag 0x17 UTCTime YYMMDDHHMMSSZ (YY &gt;= 50 is 19YY) or tag 0x18 GeneralizedTime YYYYMMDDHHMMSSZ,
    /// every field in range, no roll-over.</summary>
    internal static DerInstant ParseDerTime(int tag, string text)
    {
        int y; string rest;
        if (tag == 0x17 && text.Length == 13)
        {
            if (!AllAsciiDigits(text[..12]) || text[12] != 'Z') return default;
            int yy = int.Parse(text[..2], CultureInfo.InvariantCulture);
            y = yy >= 50 ? 1900 + yy : 2000 + yy;
            rest = text[2..];
        }
        else if (tag == 0x18 && text.Length == 15)
        {
            if (!AllAsciiDigits(text[..14]) || text[14] != 'Z') return default;
            y = int.Parse(text[..4], CultureInfo.InvariantCulture);
            rest = text[4..];
        }
        else return default;
        int mon = int.Parse(rest[0..2], CultureInfo.InvariantCulture), day = int.Parse(rest[2..4], CultureInfo.InvariantCulture);
        int h = int.Parse(rest[4..6], CultureInfo.InvariantCulture), mi = int.Parse(rest[6..8], CultureInfo.InvariantCulture), sec = int.Parse(rest[8..10], CultureInfo.InvariantCulture);
        if (mon < 1 || mon > 12 || day < 1 || h > 23 || mi > 59 || sec > 59) return default;
        bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        int dim = mon == 2 ? (leap ? 29 : 28) : mon is 4 or 6 or 9 or 11 ? 30 : 31;
        if (day > dim) return default;
        return new DerInstant(EpochMs(y, mon, day, h, mi, sec), true);
    }

    /// <summary>Date.UTC / Go time.Date: proleptic Gregorian, every field rolls over (a month outside 1..12 carries into the year).</summary>
    internal static long EpochMs(long y, long mon, long day, long h, long mi, long sec)
    {
        long m0 = mon - 1;
        long yq = (m0 >= 0 ? m0 : m0 - 11) / 12;
        y += yq; mon = m0 - yq * 12 + 1;
        // days since 1970-01-01 of the first of the month (Hinnant's days_from_civil)
        long yy = mon <= 2 ? y - 1 : y;
        long era = (yy >= 0 ? yy : yy - 399) / 400;
        long yoe = yy - era * 400;
        long doy = (153 * (mon + (mon > 2 ? -3 : 9)) + 2) / 5;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        long days = era * 146097 + doe - 719468 + (day - 1);
        return ((days * 24 + h) * 60 + mi) * 60_000 + sec * 1000;
    }

    /// <summary>The validity window of a DER certificate (Certificate -> tbsCertificate -> validity); both not ok when malformed.</summary>
    internal static (DerInstant From, DerInstant To) DerValidity(byte[] der)
    {
        try
        {
            var cert = TlvAt(der, 0);
            if (cert.Tag != 0x30) return default;
            var tbs = TlvAt(der, cert.Start);
            if (tbs.Tag != 0x30) return default;
            var el = TlvAt(der, tbs.Start);
            if (el.Tag == 0xa0) el = TlvAt(der, el.End);
            if (el.Tag != 0x02) return default; // serialNumber
            el = TlvAt(der, el.End);
            if (el.Tag != 0x30) return default; // signature
            el = TlvAt(der, el.End);
            if (el.Tag != 0x30) return default; // issuer
            var validity = TlvAt(der, el.End);
            if (validity.Tag != 0x30 || validity.End > tbs.End) return default;
            var nb = TlvAt(der, validity.Start);
            var na = TlvAt(der, nb.End);
            if (na.End != validity.End) return default;
            return (ParseDerTime(nb.Tag, Encoding.Latin1.GetString(der, nb.Start, nb.End - nb.Start)), ParseDerTime(na.Tag, Encoding.Latin1.GetString(der, na.Start, na.End - na.Start)));
        }
        catch (AttestError) { return default; }
    }

    /// <summary>True iff both bounds parse and from - skew &lt;= nowMs &lt;= to + skew (fail closed on an unparseable bound).</summary>
    internal static bool DerValidAt(byte[] der, long nowMs, long skewMs)
    {
        var (vFrom, vTo) = DerValidity(der);
        return vFrom.Ok && vTo.Ok && nowMs + skewMs >= vFrom.Ms && nowMs - skewMs <= vTo.Ms;
    }

    /// <summary><see cref="DerValidAt"/> with a fractional skew (milliseconds).</summary>
    internal static bool DerValidAtF(byte[] der, long nowMs, double skewMs)
    {
        var (vFrom, vTo) = DerValidity(der);
        return vFrom.Ok && vTo.Ok && (double)nowMs + skewMs >= vFrom.Ms && (double)nowMs - skewMs <= vTo.Ms;
    }
}
