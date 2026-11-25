using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Spiffe;

/// <summary>A SPIFFE validation / parse failure with a stable <see cref="Code"/> (e.g. <c>malformed_spiffe_id</c>).</summary>
public sealed class SpiffeError : Exception
{
    public string Code { get; }
    public SpiffeError(string code, string message) : base(message) { Code = code; }
}

/// <summary>The X.509 facts the SVID rules need.</summary>
public sealed class CertFacts
{
    public bool BasicConstraintsPresent, IsCa, KeyUsagePresent, DigitalSignature, KeyCertSign, CrlSign;
    /// <summary>pathLenConstraint, or null when absent (a JavaScript number: precision is lost above 2^53, as in the reference).</summary>
    public double? PathLen;
    public readonly List<string> UriSans = new();
    public readonly List<string> UnknownCritical = new();

    public D ToJson() => new()
    {
        ["basicConstraintsPresent"] = BasicConstraintsPresent,
        ["isCa"] = IsCa,
        ["pathLen"] = PathLen is double p ? new Num(AtlasPca.Js.JsJson.NumberToString(p)) : null,
        ["keyUsagePresent"] = KeyUsagePresent,
        ["digitalSignature"] = DigitalSignature,
        ["keyCertSign"] = KeyCertSign,
        ["crlSign"] = CrlSign,
        ["uriSans"] = new L(UriSans.Select(x => (object?)x)),
        ["unknownCritical"] = new L(UnknownCritical.Select(x => (object?)x)),
    };
}

/// <summary>Minimal, bounds-checked DER reader for the X.509 extensions the SPIFFE X.509-SVID rules depend on (basicConstraints, keyUsage,
/// subjectAltName) plus the list of critical extensions. No cryptography. Malformed DER throws <see cref="ArgumentException"/>.</summary>
public static class SpiffeDer
{
    sealed record Tlv(int Tag, int Start, int End);

    static Tlv ReadTlv(byte[] buf, int off, int limit)
    {
        if ((long)off + 2 > limit) throw new ArgumentException("der: truncated header");
        int tag = buf[off];
        if ((tag & 0x1f) == 0x1f) throw new ArgumentException("der: high-tag-number form is not supported");
        long len = buf[off + 1];
        long p = off + 2;
        if ((len & 0x80) != 0)
        {
            int n = (int)(len & 0x7f);
            if (n == 0 || n > 4) throw new ArgumentException("der: unsupported length form");
            if (p + n > limit) throw new ArgumentException("der: truncated length");
            len = 0;
            for (int i = 0; i < n; i++) len = len * 256 + buf[(int)p + i];
            p += n;
        }
        if (p + len > limit) throw new ArgumentException("der: content exceeds container");
        return new Tlv(tag, (int)p, (int)(p + len));
    }

    static List<Tlv> Children(byte[] buf, Tlv parent)
    {
        var o = new List<Tlv>();
        int off = parent.Start;
        while (off < parent.End)
        {
            var t = ReadTlv(buf, off, parent.End);
            o.Add(t);
            off = t.End;
        }
        return o;
    }

    /// <summary><c>der[i]</c> as JavaScript reads it: -1 (undefined) past the end.</summary>
    static int At(byte[] der, int i) => i >= 0 && i < der.Length ? der[i] : -1;

    static string Hex(byte[] buf, Tlv t) => Convert.ToHexString(buf, t.Start, t.End - t.Start).ToLowerInvariant();

    const string OidKeyUsage = "551d0f", OidSan = "551d11", OidBasicConstraints = "551d13";
    static readonly HashSet<string> KnownCritical = new() { OidKeyUsage, OidSan, OidBasicConstraints, "551d25", "551d0e", "551d23" };

    /// <summary>Read the X.509 facts the SVID rules need from a DER certificate. Throws <see cref="ArgumentException"/> on malformed DER.</summary>
    public static CertFacts ReadCertFacts(byte[] der)
    {
        var cert = ReadTlv(der, 0, der.Length);
        if (cert.Tag != 0x30 || cert.End != der.Length) throw new ArgumentException("der: certificate is not a single SEQUENCE");
        var top = Children(der, cert);
        var tbs = top.Count == 0 ? null : top[0];
        if (tbs == null || tbs.Tag != 0x30) throw new ArgumentException("der: missing tbsCertificate");
        Tlv? extWrap = null;
        foreach (var f in Children(der, tbs)) if (f.Tag == 0xa3) { extWrap = f; break; }
        var facts = new CertFacts();
        if (extWrap == null) return facts;
        var wrapKids = Children(der, extWrap);
        var extSeq = wrapKids.Count == 0 ? null : wrapKids[0];
        if (extSeq == null || extSeq.Tag != 0x30) throw new ArgumentException("der: malformed extensions");
        var seen = new HashSet<string>();
        foreach (var ext in Children(der, extSeq))
        {
            var parts = Children(der, ext);
            var oidT = parts.Count == 0 ? null : parts[0];
            if (oidT == null || oidT.Tag != 0x06) throw new ArgumentException("der: malformed extension");
            var oid = Hex(der, oidT);
            if (!seen.Add(oid)) throw new ArgumentException("der: duplicate extension");
            bool critical = parts.Count == 3 && parts[1].Tag == 0x01 && At(der, parts[1].Start) == 0xff;
            var valueT = parts[^1];
            if (valueT.Tag != 0x04) throw new ArgumentException("der: malformed extension value");
            if (critical && !KnownCritical.Contains(oid)) facts.UnknownCritical.Add(oid);
            var inner = ReadTlv(der, valueT.Start, valueT.End);
            if (oid == OidBasicConstraints)
            {
                facts.BasicConstraintsPresent = true;
                foreach (var c in Children(der, inner))
                {
                    if (c.Tag == 0x01) facts.IsCa = At(der, c.Start) == 0xff;
                    else if (c.Tag == 0x02)
                    {
                        double n = 0;
                        for (int i = c.Start; i < c.End; i++) n = n * 256 + der[i];
                        facts.PathLen = n;
                    }
                }
            }
            else if (oid == OidKeyUsage)
            {
                if (inner.Tag != 0x03 || inner.End - inner.Start < 2) throw new ArgumentException("der: malformed keyUsage");
                int b0 = der[inner.Start + 1];
                facts.KeyUsagePresent = true;
                facts.DigitalSignature = (b0 & 0x80) != 0;
                facts.KeyCertSign = (b0 & 0x04) != 0;
                facts.CrlSign = (b0 & 0x02) != 0;
            }
            else if (oid == OidSan)
            {
                foreach (var gn in Children(der, inner))
                    if (gn.Tag == 0x86) facts.UriSans.Add(Encoding.Latin1.GetString(der, gn.Start, gn.End - gn.Start));
            }
        }
        return facts;
    }
}
