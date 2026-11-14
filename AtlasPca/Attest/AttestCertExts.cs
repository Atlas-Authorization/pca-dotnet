// SPDX-License-Identifier: Apache-2.0
namespace AtlasPca;

/// <summary>The extensions OpenSSL decodes before it links a certificate to its issuer (x509v3_cache_extensions): a repeated or undecodable
/// one, on either certificate, means "not issued". Bytes after a decoded extension value are ignored, as X509V3_EXT_d2i ignores them.
/// shortcut: proxyCertInfo, x400Address, ediPartyName and nameRelativeToCRLIssuer are refused, where OpenSSL decodes them; decode them if a PKI here ever sets one.</summary>
internal static class CertExts
{
    static (string Oid, Action<byte[]> Decode)[] Decoded => new (string Oid, Action<byte[]> Decode)[]
    {
        ("2.5.29.19", BasicConstraints),
        ("2.5.29.15", v => BitString(v, Top(v, 0x03))),
        ("2.16.840.1.113730.1.1", v => BitString(v, Top(v, 0x03))),
        ("2.5.29.37", ExtKeyUsage),
        ("2.5.29.17", v => GeneralNames(v, Top(v, 0x30))),
        ("2.5.29.30", NameConstraints),
        ("2.5.29.31", CrlDistributionPoints),
        ("1.3.6.1.5.5.7.1.14", _ => Need(false)),
    };

    internal static void Check(AttCert c)
    {
        foreach (var (oid, decode) in Decoded)
        {
            var found = c.Exts.Where(e => e.Oid == oid).ToList();
            Need(found.Count < 2);
            if (found.Count == 1) decode(found[0].Value);
        }
    }

    static void Need(bool ok)
    {
        if (!ok) throw new AttestError("certificate extension is malformed");
    }

    static CertElem Top(byte[] v, byte tag) => AttestCerts.ReadElem(v, 0, v.Length, tag);

    /// <summary>Each element's rank must grow: the optional fields of a SEQUENCE, once each and in order; -1 is an unknown tag.</summary>
    static void InOrder(IEnumerable<CertElem> kids, Func<byte, int> rank)
    {
        int last = -1;
        foreach (var k in kids)
        {
            Need(rank(k.Tag) > last);
            last = rank(k.Tag);
        }
    }

    /// <summary>c2i_ibuf: not empty, and the first nine bits not all equal.</summary>
    static void Integer(byte[] b, CertElem e)
    {
        Need(e.End > e.Start);
        if (e.End - e.Start >= 2)
            Need(!(b[e.Start] == 0 && b[e.Start + 1] < 0x80) && !(b[e.Start] == 0xff && b[e.Start + 1] >= 0x80));
    }

    static void BitString(byte[] b, CertElem e) => Need(e.End > e.Start && b[e.Start] <= 7);

    static void BasicConstraints(byte[] v)
    {
        var kids = AttestCerts.Kids(v, Top(v, 0x30));
        InOrder(kids, t => t switch { 0x01 => 0, 0x02 => 1, _ => -1 });
        foreach (var k in kids)
        {
            if (k.Tag == 0x01) Need(k.End - k.Start == 1);
            else
            {
                Integer(v, k);
                Need(v[k.Start] < 0x80); // x509v3_cache_extensions: a negative pathLenConstraint is invalid
            }
        }
    }

    static void ExtKeyUsage(byte[] v)
    {
        foreach (var k in AttestCerts.Kids(v, Top(v, 0x30))) Need(AttestCerts.ValidOid(v, k));
    }

    static void GeneralNames(byte[] b, CertElem e)
    {
        foreach (var g in AttestCerts.Kids(b, e)) GeneralName(b, g);
    }

    internal static void GeneralName(byte[] b, CertElem g)
    {
        switch (g.Tag)
        {
            case 0x81 or 0x82 or 0x86 or 0x87:
                break;
            case 0x88:
                Need(AttestCerts.ValidOid(b, g with { Tag = 0x06 }));
                break;
            case 0xa0:
                var other = AttestCerts.Kids(b, g);
                Need(other.Count == 2 && AttestCerts.ValidOid(b, other[0]) && other[1].Tag == 0xa0 && AttestCerts.Kids(b, other[1]).Count == 1);
                break;
            case 0xa4:
                var name = AttestCerts.ReadElem(b, g.Start, g.End, 0x30);
                Need(name.End == g.End);
                AttestCerts.CheckName(b, name);
                break;
            default:
                Need(false);
                break;
        }
    }

    static void NameConstraints(byte[] v)
    {
        var lists = AttestCerts.Kids(v, Top(v, 0x30));
        InOrder(lists, t => t switch { 0xa0 => 0, 0xa1 => 1, _ => -1 });
        foreach (var list in lists)
            foreach (var subtree in AttestCerts.Kids(v, list))
            {
                Need(subtree.Tag == 0x30);
                var kids = AttestCerts.Kids(v, subtree);
                Need(kids.Count > 0);
                GeneralName(v, kids[0]);
                var limits = kids.Skip(1).ToList();
                InOrder(limits, t => t switch { 0x80 => 0, 0x81 => 1, _ => -1 });
                foreach (var limit in limits) Integer(v, limit);
            }
    }

    static void CrlDistributionPoints(byte[] v)
    {
        foreach (var dp in AttestCerts.Kids(v, Top(v, 0x30)))
        {
            Need(dp.Tag == 0x30);
            var fields = AttestCerts.Kids(v, dp);
            InOrder(fields, t => t switch { 0xa0 => 0, 0x81 => 1, 0xa2 => 2, _ => -1 });
            foreach (var f in fields)
            {
                if (f.Tag == 0x81) BitString(v, f);
                else if (f.Tag == 0xa2) GeneralNames(v, f);
                else
                {
                    var choice = AttestCerts.Kids(v, f);
                    Need(choice.Count == 1 && choice[0].Tag == 0xa0);
                    GeneralNames(v, choice[0]);
                }
            }
        }
    }
}
