using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using AtlasPca;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Shared forgers for the Intel PCS collateral kill tests: a small DER/CRL writer and a synthetic Intel PKI (root, PCK CA, PCK leaf, TCB
/// signing certificate), a genuine-shaped TDX quote and signed TCB info / QE identity documents. Keys are generated at class load.</summary>
internal static class K05R3AIntelKit
{
    internal static readonly DateTimeOffset From = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero), To = new(2035, 1, 1, 0, 0, 0, TimeSpan.Zero);

    internal static long Ms(int y, int mo, int d, int h, int mi, int s) => new DateTimeOffset(y, mo, d, h, mi, s, TimeSpan.Zero).ToUnixTimeMilliseconds();

    internal static readonly long Now = Ms(2030, 1, 1, 0, 0, 0);

    // ---- DER

    internal static byte[] Cat(params byte[][] p) => p.SelectMany(x => x).ToArray();

    internal static byte[] Tlv(byte tag, params byte[][] parts)
    {
        var body = parts.SelectMany(x => x).ToArray();
        byte[] hdr = body.Length < 0x80 ? new byte[] { tag, (byte)body.Length }
            : body.Length < 0x100 ? new byte[] { tag, 0x81, (byte)body.Length }
            : new byte[] { tag, 0x82, (byte)(body.Length >> 8), (byte)body.Length };
        return hdr.Concat(body).ToArray();
    }

    internal static byte[] Utc(string s) => Tlv(0x17, Encoding.ASCII.GetBytes(s));
    internal static byte[] Gen(string s) => Tlv(0x18, Encoding.ASCII.GetBytes(s));

    internal static readonly byte[] AlgSha256 = { 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    internal static readonly byte[] Ver = { 0x02, 0x01, 0x01 };
    internal static readonly byte[] EmptySeq = { 0x30, 0x00 };
    internal static readonly byte[] ThisU = Utc("261008212848Z"), NextU = Utc("261107212848Z");

    /// <summary>version, signature algorithm, an empty issuer name, then whatever follows (times, revoked list).</summary>
    internal static byte[][] Items(params byte[][] rest) => new[] { Ver, AlgSha256, EmptySeq }.Concat(rest).ToArray();

    internal static byte[] RevokedOf(params byte[][] serials) =>
        Tlv(0x30, serials.Select(s => Tlv(0x30, Tlv(0x02, s), Utc("261008212848Z"))).ToArray());

    internal static byte[] Crl(ECDsa key, byte[][] tbsItems, byte tbsTag = 0x30, byte sigTag = 0x03, byte[]? sigContent = null, byte[]? extra = null)
    {
        var tbs = Tlv(tbsTag, tbsItems);
        var sig = sigContent ?? Cat(new byte[] { 0 }, key.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        return Tlv(0x30, tbs, AlgSha256, Tlv(sigTag, sig), extra ?? Array.Empty<byte>());
    }

    // ---- PKI

    internal static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    internal static readonly ECDsa RootKey = NewKey(), CaKey = NewKey(), PckKey = NewKey(), AkKey = NewKey(), SignKey = NewKey(), StrangerKey = NewKey();

    internal static byte[] MakeCert(string subject, ECDsa key, string issuer, ECDsa issuerKey, byte serial, bool ca, DateTimeOffset from, DateTimeOffset to, params X509Extension[] exts)
    {
        var r = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        r.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
        if (ca) r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        foreach (var e in exts) r.CertificateExtensions.Add(e);
        return r.Create(new X500DistinguishedName(issuer), X509SignatureGenerator.CreateForECDsa(issuerKey), from, to, new byte[] { serial }).RawData;
    }

    internal static string Pem(byte[] der) => "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n";

    internal static readonly byte[] RootDer = MakeCert("CN=root", RootKey, "CN=root", RootKey, 1, true, From, To);
    internal static readonly byte[] CaDer = MakeCert("CN=ca", CaKey, "CN=root", RootKey, 2, true, From, To);
    internal static readonly byte[] SignDer = MakeCert("CN=tcbsign", SignKey, "CN=root", RootKey, 4, false, From, To);
    internal static string RootPin => PinOf(RootDer);

    internal static string PinOf(byte[] der) => AttestCerts.KeyOf(AttestCerts.ParseDer(der)).SpkiSha256();

    /// <summary>The TCB signing certificate and the pinned root: the issuer chain the collateral carries.</summary>
    internal static readonly string SignChain = Pem(SignDer) + Pem(RootDer);

    /// <summary>A signing certificate that expired before <see cref="Now"/>, under the pinned root.</summary>
    internal static readonly string ExpiredSignChain =
        Pem(MakeCert("CN=tcbsign", SignKey, "CN=root", RootKey, 4, false, From, new DateTimeOffset(2028, 1, 1, 0, 0, 0, TimeSpan.Zero))) + Pem(RootDer);

    /// <summary>A well-formed chain that ends at a different (unpinned) self-signed root.</summary>
    internal static readonly string StrangerChain =
        Pem(MakeCert("CN=tcbsign2", SignKey, "CN=root2", StrangerKey, 8, false, From, To)) + Pem(MakeCert("CN=root2", StrangerKey, "CN=root2", StrangerKey, 9, true, From, To));

    static readonly byte[] OidF = { 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04 };
    static readonly byte[] OidT = { 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02 };

    /// <summary>The Intel SGX extension: FMSPC 010203040506, the 16 SGX TCB components and the PCESVN (all values below 0x80).</summary>
    internal static X509Extension SgxExt(byte[] sgx, byte pcesvn)
    {
        var comps = new List<byte[]>();
        for (int i = 0; i < 16; i++) comps.Add(Tlv(0x30, new byte[] { 0x06, 0x01, (byte)(i + 1) }, Tlv(0x02, new byte[] { sgx[i] })));
        comps.Add(Tlv(0x30, new byte[] { 0x06, 0x01, 17 }, Tlv(0x02, new byte[] { pcesvn })));
        return new X509Extension(new Oid("1.2.840.113741.1.13.1"), Cat(OidF, Tlv(0x04, new byte[] { 1, 2, 3, 4, 5, 6 }), OidT, Tlv(0x30, comps.ToArray())), false);
    }

    internal static byte[] PckLeaf(byte[] sgx, byte pcesvn) => MakeCert("CN=pck", PckKey, "CN=ca", CaKey, 3, false, From, To, SgxExt(sgx, pcesvn));

    // ---- documents

    internal static string Rep(byte v, int n) => string.Concat(Enumerable.Repeat(v.ToString("x2"), n));

    internal static JL Comps(int v) => new(Enumerable.Range(0, 16).Select(_ => (object?)new JD { ["svn"] = v }));

    /// <summary>16 TDX components: the first two are a and b, the rest 0.</summary>
    internal static JL TdxComps(int a, int b)
    {
        var l = Comps(0);
        l[0] = new JD { ["svn"] = a };
        l[1] = new JD { ["svn"] = b };
        return l;
    }

    internal static JD Level(string status, JL? tdx = null, int pcesvn = 11, string[]? adv = null) => new()
    {
        ["tcb"] = new JD { ["sgxtcbcomponents"] = Comps(5), ["pcesvn"] = pcesvn, ["tdxtcbcomponents"] = tdx ?? Comps(0) },
        ["tcbStatus"] = status,
        ["advisoryIDs"] = new JL((adv ?? Array.Empty<string>()).Cast<object?>()),
    };

    internal static JD Ident(string id, byte mrsigner = 0x22, int isvsvn = 2, string[]? adv = null) => new()
    {
        ["id"] = id,
        ["mrsigner"] = Rep(mrsigner, 48),
        ["attributes"] = Rep(0, 8),
        ["attributesMask"] = Rep(0xff, 8),
        ["tcbLevels"] = new JL { new JD { ["tcb"] = new JD { ["isvsvn"] = isvsvn }, ["tcbStatus"] = "UpToDate", ["advisoryIDs"] = new JL((adv ?? Array.Empty<string>()).Cast<object?>()) } },
    };

    internal static JD QeLevel(int isvsvn, string[]? adv = null) => new()
    {
        ["tcb"] = new JD { ["isvsvn"] = isvsvn },
        ["tcbStatus"] = "UpToDate",
        ["advisoryIDs"] = new JL((adv ?? Array.Empty<string>()).Cast<object?>()),
    };

    internal static JD DefaultTcb() => new()
    {
        ["id"] = "TDX",
        ["version"] = 3,
        ["issueDate"] = "2029-12-01T00:00:00Z",
        ["nextUpdate"] = "2030-02-01T00:00:00Z",
        ["fmspc"] = "010203040506",
        ["tcbEvaluationDataNumber"] = 7,
        ["tdxModule"] = new JD { ["mrsigner"] = Rep(0x22, 48), ["attributes"] = Rep(0, 8), ["attributesMask"] = Rep(0xff, 8) },
        ["tcbLevels"] = new JL { Level("UpToDate") },
    };

    internal static JD DefaultQe() => new()
    {
        ["id"] = "TD_QE",
        ["version"] = 2,
        ["issueDate"] = "2029-12-01T00:00:00Z",
        ["nextUpdate"] = "2030-02-01T00:00:00Z",
        ["tcbEvaluationDataNumber"] = 7,
        ["miscselect"] = "00000000",
        ["miscselectMask"] = "ffffffff",
        ["attributes"] = Rep(0, 16),
        ["attributesMask"] = Rep(0xff, 16),
        ["mrsigner"] = Rep(0x33, 32),
        ["isvprodid"] = 1,
        ["tcbLevels"] = new JL { QeLevel(3) },
    };

    /// <summary>{"name": body, "signature": hex}: the signature is ECDSA-P256/SHA-256 (r||s) over the exact serialised body.</summary>
    internal static string Doc(string name, JD body, ECDsa? key = null)
    {
        var raw = JsonSerializer.Serialize(body);
        var sig = Convert.ToHexString((key ?? SignKey).SignHash(SHA256.HashData(Encoding.UTF8.GetBytes(raw)), DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        return "{\"" + name + "\":" + raw + ",\"signature\":\"" + sig + "\"}";
    }

    static byte[] U16(int v) { var b = new byte[2]; BinaryPrimitives.WriteUInt16LittleEndian(b, (ushort)v); return b; }
    static byte[] U32(int v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)v); return b; }
    static byte[] P256Sig(ECDsa k, byte[] m) => k.SignHash(SHA256.HashData(m), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    internal static byte[] StdCrl(ECDsa key) => Crl(key, Items(Utc("291201000000Z"), Utc("300201000000Z")));

    /// <summary>Everything one Verify call needs; each field is the honest default and a test overrides what it attacks.</summary>
    internal sealed class Rig
    {
        public byte[] TeeTcb = new byte[16];
        public byte[] PckSgx = Enumerable.Repeat((byte)5, 16).ToArray();
        public byte[] MrSignerSeam = Enumerable.Repeat((byte)0x22, 48).ToArray();
        public byte[] SeamAttrs = new byte[8];
        public byte PckPcesvn = 11;
        public int QeProd = 1, QeSvn = 3;
        public JD Tcb = DefaultTcb(), Qe = DefaultQe();
        public string? TcbChain, QeChain, TcbJson, QeJson, QuoteChain;
        public byte[]? PckCrlDer, RootCrlDer;

        public byte[] QuoteBytes()
        {
            var hdr = new byte[48];
            hdr[0] = 4; hdr[2] = 2; hdr[4] = 0x81;
            var td = new byte[584];
            TeeTcb.CopyTo(td, 0);
            MrSignerSeam.CopyTo(td, 64);
            SeamAttrs.CopyTo(td, 112);
            Array.Fill(td, (byte)0x11, 136, 48);
            var q = AkKey.ExportParameters(false).Q;
            var ak = Cat(q.X!, q.Y!);
            var qe = new byte[384];
            Array.Fill(qe, (byte)0x33, 128, 32);
            qe[256] = (byte)QeProd; qe[257] = (byte)(QeProd >> 8);
            qe[258] = (byte)QeSvn; qe[259] = (byte)(QeSvn >> 8);
            SHA256.HashData(ak).CopyTo(qe, 0x140);
            var pem = Encoding.ASCII.GetBytes(QuoteChain ?? Pem(PckLeaf(PckSgx, PckPcesvn)) + Pem(CaDer) + Pem(RootDer));
            var outer = Cat(qe, P256Sig(PckKey, qe), U16(0), U16(5), U32(pem.Length), pem);
            var sig = Cat(P256Sig(AkKey, Cat(hdr, td)), ak, U16(6), U32(outer.Length), outer);
            return Cat(hdr, td, U32(sig.Length), sig);
        }

        public IntelCollateral Collateral() => new IntelCollateral
        {
            TcbInfoJson = TcbJson ?? Doc("tcbInfo", Tcb),
            TcbInfoChain = TcbChain ?? SignChain,
            QeIdentityJson = QeJson ?? Doc("enclaveIdentity", Qe),
            QeIdentityChain = QeChain ?? SignChain,
            PckCrl = PckCrlDer ?? StdCrl(CaKey),
            RootCrl = RootCrlDer ?? StdCrl(RootKey),
        };
    }
}
