using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Direct kill tests for mutants that only the (heap-hungry) attestation vector replay used to catch. Reasons are the reference's
/// (attest-intel-tdx.ts:496/504/595/611/634/646). Keys and certificates are generated at class load; nothing secret is committed.</summary>
public class K05R2DKillTests
{
    // ---- StoreConformance.OpenN: an Open that throws is reported as "Open: <message>"

    [Fact]
    public void AThrowingOpenFailsTheCheckWithItsMessage()
    {
        var st = new MemoryStateStore();
        int calls = 0;
        // claim-burst opens 1 handle, claim-concurrent's first handle is the 2nd call; the 3rd throws (the mutant would just run on fewer stores)
        var r = StoreConformance.RunStateStore(new StateStoreConformance
        {
            Name = "boom",
            Open = () => Interlocked.Increment(ref calls) <= 2 ? st : throw new InvalidOperationException("boom"),
            Shared = true,
            Handles = 4,
        });
        Assert.Equal("fail", r.StatusOf("claim-concurrent"));
        Assert.Equal("Open: boom", r.Checks.First(c => c.Name == "claim-concurrent").Note);
    }

    // ---- CaveatLang.ReserveMaxUses: the slot loop stops after n slots

    sealed class CountingRefuser : IStateStore
    {
        public int Calls;
        public ClaimResult? Claim(string key, long counter) => new ClaimResult(false);
        public bool ConsumeOnce(string key, long retainUntilMs, long nowMs)
        {
            if (++Calls > 100) throw new InvalidOperationException("slot loop did not stop");
            return false;
        }
    }

    static BoundCaveat[] Uses(long n) => new[] { new BoundCaveat(new JD { ["type"] = "max_uses", ["id"] = "u", ["n"] = IntentJs.OfLong(n), ["until"] = IntentJs.OfLong(100) }, 0, "c") };

    [Fact]
    public void AnExhaustedMaxUsesAsksExactlyNSlots()
    {
        var store = new MemoryStateStore();
        Assert.True(store.ConsumeOnce(CaveatLang.MaxUsesSlotKey("c", "u", 0), 100, 1));
        Assert.True(store.ConsumeOnce(CaveatLang.MaxUsesSlotKey("c", "u", 1), 100, 1));
        Assert.Equal(new UsesVerdict(false, 0, "max_uses 'u' is exhausted"), CaveatLang.ReserveMaxUses(store, Uses(2), 1));
        // slot 2 was never touched
        Assert.True(store.ConsumeOnce(CaveatLang.MaxUsesSlotKey("c", "u", 2), 100, 1));

        var refuser = new CountingRefuser();
        Assert.Equal(new UsesVerdict(false, 0, "max_uses 'u' is exhausted"), CaveatLang.ReserveMaxUses(refuser, Uses(3), 1));
        Assert.Equal(3, refuser.Calls);
    }

    // ---- AttestIntel: PCK chain + genuine quote

    static readonly DateTimeOffset From = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero), To = new(2035, 1, 1, 0, 0, 0, TimeSpan.Zero);
    static readonly long Now = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeMilliseconds();
    static readonly ECDsa RootKey = ECDsa.Create(ECCurve.NamedCurves.nistP384), PckKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), AkKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    static readonly string Mrtd = string.Concat(Enumerable.Repeat("11", 48));

    static byte[] Cat(params byte[][] p) => p.SelectMany(x => x).ToArray();
    static byte[] U16(int v) { var b = new byte[2]; BinaryPrimitives.WriteUInt16LittleEndian(b, (ushort)v); return b; }
    static byte[] U32(int v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)v); return b; }
    static string Pem(byte[] der) => "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n";
    static byte[] P256Sig(ECDsa k, byte[] m) => k.SignHash(SHA256.HashData(m), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    static byte[] Sign(CertificateRequest r, string issuer, ECDsa issuerKey) =>
        r.Create(new X500DistinguishedName(issuer), X509SignatureGenerator.CreateForECDsa(issuerKey), From, To, new byte[] { 1 }).RawData;

    static readonly byte[] RootDer = MakeRoot();
    static byte[] MakeRoot()
    {
        var r = new CertificateRequest("CN=root", RootKey, HashAlgorithmName.SHA384);
        r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return Sign(r, "CN=root", RootKey);
    }

    static byte[] Leaf(params X509Extension[] exts)
    {
        var r = new CertificateRequest("CN=pck", PckKey, HashAlgorithmName.SHA384);
        r.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        foreach (var e in exts) r.CertificateExtensions.Add(e);
        return Sign(r, "CN=root", RootKey);
    }

    // the SGX extension (FMSPC 010203040506, TCB with a PCESVN component) the leaf must carry
    static readonly X509Extension SgxExt = new(new Oid("1.2.840.113741.1.13.1"), Cat(
        new byte[] { 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04, 0x04, 0x06, 1, 2, 3, 4, 5, 6 },
        new byte[] { 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x30, 0x08, 0x30, 0x06, 0x06, 0x01, 17, 0x02, 0x01, 1 }), false);

    static string RootPin => AttestCerts.KeyOf(AttestCerts.ParseDer(RootDer)).SpkiSha256();
    static readonly string GoodChain = Pem(Leaf(SgxExt)) + Pem(RootDer);

    [Fact]
    public void AnUnknownCriticalExtensionOnTheLeafRefusesTheChain()
    {
        Assert.True(AttestIntel.VerifyPckChain(GoodChain, RootPin, Now).Ok);
        var bad = Pem(Leaf(SgxExt, new X509Extension(new Oid("1.2.3.4.5"), new byte[] { 0x05, 0x00 }, true))) + Pem(RootDer);
        var r = AttestIntel.VerifyPckChain(bad, RootPin, Now);
        Assert.False(r.Ok);
        Assert.Equal("PCK chain certificate at depth 0 has an unrecognised critical extension 1.2.3.4.5", r.Reason);
    }

    [Fact]
    public void AMalformedChainCertificateIsAFailClosedReason()
    {
        var r = AttestIntel.VerifyPckChain(Pem(new byte[] { 1, 2, 3, 4 }), RootPin, Now);
        Assert.False(r.Ok);
        Assert.StartsWith("PCK chain X.509 verification error (fail closed): ", r.Reason);
        Assert.True(r.Reason.Length > "PCK chain X.509 verification error (fail closed): ".Length);
    }

    static byte[] Quote(bool qeDebug = false, bool flipTdSig = false, byte rtmr0Fill = 0)
    {
        var hdr = new byte[48];
        hdr[0] = 4; hdr[2] = 2; hdr[4] = 0x81;
        var td = new byte[584];
        Array.Fill(td, (byte)0x11, 136, 48);
        if (rtmr0Fill != 0) Array.Fill(td, rtmr0Fill, 328, 48);
        var q = AkKey.ExportParameters(false).Q;
        var ak = Cat(q.X!, q.Y!);
        var qe = new byte[384];
        if (qeDebug) qe[48] |= 0x02;
        SHA256.HashData(ak).CopyTo(qe, 0x140);
        var pem = Encoding.ASCII.GetBytes(GoodChain);
        var outer = Cat(qe, P256Sig(PckKey, qe), U16(0), U16(5), U32(pem.Length), pem);
        var tdSig = P256Sig(AkKey, Cat(hdr, td));
        if (flipTdSig) tdSig[10] ^= 1;
        var sig = Cat(tdSig, ak, U16(6), U32(outer.Length), outer);
        return Cat(hdr, td, U32(sig.Length), sig);
    }

    static TdxResult Run(byte[] quote, TdxQuotePolicy? pol) => AttestIntel.VerifyGenuineTdxQuote(quote, RootPin, Now, pol, false);

    [Fact]
    public void ABaselineQuoteVerifies()
    {
        var r = Run(Quote(), new TdxQuotePolicy { Mrtds = { Mrtd } });
        Assert.True(r.Ok, r.Reason);
    }

    [Fact]
    public void ADebugQuotingEnclaveIsNamed()
    {
        var r = Run(Quote(qeDebug: true), null);
        Assert.False(r.Ok);
        Assert.Equal("QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)", r.Reason);
    }

    [Fact]
    public void ABadTdQuoteSignatureIsNamed()
    {
        var r = Run(Quote(flipTdSig: true), null);
        Assert.False(r.Ok);
        Assert.Equal("TD quote signature does not verify under the attestation key", r.Reason);
    }

    [Fact]
    public void AnMrtdOutsideTheAllowlistIsNamed()
    {
        var r = Run(Quote(), new TdxQuotePolicy { Mrtds = { string.Concat(Enumerable.Repeat("22", 48)) } });
        Assert.False(r.Ok);
        Assert.Equal("MRTD not in policy allowlist", r.Reason);
    }

    [Fact]
    public void TheRtmr0AllowlistAdmitsAMemberAndRefusesAStranger()
    {
        var q = Quote(rtmr0Fill: 0x33);
        var member = string.Concat(Enumerable.Repeat("33", 48));
        var r1 = Run(q, new TdxQuotePolicy { Rtmrs = { member } });
        Assert.True(r1.Ok, r1.Reason);
        var r2 = Run(q, new TdxQuotePolicy { Rtmrs = { string.Concat(Enumerable.Repeat("44", 48)) } });
        Assert.False(r2.Ok);
        Assert.Equal("RTMR0 not in policy allowlist", r2.Reason);
    }
}
