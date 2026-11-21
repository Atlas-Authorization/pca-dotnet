using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using K = AtlasPca.Corpus.Tests.K05R3AIntelKit;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Kill tests for the parsing half of AttestIntelCollateral: the wire form, the lenient DER reader, the CRL reader (attest-intel-collateral.ts
/// tlv/derTime/parseCrl/verifyCrl), the signed-JSON slicer and the ISO date parser. Every message is the reference's.</summary>
public class K05R3AIntelCollateralParseTests
{
    // ---- the wire form and the defaults

    [Fact]
    public void ADefaultCollateralHasEmptyFields()
    {
        var d = new IntelCollateral();
        Assert.Equal("", d.TcbInfoJson);
        Assert.Equal("", d.TcbInfoChain);
        Assert.Equal("", d.QeIdentityJson);
        Assert.Equal("", d.QeIdentityChain);
        Assert.Empty(d.PckCrl);
        Assert.Empty(d.RootCrl);
    }

    [Fact]
    public void AMissingWireMemberIsEmptyNeverNull()
    {
        var c = IntelCollateral.FromWire(new JD());
        Assert.Equal("", c.TcbInfoJson);
        Assert.Equal("", c.TcbInfoChain);
        Assert.Equal("", c.QeIdentityJson);
        Assert.Equal("", c.QeIdentityChain);
        Assert.Empty(c.PckCrl);
        Assert.Empty(c.RootCrl);

        var w = IntelCollateral.FromWire(new JD
        {
            ["tcbInfoJson"] = "a", ["tcbInfoIssuerChainPem"] = "b", ["qeIdentityJson"] = "c", ["qeIdentityIssuerChainPem"] = "d",
            ["pckCrlDer"] = "AQID", ["rootCrlDer"] = "BAUG",
        });
        Assert.Equal("a", w.TcbInfoJson);
        Assert.Equal("b", w.TcbInfoChain);
        Assert.Equal("c", w.QeIdentityJson);
        Assert.Equal("d", w.QeIdentityChain);
        Assert.Equal(new byte[] { 1, 2, 3 }, w.PckCrl);
        Assert.Equal(new byte[] { 4, 5, 6 }, w.RootCrl);
    }

    // ---- the lenient TLV reader

    static string TlvErr(byte[] b, int off, int limit) => Assert.Throws<AttestError>(() => AttestIntelCollateral.TlvLenient(b, off, limit)).Message;

    [Fact]
    public void TheLenientTlvHeaderNeedsTwoBytes()
    {
        Assert.Equal("DER truncated", TlvErr(new byte[] { 0x30 }, 0, 1));
        Assert.Equal("DER truncated", TlvErr(new byte[] { 0x04, 0x00 }, 1, 2));
        // exactly two bytes remain: a complete empty element
        Assert.Equal(new DerTlv(0x04, 2, 2), AttestIntelCollateral.TlvLenient(new byte[] { 0x04, 0x00 }, 0, 2));
        Assert.Equal(new DerTlv(0x04, 2, 3), AttestIntelCollateral.TlvLenient(new byte[] { 0x04, 0x01, 0xaa }, 0, 3));
    }

    [Fact]
    public void TheLenientTlvLengthForm()
    {
        Assert.Equal("DER bad length", TlvErr(new byte[] { 0x30, 0x80 }, 0, 2));
        Assert.Equal("DER bad length", TlvErr(new byte[] { 0x30, 0x85, 0, 0, 0, 0, 0 }, 0, 7));
        Assert.Equal("DER bad length", TlvErr(new byte[] { 0x30, 0x82, 0x00 }, 0, 3));
        // four length octets are accepted, and a length octet that ends exactly at the limit is in range
        Assert.Equal(new DerTlv(0x30, 6, 6), AttestIntelCollateral.TlvLenient(new byte[] { 0x30, 0x84, 0, 0, 0, 0 }, 0, 6));
        Assert.Equal(new DerTlv(0x30, 3, 3), AttestIntelCollateral.TlvLenient(new byte[] { 0x30, 0x81, 0x00 }, 0, 3));
        Assert.Equal("DER overrun", TlvErr(new byte[] { 0x04, 0x05, 0x00 }, 0, 3));
    }

    // ---- the CRL reader

    static ParsedCrl Parse(byte[] der) => AttestIntelCollateral.ParseCrl(der);
    static string ParseErr(byte[] der) => Assert.Throws<AttestError>(() => AttestIntelCollateral.ParseCrl(der)).Message;

    [Fact]
    public void AGoodCrlIsReadInFull()
    {
        var der = K.Crl(K.RootKey, K.Items(K.ThisU, K.NextU, K.RevokedOf(new byte[] { 0x00, 0xAB }, new byte[] { 0x07 })), sigContent: new byte[] { 0x00, 1, 2, 3 });
        var crl = Parse(der);
        Assert.Equal(K.Ms(2026, 10, 8, 21, 28, 48), crl.ThisUpdate);
        Assert.Equal(K.Ms(2026, 11, 7, 21, 28, 48), crl.NextUpdate);
        Assert.True(crl.HasNext);
        Assert.Equal(new[] { "7", "ab" }, crl.Revoked.OrderBy(x => x, StringComparer.Ordinal).ToArray());
        Assert.Equal(new byte[] { 1, 2, 3 }, crl.SigDer);
        // the TBS is the whole first element, header included
        Assert.Equal(0x30, crl.Tbs[0]);
        Assert.Equal(K.Tlv(0x30, K.Items(K.ThisU, K.NextU, K.RevokedOf(new byte[] { 0x00, 0xAB }, new byte[] { 0x07 }))), crl.Tbs);
    }

    [Fact]
    public void AnEmptySignatureBitStringIsAnEmptySignature()
    {
        Assert.Empty(Parse(K.Crl(K.RootKey, K.Items(K.ThisU, K.NextU), sigContent: Array.Empty<byte>())).SigDer);
        Assert.Empty(Parse(K.Crl(K.RootKey, K.Items(K.ThisU, K.NextU), sigContent: new byte[] { 0x00 })).SigDer);
    }

    [Fact]
    public void ACrlWithoutNextUpdateIsRefusedWhereverTheTbsEnds()
    {
        // the TBS ends right after thisUpdate
        Assert.Equal("CRL: missing nextUpdate", ParseErr(K.Crl(K.RootKey, K.Items(K.ThisU))));
        // the revoked list directly after thisUpdate and no nextUpdate
        Assert.Equal("CRL: missing nextUpdate", ParseErr(K.Crl(K.RootKey, K.Items(K.ThisU, K.RevokedOf(new byte[] { 5 })))));
    }

    [Fact]
    public void TheCrlStructureRefusals()
    {
        Assert.Equal("CRL: bad TBSCertList", ParseErr(K.Crl(K.RootKey, K.Items(K.ThisU, K.NextU), tbsTag: 0x31)));
        Assert.Equal("CRL: bad signature", ParseErr(K.Crl(K.RootKey, K.Items(K.ThisU, K.NextU), sigTag: 0x04)));
        // a BIT STRING that is not the last element of the outer SEQUENCE
        Assert.Equal("CRL: bad signature", ParseErr(K.Crl(K.RootKey, K.Items(K.ThisU, K.NextU), extra: new byte[] { 0x05, 0x00 })));
        var badIssuer = new[] { K.Ver, K.AlgSha256, new byte[] { 0x31, 0x00 }, K.ThisU, K.NextU };
        Assert.Equal("CRL: bad issuer", ParseErr(K.Crl(K.RootKey, badIssuer)));
        var badEntry = K.Items(K.ThisU, K.NextU, K.Tlv(0x30, K.Tlv(0x30, K.Tlv(0x04, new byte[] { 1 }))));
        Assert.Equal("CRL: bad revoked entry", ParseErr(K.Crl(K.RootKey, badEntry)));
    }

    [Fact]
    public void AGeneralizedTimeNextUpdateIsRead()
    {
        var crl = Parse(K.Crl(K.RootKey, K.Items(K.ThisU, K.Gen("20261107212848Z"))));
        Assert.True(crl.HasNext);
        Assert.Equal(K.Ms(2026, 11, 7, 21, 28, 48), crl.NextUpdate);
    }

    [Fact]
    public void TheTimeTextIsParsedStrictly()
    {
        Assert.Equal("bad UTCTime", ParseErr(K.Crl(K.RootKey, K.Items(K.Utc("xx261008212848Z"), K.NextU))));
        Assert.Equal("bad UTCTime", ParseErr(K.Crl(K.RootKey, K.Items(K.Utc("2610082128Z"), K.NextU))));
        Assert.Equal("bad GeneralizedTime", ParseErr(K.Crl(K.RootKey, K.Items(K.Gen("2026"), K.NextU))));
        Assert.Equal("bad GeneralizedTime", ParseErr(K.Crl(K.RootKey, K.Items(K.Gen("20261008212848Zxx"), K.NextU))));
        Assert.Equal("not a DER time", ParseErr(K.Crl(K.RootKey, K.Items(K.Tlv(0x04, new byte[] { 1 }), K.NextU))));
    }

    [Fact]
    public void ATwoDigitYearPivotsAtFifty()
    {
        long Utc(string s) => Parse(K.Crl(K.RootKey, K.Items(K.Utc(s), K.NextU))).ThisUpdate;
        Assert.Equal(K.Ms(1950, 1, 1, 0, 0, 0), Utc("500101000000Z"));
        Assert.Equal(K.Ms(2049, 12, 31, 23, 59, 59), Utc("491231235959Z"));
        Assert.Equal(K.Ms(1999, 1, 1, 0, 0, 0), Utc("990101000000Z"));
        Assert.Equal(K.Ms(2000, 1, 1, 0, 0, 0), Utc("000101000000Z"));
    }

    [Fact]
    public void AGeneralizedYearBelowOneHundredMeansNineteenYy()
    {
        // Date.UTC(0..99, ...) is 1900 + year; year 100 is year 100
        long Gen(string s) => Parse(K.Crl(K.RootKey, K.Items(K.Gen(s), K.NextU))).ThisUpdate;
        Assert.Equal(K.Ms(1950, 1, 1, 0, 0, 0), Gen("00500101000000Z"));
        Assert.Equal(K.Ms(1900, 1, 1, 0, 0, 0), Gen("00000101000000Z"));
        Assert.Equal(K.Ms(1999, 1, 1, 0, 0, 0), Gen("00990101000000Z"));
        Assert.Equal(K.Ms(100, 1, 1, 0, 0, 0), Gen("01000101000000Z"));
        Assert.Equal(0L, Gen("19700101000000Z"));
    }

    // ---- CRL signature and time checks

    [Fact]
    public void ACrlSignatureOkNeedsAUsableKey()
    {
        var msg = new byte[] { 1, 2, 3 };
        using var ec = K.NewKey();
        var sig = ec.SignData(msg, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.True(AttestIntelCollateral.CrlSigOk(msg, sig, new CertKey { Ec = ec }));
        // a key of no known kind, and a primitive that throws, refuse
        Assert.False(AttestIntelCollateral.CrlSigOk(msg, sig, new CertKey()));
        var dead = K.NewKey();
        dead.Dispose();
        Assert.False(AttestIntelCollateral.CrlSigOk(msg, sig, new CertKey { Ec = dead }));
    }

    [Fact]
    public void ACrlIsCurrentFromThisUpdateThroughNextUpdateInclusive()
    {
        var der = K.Crl(K.RootKey, K.Items(K.ThisU, K.NextU, K.RevokedOf(new byte[] { 9 })));
        var key = new CertKey { Ec = K.RootKey };
        long thisU = K.Ms(2026, 10, 8, 21, 28, 48), nextU = K.Ms(2026, 11, 7, 21, 28, 48);

        var at = AttestIntelCollateral.VerifyCrl(der, key, thisU);
        Assert.Equal("", at.Why);
        Assert.Contains("9", at.Revoked!);
        Assert.Equal("", AttestIntelCollateral.VerifyCrl(der, key, nextU).Why);
        Assert.Equal("", AttestIntelCollateral.VerifyCrl(der, key, thisU + 1).Why);
        Assert.Equal("CRL thisUpdate is in the future", AttestIntelCollateral.VerifyCrl(der, key, thisU - 1).Why);
        Assert.Equal("CRL is stale (nextUpdate passed)", AttestIntelCollateral.VerifyCrl(der, key, nextU + 1).Why);
        Assert.Null(AttestIntelCollateral.VerifyCrl(der, key, nextU + 1).Revoked);
    }

    [Fact]
    public void ACrlUnderTheWrongIssuerOrUnparsedIsNamed()
    {
        var der = K.Crl(K.RootKey, K.Items(K.ThisU, K.NextU));
        long mid = K.Ms(2026, 10, 20, 0, 0, 0);
        Assert.Equal("CRL signature does not verify under the issuer", AttestIntelCollateral.VerifyCrl(der, new CertKey { Ec = K.StrangerKey }, mid).Why);
        Assert.Equal("CRL parse failed: DER truncated", AttestIntelCollateral.VerifyCrl(new byte[] { 0x30 }, new CertKey { Ec = K.RootKey }, mid).Why);
    }

    // ---- the signed-JSON slicer

    static string? Raw(string text, string name) => AttestIntelCollateral.RawJsonObject(text, name);

    [Fact]
    public void TheSlicerReadsOnlyAWellFormedLeadingMember()
    {
        Assert.Equal("{}", Raw(" \t{ \"a\" \n: \r{}}", "a"));
        Assert.Equal("{\"b\":1}", Raw("{\"a\":{\"b\":1},\"signature\":\"x\"}", "a"));
        Assert.Null(Raw("", "a"));
        Assert.Null(Raw("   ", "a"));
        Assert.Null(Raw("x\"a\":{}", "a"));
        Assert.Null(Raw("{\"a\"", "a"));
        Assert.Null(Raw("{\"a\"x{}}", "a"));
        Assert.Null(Raw("{\"a\":", "a"));
        Assert.Null(Raw("{\"a\":x{}}", "a"));
        Assert.Null(Raw("{\"a\":{\"b\":1", "a"));
        Assert.Null(Raw("{\"b\":{}}", "a"));
    }

    [Fact]
    public void BracesInsideStringsAndEscapesDoNotCloseTheObject()
    {
        Assert.Equal("{\"k\":\"}\"}", Raw("{\"a\":{\"k\":\"}\"}}", "a"));
        Assert.Equal("{\"k\":\"x\\\"}y\"}", Raw("{\"a\":{\"k\":\"x\\\"}y\"}}", "a"));
        Assert.Equal("{\"k\":{\"m\":1}}", Raw("{\"a\":{\"k\":{\"m\":1}}}", "a"));
    }

    // ---- the signed document

    [Fact]
    public void AKeyThatIsNotEcNeverVerifiesASignature()
    {
        var doc = "{\"tcbInfo\":{\"a\":1},\"signature\":\"" + new string('0', 128) + "\"}";
        Assert.Equal("tcbInfo signature does not verify under the TCB Signing certificate", AttestIntelCollateral.VerifySignedJson(doc, "tcbInfo", new CertKey()).Why);

        var dead = K.NewKey();
        dead.Dispose();
        Assert.Equal("tcbInfo signature does not verify under the TCB Signing certificate", AttestIntelCollateral.VerifySignedJson(doc, "tcbInfo", new CertKey { Ec = dead }).Why);
    }

    [Fact]
    public void ASignatureThatIsMissingOrNotHexIsNamed()
    {
        Assert.Equal("tcbInfo signature missing or malformed", AttestIntelCollateral.VerifySignedJson("{\"tcbInfo\":{\"a\":1}}", "tcbInfo", new CertKey()).Why);
        Assert.Equal("tcbInfo signature missing or malformed", AttestIntelCollateral.VerifySignedJson("{\"tcbInfo\":{\"a\":1},\"signature\":\"" + new string('0', 127) + "\"}", "tcbInfo", new CertKey()).Why);
        Assert.Equal("tcbInfo signature missing or malformed", AttestIntelCollateral.VerifySignedJson("{\"tcbInfo\":{\"a\":1},\"signature\":7}", "tcbInfo", new CertKey()).Why);
        Assert.Equal("tcbInfo not found / malformed", AttestIntelCollateral.VerifySignedJson("{\"x\":{\"a\":1}}", "tcbInfo", new CertKey()).Why);
    }

    // ---- ISO-8601 dates (Date.parse forms)

    [Fact]
    public void EveryIsoFormTheDocumentsUseIsParsed()
    {
        long day = K.Ms(2026, 1, 1, 0, 0, 0);
        Assert.Equal(day + 123, AttestIntelCollateral.JsDateParse("2026-01-01T00:00:00.123Z"));
        Assert.Equal(day + 100, AttestIntelCollateral.JsDateParse("2026-01-01T00:00:00.1Z"));
        Assert.Equal(day + 123, AttestIntelCollateral.JsDateParse("2026-01-01T00:00:00.1234567Z"));
        Assert.Equal(day + 123, AttestIntelCollateral.JsDateParse("2026-01-01T00:00:00.123456789Z"));
        Assert.Equal(day + 123, AttestIntelCollateral.JsDateParse("2026-01-01T00:00:00.123456789012Z"));
        Assert.Equal(day, AttestIntelCollateral.JsDateParse("2026-01-01T00:00:00Z"));
        Assert.Equal(day, AttestIntelCollateral.JsDateParse("2026-01-01T00:00Z"));
        Assert.Equal(day, AttestIntelCollateral.JsDateParse("2026-01-01"));
        Assert.Null(AttestIntelCollateral.JsDateParse("01/01/2026"));
        Assert.Null(AttestIntelCollateral.JsDateParse(""));
    }
}
