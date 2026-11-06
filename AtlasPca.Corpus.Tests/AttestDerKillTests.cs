using System.Text;
using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The strict DER readers against the reference (packages/pca/src/x509-strict.ts and x509-validity.ts): exact messages, both sides of
/// every condition and the boundary of every comparison, on small hand-built elements.</summary>
public class AttestDerKillTests
{
    const string PathLenBad = "BasicConstraints pathLenConstraint malformed";

    static string Why(Action a)
    {
        try { a(); }
        catch (Exception e) { return e.Message; }
        return "";
    }

    static byte[] B(params byte[] b) => b;

    static byte[] T(byte tag, params byte[][] parts)
    {
        var body = parts.SelectMany(x => x).ToArray();
        return (body.Length < 0x80 ? new[] { tag, (byte)body.Length } : new[] { tag, (byte)0x82, (byte)(body.Length >> 8), (byte)body.Length }).Concat(body).ToArray();
    }

    static byte[] Tbs(params byte[][] exts) => T(0x30, T(0xa3, T(0x30, exts)));
    static byte[] Cert(params byte[][] exts) => T(0x30, Tbs(exts));
    static byte[] Ext(byte[] id, byte[] value) => T(0x30, id, T(0x04, value));
    static byte[] BcCert(params byte[][] kids) => Cert(Ext(T(0x06, B(0x55, 0x1d, 0x13)), T(0x30, kids)));
    static string Dotted(params byte[] oid) => Assert.Single(AttestDer.ParseTbsExtensions(Tbs(T(0x30, T(0x06, oid), T(0x04)))).Oids);

    static long Utc(int y, int mo, int d = 1) => new DateTimeOffset(y, mo, d, 0, 0, 0, TimeSpan.Zero).ToUnixTimeMilliseconds();

    // ---- ReadTlvStrict (x509-strict.ts:27-36)

    [Fact]
    public void AOneOctetLongFormZeroIsBelow128NotALeadingZero()
    {
        Assert.Equal("DER: non-minimal length (long form below 128)", Why(() => AttestDer.ReadTlvStrict(B(0x30, 0x81, 0x00), 0, 3)));
        Assert.Equal("DER: non-minimal length (leading zero)", Why(() => AttestDer.ReadTlvStrict(B(0x30, 0x82, 0x00, 0x80), 0, 4)));
    }

    [Fact]
    public void TheLongFormStartsAt128()
    {
        var at128 = new byte[3 + 128];
        at128[0] = 0x30; at128[1] = 0x81; at128[2] = 0x80;
        Assert.Equal(new DerTlv(0x30, 3, 131), AttestDer.ReadTlvStrict(at128, 0, at128.Length));
        Assert.Equal("DER: non-minimal length (long form below 128)", Why(() => AttestDer.ReadTlvStrict(B(0x30, 0x81, 0x7f), 0, 3)));
    }

    // ---- ReadCertRoleInfo (x509-strict.ts:57-61, 64-125)

    [Fact]
    public void OnlyTheExactBasicConstraintsOidIsRead()
    {
        var caTrue = T(0x30, T(0x01, B(0xff)));
        foreach (var id in new[] { T(0x04, B(0x55, 0x1d, 0x13)), T(0x06, B(0x55, 0x1d, 0x13, 0x01)), T(0x06, B(0x55, 0x1d)) })
        {
            var info = AttestDer.ReadCertRoleInfo(Cert(Ext(id, caTrue)));
            Assert.False(info.HasBasicConstraints);
            Assert.False(info.Ca);
        }
        var real = AttestDer.ReadCertRoleInfo(Cert(Ext(T(0x06, B(0x55, 0x1d, 0x13)), caTrue)));
        Assert.True(real.HasBasicConstraints);
        Assert.True(real.Ca);
    }

    [Fact]
    public void ACertificateWithoutASequenceTbsHasNoRoles()
    {
        Assert.Equal("certificate has no tbsCertificate", Why(() => AttestDer.ReadCertRoleInfo(T(0x30, T(0x31)))));
    }

    [Fact]
    public void PathLenIsAOneOrTwoOctetBigEndianInteger()
    {
        var ca = T(0x01, B(0xff));
        Assert.Equal(1, AttestDer.ReadCertRoleInfo(BcCert(ca, T(0x02, B(1)))).PathLen);
        Assert.Equal(1, AttestDer.ReadCertRoleInfo(BcCert(T(0x02, B(1)))).PathLen);
        Assert.Equal(256, AttestDer.ReadCertRoleInfo(BcCert(ca, T(0x02, B(1, 0)))).PathLen);
        Assert.Equal(0x7fff, AttestDer.ReadCertRoleInfo(BcCert(ca, T(0x02, B(0x7f, 0xff)))).PathLen);
    }

    [Fact]
    public void AnyOtherPathLenIsMalformed()
    {
        var ca = T(0x01, B(0xff));
        foreach (var pl in new[] { T(0x02), T(0x02, B(1, 0, 0)), T(0x02, B(0x80)), T(0x04, B(1)), T(0x04) })
            Assert.Equal(PathLenBad, Why(() => AttestDer.ReadCertRoleInfo(BcCert(ca, pl))));
        // an empty INTEGER followed by a byte without the sign bit: only the length check refuses it
        var followed = T(0x30, BcCert(ca, T(0x02)).Skip(2).ToArray(), T(0x05));
        Assert.Equal(PathLenBad, Why(() => AttestDer.ReadCertRoleInfo(followed)));
    }

    // ---- OidToDotted, through ParseTbsExtensions (x509-strict.ts:133-152)

    [Fact]
    public void TheFirstArcSplitsAt40And80()
    {
        Assert.Equal("0.39.1", Dotted(0x27, 0x01));
        Assert.Equal("1.0.1", Dotted(0x28, 0x01));
        Assert.Equal("1.39.1", Dotted(0x4f, 0x01));
        Assert.Equal("2.0.1", Dotted(0x50, 0x01));
    }

    [Fact]
    public void AnArcMayNotStartWith0x80()
    {
        foreach (var oid in new[] { B(0x80, 0x01), B(0x2a, 0x80, 0x01) })
            Assert.Equal("extension OID has a non-minimal arc", Why(() => Dotted(oid)));
        Assert.Equal("1.2.128", Dotted(0x2a, 0x81, 0x00));
        Assert.Equal("1.2.16385", Dotted(0x2a, 0x81, 0x80, 0x01));
    }

    // ---- ParseTbsExtensions, TbsOfCertificate (x509-strict.ts:161-214)

    [Fact]
    public void ATbsMustBeASequence()
    {
        Assert.Equal("tbsCertificate is not a SEQUENCE", Why(() => AttestDer.ParseTbsExtensions(T(0x31))));
    }

    [Fact]
    public void AnExtensionMustBeASequence()
    {
        Assert.Equal("extension is not a SEQUENCE", Why(() => AttestDer.ParseTbsExtensions(Tbs(T(0x31, T(0x06, B(0x2a)), T(0x04))))));
    }

    [Fact]
    public void TbsOfCertificateRefusesAnOuterOrInnerNonSequence()
    {
        Assert.Equal("certificate is not a DER SEQUENCE", Why(() => AttestDer.TbsOfCertificate(T(0x31, T(0x30)))));
        Assert.Equal("certificate has no tbsCertificate", Why(() => AttestDer.TbsOfCertificate(T(0x30, T(0x31)))));
        var tbs = T(0x30, T(0x05));
        Assert.Equal(tbs, AttestDer.TbsOfCertificate(T(0x30, tbs, T(0x05))));
    }

    // ---- StrictChainError (x509-strict.ts:266-278)

    [Fact]
    public void AnExtensionTableTheRoleReaderToleratesStillFailsTheStrictProfile()
    {
        // the role reader takes any critical flag, the strict table only the DER TRUE
        var cert = Cert(T(0x30, T(0x06, B(0x2a, 0x03)), T(0x01, B(0x00)), T(0x04)));
        Assert.Null(AttestDer.CheckChainRoles(new[] { cert }));
        Assert.Equal("certificate extension parse failed: extension 1.2.3 has a non-DER critical flag", AttestDer.StrictChainError(new[] { cert }));
    }

    // ---- TlvAt (x509-validity.ts:29-44)

    [Fact]
    public void TlvAtReadsDefiniteLengthsUpToFourOctets()
    {
        Assert.Equal(new DerTlv(0x30, 2, 3), AttestDer.TlvAt(B(0x30, 0x01, 0xaa), 0));
        Assert.Equal(new DerTlv(0x30, 3, 4), AttestDer.TlvAt(B(0x30, 0x81, 0x01, 0xaa), 0));
        Assert.Equal(new DerTlv(0x30, 6, 7), AttestDer.TlvAt(B(0x30, 0x84, 0, 0, 0, 1, 0xaa), 0));
    }

    [Fact]
    public void TlvAtRefusalsCarryTheReferenceMessages()
    {
        Assert.Equal("truncated", Why(() => AttestDer.TlvAt(B(0x30), 0)));
        Assert.Equal("truncated", Why(() => AttestDer.TlvAt(B(0x30, 0x05, 0x01), 0)));
        Assert.Equal("truncated", Why(() => AttestDer.TlvAt(B(0x30, 0x81, 0x02, 0x01), 0)));
        Assert.Equal("bad length", Why(() => AttestDer.TlvAt(B(0x30, 0x80, 0x00), 0)));
        Assert.Equal("bad length", Why(() => AttestDer.TlvAt(B(0x30, 0x85, 0, 0, 0, 0, 1, 0xaa), 0)));
        Assert.Equal("bad length", Why(() => AttestDer.TlvAt(B(0x30, 0x82, 0x01), 0)));
        Assert.Equal("bad length", Why(() => AttestDer.TlvAt(B(0x30, 0x84, 0x00, 0x00), 0)));
    }

    // ---- ParseDerTime (x509-validity.ts:46, 53-72)

    [Fact]
    public void AnEmptyStringIsNotDigits()
    {
        Assert.False(AttestDer.AllAsciiDigits("")); // DIGITS is /^\d+$/
        Assert.True(AttestDer.AllAsciiDigits("0189"));
        Assert.False(AttestDer.AllAsciiDigits("01a"));
    }

    [Fact]
    public void AGeneralizedTimeNeedsDigitsAndTheZ()
    {
        Assert.Equal(new DerInstant(Utc(2024, 1, 1), true), AttestDer.ParseDerTime(0x18, "20240101000000Z"));
        Assert.False(AttestDer.ParseDerTime(0x18, "2024010100000aZ").Ok);
        Assert.False(AttestDer.ParseDerTime(0x18, "20240101000000X").Ok);
    }

    [Fact]
    public void TheLeapYearRuleIsGregorian()
    {
        foreach (var (y, d) in new[] { (2000, "20000229"), (1996, "19960229"), (2400, "24000229") })
            Assert.Equal(new DerInstant(Utc(y, 2, 29), true), AttestDer.ParseDerTime(0x18, d + "000000Z"));
        foreach (var d in new[] { "19000229", "21000229", "20230229", "20000230" })
            Assert.False(AttestDer.ParseDerTime(0x18, d + "000000Z").Ok);
    }

    [Fact]
    public void EachShortMonthHasThirtyDays()
    {
        foreach (var m in new[] { 4, 6, 9, 11 })
        {
            Assert.Equal(new DerInstant(Utc(2024, m, 30), true), AttestDer.ParseDerTime(0x18, $"2024{m:00}30000000Z"));
            Assert.False(AttestDer.ParseDerTime(0x18, $"2024{m:00}31000000Z").Ok);
        }
        foreach (var m in new[] { 1, 3, 5, 7, 8, 10, 12 })
            Assert.Equal(new DerInstant(Utc(2024, m, 31), true), AttestDer.ParseDerTime(0x18, $"2024{m:00}31000000Z"));
    }

    [Fact]
    public void YearZeroIsAProlepticLeapYear()
    {
        // setUTCFullYear(0, ...): days_from_civil 0000-03-01 is -719468; January and February of year 0 fall in the era before it
        const long day = 86_400_000;
        Assert.Equal(new DerInstant(-719528L * day, true), AttestDer.ParseDerTime(0x18, "00000101000000Z"));
        Assert.Equal(new DerInstant(-719469L * day, true), AttestDer.ParseDerTime(0x18, "00000229000000Z"));
        Assert.Equal(new DerInstant(-719468L * day, true), AttestDer.ParseDerTime(0x18, "00000301000000Z"));
        Assert.Equal(-719834L * day, AttestDer.EpochMs(-1, 3, 1, 0, 0, 0));
    }

    // ---- EpochMs (Date.UTC: a month outside 1..12 carries into the year)

    [Fact]
    public void MonthsCarryIntoTheYearInBothDirections()
    {
        foreach (var (mon, y, m) in new[] { (14, 1971, 2), (15, 1971, 3), (25, 1972, 1), (-1, 1969, 11), (-10, 1969, 2), (-11, 1969, 1), (-12, 1968, 12) })
            Assert.Equal(Utc(y, m), AttestDer.EpochMs(1970, mon, 1, 0, 0, 0));
    }

    // ---- DerValidity (x509-validity.ts:75-100)

    static readonly byte[] Nb = T(0x17, Encoding.ASCII.GetBytes("200101000000Z")), Na = T(0x17, Encoding.ASCII.GetBytes("300101000000Z"));
    static readonly byte[] Serial = T(0x02, B(1)), Sig = T(0x30), Issuer = T(0x30);
    static readonly long From = Utc(2020, 1), To = Utc(2030, 1);
    static readonly byte[] Windowed = T(0x30, T(0x30, Serial, Sig, Issuer, T(0x30, Nb, Na)));

    [Fact]
    public void ValidityMayBeTheLastTbsElement()
    {
        var (f, t) = AttestDer.DerValidity(Windowed);
        Assert.Equal(new DerInstant(From, true), f);
        Assert.Equal(new DerInstant(To, true), t);
    }

    [Fact]
    public void ValidityMustBeASequenceInsideTheTbs()
    {
        Assert.False(AttestDer.DerValidity(T(0x30, T(0x30, Serial, Sig, Issuer, T(0x31, Nb, Na)))).From.Ok);
        // the element is a well-formed SEQUENCE of two times, but its header sits in the TBS and its content after it
        var times = Nb.Concat(Na).ToArray();
        var cut = T(0x30, T(0x30, Serial, Sig, Issuer, new byte[] { 0x30, (byte)times.Length }), times);
        Assert.False(AttestDer.DerValidity(cut).From.Ok);
    }

    // ---- x509ValidAt (x509-validity.ts:137-141)

    [Fact]
    public void TheSkewWidensBothBounds()
    {
        foreach (var (now, skew, want) in new (long, long, bool)[]
        {
            (From, 0, true), (From - 1, 0, false), (To, 0, true), (To + 1, 0, false),
            (From - 500, 1000, true), (From - 1000, 1000, true), (From - 1001, 1000, false),
            (To + 500, 1000, true), (To + 1000, 1000, true), (To + 1001, 1000, false),
        })
            Assert.Equal(want, AttestDer.DerValidAt(Windowed, now, skew));
        Assert.False(AttestDer.DerValidAt(B(0x30), From, 0));
    }

    [Fact]
    public void TheFractionalSkewWidensBothBounds()
    {
        foreach (var (now, skew, want) in new (long, double, bool)[]
        {
            (From, 0, true), (From - 1, 0, false), (To, 0, true), (To + 1, 0, false),
            (From - 500, 1000, true), (From - 1000, 1000, true), (From - 1001, 1000, false),
            (To + 500, 1000, true), (To + 1000, 1000, true), (To + 1001, 1000, false),
            (To, 0.5, true), (To + 1, 0.5, false), (From - 1, 0.5, false),
        })
            Assert.Equal(want, AttestDer.DerValidAtF(Windowed, now, skew));
        Assert.False(AttestDer.DerValidAtF(B(0x30), From, 0));
    }
}
