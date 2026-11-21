using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The compact-JWS plumbing against the reference (packages/pca/src/strict-jws.ts, attest-azure-maa.ts:236-268 and
/// attest-gcp-confidential-space.ts:247-280, 325-335, 482-505): the key builders, the signature checks and the wording of V8's JSON.parse
/// failures, which the token verifiers embed in the reason they return.</summary>
public class AttestJwsKillTests
{
    const string Unsupported = "error:1E08010C:DECODER routines::unsupported";
    const string TooDeep = "nesting too deep";
    const string ArrayEnd = "Expected ',' or ']' after array element";
    const string BadUnicode = "Bad Unicode escape";
    const string BadControl = "Bad control character in string literal";
    const string BadEscape = "Bad escaped character";
    const string Unterminated = "Unterminated string";

    static readonly byte[] Msg = Encoding.ASCII.GetBytes("h.p");
    static readonly RSA Kp = RSA.Create(2048);
    static readonly ECDsa P256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    static string Err(string text) => V8Json.Error(text);
    static string At(string what, int pos, int line, int col) => $"{what} in JSON at position {pos} (line {line} column {col})";
    static string At1(string what, int pos) => At(what, pos, 1, pos + 1);
    static string Refused(Action a) => Assert.Throws<AttestError>(a).Message;
    static string B64(params byte[] b) => Pca.B64u(b);
    static string Seg(string s) => Pca.B64u(Encoding.UTF8.GetBytes(s));
    static byte[] Cat(params byte[][] a) => a.SelectMany(x => x).ToArray();
    static byte[] B(params byte[] b) => b;
    static string Deep(int n) => new string('[', n) + new string(']', n);

    sealed class ThrowEc : ECDsa
    {
        public override byte[] SignHash(byte[] hash) => throw new CryptographicException("boom");
        public override bool VerifyHash(byte[] hash, byte[] signature) => throw new CryptographicException("boom");
    }

    sealed class ThrowRsa : RSA
    {
        public override RSAParameters ExportParameters(bool includePrivateParameters) => throw new CryptographicException("boom");
        public override void ImportParameters(RSAParameters parameters) => throw new CryptographicException("boom");
        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) => throw new CryptographicException("boom");
    }

    // ---- JwtParsed defaults, JwkKtyCrv

    [Fact]
    public void AParsedTokenStartsWithNoAlgAndNoKid()
    {
        Assert.Equal("", new JwtParsed().Alg);
        Assert.Equal("", new JwtParsed().Kid);
    }

    [Fact]
    public void KtyAndCrvFollowTheJwkExportOfEachKeyType()
    {
        Assert.Equal(("OKP", "Ed25519"), AttestJws.JwkKtyCrv(new CertKey { Type = "ed25519" }));
        Assert.Equal(("x448", "undefined"), AttestJws.JwkKtyCrv(new CertKey { Type = "x448" }));
        Assert.Equal(("RSA", "undefined"), AttestJws.JwkKtyCrv(new CertKey { Type = "rsa", Rsa = Kp }));
        Assert.Equal(("EC", "P-256"), AttestJws.JwkKtyCrv(new CertKey { Type = "ec", Ec = P256, GoCurve = "P-256" }));
    }

    // ---- Es256Ok, Rs256Ok

    [Fact]
    public void Es256VerifiesOnlyARawSignatureUnderAP256Key()
    {
        var sig = P256.SignData(Msg, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.True(AttestJws.Es256Ok(sig, Msg, new CertKey { Ec = P256, GoCurve = "P-256" }));
        Assert.False(AttestJws.Es256Ok(sig, Msg, new CertKey { GoCurve = "P-256" }));
        Assert.False(AttestJws.Es256Ok(sig, Msg, new CertKey()));
        // a genuine signature under a key that does not claim P-256: only the curve check refuses it
        Assert.False(AttestJws.Es256Ok(sig, Msg, new CertKey { Ec = P256, GoCurve = "P-384" }));
        Assert.False(AttestJws.Es256Ok(sig[..63], Msg, new CertKey { Ec = P256, GoCurve = "P-256" }));
    }

    [Fact]
    public void AVerificationFailureInsideTheEngineIsARefusal()
    {
        Assert.False(AttestJws.Es256Ok(new byte[64], Msg, new CertKey { Ec = new ThrowEc(), GoCurve = "P-256" }));
        Assert.False(AttestJws.Rs256Ok(new byte[256], Msg, new CertKey { Type = "rsa", Rsa = new ThrowRsa() }));
    }

    [Fact]
    public void Rs256VerifiesOnlyAPkcs1SignatureUnderAnUnrestrictedRsaKey()
    {
        var sig = Kp.SignData(Msg, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(AttestJws.Rs256Ok(sig, Msg, new CertKey { Type = "rsa", Rsa = Kp }));
        Assert.False(AttestJws.Rs256Ok(sig, Msg, new CertKey { Type = "rsa" }));
        Assert.False(AttestJws.Rs256Ok(sig, Msg, new CertKey()));
        Assert.False(AttestJws.Rs256Ok(sig, Msg, new CertKey { Type = "rsa-pss", Rsa = Kp }));
    }

    // ---- JwkRsaKey

    [Fact]
    public void AnRsaJwkBuildsAPublicKeyWithItsModulusTrimmed()
    {
        var p = Kp.ExportParameters(false);
        var k = AttestJws.JwkRsaKey(B64(Cat(B(0, 0), p.Modulus!)), B64(Cat(B(0), p.Exponent!)));
        Assert.Equal("rsa", k.Type);
        Assert.Equal(p.Modulus, k.Rsa!.ExportParameters(false).Modulus);
        Assert.Equal(Kp.ExportSubjectPublicKeyInfo(), k.Spki);
        Assert.False(k.RsaBc!.IsPrivate);
        Assert.True(AttestJws.Rs256Ok(Kp.SignData(Msg, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Msg, k));
    }

    [Fact]
    public void AnEmptyModulusOrExponentIsRefused()
    {
        var n = B64(Kp.ExportParameters(false).Modulus!);
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey("", "AQAB")));
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(n, "")));
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey("", "")));
    }

    [Fact]
    public void TheRsaExponentIsABigEndianUnsignedValueFrom3To2147483647()
    {
        var n = B64(Kp.ExportParameters(false).Modulus!);
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(n, B64(1))));
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(n, B64(2))));
        Assert.Equal("rsa", AttestJws.JwkRsaKey(n, B64(3)).Type);
        Assert.Equal("rsa", AttestJws.JwkRsaKey(n, B64(0x83)).Type); // the high bit is not a sign
        Assert.Equal("rsa", AttestJws.JwkRsaKey(n, B64(0x7f, 0xff, 0xff, 0xff)).Type);
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(n, B64(0x80, 0, 0, 1))));
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(n, B64(0x83, 0, 0, 1)))); // small only when read little-endian
    }

    // ---- JwkEcKey

    static void PinEcKey(string crv, string ossl, ECCurve curve)
    {
        using var ec = ECDsa.Create(curve);
        var q = ec.ExportParameters(false).Q;
        var k = AttestJws.JwkEcKey(crv, B64(q.X!), B64(q.Y!));
        Assert.Equal("ec", k.Type);
        Assert.Equal(ossl, k.Curve);
        Assert.Equal(crv, k.GoCurve);
        Assert.Equal(Cat(B(4), q.X!, q.Y!), k.EcPoint);
        Assert.Equal(ec.ExportSubjectPublicKeyInfo(), k.Spki);
    }

    [Fact]
    public void EachNamedCurveBuildsItsKeyAndNames()
    {
        PinEcKey("P-256", "prime256v1", ECCurve.NamedCurves.nistP256);
        PinEcKey("P-384", "secp384r1", ECCurve.NamedCurves.nistP384);
        PinEcKey("P-521", "secp521r1", ECCurve.NamedCurves.nistP521);
    }

    [Fact]
    public void AnUnknownCurveIsRefused() => Assert.Equal(Unsupported, Refused(() => AttestJws.JwkEcKey("P-224", "AQ", "AQ")));

    [Fact]
    public void ACoordinateWithLeadingZerosIsTrimmedThenPadded()
    {
        var q = P256.ExportParameters(false).Q;
        var k = AttestJws.JwkEcKey("P-256", B64(Cat(B(0), q.X!)), B64(Cat(B(0, 0), q.Y!)));
        Assert.Equal(Cat(B(4), q.X!, q.Y!), k.EcPoint);
    }

    [Fact]
    public void ACoordinateShorterThanTheFieldIsLeftPadded()
    {
        // half of the P-521 coordinates have a zero top byte, so this ends in a few tries
        for (int i = 0; i < 4096; i++)
        {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP521);
            var q = ec.ExportParameters(false).Q;
            if (q.X![0] != 0 || q.Y![0] != 0) continue;
            var k = AttestJws.JwkEcKey("P-521", B64(q.X[1..]), B64(q.Y[1..]));
            Assert.Equal(Cat(B(4), q.X, q.Y), k.EcPoint);
            return;
        }
        Assert.Fail("no short coordinates generated");
    }

    [Fact]
    public void ACoordinateLongerThanTheFieldIsRefused()
    {
        var q = P256.ExportParameters(false).Q;
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkEcKey("P-256", B64(Cat(B(1), q.X!)), B64(q.Y!))));
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkEcKey("P-256", B64(q.X!), B64(Cat(B(1), q.Y!)))));
    }

    [Fact]
    public void AnAllZeroCoordinateIsOffTheCurveAndRefused()
    {
        var q = P256.ExportParameters(false).Q;
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkEcKey("P-256", "AAAA", B64(q.Y!))));
    }

    // ---- the depth cap of the wording walk

    [Fact]
    public void TheWordingWalkStopsAtTheDepthCapOfTheParser()
    {
        Assert.Equal(512, Pca.LenientMaxDepth);
        Assert.Equal("", Err(Deep(512)));
        Assert.Equal(TooDeep, Err(Deep(513)));
        string Objs(int n) => string.Concat(Enumerable.Repeat("{\"a\":", n)) + "1" + new string('}', n);
        Assert.Equal("", Err(Objs(512)));
        Assert.Equal(TooDeep, Err(Objs(513)));
    }

    [Fact]
    public void TheDepthCapEndsTheWalkAtOnce()
    {
        Assert.Equal("Unexpected token 'x', ...\"[[[[[[[[[[x\" is not valid JSON", Err(new string('[', 512) + "x"));
        Assert.Equal(TooDeep, Err(new string('[', 513) + "x"));
    }

    [Fact]
    public void SiblingsDoNotCountAsDepth() => Assert.Equal("", Err("[" + string.Join(",", Enumerable.Repeat("[]", 600)) + "]"));

    [Fact]
    public void ATokenSegmentOverTheDepthCapIsAMalformedSegment()
    {
        Assert.Equal("p: header is not a JSON object", Refused(() => AttestJws.ParseJwt($"{Seg(Deep(512))}.{Seg("{}")}.AQ", "p")));
        Assert.Equal("p: malformed JSON segment: nesting too deep", Refused(() => AttestJws.ParseJwt($"{Seg(Deep(513))}.{Seg("{}")}.AQ", "p")));
    }

    [Fact, Trait("Category", "Huge")]
    public void AHostileDeepSegmentDoesNotExhaustTheStack()
    {
        Assert.Equal(TooDeep, Err(new string('[', 1_000_000)));
        Assert.Equal("p: malformed JSON segment: nesting too deep", Refused(() => AttestJws.ParseJwt($"{Seg(new string('[', 1_000_000))}.{Seg("{}")}.AQ", "p")));
    }

    // ---- line and column

    [Fact]
    public void EveryLineTerminatorSpellingCountsOnce()
    {
        Assert.Equal(At(ArrayEnd, 4, 2, 3), Err("[\n1 x"));
        Assert.Equal(At(ArrayEnd, 4, 2, 3), Err("[\r1 x"));
        Assert.Equal(At(ArrayEnd, 5, 2, 3), Err("[\r\n1 x"));
        Assert.Equal(At(ArrayEnd, 5, 3, 3), Err("[\n\n1 x"));
    }

    [Fact]
    public void ACarriageReturnAtTheEndOfTheDocumentIsALineTerminator() => Assert.Equal(At(ArrayEnd, 3, 2, 1), Err("[1\r"));

    [Fact]
    public void LineTerminatorsAtOrAfterTheFailureDoNotCount()
    {
        Assert.Equal(At(BadControl, 2, 1, 3), Err("\"a\nb\""));
        Assert.Equal(At(ArrayEnd, 3, 1, 4), Err("[1 x\n]"));
    }

    // ---- the unexpected-token wording (ctx = 10, short below 21 characters)

    [Fact]
    public void AnUnexpectedTokenInAShortDocumentQuotesItWhole()
    {
        Assert.Equal("Unexpected token 'x', \"x\" is not valid JSON", Err("x"));
        Assert.Equal("Unexpected token 'x', \"[\"abcdefghijklmn\",xA\" is not valid JSON", Err("[\"abcdefghijklmn\",xA"));
    }

    [Fact]
    public void TwentyOneCharactersIsNoLongerShort() =>
        Assert.Equal("Unexpected token 'x', ...\"ghijklmn\",xAB\" is not valid JSON", Err("[\"abcdefghijklmn\",xAB"));

    [Fact]
    public void AnUnexpectedTokenNearTheStartQuotesTheStart()
    {
        Assert.Equal("Unexpected token 'x', \"xABCDEFGHI\"... is not valid JSON", Err("xABCDEFGHIJKLMNOPQRSTUVWXYZ123"));
        Assert.Equal("Unexpected token 'x', \"[\"abcde\",xABCDEFGHI\"... is not valid JSON", Err("[\"abcde\",xABCDEFGHIJKLMNOPQRST"));
    }

    [Fact]
    public void AnUnexpectedTokenInTheMiddleQuotesBothSides()
    {
        Assert.Equal("Unexpected token 'x', ...\"[\"abcdef\",xABCDEFGHI\"... is not valid JSON", Err("[\"abcdef\",xABCDEFGHIJKLMNOPQRS"));
        Assert.Equal("Unexpected token 'x', ...\"hijklmno\",xABCDEFGHI\"... is not valid JSON", Err("[\"abcdefghijklmno\",xABCDEFGHIJ"));
    }

    [Fact]
    public void AnUnexpectedTokenNearTheEndQuotesTheEnd() =>
        Assert.Equal("Unexpected token 'x', ...\"ijklmnop\",xABCDEFGHI\" is not valid JSON", Err("[\"abcdefghijklmnop\",xABCDEFGHI"));

    [Fact]
    public void TheEngineSpecialStringsHaveTheirOwnWording()
    {
        Assert.Equal("\"NaN\" is not valid JSON", Err("NaN"));
        Assert.Equal("\"Infinity\" is not valid JSON", Err("Infinity"));
        Assert.Equal("\"undefined\" is not valid JSON", Err("undefined"));
        Assert.Equal("\"[object Object]\" is not valid JSON", Err("[object Object]"));
        Assert.Equal("Unexpected token 'N', \"NaNx\" is not valid JSON", Err("NaNx"));
    }

    [Fact]
    public void ANulIsAnUnexpectedTokenNotTheEndOfInput() => Assert.Equal("Unexpected token '\0', \"\0\" is not valid JSON", Err("\0"));

    // ---- whitespace, literals, numbers

    [Fact]
    public void AllFourWhitespaceCharactersAreSkipped()
    {
        foreach (var d in new[] { " 1", "\t1", "\n1", "\r1", "1 ", "1\t", "1\n", "1\r", "[\n1]", "[\r1]", "\t[\n1\r]\n" }) Assert.Equal("", Err(d));
    }

    [Fact]
    public void EachLiteralIsConsumedInFull()
    {
        foreach (var d in new[] { "true", "false", "null", "[true,false,null]" }) Assert.Equal("", Err(d));
    }

    [Fact]
    public void ATruncatedLiteralIsTheEndOfInput()
    {
        foreach (var d in new[] { "t", "tru", "fals", "nul" }) Assert.Equal("Unexpected end of JSON input", Err(d));
    }

    [Fact]
    public void AWrongLiteralCharacterIsAnUnexpectedToken()
    {
        Assert.Equal("Unexpected token 'x', \"tx\" is not valid JSON", Err("tx"));
        Assert.Equal("Unexpected token 'a', \"nan\" is not valid JSON", Err("nan"));
    }

    [Fact]
    public void ValidNumbersPass()
    {
        foreach (var d in new[] { "0", "9", "19", "-0", "-9", "1.5", "1.25", "1.9", "1e5", "1E5", "1e+5", "1e-5", "1.25e-12", "1e19", "[9]" }) Assert.Equal("", Err(d));
    }

    [Fact]
    public void EachNumberFailureEndsTheNumber()
    {
        Assert.Equal(At1("No number after minus sign", 1), Err("-."));
        Assert.Equal(At1("Unterminated fractional number", 2), Err("1.e"));
        Assert.Equal(At1("Unterminated fractional number", 2), Err("1.x"));
        Assert.Equal(At1("Exponent part is missing a number", 3), Err("1e+"));
        Assert.Equal(At1("Exponent part is missing a number", 3), Err("1e-x"));
        Assert.Equal(At1("Unexpected number", 1), Err("01"));
    }

    // ---- strings

    [Fact]
    public void ControlCharactersEndAStringButASpaceDoesNot()
    {
        Assert.Equal("", Err("\"a b\""));
        Assert.Equal(At(BadControl, 2, 1, 3), Err("\"a\nb"));
        Assert.Equal(At1(BadControl, 2), Err("\"a\tb\""));
        Assert.Equal(At1(BadControl, 2), Err("\"a\u001fb\""));
        Assert.Equal(At1(BadControl, 2), Err("\"a\0b\""));
    }

    [Fact]
    public void AnUnterminatedStringIsReportedAtTheEnd()
    {
        Assert.Equal(At1(Unterminated, 2), Err("\"a"));
        Assert.Equal(At1(Unterminated, 2), Err("\"\\"));
    }

    [Fact]
    public void EachSimpleEscapeIsConsumed()
    {
        foreach (var e in "\"\\/bfnrt") Assert.Equal("", Err($"\"\\{e}\""));
        Assert.Equal("", Err("\"\\\\x\""));
    }

    [Fact]
    public void AnyOtherEscapedCharacterIsRefused()
    {
        Assert.Equal(At1(BadEscape, 2), Err("\"\\x\""));
        Assert.Equal(At1(BadEscape, 2), Err("\"\\x"));
        Assert.Equal(At1(BadEscape, 2), Err("\"\\\0\""));
    }

    [Fact]
    public void AUnicodeEscapeTakesExactlyFourHexDigits()
    {
        Assert.Equal("", Err("\"\\u0041\""));
        Assert.Equal("", Err("\"\\u00410\""));
        Assert.Equal("", Err("\"\\u09aF\""));
        Assert.Equal(At1(BadUnicode, 6), Err("\"\\u004\""));
        Assert.Equal(At1(BadUnicode, 4), Err("\"\\u0Z\""));
        Assert.Equal(At1(BadUnicode, 3), Err("\"\\uZ"));
        Assert.Equal(At1(BadUnicode, 3), Err("\"\\uZZZZ\""));
    }

    [Fact]
    public void TheHexDigitRangesAreExact()
    {
        foreach (var c in "09afAF") Assert.Equal("", Err($"\"\\u{c}{c}{c}{c}\""));
        foreach (var c in "/:`g@G") Assert.Equal(At1(BadUnicode, 3), Err($"\"\\u{c}000\""));
    }

    // ---- objects

    [Fact]
    public void ValidObjectsPass()
    {
        foreach (var d in new[] { "{}", "{ }", "{\"a\":1}", "{\"a\":1,\"b\":2}", "{ \"a\" : 1 , \"b\" : 2 }", "{\"a\":[]}" }) Assert.Equal("", Err(d));
    }

    [Fact]
    public void EachObjectFailureEndsTheWalk()
    {
        Assert.Equal(At1("Expected property name or '}'", 1), Err("{x"));
        Assert.Equal(At1(Unterminated, 3), Err("{\"a"));
        Assert.Equal(At1("Expected ':' after property name", 4), Err("{\"a\"x"));
        Assert.Equal("Unexpected token 'x', \"{\"a\":x\" is not valid JSON", Err("{\"a\":x"));
        Assert.Equal(At1("Expected double-quoted property name", 7), Err("{\"a\":1,}"));
        Assert.Equal(At1("Expected ',' or '}' after property value", 7), Err("{\"a\":1 x"));
    }

    // ---- arrays

    [Fact]
    public void ValidArraysPass()
    {
        foreach (var d in new[] { "[]", "[ ]", "[1]", "[1 ]", "[1,2]", "[1, 2]", " [ 1 , 2 ] " }) Assert.Equal("", Err(d));
    }

    [Fact]
    public void EachArrayFailureEndsTheWalk()
    {
        Assert.Equal("Unexpected token 'x', \"[x\" is not valid JSON", Err("[x"));
        Assert.Equal(At1(ArrayEnd, 3), Err("[1 x"));
        Assert.Equal(At1(ArrayEnd, 3), Err("[1 x]"));
    }

    [Fact]
    public void AnRsaKeyOutsideTheKeyRuleIsRefusedWhateverTheImportWouldDo()
    {
        var n = B64(Kp.ExportParameters(false).Modulus!);
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(n, B64(4)))); // an even exponent
        var small = new byte[32]; // an odd 256-bit modulus
        Array.Fill(small, (byte)0xff);
        Assert.Equal(Unsupported, Refused(() => AttestJws.JwkRsaKey(B64(small), B64(1, 0, 1))));
    }
}
