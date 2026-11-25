using System.Text;
using AtlasPca;
using AtlasPca.Events;
using AtlasPca.WebBotAuth;
using Xunit;
using Vc_ = AtlasPca.Vc.Vc;

namespace AtlasPca.Corpus.Tests;

/// <summary>Signed JSON received from outside is read as the signer wrote it: a duplicate member is refused (a plain parse keeps the last one). Events use
/// the strict canonical profile; third-party documents (WebAuthn client data, key directories) get the duplicate check only; attestation tokens are strict.</summary>
public class DuplicateMemberKillTests
{
    [Theory]
    [InlineData("{\"id\":\"a\",\"id\":\"b\"}")]            // duplicate member
    [InlineData("{\"id\":\"a\",\"at\":1e3}")]              // exponent form
    [InlineData("{\"id\":\"a\",\"at\":1.0}")]              // trailing-zero fraction
    [InlineData("{\"id\":\"\\ud800\"}")]                   // lone surrogate escape
    public void AnEventTextOutsideTheStrictProfileIsRefusedAtParseTime(string text) =>
        Assert.Throws<StrictJsonException>(() => StepUpEvents.ParseEvent(text));

    [Fact]
    public void TheDuplicateCheckSeesNestedAndEscapedMembersAndLeavesNumbersAlone()
    {
        Assert.Equal("a", NoDuplicateKeys.DuplicateKey("{\"x\":{\"a\":1,\"a\":2}}"));
        Assert.Equal("a", NoDuplicateKeys.DuplicateKey("{\"a\":1,\"\\u0061\":2}")); // keys compare after unescaping
        Assert.Null(NoDuplicateKeys.DuplicateKey("{\"a\":{\"a\":1},\"b\":[{\"a\":1},{\"a\":2}]}")); // the same name in different objects is fine
        Assert.NotNull(NoDuplicateKeys.Parse("{\"n\":1e3,\"m\":1.0}")); // no number profile here
        var e = Assert.Throws<FormatException>(() => NoDuplicateKeys.Parse("{\"keys\":[],\"keys\":[]}"));
        Assert.Equal("duplicate key \"keys\"", e.Message);
    }

    [Fact]
    public void AKeyDirectoryWithADuplicateMemberIsRefused() =>
        Assert.Equal("duplicate key \"keys\"", Assert.Throws<FormatException>(() => SignedDirectory.ParseKeyDirectory("{\"keys\":[],\"keys\":[]}")).Message);

    static string Seg(string json) => Pca.B64u(Encoding.UTF8.GetBytes(json));

    [Theory]
    [InlineData("parseMaaJwt")]
    [InlineData("parseGcpCsJwt")]
    public void AnAttestationTokenWithADuplicateMemberIsInvalidJson(string parser)
    {
        var dupPayload = Seg("{\"a\":1,\"a\":2}");
        var dupHeader = Seg("{\"alg\":\"ES256\",\"alg\":\"none\"}");
        var ok = Seg("{\"alg\":\"ES256\"}");
        Assert.Equal(parser + ": malformed JSON segment: invalid JSON", Assert.Throws<AttestError>(() => AttestJws.ParseJwt(ok + "." + dupPayload + ".c2ln", parser)).Message);
        Assert.Equal(parser + ": malformed JSON segment: invalid JSON", Assert.Throws<AttestError>(() => AttestJws.ParseJwt(dupHeader + "." + Seg("{}") + ".c2ln", parser)).Message);
    }
}

/// <summary>The sites that read signed or digested JSON received from outside: a duplicate member is refused (only the first is what another parser sees as
/// signed), with the duplicate check only (no number profile). Fixtures are signed here with throwaway keys.</summary>
public class DuplicateMemberSiteKillTests
{
    static string B64u(string s) => Pca.B64u(Encoding.UTF8.GetBytes(s));

    [Fact]
    public void AStripeWebhookBodyWithADuplicateMemberIsBadJson()
    {
        var secret = "whsec_" + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        const long now = 1_700_000_000;
        var body = "{\"type\":\"x\",\"type\":\"issuing_authorization.request\"}";
        var header = Payments.StripeRails.SignStripePayload(body, secret, now);
        var r = Payments.StripeRails.StripeIssuingWebhook(body, header, secret, now, _ => new Dictionary<string, object?> { ["approved"] = true });
        Assert.Equal("{\"error\":\"bad_json\"}", r["body"]);
        Assert.Equal("400", Convert.ToString(((Num)r["status"]!).Raw));
        // numbers keep the sender's spelling: 8.0 / 1e3 are not a refusal here
        var okBody = "{\"type\":\"other\",\"n\":8.0,\"e\":1e3}";
        var ok = Payments.StripeRails.StripeIssuingWebhook(okBody, Payments.StripeRails.SignStripePayload(okBody, secret, now), secret, now, _ => new Dictionary<string, object?> { ["approved"] = true });
        Assert.Equal("{}", ok["body"]);
    }

    [Fact]
    public void AnSdJwtIssuerPayloadWithADuplicateMemberIsRefused()
    {
        var sig = Pca.B64u(new byte[64]);
        var sdjwt = $"{B64u("{\"alg\":\"EdDSA\"}")}.{B64u("{\"_sd\":[],\"_sd\":[\"x\"]}")}.{sig}~";
        Assert.ThrowsAny<Exception>(() => AtlasPca.Sdjwt.Sdjwt.Present(sdjwt, new List<object?>()));
    }

    [Fact]
    public void AVcDisclosureWithADuplicateMemberIsMalformed()
    {
        var seed = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var pub = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded();
        string Vc(string disclosureText)
        {
            var disclosure = B64u(disclosureText);
            var digest = Pca.B64u(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));
            var subject = new Dictionary<string, object?>
            {
                ["id"] = "did:example:s", ["passport_id"] = "p", ["model_id"] = "m", ["operator"] = "o", ["hardware_rooted"] = true, ["issued_at"] = new Num("1"),
                ["_sd"] = new List<object?> { digest },
            };
            var payload = new Dictionary<string, object?>
            {
                ["vc"] = new Dictionary<string, object?>
                {
                    ["@context"] = new List<object?> { Vc_.VcContext, Vc_.AgentPassportContext },
                    ["type"] = new List<object?> { "VerifiableCredential", Vc_.AgentPassportVcType },
                    ["credentialSubject"] = subject,
                },
                ["_sd_alg"] = "sha-256", ["iss"] = "did:example:i", ["sub"] = "did:example:s",
            };
            var jwt = AtlasPca.Jose.Jose.SignJwt(new Dictionary<string, object?> { ["alg"] = "EdDSA", ["typ"] = "vc+sd-jwt" }, payload, AtlasPca.Jose.Jose.Ed25519SeedJwk(seed));
            return jwt + "~" + disclosure + "~";
        }
        var e = Assert.Throws<InvalidOperationException>(() => Vc_.VerifyPassportVC(Vc("[\"s\",\"weights_digest\",{\"a\":1,\"a\":2}]"), pub));
        Assert.Equal("pca-vc: malformed disclosure", e.Message);
        // a number spelled 8.0 / 1e3 is not a refusal
        Assert.NotNull(Vc_.VerifyPassportVC(Vc("[8.0,\"weights_digest\",\"dd\"]"), pub));
        Assert.NotNull(Vc_.VerifyPassportVC(Vc("[1e3,\"weights_digest\",\"dd\"]"), pub));
    }

    [Theory]
    [InlineData("parseMaaJwt")]
    [InlineData("parseGcpCsJwt")]
    public void VendorTokenNumbersStayAsWrittenAndNonJsonReadsInvalidJson(string parser)
    {
        // real vendor tokens are not canonical JSON: 8.0, 1e3 and -0 are not a refusal (only a duplicate member is)
        var ok = AttestJws.ParseJwt(B64u("{\"alg\":\"ES256\"}") + "." + B64u("{\"a\":8.0,\"b\":1e3,\"c\":-0}") + ".c2ln", parser);
        Assert.Equal("ES256", ok.Alg);
        Assert.Equal(parser + ": malformed JSON segment: invalid JSON", Assert.Throws<AttestError>(() => AttestJws.ParseJwt(B64u("not json") + "." + B64u("{}") + ".c2ln", parser)).Message);
    }

    // an EAT (header and payload) with a duplicate member is refused (the native's canonical gate is strict JSON, which also refuses a duplicate)
    [Fact]
    public void AnEatWithADuplicateHeaderOrPayloadMemberIsRefused()
    {
        var seed = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var priv = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(seed, 0);
        var key = AtlasPca.AttestEat.EatKey.Ed25519Public(priv.GeneratePublicKey().GetEncoded());
        string Eat(string header, string payload)
        {
            var input = B64u(header) + "." + B64u(payload);
            var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
            signer.Init(true, priv);
            var data = Encoding.UTF8.GetBytes(input);
            signer.BlockUpdate(data, 0, data.Length);
            return input + "." + Pca.B64u(signer.GenerateSignature());
        }
        const string hdr = "{\"alg\":\"EdDSA\",\"typ\":\"eat+jwt\"}";
        var e1 = Assert.Throws<ArgumentException>(() => AtlasPca.AttestEat.EatToken.VerifyEat(Eat(hdr, "{\"iss\":\"a\",\"iss\":\"b\",\"iat\":1}"), key));
        Assert.StartsWith("EAT invalid:", e1.Message);
        var e2 = Assert.Throws<ArgumentException>(() => AtlasPca.AttestEat.EatToken.VerifyEat(Eat("{\"alg\":\"EdDSA\",\"alg\":\"none\",\"typ\":\"eat+jwt\"}", "{\"iss\":\"a\",\"iat\":1}"), key));
        Assert.StartsWith("EAT invalid:", e2.Message);
        Assert.Equal("a", AtlasPca.AttestEat.EatToken.VerifyEat(Eat(hdr, "{\"iss\":\"a\",\"iat\":1}"), key)["iss"]);
    }
}
