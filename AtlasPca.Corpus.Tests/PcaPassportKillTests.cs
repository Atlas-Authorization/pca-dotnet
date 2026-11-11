using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 Stryker survivors of Pca.cs (goal v3 messages, the stored-grant root PQ authority, PQ length pins) and Passport.cs
/// (every structural refusal on both sides of each <c>||</c>, the clock / evidence-age boundaries, the default hardware verifier).</summary>
public class PcaPassportKillTests
{
    const long T = 1_800_000_000_000L;
    static string B32a => Pca.B64u(new byte[32]);
    static string B32b => Pca.B64u(Enumerable.Repeat((byte)7, 32).ToArray());

    static EdKey Ed(byte b) => EdKey.FromSeed(Enumerable.Repeat(b, 32).ToArray());

    // ================= Pca.cs =================

    [Fact]
    public void IntentGoalV3RefusesAMalformedDigestWithTheExactMessage()
    {
        var e = Assert.Throws<ArgumentException>(() => Pca.IntentGoalV3(new ApprovedGoalRef("x", B32b)));
        Assert.Equal("IntentGoalV3: goal_digest and policy_digest must be canonical base64url (32 bytes)", e.Message);
        Assert.Equal("pca-intent:v3:" + B32a + ":" + B32b, Pca.IntentGoalV3(new ApprovedGoalRef(B32a, B32b)));
    }

    [Fact]
    public void DecideIntentV3MismatchNamesTheApprovedGoal()
    {
        var ag = new ApprovedGoalRef(B32a, B32b);
        var policy = new IntentPolicy(ApprovedGoal: ag);
        var intent = new JD { ["ref"] = B32a, ["map_digest"] = B32b, ["goal_salt"] = "salt", ["fidelity_ppm"] = new Num("1000000"), ["residual_risk_ppm"] = new Num("0") };
        JD Grant(string commit) => new() { ["caveats"] = new JL { new JD { ["type"] = "envelope", ["goal_commit"] = commit } } };
        Assert.Equal("the root grant's goal commitment does not open to the approved goal and compiled policy (v3)",
            Pca.DecideIntent(intent, true, Grant(B32a), policy));
        Assert.Equal("", Pca.DecideIntent(intent, true, Grant(Pca.IntentGoalCommitV3(ag, "salt")), policy));
        // without v3 the other reason
        Assert.Equal("intent ref / map_digest / goal_salt do not open the root grant's goal commitment",
            Pca.DecideIntent(intent, true, Grant(B32a), new IntentPolicy(Require: true)));
    }

    static JD Envelope() => new()
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } },
        ["caveats"] = new JL(),
        ["risk_policy"] = Issue.DefaultRiskPolicy(),
    };

    const string RootNeedsPin = "hop 0: root suite 'hybrid-ed25519-ml-dsa-65' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)";

    [Fact]
    public void HybridRootIsAcceptedOnlyUnderTheStoredGrantOrAPin()
    {
        var principal = SuiteKey.Create("hybrid-ed25519-ml-dsa-65", Ed(0x21), PqKey.Generate(Pq.Prim.MlDsa65));
        var g = Issue.MintGrant(principal, Ed(0x22).Id, null, Envelope(), "g");
        var root = Issue.NormJ(g.Grant);
        var chain = new JL { root };
        // the verifier's own stored grant (same content hash) is the PQ authority
        Assert.Equal(("", true), Pca.VerifyChain(chain, principal.Id, true, trustedRoot: Issue.NormJ(g.Grant)));
        Assert.Equal(("", true), Pca.VerifyChain(chain, principal.Id, true, pqPins: principal.PqPin()));
        // no authority, a different stored grant, or one that cannot be canonicalised: refused (fail closed)
        Assert.Equal((RootNeedsPin, false), Pca.VerifyChain(chain, principal.Id, true));
        var other = Issue.NormJ(Issue.MintGrant(principal, Ed(0x23).Id, null, Envelope(), "g").Grant);
        Assert.Equal((RootNeedsPin, false), Pca.VerifyChain(chain, principal.Id, true, trustedRoot: other));
        var junk = new JD(root) { ["x"] = 9007199254740992L }; // unsafe integer: CapHash throws
        Assert.Equal((RootNeedsPin, false), Pca.VerifyChain(chain, principal.Id, true, trustedRoot: junk));
    }

    [Fact]
    public void PqVerifyPinsExactKeyAndSignatureLengths()
    {
        var msg = new byte[] { 1, 2, 3 };
        foreach (var prim in new[] { Pq.Prim.MlDsa65, Pq.Prim.Slh128f })
        {
            var k = PqKey.Generate(prim);
            var sig = k.Sign(msg);
            Assert.True(Pq.Verify(prim, k.Pk, msg, sig), $"{prim}: a real signature verifies");
            Assert.False(Pq.Verify(prim, k.Pk, new byte[] { 1, 2, 4 }, sig));
            Assert.False(Pq.Verify(prim, [.. k.Pk, 0], msg, sig));
            Assert.False(Pq.Verify(prim, k.Pk[..^1], msg, sig));
            Assert.False(Pq.Verify(prim, k.Pk, msg, [.. sig, 0]));
            Assert.False(Pq.Verify(prim, k.Pk, msg, sig[..^1]));
        }
        Assert.False(Pq.Verify(Pq.Prim.None, Array.Empty<byte>(), msg, Array.Empty<byte>()));
    }

    // ================= Passport.cs: structure (no signature needed: an untrusted issuer is the next refusal) =================

    static JD Raw() => new()
    {
        ["typ"] = "atlas-pca/passport", ["ver"] = 1L,
        ["passport"] = new JD { ["id"] = "pid", ["model_id"] = "m", ["operator"] = "o", ["hardware_rooted"] = false },
        ["iss"] = "iss", ["sub"] = "sub", ["sig"] = "sig", ["nbf"] = 1L, ["exp"] = 2L, ["iat"] = 1L,
    };

    static PassportOptions Untrusted(long now = 1) => new() { NowMs = now, Revoked = (_, _, _) => false };

    static string? R(JD s, PassportOptions? o = null) => Passports.Verify(s, o ?? Untrusted()).Reason;

    [Fact]
    public void EachRequiredFieldAloneIsMalformed()
    {
        Assert.Equal("unknown_issuer", R(Raw()));
        foreach (var k in new[] { "iss", "sub", "sig" })
        {
            var s = Raw(); s.Remove(k);
            Assert.Equal("malformed", R(s));
            s = Raw(); s[k] = ""; // an empty string is absent
            Assert.Equal("malformed", R(s));
        }
        foreach (var k in new[] { "id", "model_id", "operator" })
        {
            var s = Raw(); ((JD)s["passport"]!).Remove(k);
            Assert.Equal("malformed", R(s));
            s = Raw(); ((JD)s["passport"]!)[k] = "";
            Assert.Equal("malformed", R(s));
        }
    }

    [Fact]
    public void TimesMustBeSafeIntegersWithExpAfterNbf()
    {
        var s = Raw(); s.Remove("iat");
        Assert.Equal("malformed", R(s));
        s = Raw(); s["nbf"] = -9007199254740992L; // unsafe, with exp/iat fine and exp > nbf
        Assert.Equal("malformed", R(s));
        s = Raw(); s["exp"] = 9007199254740992L;
        Assert.Equal("malformed", R(s));
        s = Raw(); s["nbf"] = 2L; s["exp"] = 2L;
        Assert.Equal("malformed", R(s));
        s = Raw(); s["nbf"] = 2L; s["exp"] = 3L;
        Assert.Equal("unknown_issuer", R(s));
        Assert.Equal("unknown_issuer", R(Raw(), Untrusted(Pca.MaxSafeInt)));
        Assert.Equal("unknown_issuer", R(Raw(), Untrusted(-Pca.MaxSafeInt)));
        Assert.Equal("malformed", R(Raw(), Untrusted(Pca.MaxSafeInt + 1)));
    }

    [Fact]
    public void AnUncanonicalisableBodyAndAThrowAreMalformed()
    {
        var s = Raw(); s["x"] = 9007199254740992L;
        var v = Passports.Verify(s, new PassportOptions { TrustedIssuers = new[] { "iss" }, NowMs = 1, Revoked = (_, _, _) => false });
        Assert.Equal("malformed", v.Reason);
        Assert.False(v.Ok);
        v = Passports.Verify(Raw(), null!); // the outer catch
        Assert.Equal("malformed", v.Reason);
        Assert.False(v.Ok);
    }

    // ================= Passport.cs: signed =================

    static SuiteKey Issuer => SuiteKey.Ed25519(Ed(0x31));
    const long Exp = T + 3_600_000L;

    static JD Signed(bool hw = false, JD? evidence = null) =>
        Issue.SignPassport(Issue.IssuePassport(new JD { ["model_id"] = "m1", ["operator"] = "acme", ["hardware_rooted"] = hw }), Issuer, "agent", T, Exp, null, evidence);

    static PassportOptions Opt(long now, long? skew = null) => new()
    {
        TrustedIssuers = new[] { Issuer.Id! }, NowMs = now, ClockSkewMs = skew, Revoked = (_, _, _) => false,
        Attest = (_, _) => new PassportAttestation(true, true, new JD { ["model_id"] = "m1", ["operator"] = "acme" }),
    };

    [Fact]
    public void OkIsTheAbsenceOfAReason()
    {
        var v = Passports.Verify(Signed(), Opt(T));
        Assert.Null(v.Reason);
        Assert.True(v.Ok);
        Assert.False(new PassportVerdict("expired").Ok);
    }

    [Fact]
    public void ClockSkewIsClampedToZeroAndSixtySeconds()
    {
        var s = Signed();
        Assert.Equal("not_yet_valid", Passports.Verify(s, Opt(T - 1, 0)).Reason);
        Assert.Equal("not_yet_valid", Passports.Verify(s, Opt(T - 1, -5000)).Reason);
        Assert.Equal("not_yet_valid", Passports.Verify(s, Opt(T - 1)).Reason);
        Assert.Null(Passports.Verify(s, Opt(T - 60_000, 120_000)).Reason);
        Assert.Equal("not_yet_valid", Passports.Verify(s, Opt(T - 60_001, 120_000)).Reason);
    }

    [Fact]
    public void ExpiryAppliesSkewInTheHoldersFavour()
    {
        var s = Signed();
        Assert.Null(Passports.Verify(s, Opt(Exp - 500, 1000)).Reason);
        Assert.Null(Passports.Verify(s, Opt(Exp + 999, 1000)).Reason);
        Assert.Equal("expired", Passports.Verify(s, Opt(Exp + 1000, 1000)).Reason);
        Assert.Equal("expired", Passports.Verify(s, Opt(Exp)).Reason);
        Assert.Null(Passports.Verify(s, Opt(Exp - 1)).Reason);
    }

    static JD Ev(object? at) => new() { ["document"] = new JD { ["nonce"] = "n1" }, ["at"] = at };

    [Fact]
    public void EvidenceTimeMustBeASafeInteger()
    {
        // signPassport refuses it (passport.ts:227), so the verifier's own refusal is reached by a passport another issuer signed
        var bad = new JD(Signed(true, Ev(T)));
        bad.Remove("sig");
        bad["evidence"] = new JD((JD)bad["evidence"]!) { ["at"] = "x" };
        bad["sig"] = Issuer.Sign(Pca.Cat(System.Text.Encoding.UTF8.GetBytes(Passports.SigDomain), Pca.Canon(bad))).Sig;
        Assert.Equal("hardware_evidence_missing", Passports.Verify(bad, Opt(T)).Reason);
        Assert.Null(Passports.Verify(Signed(true, Ev(T)), Opt(T)).Reason);
    }

    [Fact]
    public void SignPassportRefusesAnEvidenceTimeThatIsNoSafeInteger()
    {
        foreach (var at in new object?[] { "x", null, 1.5, 9007199254740992L })
            Assert.Equal("signPassport: evidence.at must be a safe integer", Assert.Throws<ArgumentException>(() => Signed(true, Ev(at))).Message);
    }

    [Fact]
    public void EvidenceAgeBoundariesAreInclusive()
    {
        var s = Signed(true, Ev(T));
        PassportOptions Age(long now, long? max, long? skew = null) { var o = Opt(now, skew); o.MaxEvidenceAgeMs = max; return o; }
        Assert.Null(Passports.Verify(s, Age(T, 0)).Reason); // max age 0 accepts evidence taken right now
        Assert.Equal("hardware_evidence_stale", Passports.Verify(s, Age(T, -1)).Reason);
        Assert.Null(Passports.Verify(s, Age(T + 1000, 1000)).Reason);
        Assert.Equal("hardware_evidence_stale", Passports.Verify(s, Age(T + 1001, 1000)).Reason);
        // evidence from the future: tolerated up to the clock skew
        Assert.Null(Passports.Verify(Signed(true, Ev(T + 500)), Age(T, null, 500)).Reason);
        Assert.Equal("hardware_evidence_stale", Passports.Verify(Signed(true, Ev(T + 501)), Age(T, null, 500)).Reason);
    }

    sealed class StubVendor : IVendorVerifier
    {
        public JD? Got;
        public string Vendor => "stub";
        public HardwareResult Verify(JD? evidence, AttestationBinding? expected, long nowMs)
        {
            Got = evidence;
            return new HardwareResult(true, true, null, new JD { ["model_id"] = "m1", ["operator"] = "acme" });
        }
    }

    [Fact]
    public void DefaultHardwareWithoutAnEvidenceMapperVerifiesTheDocumentItself()
    {
        var s = Signed(true, Ev(T));
        var stub = new StubVendor();
        var o = new PassportOptions { TrustedIssuers = new[] { Issuer.Id! }, NowMs = T, Revoked = (_, _, _) => false, DefaultHardware = new DefaultHardware(stub) };
        var v = Passports.Verify(s, o);
        Assert.Null(v.Reason);
        Assert.True(v.HardwareVerified);
        Assert.Same(((JD)s["evidence"]!)["document"], stub.Got);
    }
}
